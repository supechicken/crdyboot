// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides an implementation of the kernel's UEFI initrd loading
//! protocol required for providing an initramfs buffer to the kernel.
//!
//! This allows the kernel to boot from a normal PE/COFF entry point
//! instead of using the [deprecated EFI handover protocol].
//!
//! This includes a [LoadFile2Protocol] implementation that provides the
//! passed in initramfs to the kernel.
//! This protocol is registered on the [LINUX_EFI_INITRD_MEDIA_GUID] vendor device path
//! the kernel will use to locate the protocol.
//!
//! The kernel will:
//!  * Call [`LocateDevicePath`] with a path containing the vendor device with
//!    [LINUX_EFI_INITRD_MEDIA_GUID] supports the [LoadFile2Protocol].
//!  * Call this [LoadFile2Protocol] with NULL to get the size of the initramfs.
//!  * Allocate a buffer of the necessary size.
//!  * Call the [LoadFile2Protocol] again to request a copy of the the initramfs.
//!
//! [LoadFile2Protocol]: https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#efi-load-file2-protocol
//! [deprecated EFI handover protocol]: https://docs.kernel.org/arch/x86/boot.html#efi-handover-protocol-deprecated
//! [LINUX_EFI_INITRD_MEDIA_GUID]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/drivers/firmware/efi/libstub/efi-stub-helper.c?h=v6.6.60#n467
//! [`LocateDevicePath`]: https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#efi-boot-services-locatedevicepath
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr;
use libcrdy::page_alloc::ScopedPageAllocation;
use log::error;
use uefi::proto::device_path::build;
use uefi::runtime::VariableVendor;
use uefi::{boot, guid, Handle};
use uefi_raw::protocol::device_path::DevicePathProtocol;
use uefi_raw::protocol::media::LoadFile2Protocol;
use uefi_raw::Status;

/// GUID of the vendor device the kernel uses to search
/// for the initrd protocol.
///
/// See [LINUX_EFI_INITRD_MEDIA_GUID].
///
/// [LINUX_EFI_INITRD_MEDIA_GUID]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/dc4cbf9e2df4d2ad361659aa037f5a9b0d32691f/drivers/firmware/efi/libstub/efi-stub-helper.c#467
const LINUX_EFI_INITRD_MEDIA_GUID: VariableVendor =
    VariableVendor(guid!("5568e427-68fc-4f3d-ac74-ca555231cc68"));

/// Configure and install the protocol handler for the kernel during the
/// UEFI boot process.
/// `initramfs_buffer` will be provided to the kernel when it requests
/// the initrd.
pub fn set_up_loadfile_protocol(initramfs_buffer: ScopedPageAllocation) -> InitramfsProtoHolder {
    // TODO: return errors when it is unable to be loaded.
    let mut ph = InitramfsProtoHolder::new(initramfs_buffer);
    ph.install_protocol();
    ph
}

/// C callback for [EFI_LOAD_FILE2_PROTOCOL.LoadFile].
///
/// [EFI_LOAD_FILE2_PROTOCOL.LoadFile]: https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#efi-load-file2-protocol-loadfile
unsafe extern "efiapi" fn efi_load_file_initramfs(
    this: *mut LoadFile2Protocol,
    _file_path: *const DevicePathProtocol,
    boot_policy: bool,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if boot_policy {
        return Status::UNSUPPORTED;
    }
    // Ignorning `_file_path` as it will always point to
    // the terminator `DeviceType::END`, `DeviceSubType::END_ENTIRE`
    // since it is an exact match from [`LocateDevicePath`].
    // This callback is only registered for that exact path.
    //
    // [`LocateDevicePath`]: https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#efi-boot-services-locatedevicepath
    // DeviceSubType
    let this = &*this.cast::<InitramfsLoadFile2Protocol>();
    this.load_file(buffer_size, buffer.cast())
}

/// Manages the loadfile2 protocol handler for the kernel's EFI
/// bootstub's initrd discovery and load mechanism.
pub struct InitramfsProtoHolder {
    proto: Pin<Box<InitramfsLoadFile2Protocol>>,
    device_path: Pin<Vec<u8>>,
    handle: Option<Handle>,
}

impl InitramfsProtoHolder {
    fn new(initramfs_buffer: ScopedPageAllocation) -> Self {
        // Buffer for the device path builder.
        let mut device_path: Vec<u8> = Vec::new();

        // Build the Linux initramfs media device path.
        build::DevicePathBuilder::with_vec(&mut device_path)
            .push(&build::media::Vendor {
                vendor_guid: LINUX_EFI_INITRD_MEDIA_GUID.0,
                vendor_defined_data: &[],
            })
            .unwrap()
            .finalize()
            .unwrap();

        let proto = InitramfsLoadFile2Protocol::new(initramfs_buffer);
        InitramfsProtoHolder {
            proto,
            handle: None,
            device_path: Pin::new(device_path),
        }
    }

    fn proto_ptr(&self) -> *const c_void {
        ptr::from_ref(&*self.proto).cast()
    }

    /// Install the `LINUX_EFI_INITRD_MEDIA_GUID` vendor device path
    /// and the `LoadFile2Protocol` handler onto that path.
    fn install_protocol(&mut self) {
        // Register the path and protocol with two calls to
        // install interface.
        // Potentially this could use [`InstallMultipleProtocolInterfaces`]
        // but that variadic interface isn't provided by the uefi crate.
        //
        // [`InstallMultipleProtocolInterfaces`]: https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#efi-boot-services-installmultipleprotocolinterfaces
        self.handle = None;
        // Install the special Linux media vendor device
        // path.
        let dev_handle = match unsafe {
            boot::install_protocol_interface(
                None,
                &DevicePathProtocol::GUID,
                self.device_path.as_ptr().cast(),
            )
        } {
            Ok(dev_handle) => dev_handle,
            Err(err) => {
                error!("Unable to install device path: {err}");
                return;
            }
        };

        // Install the loadfile2 protocol handler on the Linux
        // vendor device path handle.
        self.handle = match unsafe {
            boot::install_protocol_interface(
                Some(dev_handle),
                &LoadFile2Protocol::GUID,
                self.proto_ptr(),
            )
        } {
            Ok(proto_handle) => Some(proto_handle),
            Err(err) => {
                error!("Unable to install the LoadFile2Protocol: {err}");
                self.uninstall_device_protocol(dev_handle);
                None
            }
        };
    }

    fn uninstall_device_protocol(&self, handle: Handle) {
        if let Err(err) = unsafe {
            boot::uninstall_protocol_interface(
                handle,
                &DevicePathProtocol::GUID,
                self.device_path.as_ptr().cast(),
            )
        } {
            error!("Unable to uninstall the device path: {err}.");
        };
    }

    fn uninstall_protocol(&mut self) {
        let Some(handle) = self.handle else {
            return;
        };
        self.handle = None;
        unsafe {
            if let Err(err) = boot::uninstall_protocol_interface(
                handle,
                &LoadFile2Protocol::GUID,
                self.proto_ptr(),
            ) {
                error!("Unable to uninstall the LoadFile2Protocol: {err}.");
            };
            self.uninstall_device_protocol(handle);
        }
    }
}

impl Drop for InitramfsProtoHolder {
    fn drop(&mut self) {
        self.uninstall_protocol();
    }
}

/// `LoadFile2Protocol` implementation that loads the given `initramfs_buffer`
/// for any callers.
#[repr(C)]
struct InitramfsLoadFile2Protocol {
    efi_protocol: LoadFile2Protocol,
    initramfs_buffer: ScopedPageAllocation,
    _pin: PhantomPinned,
}

impl InitramfsLoadFile2Protocol {
    fn new(initramfs_buffer: ScopedPageAllocation) -> Pin<Box<Self>> {
        Box::pin(Self {
            efi_protocol: LoadFile2Protocol {
                load_file: efi_load_file_initramfs,
            },
            initramfs_buffer,
            _pin: PhantomPinned,
        })
    }

    /// Perform the buffer loading part of [EFI_LOAD_FILE2_PROTOCOL.LoadFile].
    ///
    /// # Returns
    ///
    /// - `Status::BUFFER_TOO_SMALL` if `buf` is NULL or `buf_len` is too
    ///   small and `buf_len` is set to the required size of the buffer.
    /// - `Status::SUCCESS` and `buf_len` is set to the number of bytes
    ///   copied to `buf`.
    ///
    /// [EFI_LOAD_FILE2_PROTOCOL.LoadFile]: https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#efi-load-file2-protocol-loadfile
    fn load_file(&self, buf_len: *mut usize, buf: *mut c_void) -> Status {
        let buf_len = unsafe { &mut *buf_len };
        if buf.is_null() || *buf_len < self.initramfs_buffer.len() {
            *buf_len = self.initramfs_buffer.len();
            Status::BUFFER_TOO_SMALL
        } else {
            unsafe {
                ptr::copy_nonoverlapping(
                    self.initramfs_buffer.as_ptr(),
                    buf.cast(),
                    self.initramfs_buffer.len(),
                );
            }
            *buf_len = self.initramfs_buffer.len();
            Status::SUCCESS
        }
    }
}
