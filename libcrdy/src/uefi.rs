// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod uefi_disk;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::device_path::DevicePath;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::disk::DiskIo;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::{unsafe_protocol, Protocol};
use uefi::runtime::{
    self, CapsuleBlockDescriptor, CapsuleHeader, CapsuleInfo, ResetType, Time, VariableAttributes,
    VariableKey, VariableVendor,
};
use uefi::table::Revision;
use uefi::{guid, system, CStr16, Handle, Status};

pub use uefi_disk::BlockIoError;

/// Arbitrarily-chosen GUID for UEFI variables specific to crdyboot and
/// crdyshim.
pub const CRDYBOOT_VAR_VENDOR: VariableVendor =
    VariableVendor(guid!("2a6f93c9-29ea-46bf-b618-271b63baacf3"));

/// Interface for accessing UEFI boot services and UEFI runtime services.
///
/// The implementation used at runtime is normally `UefiImpl`; unit
/// tests can use `MockUefi` instead.
#[cfg_attr(feature = "test_util", mockall::automock)]
pub trait Uefi {
    fn get_uefi_revision(&self) -> Revision;

    fn get_time(&self) -> uefi::Result<Time>;

    /// Get an iterator over all UEFI variable keys.
    fn variable_keys(&self) -> VariableKeys;

    /// Read a UEFI variable into `buf`.
    ///
    /// If successful, returns the size of the variable and the variable
    /// attributes.
    ///
    /// If the buffer is not large enough, the error value contains the
    /// required size.
    fn get_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        buf: &mut [u8],
    ) -> uefi::Result<(usize, VariableAttributes), Option<usize>>;

    fn get_variable_boxed(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
    ) -> uefi::Result<(Box<[u8]>, VariableAttributes)>;

    /// Set a UEFI variable, or delete it if `data` is empty.
    fn set_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> uefi::Result;

    fn delete_variable(&self, name: &CStr16, vendor: &VariableVendor) -> uefi::Result;

    // Lifetime needed here due to the `mockall::automock` macro.
    #[allow(clippy::needless_lifetimes)]
    fn query_capsule_capabilities<'a>(
        &self,
        capsule_header_array: &[&'a CapsuleHeader],
    ) -> uefi::Result<CapsuleInfo>;

    // Lifetime needed here due to the `mockall::automock` macro.
    #[allow(clippy::needless_lifetimes)]
    fn update_capsule<'a>(
        &self,
        capsule_header_array: &[&'a CapsuleHeader],
        capsule_block_descriptors: &[CapsuleBlockDescriptor],
    ) -> uefi::Result;

    /// Reset the system.
    ///
    /// The actual UEFI implementation of this never returns.
    fn reset(&self, reset_type: ResetType);

    fn find_ata_pass_through_handles(&self) -> uefi::Result<Vec<Handle>>;

    fn find_block_io_handles(&self) -> uefi::Result<Vec<Handle>>;

    fn find_nvme_express_pass_through_handles(&self) -> uefi::Result<Vec<Handle>>;

    fn find_sd_mmc_pass_through_handles(&self) -> uefi::Result<Vec<Handle>>;

    fn find_simple_file_system_handles(&self) -> uefi::Result<Vec<Handle>>;

    fn device_path_for_handle(&self, handle: Handle) -> uefi::Result<ScopedDevicePath>;

    /// Find the [`Handle`] corresponding to the ESP partition that this
    /// executable is running from.
    fn find_esp_partition_handle(&self) -> uefi::Result<Option<Handle>>;

    /// Open the Block IO protocol for `handle`.
    ///
    /// # Safety
    ///
    /// This is `unsafe` because the protocol is opened in non-exclusive
    /// mode. Opening disk handles in exclusive mode can be very slow --
    /// on the x1cg9, it takes over 800ms.
    unsafe fn open_block_io(&self, handle: Handle) -> uefi::Result<ScopedBlockIo>;

    /// Open the Disk IO protocol for `handle`.
    ///
    /// # Safety
    ///
    /// This is `unsafe` because the protocol is opened in non-exclusive
    /// mode. Opening disk handles in exclusive mode can be very slow --
    /// on the x1cg9, it takes over 800ms.
    unsafe fn open_disk_io(&self, handle: Handle) -> uefi::Result<ScopedDiskIo>;

    /// Open the `LoadedImage` protocol for handle in exclusive mode.
    fn open_loaded_image(&self, handle: Handle) -> uefi::Result<ScopedLoadedImage>;

    /// Connect one or more drivers to a controller.
    ///
    /// This sets the `recursive` parameter of `connect_controller` to true.
    fn connect_controller_recursive(&self, controller: Handle) -> uefi::Result;
}

pub struct UefiImpl;

impl Uefi for UefiImpl {
    fn get_uefi_revision(&self) -> Revision {
        system::uefi_revision()
    }

    fn get_time(&self) -> uefi::Result<Time> {
        runtime::get_time()
    }

    fn variable_keys(&self) -> VariableKeys {
        VariableKeys::Real(uefi::runtime::variable_keys())
    }

    fn get_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        buf: &mut [u8],
    ) -> uefi::Result<(usize, VariableAttributes), Option<usize>> {
        runtime::get_variable(name, vendor, buf)
            // Map from buf to buf.len to avoid needing a buffer
            // lifetime tying input to output; that wouldn't work with
            // mockall.
            .map(|(buf, attr)| (buf.len(), attr))
    }

    fn get_variable_boxed(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
    ) -> uefi::Result<(Box<[u8]>, VariableAttributes)> {
        runtime::get_variable_boxed(name, vendor)
    }

    fn set_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> uefi::Result {
        runtime::set_variable(name, vendor, attributes, data)
    }

    fn delete_variable(&self, name: &CStr16, vendor: &VariableVendor) -> uefi::Result {
        runtime::delete_variable(name, vendor)
    }

    fn query_capsule_capabilities(
        &self,
        capsule_header_array: &[&CapsuleHeader],
    ) -> uefi::Result<CapsuleInfo> {
        runtime::query_capsule_capabilities(capsule_header_array)
    }

    fn update_capsule(
        &self,
        capsule_header_array: &[&CapsuleHeader],
        capsule_block_descriptors: &[CapsuleBlockDescriptor],
    ) -> uefi::Result {
        runtime::update_capsule(capsule_header_array, capsule_block_descriptors)
    }

    fn reset(&self, reset_type: ResetType) {
        runtime::reset(reset_type, Status::SUCCESS, None);
    }

    fn find_block_io_handles(&self) -> uefi::Result<Vec<Handle>> {
        boot::find_handles::<BlockIO>()
    }

    fn find_ata_pass_through_handles(&self) -> uefi::Result<Vec<Handle>> {
        boot::find_handles::<AtaPassThrough>()
    }

    fn find_nvme_express_pass_through_handles(&self) -> uefi::Result<Vec<Handle>> {
        boot::find_handles::<NvmeExpressPassThrough>()
    }

    fn find_sd_mmc_pass_through_handles(&self) -> uefi::Result<Vec<Handle>> {
        boot::find_handles::<SdMmcPassThrough>()
    }

    fn find_simple_file_system_handles(&self) -> uefi::Result<Vec<Handle>> {
        boot::find_handles::<SimpleFileSystem>()
    }

    fn device_path_for_handle(&self, handle: Handle) -> uefi::Result<ScopedDevicePath> {
        // Safety: this protocol cannot be opened in exclusive
        // mode. This is OK here as device paths are immutable.
        unsafe {
            boot::open_protocol(
                OpenProtocolParams {
                    handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .map(ScopedDevicePath::new)
    }

    fn find_esp_partition_handle(&self) -> uefi::Result<Option<Handle>> {
        // Get the LoadedImage protocol for the image handle. This provides
        // a device handle which should correspond to the partition that the
        // image was loaded from.
        let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;
        Ok(loaded_image.device())
    }

    unsafe fn open_block_io(&self, handle: Handle) -> uefi::Result<ScopedBlockIo> {
        boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map(ScopedBlockIo::new)
    }

    unsafe fn open_disk_io(&self, handle: Handle) -> uefi::Result<ScopedDiskIo> {
        boot::open_protocol::<DiskIo>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map(ScopedDiskIo::new)
    }

    fn open_loaded_image(&self, handle: Handle) -> uefi::Result<ScopedLoadedImage> {
        boot::open_protocol_exclusive::<LoadedImage>(handle).map(ScopedLoadedImage::new)
    }

    fn connect_controller_recursive(&self, controller: Handle) -> uefi::Result {
        let driver_image_handle = None;
        let remaining_device_path = None;
        let recursive = true;
        boot::connect_controller(
            controller,
            driver_image_handle,
            remaining_device_path,
            recursive,
        )
    }
}

enum ScopedProtocolInner<P: Protocol + ?Sized> {
    Protocol(boot::ScopedProtocol<P>),
    #[cfg(feature = "test_util")]
    ForTest(Box<P>),
    #[cfg(feature = "test_util")]
    ForTestUnsafe(*mut P),
}

/// Wrapper around `uefi::boot::ScopedProtocol` that allows for mocking.
pub struct ScopedProtocol<P: Protocol + ?Sized>(ScopedProtocolInner<P>);

impl<P: Protocol + ?Sized> ScopedProtocol<P> {
    /// Create a `ScopedProtocol` that wraps a `uefi::boot::ScopedProtocol`.
    #[inline]
    fn new(p: boot::ScopedProtocol<P>) -> Self {
        Self(ScopedProtocolInner::Protocol(p))
    }

    /// Create a `ScopedProtocol` from a boxed protocol.
    ///
    /// The protocol is boxed so that dynamically-sized structs such as
    /// `DevicePath` work.
    ///
    /// This method is only available in tests.
    #[cfg(feature = "test_util")]
    pub fn for_test(p: Box<P>) -> Self {
        Self(ScopedProtocolInner::ForTest(p))
    }

    /// Create a `ScopedProtocol` from a raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this pointer is valid until the
    /// `ScopedProtocol` is dropped. The caller must ensure that the
    /// pointer is not dereferenced except through this
    /// `ScopedProtocol`, until the `ScopedProtocol` is dropped.
    #[cfg(feature = "test_util")]
    pub unsafe fn for_test_unsafe(p: *mut P) -> Self {
        Self(ScopedProtocolInner::ForTestUnsafe(p))
    }
}

impl<P: Protocol + ?Sized> Deref for ScopedProtocol<P> {
    type Target = P;

    #[inline]
    fn deref(&self) -> &P {
        match &self.0 {
            ScopedProtocolInner::Protocol(p) => p,
            #[cfg(feature = "test_util")]
            ScopedProtocolInner::ForTest(p) => p,
            #[cfg(feature = "test_util")]
            ScopedProtocolInner::ForTestUnsafe(p) => unsafe { &**p },
        }
    }
}

impl<P: Protocol + ?Sized> DerefMut for ScopedProtocol<P> {
    #[inline]
    fn deref_mut(&mut self) -> &mut P {
        match &mut self.0 {
            ScopedProtocolInner::Protocol(p) => p,
            #[cfg(feature = "test_util")]
            ScopedProtocolInner::ForTest(p) => p,
            #[cfg(feature = "test_util")]
            ScopedProtocolInner::ForTestUnsafe(p) => unsafe { &mut **p },
        }
    }
}

pub type ScopedBlockIo = ScopedProtocol<BlockIO>;
pub type ScopedDevicePath = ScopedProtocol<DevicePath>;
pub type ScopedDiskIo = ScopedProtocol<DiskIo>;
pub type ScopedLoadedImage = ScopedProtocol<LoadedImage>;

/// Iterator over all UEFI variable keys.
pub enum VariableKeys {
    Real(uefi::runtime::VariableKeys),
    #[cfg(feature = "test_util")]
    ForTest(Vec<uefi::Result<VariableKey>>),
}

impl Iterator for VariableKeys {
    type Item = uefi::Result<VariableKey>;

    fn next(&mut self) -> Option<uefi::Result<VariableKey>> {
        match self {
            Self::Real(iter) => iter.next().map(|r| match r {
                Ok(key) => Ok(VariableKey {
                    vendor: key.vendor,
                    name: key.name,
                }),
                Err(err) => Err(err),
            }),
            #[cfg(feature = "test_util")]
            Self::ForTest(v) => {
                if v.is_empty() {
                    None
                } else {
                    Some(v.remove(0))
                }
            }
        }
    }
}

// Stub definitions for protocols not defined in uefi-rs.

#[unsafe_protocol("1d3de7f0-0807-424f-aa69-11a54e19a46f")]
#[repr(C)]
struct AtaPassThrough {
    _data: [usize; 8],
}

#[unsafe_protocol("52c78312-8edc-4233-98f2-1a1aa5e388a5")]
#[repr(C)]
struct NvmeExpressPassThrough {
    _data: [usize; 5],
}

#[unsafe_protocol("716ef0d9-ff83-4f69-81e9-518bd39a8e70")]
#[repr(C)]
struct SdMmcPassThrough {
    _data: [usize; 5],
}
