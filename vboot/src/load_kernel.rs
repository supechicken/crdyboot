// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::{Disk, DiskIo};
use crate::{return_code_to_str, vboot_sys, ReturnCode};
use alloc::string::{String, ToString};
use core::ffi::c_void;
use core::ops::Range;
use core::{fmt, mem, ptr, str};
use log::{error, info};
use uguid::Guid;

/// Fully verified kernel loaded into memory.
pub struct LoadedKernel<'a> {
    data: &'a [u8],
    cros_config: Range<usize>,
    unique_partition_guid: Guid,
}

/// Errors produced by `load_kernel`.
#[derive(Clone, Copy)]
pub enum LoadKernelError {
    /// Failed to convert numeric type.
    BadNumericConversion(&'static str),

    /// An arithmetic operation overflowed.
    Overflow(&'static str),

    /// Packed pubkey buffer is too small.
    PubkeyTooSmall(usize),

    /// Call to `vb2api_init` failed.
    ApiInitFailed(ReturnCode),

    /// Call to vb2api_init_ctx_for_kernel_verification_only` failed.
    ApiKernelInitFailed(ReturnCode),

    /// Call to `LoadKernel` failed.
    LoadKernelFailed(ReturnCode),

    /// Bootloader range is not valid.
    BadBootloaderRange {
        /// Bootloader offset relative to the start of the kernel data.
        offset: u64,

        /// Bootloader size padded to 4K alignment.
        size: u32,
    },

    /// The kernel's x86 real-mode header doesn't have the expected magic.
    BadHeaderMagic([u8; 4]),

    /// The kernel's x86 real-mode header's `setup_sects` field is invalid.
    BadHeaderSetupSectors(u8),

    /// The expected UEFI stub signature was not found.
    MissingUefiStub,
}

impl fmt::Display for LoadKernelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LoadKernelError::*;

        let mut write_with_rc =
            |msg, rc: &ReturnCode| write!(f, "{msg}: 0x{:x} ({})", rc.0, return_code_to_str(*rc));

        match self {
            BadNumericConversion(info) => {
                write!(f, "failed to convert numeric type: {info}")
            }
            Overflow(info) => {
                write!(f, "overflow: {info}")
            }
            PubkeyTooSmall(size) => {
                write!(f, "packed pubkey buffer is too small: {size}")
            }
            ApiInitFailed(rc) => write_with_rc("call to vb2api_init failed", rc),
            ApiKernelInitFailed(rc) => write_with_rc(
                "call to vb2api_init_ctx_for_kernel_verification_only failed",
                rc,
            ),
            LoadKernelFailed(rc) => write_with_rc("call to LoadKernel failed", rc),
            BadBootloaderRange { offset, size } => {
                write!(
                    f,
                    "invalid bootloader offset and/or size: offset={offset:#x}, size={size:#x}"
                )
            }
            BadHeaderMagic(val) => write!(f, "invalid real-mode header magic: {val:04x?}"),
            BadHeaderSetupSectors(val) => write!(
                f,
                "invalid `setup_sects` field in the read-mode header: {val:#x}"
            ),
            MissingUefiStub => {
                write!(
                    f,
                    "the UEFI stub is missing or not in the expected location"
                )
            }
        }
    }
}

fn u32_to_usize(v: u32) -> usize {
    v.try_into().expect("size of usize is smaller than u32")
}

impl<'a> LoadedKernel<'a> {
    fn command_line_with_placeholders(&self) -> Option<&str> {
        let cros_config = self.data.get(self.cros_config.clone())?;

        // Find the null terminator and narrow the slice to end just before
        // that.
        let command_line_end = cros_config.iter().position(|b| *b == 0)?;
        let command_line = cros_config.get(..command_line_end)?;

        str::from_utf8(command_line).ok()
    }

    /// Get the kernel command-line with partition placeholders replaced
    /// with the kernel partition's unique GUID.
    #[must_use]
    pub fn command_line(&self) -> Option<String> {
        let with_placeholders = self.command_line_with_placeholders()?;
        let unique_partition_guid = self.unique_partition_guid.to_string();
        Some(with_placeholders.replace("%U", &unique_partition_guid))
    }

    /// Raw kernel data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

unsafe fn init_vb2_context(
    packed_pubkey: &[u8],
    workbuf: &mut [u8],
) -> Result<*mut vboot_sys::vb2_context, LoadKernelError> {
    let mut ctx_ptr = ptr::null_mut();

    let packed_pubkey_len = u32::try_from(packed_pubkey.len())
        .map_err(|_| LoadKernelError::BadNumericConversion("pubkey length"))?;

    info!("vb2api_init");
    let mut status = ReturnCode(vboot_sys::vb2api_init(
        workbuf.as_mut_ptr().cast::<c_void>(),
        workbuf
            .len()
            .try_into()
            .map_err(|_| LoadKernelError::BadNumericConversion("workbuf length"))?,
        &mut ctx_ptr,
    ));
    if status != ReturnCode::VB2_SUCCESS {
        error!("vb2api_init failed: 0x{:x}", status.0);
        return Err(LoadKernelError::ApiInitFailed(status));
    }

    info!("vb2api_inject_kernel_subkey");
    status = ReturnCode(vboot_sys::vb2api_inject_kernel_subkey(
        ctx_ptr,
        packed_pubkey.as_ptr(),
        packed_pubkey_len,
    ));
    if status != ReturnCode::VB2_SUCCESS {
        error!("vb2api_inject_kernel_subkey failed: 0x{:x}", status.0);
        return Err(LoadKernelError::ApiKernelInitFailed(status));
    }

    Ok(ctx_ptr)
}

/// Inputs for [`load_kernel`].
pub struct LoadKernelInputs<'kernel, 'other> {
    /// Big buffer used by vboot for most of its data. Should be at
    /// least [`Self::RECOMMENDED_WORKBUF_SIZE`] bytes in size.
    pub workbuf: &'other mut [u8],

    /// Big buffer used to store the kernel loaded by vboot from the
    /// kernel partition.
    pub kernel_buffer: &'kernel mut [u8],

    /// Kernel verification key in the vbpubk format.
    pub packed_pubkey: &'other [u8],
}

impl<'kernel, 'other> LoadKernelInputs<'kernel, 'other> {
    /// Recommended size in bytes of [`LoadKernelInputs::workbuf`].
    pub const RECOMMENDED_WORKBUF_SIZE: usize =
        vboot_sys::VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE as usize;
}

/// The bootloader size reported by vboot is rounded up to 4K
/// alignment. Get the actual bootloader size via the kernel's
/// real-mode header.
///
/// See <https://www.kernel.org/doc/Documentation/x86/boot.txt>
/// for details of the header.
fn get_actual_bootloader_size(full_bootloader_data: &[u8]) -> Result<usize, LoadKernelError> {
    // These constants are derived from the above doc link.
    const SETUP_SECTS_OFFSET: usize = 0x01f1;
    const MAGIC_SIGNATURE_START: usize = 0x202;
    const MAGIC_SIGNATURE_END: usize = MAGIC_SIGNATURE_START + mem::size_of::<u32>();
    const BYTES_PER_SECTOR: usize = 512;

    // Check that the header's four-byte magic signature is in the
    // expected place. This serves to make it immediately obvious if any
    // offset calculations so far are incorrect.
    let magic_signature = &full_bootloader_data[MAGIC_SIGNATURE_START..MAGIC_SIGNATURE_END];
    if magic_signature != b"HdrS" {
        return Err(LoadKernelError::BadHeaderMagic(
            magic_signature.try_into().unwrap(),
        ));
    }

    // Get the one-byte `setup_sects` field. To get the actual
    // bootloader size, add one more sector to account for the boot
    // sector, then convert from sectors to bytes.
    let setup_sectors = full_bootloader_data[SETUP_SECTS_OFFSET];
    // Add one to `setup_sects` to account for the boot sector, then
    // convert from sectors to bytes.
    let setup_sectors_err = LoadKernelError::BadHeaderSetupSectors(setup_sectors);
    let bootloader_size = (usize::from(setup_sectors)
        .checked_add(1)
        .ok_or(setup_sectors_err)?)
    .checked_mul(BYTES_PER_SECTOR)
    .ok_or(setup_sectors_err)?;

    Ok(bootloader_size)
}

/// Find the best kernel. The details are up to the firmware library in
/// `vboot_reference`. If successful, the kernel and the command-line data
/// have been verified against `packed_pubkey`.
#[allow(clippy::needless_pass_by_value)]
pub fn load_kernel<'kernel>(
    inputs: LoadKernelInputs<'kernel, '_>,
    disk_io: &mut dyn DiskIo,
) -> Result<LoadedKernel<'kernel>, LoadKernelError> {
    // Reserve space at the beginning of the kernel_buffer so that we
    // can later copy in the bootloader (UEFI stub).
    //
    // The bootloader size as of 2023-06-29 is around 16KiB, reserve
    // double that to give some headroom.
    const MAX_BOOTLOADER_SIZE: u32 = 1024 * 32;

    let ctx_ptr = unsafe { init_vb2_context(inputs.packed_pubkey, inputs.workbuf) }?;

    let full_kernel_buffer = inputs.kernel_buffer.as_mut_ptr();
    let full_kernel_buffer_size: u32 = inputs
        .kernel_buffer
        .len()
        .try_into()
        .map_err(|_| LoadKernelError::BadNumericConversion("kernel buffer size"))?;

    let kernel_buffer = unsafe { full_kernel_buffer.add(u32_to_usize(MAX_BOOTLOADER_SIZE)) };
    let kernel_buffer_size = full_kernel_buffer_size
        .checked_sub(MAX_BOOTLOADER_SIZE)
        .ok_or(LoadKernelError::Overflow("kernel_buffer_size"))?;

    let mut params = vboot_sys::vb2_kernel_params {
        // Initialize inputs.
        kernel_buffer: kernel_buffer.cast(),
        kernel_buffer_size,

        // Initialize outputs.
        disk_handle: ptr::null_mut(),
        partition_number: 0,
        bootloader_offset: 0,
        bootloader_size: 0,
        partition_guid: [0; 16],
        flags: 0,
    };

    let mut disk = Disk::new(disk_io);
    let mut disk_info = disk.info();

    info!("LoadKernel");
    let status = ReturnCode(unsafe {
        vboot_sys::vb2api_load_kernel(ctx_ptr, &mut params, disk_info.as_mut_ptr())
    });
    if status != ReturnCode::VB2_SUCCESS {
        error!("LoadKernel failed: 0x{:x}", status.0);
        return Err(LoadKernelError::LoadKernelFailed(status));
    }

    info!("LoadKernel success");

    // The layout of the full kernel buffer now looks like this:
    // +---------------------+--------+--------+--------+-----------------+
    // | Reserved            | Kernel | Config | Params | Bootloader with |
    // | max_bootloader_size | data   |        |        | padding         |
    // |                     |        |        |        | size 4K aligned |
    // +---------------------+--------+--------+--------+-----------------+
    //
    // In order to fill in `LoadedKernel`, we need to modify the kernel
    // buffer to move the actual bootloader data (without the padding to
    // 4K) into the reserved space so that it comes just before the
    // kernel data. Any additional unused reserved space at the start of
    // the buffer is dropped with a subslice.
    //
    // Output buffer layout:
    // +------------+-------------+--------+--------+
    // | Bootloader | Kernel data | Config | Params |
    // +------------+-------------+--------+--------+

    // Construct an error to be used in case any of the following
    // bootloader steps fail.
    let bootloader_err = LoadKernelError::BadBootloaderRange {
        offset: params.bootloader_offset,
        size: params.bootloader_size,
    };

    // Ensure that the bootloader fits within the reserved space.
    if params.bootloader_size > MAX_BOOTLOADER_SIZE {
        return Err(bootloader_err);
    }

    // Bootloader offset from the start of the kernel data (this
    // excludes the reserved space).
    let bootloader_offset_from_kernel_data =
        usize::try_from(params.bootloader_offset).map_err(|_| bootloader_err)?;
    // Bootloader offset from the start of the reserved space.
    let full_bootloader_start = u32_to_usize(MAX_BOOTLOADER_SIZE)
        .checked_add(bootloader_offset_from_kernel_data)
        .ok_or(bootloader_err)?;
    let full_bootloader_end = full_bootloader_start
        .checked_add(u32_to_usize(params.bootloader_size))
        .ok_or(bootloader_err)?;
    // Get the bootloader data (this includes the padding to 4K).
    let full_bootloader_data = inputs
        .kernel_buffer
        .get(full_bootloader_start..full_bootloader_end)
        .ok_or(bootloader_err)?;

    // Get the actual bootloader size, without the 4K rounding.
    let bootloader_size = get_actual_bootloader_size(full_bootloader_data)?;
    info!("Actual bootloader size: {bootloader_size:#x} bytes");

    // Calculate how much of the reserved space is unused.
    let unused_space = u32_to_usize(MAX_BOOTLOADER_SIZE)
        .checked_sub(bootloader_size)
        .ok_or(LoadKernelError::Overflow("unused_space"))?;
    info!("Unused size: {unused_space} bytes");

    // Get the slice that will be returned at the end, dropping unused
    // space from the reserved space at the beginning of the full
    // buffer.
    let kernel_buffer = &mut inputs.kernel_buffer[unused_space..];

    // Get the bootloader offset within the new `kernel_buffer` size.
    let bootloader_offset = bootloader_size
        .checked_add(bootloader_offset_from_kernel_data)
        .ok_or(bootloader_err)?;

    // Copy the bootloader data to the start of the slice,
    // essentially undoing the splitting up of kernel data that
    // futility did when creating the kernel partition.
    let (bootloader, rest) = kernel_buffer.split_at_mut(bootloader_offset);
    if &rest[0..2] != b"MZ" {
        return Err(LoadKernelError::MissingUefiStub);
    }
    bootloader[..bootloader_size].copy_from_slice(&rest[..bootloader_size]);

    // Find the config section of the kernel data (aka the kernel
    // command line). As shown in the diagram above, config and params
    // data are packed just before the bootloader data.
    let cros_config_size = u32_to_usize(vboot_sys::CROS_CONFIG_SIZE);
    let cros_params_size = u32_to_usize(vboot_sys::CROS_PARAMS_SIZE);
    let cros_config_start = bootloader_offset
        .checked_sub(cros_config_size)
        .ok_or(bootloader_err)?
        .checked_sub(cros_params_size)
        .ok_or(bootloader_err)?;
    let cros_config_end = cros_config_start
        .checked_add(cros_config_size)
        .ok_or(bootloader_err)?;

    Ok(LoadedKernel {
        data: kernel_buffer,
        cros_config: cros_config_start..cros_config_end,
        unique_partition_guid: Guid::from_bytes(params.partition_guid),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use std::fs;
    use std::path::Path;
    use uguid::guid;

    struct MemDisk {
        data: Vec<u8>,
    }

    impl DiskIo for MemDisk {
        fn bytes_per_lba(&self) -> NonZeroU64 {
            NonZeroU64::new(512).unwrap()
        }

        fn lba_count(&self) -> u64 {
            self.data.len() as u64 / self.bytes_per_lba()
        }

        fn read(&self, lba_start: u64, buffer: &mut [u8]) -> ReturnCode {
            let start = (lba_start * self.bytes_per_lba().get()) as usize;
            let end = start + buffer.len();
            buffer.copy_from_slice(&self.data[start..end]);
            ReturnCode::VB2_SUCCESS
        }

        fn write(&mut self, _lba_start: u64, _buffer: &[u8]) -> ReturnCode {
            panic!("write called");
        }
    }

    #[test]
    fn test_error_display() {
        let expected = "call to LoadKernel failed: 0x100b2000 (VB2_ERROR_LK_NO_KERNEL_FOUND)";
        assert_eq!(
            format!(
                "{}",
                LoadKernelError::LoadKernelFailed(ReturnCode::VB2_ERROR_LK_NO_KERNEL_FOUND)
            ),
            expected
        );
    }

    /// Read the disk file generated by this command:
    /// `cargo xtask gen-test-data-tarball`.
    fn read_test_disk() -> MemDisk {
        let search_paths = [
            // Used when building outside the chroot.
            "../workspace/",
            // Used when building via ebuild inside the chroot.
            "../",
        ];

        for dir in search_paths {
            // The disk file was generated with:
            // `cargo xtask gen-test-data-tarball`.
            let path = Path::new(dir).join("crdyboot_test_data/vboot_test_disk.bin");
            if let Ok(data) = fs::read(path) {
                return MemDisk { data };
            }
        }

        panic!("failed to load vboot test disk");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_load_kernel() {
        let test_key_vbpubk =
            include_bytes!("../../third_party/vboot_reference/tests/devkeys/kernel_subkey.vbpubk");
        let expected_command_line_with_placeholders = "console= loglevel=7 init=/sbin/init cros_efi drm.trace=0x106 root=/dev/dm-0 rootwait ro dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 dm=\"1 vroot none ro 1,0 4710400 verity payload=PARTUUID=%U/PARTNROFF=1 hashtree=PARTUUID=%U/PARTNROFF=1 hashstart=4710400 alg=sha256 root_hexdigest=01ca247da5417e52b6bd4854a611cef7dba48b60290c34495b32c162558c7a98 salt=5b36609e1c37c7df9dcadea77ef84694b0c09dd4c558a1debf7c97c14b784274\" noinitrd cros_debug vt.global_cursor_default=0 kern_guid=%U add_efi_memmap boot=local noresume i915.modeset=1 kvm-intel.vmentry_l1d_flush=always ";
        let expected_command_line = "console= loglevel=7 init=/sbin/init cros_efi drm.trace=0x106 root=/dev/dm-0 rootwait ro dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 dm=\"1 vroot none ro 1,0 4710400 verity payload=PARTUUID=c6fbb888-1b6d-4988-a66e-ace443df68f4/PARTNROFF=1 hashtree=PARTUUID=c6fbb888-1b6d-4988-a66e-ace443df68f4/PARTNROFF=1 hashstart=4710400 alg=sha256 root_hexdigest=01ca247da5417e52b6bd4854a611cef7dba48b60290c34495b32c162558c7a98 salt=5b36609e1c37c7df9dcadea77ef84694b0c09dd4c558a1debf7c97c14b784274\" noinitrd cros_debug vt.global_cursor_default=0 kern_guid=c6fbb888-1b6d-4988-a66e-ace443df68f4 add_efi_memmap boot=local noresume i915.modeset=1 kvm-intel.vmentry_l1d_flush=always ";

        let mut disk = read_test_disk();

        let mut workbuf = vec![0; LoadKernelInputs::RECOMMENDED_WORKBUF_SIZE];
        let mut kernel_buffer = vec![0; 16 * 1024 * 1024];
        let inputs = LoadKernelInputs {
            workbuf: &mut workbuf,
            kernel_buffer: &mut kernel_buffer,
            packed_pubkey: test_key_vbpubk,
        };
        match load_kernel(inputs, &mut disk) {
            Ok(loaded_kernel) => {
                assert_eq!(
                    loaded_kernel.unique_partition_guid,
                    guid!("c6fbb888-1b6d-4988-a66e-ace443df68f4")
                );

                assert_eq!(
                    loaded_kernel.command_line_with_placeholders().unwrap(),
                    expected_command_line_with_placeholders
                );

                assert_eq!(loaded_kernel.command_line().unwrap(), expected_command_line);
            }
            Err(err) => {
                panic!("load_kernel failed: {err}");
            }
        }
    }
}
