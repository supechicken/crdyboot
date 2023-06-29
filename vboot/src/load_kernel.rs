// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::{Disk, DiskIo};
use crate::{return_code_to_str, vboot_sys, ReturnCode};
use alloc::string::{String, ToString};
use core::ffi::c_void;
use core::ops::Range;
use core::{fmt, ptr, slice, str};
use log::{error, info};
use uguid::Guid;

/// Fully verified kernel loaded into memory.
pub struct LoadedKernel<'a> {
    data: &'a [u8],
    cros_config: Range<usize>,
    unique_partition_guid: Guid,
}

/// Errors produced by `load_kernel`.
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

    /// Bootloader offset is not valid.
    BadBootloaderOffset(u64),

    /// Bootloader data is larger than the reserved space.
    BootloaderTooLarge(usize),

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
            BadBootloaderOffset(offset) => {
                write!(f, "bootloader offset is invalid: {offset:#02x?}")
            }
            BootloaderTooLarge(size) => {
                write!(f, "bootloader data is too large: {size}")
            }
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

/// Offsets within the kernel buffer divined from
/// `vboot_sys::vb2_kernel_params`.
struct KernelBufferOffsets {
    bootloader: usize,
    cros_config: Range<usize>,
}

impl KernelBufferOffsets {
    fn new(params: &vboot_sys::vb2_kernel_params) -> Option<Self> {
        // This arithmetic is based on `fill_info_cros` in
        // depthcharge.
        //
        // The additional offset of `bootloader_size` is needed because
        // we move the bootloader into space at the beginning of the
        // kernel buffer.
        //
        // TODO: would be nice if vboot just provided direct offsets
        // rather than having to copy these calculations into multiple
        // projects, could maybe do a CL for that.

        let bootloader = usize::try_from(
            params
                .bootloader_offset
                .checked_add(u64::from(params.bootloader_size))?,
        )
        .ok()?;

        let cros_params_size = u32_to_usize(vboot_sys::CROS_PARAMS_SIZE);
        let cros_config_size = u32_to_usize(vboot_sys::CROS_CONFIG_SIZE);

        let cros_config_start = bootloader
            .checked_sub(cros_params_size)?
            .checked_sub(cros_config_size)?;

        let cros_config_end = cros_config_start.checked_add(cros_config_size)?;

        Some(Self {
            bootloader,
            cros_config: cros_config_start..cros_config_end,
        })
    }
}

/// Find the best kernel. The details are up to the firmware library in
/// `vboot_reference`. If successful, the kernel and the command-line data
/// have been verified against `packed_pubkey`.
#[allow(clippy::needless_pass_by_value)]
pub fn load_kernel<'kernel>(
    inputs: LoadKernelInputs<'kernel, '_>,
    disk_io: &mut dyn DiskIo,
) -> Result<LoadedKernel<'kernel>, LoadKernelError> {
    let ctx_ptr = unsafe { init_vb2_context(inputs.packed_pubkey, inputs.workbuf) }?;

    let full_kernel_buffer = inputs.kernel_buffer.as_mut_ptr();
    let full_kernel_buffer_size: u32 = inputs
        .kernel_buffer
        .len()
        .try_into()
        .map_err(|_| LoadKernelError::BadNumericConversion("kernel buffer size"))?;

    // Reserve space at the beginning of `full_kernel_buffer` so
    // that we can later copy in the bootloader (UEFI stub).
    //
    // The actual size as of 2023-05-30 is 16KiB, allocate double
    // that to give some headroom.
    let max_bootloader_size: u32 = 1024 * 32;
    let kernel_buffer = unsafe { full_kernel_buffer.add(u32_to_usize(max_bootloader_size)) };
    let kernel_buffer_size = full_kernel_buffer_size
        .checked_sub(max_bootloader_size)
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
    if status == ReturnCode::VB2_SUCCESS {
        info!("LoadKernel success");

        if params.bootloader_size > max_bootloader_size {
            return Err(LoadKernelError::BootloaderTooLarge(u32_to_usize(
                params.bootloader_size,
            )));
        }

        let offsets = KernelBufferOffsets::new(&params).ok_or(
            LoadKernelError::BadBootloaderOffset(params.bootloader_offset),
        )?;

        let unused_space = u32_to_usize(
            max_bootloader_size
                .checked_sub(params.bootloader_size)
                .ok_or(LoadKernelError::Overflow("unused_space"))?,
        );

        // Turn the kernel data back into a slice, leaving out any
        // unused space at the beginning.
        let kernel_buffer = unsafe {
            slice::from_raw_parts_mut(
                full_kernel_buffer.add(unused_space),
                u32_to_usize(full_kernel_buffer_size)
                    .checked_sub(unused_space)
                    .ok_or(LoadKernelError::Overflow("kernel_buffer"))?,
            )
        };

        // Copy the bootloader data to the start of the slice,
        // essentially undoing the splitting up of kernel data that
        // futility did when creating the kernel partition.
        let (bootloader, rest) = kernel_buffer.split_at_mut(offsets.bootloader);
        if &rest[0..2] != b"MZ" {
            return Err(LoadKernelError::MissingUefiStub);
        }
        let bootloader_size = u32_to_usize(params.bootloader_size);
        bootloader[..bootloader_size].copy_from_slice(&rest[..bootloader_size]);

        Ok(LoadedKernel {
            data: kernel_buffer,
            cros_config: offsets.cros_config,
            unique_partition_guid: Guid::from_bytes(params.partition_guid),
        })
    } else {
        error!("LoadKernel failed: 0x{:x}", status.0);
        Err(LoadKernelError::LoadKernelFailed(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use regex::Regex;
    use uguid::guid;

    struct MemDisk {
        data: &'static [u8],
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

    /// Replace verity args in the kernel command line with hardcoded
    /// values. This allows the test to run against a more or less
    /// arbitrary reven kernel partition.
    #[must_use]
    fn replace_command_line_verity_args(cmdline: &str) -> String {
        let r = Regex::new("root_hexdigest=[[:xdigit:]]{64}").unwrap();
        let cmdline = r.replace(
            &cmdline,
            "root_hexdigest=0e795f91ea7cff737a31cdc3cd1cf0ebbcbcd482812c46e424a0dd7b2e302630",
        );

        let r = Regex::new("salt=[[:xdigit:]]{64}").unwrap();
        let cmdline = r.replace(
            &cmdline,
            "salt=a4ba1dee84e2e3eb1a5aaa67f9c0a54bfb5d597ba78ae8ef634ab13141e81476",
        );

        cmdline.into()
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_load_kernel() {
        let test_key_vbpubk =
            include_bytes!("../../third_party/vboot_reference/tests/devkeys/kernel_subkey.vbpubk");
        let expected_command_line_with_placeholders = "console= loglevel=7 init=/sbin/init cros_efi drm.trace=0x106 root=/dev/dm-0 rootwait ro dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 dm=\"1 vroot none ro 1,0 4710400 verity payload=PARTUUID=%U/PARTNROFF=1 hashtree=PARTUUID=%U/PARTNROFF=1 hashstart=4710400 alg=sha256 root_hexdigest=0e795f91ea7cff737a31cdc3cd1cf0ebbcbcd482812c46e424a0dd7b2e302630 salt=a4ba1dee84e2e3eb1a5aaa67f9c0a54bfb5d597ba78ae8ef634ab13141e81476\" noinitrd cros_debug vt.global_cursor_default=0 kern_guid=%U add_efi_memmap boot=local noresume noswap i915.modeset=1 kvm-intel.vmentry_l1d_flush=always ";
        let expected_command_line = "console= loglevel=7 init=/sbin/init cros_efi drm.trace=0x106 root=/dev/dm-0 rootwait ro dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 dm=\"1 vroot none ro 1,0 4710400 verity payload=PARTUUID=c6fbb888-1b6d-4988-a66e-ace443df68f4/PARTNROFF=1 hashtree=PARTUUID=c6fbb888-1b6d-4988-a66e-ace443df68f4/PARTNROFF=1 hashstart=4710400 alg=sha256 root_hexdigest=0e795f91ea7cff737a31cdc3cd1cf0ebbcbcd482812c46e424a0dd7b2e302630 salt=a4ba1dee84e2e3eb1a5aaa67f9c0a54bfb5d597ba78ae8ef634ab13141e81476\" noinitrd cros_debug vt.global_cursor_default=0 kern_guid=c6fbb888-1b6d-4988-a66e-ace443df68f4 add_efi_memmap boot=local noresume noswap i915.modeset=1 kvm-intel.vmentry_l1d_flush=always ";

        let mut disk = MemDisk {
            // This file was generated during `cargo xtask setup`.
            data: include_bytes!("../../workspace/vboot_test_disk.bin"),
        };

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
                    replace_command_line_verity_args(
                        loaded_kernel.command_line_with_placeholders().unwrap()
                    ),
                    expected_command_line_with_placeholders
                );

                assert_eq!(
                    replace_command_line_verity_args(&loaded_kernel.command_line().unwrap()),
                    expected_command_line
                );
            }
            Err(err) => {
                panic!("load_kernel failed: {err}");
            }
        }
    }
}
