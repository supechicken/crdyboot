// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::{Disk, DiskIo};
use crate::{return_code_to_str, vboot_sys, ReturnCode};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::{fmt, ptr, str};
use cty::c_void;
use log::{error, info};
use uguid::Guid;

/// Fully verified kernel loaded into memory.
pub struct LoadedKernel {
    data: Vec<u8>,
    bootloader_address: u64,
    unique_partition_guid: Guid,
}

/// Errors produced by `load_kernel`.
pub enum LoadKernelError {
    /// Failed to convert numeric type.
    BadNumericConversion(&'static str),

    /// Packed pubkey buffer is too small.
    PubkeyTooSmall(usize),

    /// Call to `vb2api_init` failed.
    ApiInitFailed(ReturnCode),

    /// Call to vb2api_init_ctx_for_kernel_verification_only` failed.
    ApiKernelInitFailed(ReturnCode),

    /// Call to `LoadKernel` failed.
    LoadKernelFailed(ReturnCode),
}

impl fmt::Display for LoadKernelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LoadKernelError::*;

        let mut write_with_rc = |msg, rc: &ReturnCode| {
            write!(f, "{}: 0x{:x} ({})", msg, rc.0, return_code_to_str(*rc))
        };

        match self {
            BadNumericConversion(info) => {
                write!(f, "failed to convert numeric type: {}", info)
            }
            PubkeyTooSmall(size) => {
                write!(f, "packed pubkey buffer is too small: {}", size)
            }
            ApiInitFailed(rc) => {
                write_with_rc("call to vb2api_init failed", rc)
            }
            ApiKernelInitFailed(rc) => write_with_rc(
                "call to vb2api_init_ctx_for_kernel_verification_only failed",
                rc,
            ),
            LoadKernelFailed(rc) => {
                write_with_rc("call to LoadKernel failed", rc)
            }
        }
    }
}

fn u32_to_u64(v: u32) -> u64 {
    v.into()
}

fn u32_to_usize(v: u32) -> usize {
    v.try_into().expect("size of usize is smaller than u32")
}

impl LoadedKernel {
    fn command_line_with_placeholders(&self) -> Option<&str> {
        // TODO: would be nice if the command line location was returned in
        // the output parameters of vb2_kernel_params, might be
        // worth putting up a CL for that.
        //
        // This arithmetic is based on `fill_info_cros` in depthcharge,
        // which is where the magic constant comes from.
        let command_line_start: usize = (self
            .bootloader_address
            .checked_sub(0x10_0000)?
            .checked_sub(u32_to_u64(vboot_sys::CROS_PARAMS_SIZE))?
            .checked_sub(u32_to_u64(vboot_sys::CROS_CONFIG_SIZE))?)
        .try_into()
        .ok()?;

        // Get the entire command-line area.
        let command_line_end = command_line_start
            .checked_add(u32_to_usize(vboot_sys::CROS_CONFIG_SIZE))?;
        let command_line =
            self.data.get(command_line_start..command_line_end)?;

        // Find the null terminator and narrow the slice to end just before
        // that.
        let command_line_end = command_line.iter().position(|b| *b == 0)?;
        let command_line = command_line.get(..command_line_end)?;

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
        &self.data
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
        workbuf.len().try_into().map_err(|_| {
            LoadKernelError::BadNumericConversion("workbuf length")
        })?,
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

/// Find the best kernel. The details are up to the firmware library in
/// `vboot_reference`. If successful, the kernel and the command-line data
/// have been verified against `packed_pubkey`.
pub fn load_kernel(
    packed_pubkey: &[u8],
    disk_io: &mut dyn DiskIo,
) -> Result<LoadedKernel, LoadKernelError> {
    let mut workbuf =
        vec![0u8; u32_to_usize(vboot_sys::VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE)];

    // Allocate a fairly large buffer. This buffer must be big enough to
    // hold the kernel data loaded by vboot, but also big enough for the
    // kernel to successfully run without relocation. The latter requirement
    // is checked below with `validate_kernel_buffer_size`. The actual
    // required size is currently around 35 MiB, so 64 MiB should be plenty
    // for the forseeable future.
    let mut kernel_buffer = vec![0u8; 64 * 1024 * 1024];

    unsafe {
        let ctx_ptr = init_vb2_context(packed_pubkey, &mut workbuf)?;

        let mut params = vboot_sys::vb2_kernel_params {
            // Initialize inputs.
            kernel_buffer: kernel_buffer.as_mut_ptr().cast::<c_void>(),
            kernel_buffer_size: kernel_buffer.len().try_into().map_err(
                |_| LoadKernelError::BadNumericConversion("kernel buffer size"),
            )?,

            // Initialize outputs.
            disk_handle: ptr::null_mut(),
            partition_number: 0,
            bootloader_address: 0,
            bootloader_size: 0,
            partition_guid: [0; 16],
            flags: 0,
        };

        let mut disk = Disk::new(disk_io);
        let mut disk_info = disk.info();

        info!("LoadKernel");
        let status = ReturnCode(vboot_sys::vb2api_load_kernel(
            ctx_ptr,
            &mut params,
            disk_info.as_mut_ptr(),
        ));
        if status == ReturnCode::VB2_SUCCESS {
            info!("LoadKernel success");

            Ok(LoadedKernel {
                data: kernel_buffer,
                bootloader_address: params.bootloader_address,
                unique_partition_guid: Guid::from_bytes(params.partition_guid),
            })
        } else {
            error!("LoadKernel failed: 0x{:x}", status.0);
            Err(LoadKernelError::LoadKernelFailed(status))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use uguid::guid;

    struct MemDisk {
        data: &'static [u8],
    }

    impl DiskIo for MemDisk {
        fn bytes_per_lba(&self) -> u64 {
            512
        }

        fn lba_count(&self) -> u64 {
            self.data.len() as u64 / self.bytes_per_lba()
        }

        fn read(&self, lba_start: u64, buffer: &mut [u8]) -> ReturnCode {
            let start = (lba_start * self.bytes_per_lba()) as usize;
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
                LoadKernelError::LoadKernelFailed(
                    ReturnCode::VB2_ERROR_LK_NO_KERNEL_FOUND
                )
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
        let cmdline = r.replace(&cmdline, "root_hexdigest=0e795f91ea7cff737a31cdc3cd1cf0ebbcbcd482812c46e424a0dd7b2e302630");

        let r = Regex::new("salt=[[:xdigit:]]{64}").unwrap();
        let cmdline = r.replace(&cmdline, "salt=a4ba1dee84e2e3eb1a5aaa67f9c0a54bfb5d597ba78ae8ef634ab13141e81476");

        cmdline.into()
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_load_kernel() {
        simple_logger::init().unwrap();

        let test_key_vbpubk =
            include_bytes!("../../workspace/test_kernel_key/key.vbpubk");
        let expected_command_line_with_placeholders = "console= loglevel=7 init=/sbin/init cros_efi drm.trace=0x106 root=/dev/dm-0 rootwait ro dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 dm=\"1 vroot none ro 1,0 4710400 verity payload=PARTUUID=%U/PARTNROFF=1 hashtree=PARTUUID=%U/PARTNROFF=1 hashstart=4710400 alg=sha256 root_hexdigest=0e795f91ea7cff737a31cdc3cd1cf0ebbcbcd482812c46e424a0dd7b2e302630 salt=a4ba1dee84e2e3eb1a5aaa67f9c0a54bfb5d597ba78ae8ef634ab13141e81476\" noinitrd cros_debug vt.global_cursor_default=0 kern_guid=%U add_efi_memmap boot=local noresume noswap i915.modeset=1 kvm-intel.vmentry_l1d_flush=always ";
        let expected_command_line = "console= loglevel=7 init=/sbin/init cros_efi drm.trace=0x106 root=/dev/dm-0 rootwait ro dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 dm=\"1 vroot none ro 1,0 4710400 verity payload=PARTUUID=c6fbb888-1b6d-4988-a66e-ace443df68f4/PARTNROFF=1 hashtree=PARTUUID=c6fbb888-1b6d-4988-a66e-ace443df68f4/PARTNROFF=1 hashstart=4710400 alg=sha256 root_hexdigest=0e795f91ea7cff737a31cdc3cd1cf0ebbcbcd482812c46e424a0dd7b2e302630 salt=a4ba1dee84e2e3eb1a5aaa67f9c0a54bfb5d597ba78ae8ef634ab13141e81476\" noinitrd cros_debug vt.global_cursor_default=0 kern_guid=c6fbb888-1b6d-4988-a66e-ace443df68f4 add_efi_memmap boot=local noresume noswap i915.modeset=1 kvm-intel.vmentry_l1d_flush=always ";

        let mut disk = MemDisk {
            // This file was generated during `cargo xtask setup`.
            data: include_bytes!("../../workspace/vboot_test_disk.bin"),
        };

        match load_kernel(test_key_vbpubk, &mut disk) {
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
                    replace_command_line_verity_args(
                        &loaded_kernel.command_line().unwrap()
                    ),
                    expected_command_line
                );
            }
            Err(err) => {
                panic!("load_kernel failed: {}", err);
            }
        }
    }
}
