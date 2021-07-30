use crate::disk::{Disk, DiskIo};
use crate::{return_code, vboot_sys};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::convert::TryInto;
use core::ffi::c_void;
use core::{mem, ptr, str};
use log::{error, info};

/// Fully verified kernel loaded into memory.
pub struct LoadedKernel {
    data: Vec<u8>,
    bootloader_address: u64,
    unique_partition_guid: [u8; 16],
}

fn u32_to_u64(v: u32) -> u64 {
    v.into()
}

fn u32_to_usize(v: u32) -> Option<usize> {
    v.try_into().ok()
}

#[allow(clippy::many_single_char_names)]
fn guid_string(guid: [u8; 16]) -> Option<String> {
    let a = u32::from_le_bytes(guid[0..4].try_into().ok()?);
    let b = u16::from_le_bytes(guid[4..6].try_into().ok()?);
    let c = u16::from_le_bytes(guid[6..8].try_into().ok()?);
    let d = u16::from_be_bytes(guid[8..10].try_into().ok()?);
    let e = u64::from_be_bytes([
        0, 0, guid[10], guid[11], guid[12], guid[13], guid[14], guid[15],
    ]);

    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        a, b, c, d, e
    ))
}

impl LoadedKernel {
    fn command_line_with_placeholders(&self) -> Option<&str> {
        // TODO: would be nice if the command line location was returned in
        // the output parameters of VbSelectAndLoadKernelParams, might be
        // worth putting up a CL for that.
        //
        // This arithmetic is based on `fill_info_cros` in depthcharge,
        // which is where the magic constant comes from.
        let command_line_start: usize = (self
            .bootloader_address
            .checked_sub(0x100000)?
            .checked_sub(u32_to_u64(vboot_sys::CROS_PARAMS_SIZE))?
            .checked_sub(u32_to_u64(vboot_sys::CROS_CONFIG_SIZE))?)
        .try_into()
        .ok()?;

        // Get the entire command-line area.
        let command_line_end = command_line_start
            .checked_add(u32_to_usize(vboot_sys::CROS_CONFIG_SIZE)?)?;
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
    pub fn command_line(&self) -> Option<String> {
        let with_placeholders = self.command_line_with_placeholders()?;
        let unique_partition_guid = guid_string(self.unique_partition_guid)?;
        Some(with_placeholders.replace("%U", &unique_partition_guid))
    }

    /// Raw kernel data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Find the best kernel. The details are up to the firmware library in
/// vboot_reference. If successful, the kernel and the command-line data
/// have been verified against `packed_pubkey`.
pub fn load_kernel(
    packed_pubkey: &[u8],
    disk_io: &dyn DiskIo,
) -> Result<LoadedKernel, return_code> {
    // TODO: this could probably be smaller.
    let mut workbuf = vec![0u8; 4096 * 50];

    // TODO: arbitrary choose 32MiB for now.
    let mut kernel_buffer = vec![0u8; 32 * 1024 * 1024];

    unsafe {
        let mut ctx_ptr = ptr::null_mut();

        info!("vb2api_init");
        let status = return_code(
            vboot_sys::vb2api_init(
                workbuf.as_mut_ptr() as *mut c_void,
                workbuf.len().try_into().unwrap(),
                &mut ctx_ptr,
            )
            .try_into()
            .unwrap(),
        );
        if status != return_code::VB2_SUCCESS {
            error!("vb2api_init failed: 0x{:x}", status.0);
            return Err(status);
        }

        let mut kernel_key_wb = vboot_sys::vb2_workbuf {
            buf: ptr::null_mut(),
            size: 0,
        };
        vboot_sys::vb2_workbuf_from_ctx(ctx_ptr, &mut kernel_key_wb);
        let kernel_key_ptr = vboot_sys::vb2_workbuf_alloc(
            &mut kernel_key_wb,
            // TODO: unwrap
            packed_pubkey.len().try_into().unwrap(),
        ) as *mut u8;
        packed_pubkey
            .as_ptr()
            .copy_to_nonoverlapping(kernel_key_ptr, packed_pubkey.len());

        assert!(
            packed_pubkey.len() >= mem::size_of::<vboot_sys::vb2_packed_key>()
        );

        vboot_sys::crdyboot_set_kernel_key(
            ctx_ptr,
            kernel_key_ptr as *const vboot_sys::vb2_packed_key,
            &kernel_key_wb as *const vboot_sys::vb2_workbuf,
        );

        let mut params = vboot_sys::VbSelectAndLoadKernelParams {
            kernel_buffer: kernel_buffer.as_mut_ptr() as *mut c_void,
            // TODO: unwrap
            kernel_buffer_size: kernel_buffer.len().try_into().unwrap(),

            // Init outputs
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
        let status = return_code(
            vboot_sys::LoadKernel(ctx_ptr, &mut params, disk_info.as_mut_ptr())
                .try_into()
                .unwrap(),
        );
        if status == return_code::VB2_SUCCESS {
            info!("LoadKernel success");

            Ok(LoadedKernel {
                data: kernel_buffer,
                bootloader_address: params.bootloader_address,
                unique_partition_guid: params.partition_guid,
            })
        } else {
            error!("LoadKernel failed: 0x{:x}", status.0);
            Err(status)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::return_code;

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

        fn read(&self, lba_start: u64, buffer: &mut [u8]) -> return_code {
            let start = (lba_start * self.bytes_per_lba()) as usize;
            let end = start + buffer.len();
            buffer.copy_from_slice(&self.data[start..end]);
            return_code::VB2_SUCCESS
        }
    }

    #[test]
    fn test_guid_string() {
        assert_eq!(
            guid_string([
                // a
                0x01, 0x23, 0x45, 0x67, // b
                0x89, 0xab, // c
                0xcd, 0xef, // d
                0x01, 0x23, // e
                0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            ])
            .unwrap(),
            "67452301-ab89-efcd-0123-456789abcdef"
        );
    }

    #[test]
    fn test_load_kernel() {
        let test_key_vbpubk = include_bytes!("../test_data/kernel_key.vbpubk");
        let expected_command_line_with_placeholders = "console= loglevel=7 init=/sbin/init cros_secure drm.trace=0x106 root=/dev/dm-0 rootwait ro dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 dm=\"1 vroot none ro 1,0 6082560 verity payload=PARTUUID=%U/PARTNROFF=1 hashtree=PARTUUID=%U/PARTNROFF=1 hashstart=6082560 alg=sha256 root_hexdigest=69185175957ada9cb25bf34621a4a52b03d568b44adf8dfb136ce89152be524a salt=4332c7477474e9131fa629af556314ccb49e872282d6fade4801876d54d56236\" noinitrd vt.global_cursor_default=0 kern_guid=%U add_efi_memmap boot=local noresume noswap i915.modeset=1 ";
        let expected_command_line = "console= loglevel=7 init=/sbin/init cros_secure drm.trace=0x106 root=/dev/dm-0 rootwait ro dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 dm=\"1 vroot none ro 1,0 6082560 verity payload=PARTUUID=c6fbb888-1b6d-4988-a66e-ace443df68f4/PARTNROFF=1 hashtree=PARTUUID=c6fbb888-1b6d-4988-a66e-ace443df68f4/PARTNROFF=1 hashstart=6082560 alg=sha256 root_hexdigest=69185175957ada9cb25bf34621a4a52b03d568b44adf8dfb136ce89152be524a salt=4332c7477474e9131fa629af556314ccb49e872282d6fade4801876d54d56236\" noinitrd vt.global_cursor_default=0 kern_guid=c6fbb888-1b6d-4988-a66e-ace443df68f4 add_efi_memmap boot=local noresume noswap i915.modeset=1 ";

        let disk = MemDisk {
            data: include_bytes!("../test_data/disk.bin"),
        };

        match load_kernel(test_key_vbpubk, &disk) {
            Ok(loaded_kernel) => {
                assert_eq!(
                    guid_string(loaded_kernel.unique_partition_guid),
                    Some("c6fbb888-1b6d-4988-a66e-ace443df68f4".into())
                );

                assert_eq!(
                    loaded_kernel.command_line_with_placeholders(),
                    Some(expected_command_line_with_placeholders)
                );

                assert_eq!(
                    loaded_kernel.command_line(),
                    Some(expected_command_line.into())
                );
            }
            Err(status) => {
                panic!("load_kernel failed: 0x{:x}", status.0);
            }
        }
    }
}
