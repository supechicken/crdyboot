//! This module implements running the Linux kernel via the handover
//! protocol.
//!
//! This is only needed on 32-bit UEFI, and only for older kernels that
//! don't have this commit:
//!
//!     efi/x86: Implement mixed mode boot without the handover protocol
//!
//! Currently handover is needed for 5.4 kernels, it's not needed in 5.10
//! kernels.

use crate::result::{Error, Result};
use alloc::vec;
use core::convert::TryInto;
use core::{mem, ptr};
use log::info;
use uefi::table::{Boot, SystemTable};
use uefi::Handle;
use vboot::{kernel_data_as_boot_params, BootParams, BootParamsError};

/// Convert the slice to a pointer, then attempt to convert the pointer to a
/// `u32`. Return `Error::BadNumericConversion` on failure.
fn u8_slice_to_ptr_to_u32(slice: &[u8], info: &'static str) -> Result<u32> {
    let int = slice.as_ptr() as usize;
    int.try_into()
        .map_err(|_| Error::BadNumericConversion(info))
}

/// Run the kernel using the EFI handover protocol.
///
/// - https://www.kernel.org/doc/html/latest/x86/boot.html#efi-handover-protocol-deprecated
/// - linux/arch/x86/include/uapi/asm/bootparam.h
/// - https://lwn.net/Articles/589193/
/// - https://lwn.net/Articles/632528/
pub fn execute_linux_kernel_32(
    kernel_data: &[u8],
    crdyboot_image: Handle,
    system_table: SystemTable<Boot>,
    cmdline: &str,
) -> Result<()> {
    info!("booting with the EFI handover protocol");

    let image_params = match kernel_data_as_boot_params(kernel_data) {
        Ok(params) => params,
        Err(BootParamsError::InputTooSmall) => {
            return Err(Error::KernelTooSmall);
        }
        Err(BootParamsError::InvalidMagic) => {
            return Err(Error::InvalidBootParameters);
        }
    };

    if image_params.hdr.boot_flag != 0xAA55
        || image_params.hdr.version < 0x20b
        || image_params.hdr.relocatable_kernel == 0
    {
        return Err(Error::InvalidBootParameters);
    }

    let mut boot_params_raw = vec![0; 0x4000];
    let boot_params: &mut BootParams =
        unsafe { &mut *boot_params_raw.as_mut_ptr().cast::<BootParams>() };

    unsafe {
        ptr::copy(&image_params.hdr, &mut boot_params.hdr, 1);
    }
    boot_params.hdr.type_of_loader = 0xff;

    let setup_sectors: u32 = if image_params.hdr.setup_sects > 0 {
        image_params.hdr.setup_sects.into()
    } else {
        4
    };

    boot_params.hdr.code32_start =
        u8_slice_to_ptr_to_u32(kernel_data, "boot_params.hdr.code32_start")?;
    boot_params.hdr.code32_start += (setup_sectors + 1) * 512;

    let mut cmdline = cmdline.as_bytes().to_vec();
    cmdline.push(0);

    boot_params.hdr.cmd_line_ptr =
        u8_slice_to_ptr_to_u32(&cmdline, "boot_params.hdr.cmd_line_ptr")?;

    let start = boot_params.hdr.code32_start + image_params.hdr.handover_offset;

    type Handover =
        unsafe extern "sysv64" fn(Handle, SystemTable<Boot>, *mut BootParams);

    let start_ptr = start as *const ();

    let handover: Handover = unsafe { mem::transmute(start_ptr) };
    unsafe {
        (handover)(crdyboot_image, system_table, boot_params);
    }

    Err(Error::KernelDidNotTakeControl)
}
