// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::GptDisk;
use crate::pe::PeInfo;
use crate::{Error, Result};
use core::ffi::c_void;
use core::mem;
use log::info;
use uefi::proto::loaded_image::LoadedImage;
use uefi::table::boot::BootServices;
use uefi::table::{Boot, SystemTable};
use uefi::{CStr16, CString16, Handle};
use vboot::LoadedKernel;

type Entrypoint = unsafe extern "efiapi" fn(Handle, SystemTable<Boot>);

fn is_64bit() -> bool {
    match mem::size_of::<usize>() {
        8 => true,
        4 => false,
        other => panic!("invalid size of usize: {}", other),
    }
}

/// Read a little-endian u32 field from with the kernel data at the
/// given `offset`.
fn get_u32_field(kernel_data: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(mem::size_of::<u32>())
        .ok_or(Error::Overflow("get_u32_field"))?;
    let bytes = kernel_data
        .get(offset..end)
        .ok_or(Error::OutOfBounds("get_u32_field"))?;
    // OK to unwrap, the length of the slice is already known to be correct.
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// Check that the kernel buffer is big enough to run the kernel without
/// relocation. This is done by comparing the buffer size with the
/// `init_size` field in the kernel boot header.
///
/// The layout of the header is described here:
/// <https://docs.kernel.org/x86/boot.html>
pub(crate) fn validate_kernel_buffer_size(kernel_buffer: &[u8]) -> Result<()> {
    const SETUP_MAGIC: u32 = 0x5372_6448; // "HdrS"
    const MAGIC_OFFSET: usize = 0x0202;
    const INIT_SIZE_OFFSET: usize = 0x0260;

    // Check that the correct header magic is present.
    let magic = get_u32_field(kernel_buffer, MAGIC_OFFSET)?;
    if magic != SETUP_MAGIC {
        return Err(Error::InvalidKernelMagic);
    }

    // Get the `init_size` field.
    let init_size = get_u32_field(kernel_buffer, INIT_SIZE_OFFSET)?;
    info!("minimum required size: {}", init_size);

    let init_size =
        usize::try_from(init_size).map_err(|_| Error::Overflow("init_size"))?;

    if init_size <= kernel_buffer.len() {
        Ok(())
    } else {
        Err(Error::KernelBufferTooSmall(init_size, kernel_buffer.len()))
    }
}

fn entry_point_from_offset(
    data: &[u8],
    entry_point_offset: u32,
) -> Result<Entrypoint> {
    info!("entry_point_offset: 0x{:x}", entry_point_offset);

    let entry_point_offset = usize::try_from(entry_point_offset)
        .map_err(|_| Error::Overflow("entry_point_offset"))?;

    // Ensure that the entry point is somewhere in the kernel data.
    if entry_point_offset >= data.len() {
        return Err(Error::OutOfBounds("entry_point_offset"));
    }

    unsafe {
        let entry_point = data.as_ptr().add(entry_point_offset);
        info!("entry_point: 0x{:x?}", entry_point);

        // Transmute is needed to convert from a regular pointer to a
        // function pointer:
        // rust-lang.github.io/unsafe-code-guidelines/layout/function-pointers.html
        let entry_point: Entrypoint = mem::transmute(entry_point);
        Ok(entry_point)
    }
}

fn modify_loaded_image(
    bt: &BootServices,
    kernel_data: &[u8],
    cmdline_ucs2: &CStr16,
) -> Result<()> {
    let mut li = bt
        .open_protocol_exclusive::<LoadedImage>(bt.image_handle())
        .map_err(|err| Error::LoadedImageProtocolMissing(err.status()))?;

    // Set kernel command line.
    let load_options_size = cmdline_ucs2.num_bytes();
    let load_options_size = u32::try_from(load_options_size)
        .map_err(|_| Error::CommandLineTooBig(load_options_size))?;
    unsafe {
        li.set_load_options(cmdline_ucs2.as_ptr().cast(), load_options_size);
    }

    // Set kernel data.
    let image_size =
        u64::try_from(kernel_data.len()).expect("usize is larger than u64");
    unsafe {
        li.set_image(kernel_data.as_ptr().cast::<c_void>(), image_size);
    }

    Ok(())
}

/// Hand off control to the Linux EFI stub.
///
/// As mentioned in [1], the preferred method for loading the kernel
/// on UEFI is to build in the EFI stub and run it as a normal PE/COFF
/// executable. This is indeed much simpler than trying to use the EFI
/// handover protocol, which is not fully documented. The kernel's PE
/// header does not require any relocations to be performed, so the
/// only thing we need to get from the header is the entry point.
///
/// Note that we can't use LoadImage+StartImage for this, because with
/// secure boot enabled it would try to verify the signature of the
/// kernel which would fail unless we signed the kernel in the way
/// UEFI expects. Since we have already verified the kernel via the
/// vboot structures (as well as the command line parameters), this
/// would be an unnecessary verification.
///
/// [1]: kernel.org/doc/html/latest/x86/boot.html#efi-handover-protocol-deprecated
fn execute_linux_efi_stub(
    kernel_data: &[u8],
    entry_point: Entrypoint,
    system_table: SystemTable<Boot>,
    cmdline: &str,
) -> Result<()> {
    info!("booting the EFI stub");

    // Convert the string to UCS-2.
    let cmdline_ucs2 = CString16::try_from(cmdline)
        .map_err(|_| Error::CommandLineUcs2ConversionFailed)?;

    // Ideally we could create a new image here, but I'm not sure
    // there's any way to do that without calling LoadImage, which we
    // can't do due to secure boot. This is the same method shim uses:
    // modify the existing image's parameters.
    modify_loaded_image(
        system_table.boot_services(),
        kernel_data,
        &cmdline_ucs2,
    )?;

    unsafe {
        (entry_point)(
            system_table.boot_services().image_handle(),
            system_table,
        );
    }

    Err(Error::KernelDidNotTakeControl)
}

pub fn execute_linux_kernel(
    kernel: &LoadedKernel,
    system_table: SystemTable<Boot>,
) -> Result<()> {
    let cmdline = kernel.command_line().ok_or(Error::GetCommandLineFailed)?;
    info!("command line: {}", cmdline);

    let pe = PeInfo::parse(kernel.data())?;

    let execute_linux_efi_stub = |system_table, entry_point_offset| {
        execute_linux_efi_stub(
            kernel.data(),
            entry_point_from_offset(kernel.data(), entry_point_offset)?,
            system_table,
            &cmdline,
        )
    };

    if is_64bit() {
        execute_linux_efi_stub(system_table, pe.entry_point)
    } else {
        execute_linux_efi_stub(system_table, pe.ia32_compat_entry_point)
    }
}

/// Use vboot to load the kernel from the appropriate kernel partition.
pub fn load_kernel(
    boot_services: &BootServices,
    kernel_verification_key: &[u8],
) -> Result<LoadedKernel> {
    let mut gpt_disk = GptDisk::new(boot_services)?;

    let kernel = vboot::load_kernel(kernel_verification_key, &mut gpt_disk)
        .map_err(Error::LoadKernelFailed)?;

    // Ensure the buffer is large enough to actually run the
    // kernel. We could just allocate a bigger buffer here, but it
    // shouldn't be needed unless something has gone wrong anyway.
    validate_kernel_buffer_size(kernel.data())?;

    Ok(kernel)
}
