use crate::result::{Error, Result};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem;
use log::info;
use uefi::data_types::chars::NUL_16;
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::table::{Boot, SystemTable};
use uefi::{Char16, Handle};
use vboot::{LoadedKernel, PeExecutable};

type Entrypoint = unsafe extern "efiapi" fn(Handle, SystemTable<Boot>);

fn is_64bit() -> bool {
    match mem::size_of::<usize>() {
        8 => true,
        4 => false,
        other => panic!("invalid size of usize: {}", other),
    }
}
// TODO: once a version of uefi-rs with 58ae6a401 is released, drop this
// function and use CString16.
fn str_to_uefi_str(input: &str) -> Result<Vec<Char16>> {
    // Expect two bytes for each byte of the input, plus a null byte.
    let mut output = Vec::with_capacity(input.len() + 1);

    // Convert to UTF-16, then convert to UCS-2.
    for c in input.encode_utf16() {
        if let Ok(c) = Char16::try_from(c) {
            output.push(c);
        } else {
            return Err(Error::CommandLineUcs2ConversionFailed);
        }
    }

    // Add trailing nul.
    output.push(NUL_16);

    Ok(output)
}

fn entry_point_from_offset(
    data: &[u8],
    entry_point_offset: usize,
) -> Entrypoint {
    info!("entry_point_offset: 0x{:x}", entry_point_offset);

    let entry_point_address = (data.as_ptr() as usize) + entry_point_offset;
    info!("entry_point_address: 0x{:x}", entry_point_address);

    // Convert the address back to a pointer and transmute to the desired
    // function pointer type.
    let entry_point = entry_point_address as *const ();
    unsafe {
        let entry_point: Entrypoint = mem::transmute(entry_point);
        entry_point
    }
}

fn modify_loaded_image(
    image: Handle,
    system_table: &SystemTable<Boot>,
    kernel_data: &[u8],
    cmdline_ucs2: &[Char16],
) -> Result<()> {
    let bt = system_table.boot_services();

    let li = bt
        .handle_protocol::<LoadedImage>(image)
        .log_warning()
        .map_err(|err| Error::LoadedImageProtocolMissing(err.status()))?;
    let li: &mut LoadedImage = unsafe { &mut *li.get() };

    // Set kernel command line.
    let load_options_size = 2 * cmdline_ucs2.len();
    let load_options_size = u32::try_from(load_options_size)
        .map_err(|_| Error::CommandLineTooBig(load_options_size))?;
    unsafe {
        li.set_load_options(cmdline_ucs2.as_ptr(), load_options_size);
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
    crdyboot_image: Handle,
    system_table: SystemTable<Boot>,
    cmdline: &str,
) -> Result<()> {
    info!("booting the EFI stub");

    // Convert the string to UCS-2.
    let cmdline_ucs2 = str_to_uefi_str(cmdline)?;

    // Ideally we could create a new image here, but I'm not sure
    // there's any way to do that without calling LoadImage, which we
    // can't do due to secure boot. This is the same method shim uses:
    // modify the existing image's parameters.
    modify_loaded_image(
        crdyboot_image,
        &system_table,
        kernel_data,
        &cmdline_ucs2,
    )?;

    unsafe {
        (entry_point)(crdyboot_image, system_table);
    }

    Err(Error::KernelDidNotTakeControl)
}

pub fn execute_linux_kernel(
    kernel: &LoadedKernel,
    crdyboot_image: Handle,
    system_table: SystemTable<Boot>,
) -> Result<()> {
    let cmdline = kernel.command_line().ok_or(Error::GetCommandLineFailed)?;
    info!("command line: {}", cmdline);

    let pe = PeExecutable::parse(kernel.data()).map_err(Error::InvalidPe)?;

    let execute_linux_efi_stub = |system_table, entry_point_offset| {
        execute_linux_efi_stub(
            kernel.data(),
            entry_point_from_offset(kernel.data(), entry_point_offset),
            crdyboot_image,
            system_table,
            &cmdline,
        )
    };

    if is_64bit() {
        execute_linux_efi_stub(system_table, pe.entry_point())
    } else if let Some(entry) = pe.get_ia32_compat_entry_point() {
        execute_linux_efi_stub(system_table, entry)
    } else {
        Err(Error::KernelTooOld)
    }
}
