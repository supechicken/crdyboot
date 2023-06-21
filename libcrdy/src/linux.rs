// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::GptDisk;
use crate::nx;
use crate::page_alloc::ScopedPageAllocation;
use crate::pe::{get_vbpubk_from_image, PeInfo};
use crate::tpm::extend_pcr_and_log;
use crate::{Error, Result};
use core::ffi::c_void;
use core::mem;
use log::info;
use uefi::proto::loaded_image::LoadedImage;
use uefi::table::boot::{AllocateType, BootServices, MemoryType};
use uefi::table::{Boot, SystemTable};
use uefi::{CStr16, CString16, Handle};
use vboot::{LoadKernelInputs, LoadedKernel};

type Entrypoint = unsafe extern "efiapi" fn(Handle, SystemTable<Boot>);

fn is_64bit() -> bool {
    match mem::size_of::<usize>() {
        8 => true,
        4 => false,
        other => panic!("invalid size of usize: {other}"),
    }
}

fn entry_point_from_offset(data: &[u8], entry_point_offset: u32) -> Result<Entrypoint> {
    info!("entry_point_offset: 0x{:x}", entry_point_offset);

    let entry_point_offset =
        usize::try_from(entry_point_offset).map_err(|_| Error::Overflow("entry_point_offset"))?;

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

fn modify_loaded_image(bt: &BootServices, kernel_data: &[u8], cmdline_ucs2: &CStr16) -> Result<()> {
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
    let image_size = u64::try_from(kernel_data.len()).expect("usize is larger than u64");
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
    let cmdline_ucs2 =
        CString16::try_from(cmdline).map_err(|_| Error::CommandLineUcs2ConversionFailed)?;

    // Ideally we could create a new image here, but I'm not sure
    // there's any way to do that without calling LoadImage, which we
    // can't do due to secure boot. This is the same method shim uses:
    // modify the existing image's parameters.
    modify_loaded_image(system_table.boot_services(), kernel_data, &cmdline_ucs2)?;

    unsafe {
        (entry_point)(system_table.boot_services().image_handle(), system_table);
    }

    Err(Error::KernelDidNotTakeControl)
}

fn execute_linux_kernel(kernel: &LoadedKernel, system_table: SystemTable<Boot>) -> Result<()> {
    let cmdline = kernel.command_line().ok_or(Error::GetCommandLineFailed)?;
    info!("command line: {cmdline}");

    let pe = PeInfo::parse(kernel.data()).map_err(Error::InvalidPe)?;

    nx::update_mem_attrs(&pe, system_table.boot_services()).map_err(Error::MemoryProtection)?;

    let execute_linux_efi_stub = |system_table, entry_point_offset| {
        execute_linux_efi_stub(
            kernel.data(),
            entry_point_from_offset(kernel.data(), entry_point_offset)?,
            system_table,
            &cmdline,
        )
    };

    if is_64bit() {
        execute_linux_efi_stub(system_table, pe.primary_entry_point())
    } else {
        execute_linux_efi_stub(
            system_table,
            pe.ia32_compat_entry_point()
                .ok_or(Error::MissingIa32CompatEntryPoint)?,
        )
    }
}

/// Use vboot to load the kernel from the appropriate kernel partition,
/// then execute it. If successful, this function will never return.
pub fn load_and_execute_kernel(system_table: SystemTable<Boot>) -> Result<()> {
    let mut workbuf = ScopedPageAllocation::new(
        // Safety: this system table clone will remain valid until
        // ExitBootServices is called. That won't happen until after the
        // kernel is executed, at which point crdyboot code is no longer
        // running.
        unsafe { system_table.unsafe_clone() },
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        LoadKernelInputs::RECOMMENDED_WORKBUF_SIZE,
    )?;

    // Allocate a fairly large buffer. This buffer must be big enough to
    // hold the kernel data loaded by vboot. Allocating 64MiB should be
    // more than enough for the forseeable future.
    //
    // This buffer will never be freed, unless loading or executing the
    // kernel fails.
    let mut kernel_buffer = ScopedPageAllocation::new(
        // Safety: this system table clone will remain valid until
        // ExitBootServices is called. That won't happen until after the
        // kernel is executed, at which point crdyboot code is no longer
        // running.
        unsafe { system_table.unsafe_clone() },
        AllocateType::AnyPages,
        MemoryType::LOADER_CODE,
        // 64 MiB.
        64 * 1024 * 1024,
    )?;

    let boot_services = system_table.boot_services();

    let kernel_verification_key = get_vbpubk_from_image(boot_services).map_err(Error::Vbpubk)?;
    info!(
        "kernel_verification_key len={}",
        kernel_verification_key.len()
    );

    let kernel = vboot::load_kernel(
        LoadKernelInputs {
            workbuf: &mut workbuf,
            kernel_buffer: &mut kernel_buffer,
            packed_pubkey: kernel_verification_key,
        },
        &mut GptDisk::new(boot_services).map_err(Error::GptDisk)?,
    )
    .map_err(Error::LoadKernelFailed)?;

    // Go ahead and free the workbuf, not needed anymore.
    drop(workbuf);

    // Measure the kernel into the TPM.
    extend_pcr_and_log(system_table.boot_services(), kernel.data()).map_err(Error::Tpm)?;

    execute_linux_kernel(&kernel, system_table)
}
