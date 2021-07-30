#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

mod disk;
mod handover;
mod linux;
mod result;

use alloc::vec::Vec;
use core::convert::TryFrom;
use log::info;
use result::{Error, Result};
use uefi::data_types::chars::NUL_16;
use uefi::prelude::*;
use uefi::Char16;
use vboot::LoadedKernel;

// TODO: open protocol vs handle protocol

// TODO: check if uefi-rs already has a way to do this.
fn ascii_str_to_uefi_str(input: &str) -> Result<Vec<Char16>> {
    if !input.is_ascii() {
        return Err(Error::CommandLineIsNotAscii);
    }

    // Expect two bytes for each byte of the input, plus a null byte.
    let mut output = Vec::with_capacity(input.len() + 1);

    output.extend(
        input
            .encode_utf16()
            // OK to unwrap because all ASCII characters are
            // valid UCS-2.
            .map(|c| Char16::try_from(c).unwrap()),
    );
    output.push(NUL_16);

    Ok(output)
}

fn run_kernel(
    crdyboot_image: Handle,
    st: SystemTable<Boot>,
    kernel: &LoadedKernel,
) -> Result<()> {
    let load_options_utf8 =
        kernel.command_line().ok_or(Error::GetCommandLineFailed)?;
    info!("command line: {}", load_options_utf8);

    // Convert the string to UCS-2.
    let load_options_ucs2 = ascii_str_to_uefi_str(&load_options_utf8)?;

    // Run the kernel.
    linux::execute_linux_kernel(
        kernel.data(),
        crdyboot_image,
        st,
        &load_options_utf8,
        &load_options_ucs2,
    )
    .log_warning()
    .map_err(|err| Error::RunKernelFailed(err.status()))?;

    Ok(())
}

fn run(crdyboot_image: Handle, mut st: SystemTable<Boot>) -> Result<()> {
    uefi_services::init(&mut st)
        .log_warning()
        .map_err(|err| Error::UefiServicesInitFailed(err.status()))?;

    // TODO
    let test_key_vbpubk =
        include_bytes!("../../vboot/test_data/kernel_key.vbpubk");

    let gpt_disk = disk::GptDisk::new(crdyboot_image, st.boot_services())
        .log_warning()
        .map_err(|err| Error::Gpt(err.status()))?;
    let kernel = vboot::load_kernel(test_key_vbpubk, &gpt_disk)
        .map_err(Error::LoadKernelFailed)?;

    run_kernel(crdyboot_image, st, &kernel)?;

    Err(Error::KernelDidNotTakeControl)
}

#[entry]
fn efi_main(image: Handle, st: SystemTable<Boot>) -> Status {
    match run(image, st) {
        Ok(()) => unreachable!("kernel did not take control"),
        Err(err) => {
            panic!("boot failed: {}", err);
        }
    }
}

#[no_mangle]
#[link_section = ".sbat"]
static SBAT: [u8; 163] = *include_bytes!("sbat.csv");
