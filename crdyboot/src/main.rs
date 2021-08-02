#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::ptr_as_ptr)]

extern crate alloc;

mod disk;
mod handover;
mod linux;
mod result;

use alloc::vec::Vec;
use core::convert::TryFrom;
use log::{info, LevelFilter};
use result::{Error, Result};
use uefi::data_types::chars::NUL_16;
use uefi::prelude::*;
use uefi::Char16;
use vboot::LoadedKernel;

// TODO: open protocol vs handle protocol

fn ascii_str_to_uefi_str(input: &str) -> Result<Vec<Char16>> {
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
    )?;

    Ok(())
}

fn set_log_level() {
    #[cfg(feature = "verbose")]
    let level = LevelFilter::Debug;
    #[cfg(not(feature = "verbose"))]
    let level = LevelFilter::Warn;

    log::set_max_level(level);
}

/// Get the public key used to verify the kernel. By default the key is read
/// from `keys/kernel_key.vbpubk`. If the `use_test_key` feature is enabled
/// then the key is read from a test file in the repo instead.
fn get_kernel_verification_key() -> &'static [u8] {
    #[cfg(feature = "use_test_key")]
    let key = include_bytes!("../../vboot/test_data/kernel_key.vbpubk");

    #[cfg(not(feature = "use_test_key"))]
    let key = include_bytes!("../../keys/kernel_key.vbpubk");

    key
}

fn run(crdyboot_image: Handle, mut st: SystemTable<Boot>) -> Result<()> {
    uefi_services::init(&mut st)
        .log_warning()
        .map_err(|err| Error::UefiServicesInitFailed(err.status()))?;

    set_log_level();

    let kernel_verification_key = get_kernel_verification_key();
    let gpt_disk = disk::GptDisk::new(crdyboot_image, st.boot_services())?;
    let kernel = vboot::load_kernel(kernel_verification_key, &gpt_disk)
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

// See https://github.com/rhboot/shim/blob/main/SBAT.md for details of what
// this section is used for.
#[no_mangle]
#[link_section = ".sbat"]
static SBAT: [u8; 165] = *include_bytes!(concat!(env!("OUT_DIR"), "/sbat.csv"));
