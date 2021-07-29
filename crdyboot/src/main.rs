#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

mod disk;
mod handover;
mod linux;
mod truncate;

use alloc::vec::Vec;
use core::convert::TryFrom;
use log::{error, info};
use uefi::data_types::chars::NUL_16;
use uefi::prelude::*;
use uefi::{Char16, Result};
use vboot::LoadedKernel;

// TODO: open protocol vs handle protocol

// TODO: check if uefi-rs already has a way to do this.
fn ascii_str_to_uefi_str(input: &str) -> Option<Vec<Char16>> {
    if !input.is_ascii() {
        return None;
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

    Some(output)
}

fn run_kernel(
    crdyboot_image: Handle,
    st: SystemTable<Boot>,
    kernel: &LoadedKernel,
) -> Result<()> {
    let st_clone: SystemTable<Boot> = unsafe { st.unsafe_clone() };

    // TODO: unwrap
    let load_options_utf8 = kernel.command_line().unwrap();
    info!("command line: {}", load_options_utf8);

    // Convert the string to UCS-2.
    let load_options_ucs2 = ascii_str_to_uefi_str(&load_options_utf8).unwrap();

    // Run the kernel.
    linux::execute_linux_kernel(
        kernel.data(),
        crdyboot_image,
        st_clone,
        &load_options_utf8,
        &load_options_ucs2,
    )
    .log_warning()?;

    Status::SUCCESS.into()
}

fn run(crdyboot_image: Handle, st: SystemTable<Boot>) -> Result<()> {
    let st_clone = unsafe { st.unsafe_clone() };
    let bt = st_clone.boot_services();

    // TODO
    let test_key_vbpubk =
        include_bytes!("../../vboot/test_data/kernel_key.vbpubk");

    let gpt_disk = disk::GptDisk::new(crdyboot_image, bt).log_warning()?;
    let kernel = vboot::load_kernel(test_key_vbpubk, &gpt_disk).unwrap();

    if let Err(err) = run_kernel(crdyboot_image, st, &kernel).log_warning() {
        error!("failed to run kernel: {:?}", err);
    }

    // Failed to run any kernel.
    Status::LOAD_ERROR.into()
}

#[entry]
fn efi_main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st)
        .expect_success("failed to initialize utilities");

    run(image, st).expect_success("run failed");

    panic!("failed to run any kernel");
}

#[no_mangle]
#[link_section = ".sbat"]
static SBAT: [u8; 163] = *include_bytes!("sbat.csv");
