#![no_std]
#![no_main]
#![feature(abi_efiapi)]

use uefi::prelude::*;

#[entry]
fn efi_main(_image: Handle, st: SystemTable<Boot>) -> Status {
    uefi_services::init(&st).expect_success("Failed to initialize utilities");

    todo!();
}
