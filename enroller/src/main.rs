#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

use core::mem;
use log::info;
use uefi::prelude::*;
use uefi::table::runtime::{ResetType, VariableAttributes, VariableVendor};
use uefi::CString16;

#[entry]
fn efi_main(_image: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("failed to initialize utilities");

    match mem::size_of::<usize>() {
        4 => info!("32-bit UEFI"),
        8 => info!("64-bit UEFI"),
        size => info!("Weird UEFI: usize is {} bytes", size),
    }

    let pk_and_kek_var = include_bytes!(
        "../../workspace/secure_boot_root_key/key.pk_and_kek.var"
    );
    let db_var =
        include_bytes!("../../workspace/secure_boot_root_key/key.db.var");

    let rt = st.runtime_services();

    let attrs = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS
        | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

    info!("writing db var");
    rt.set_variable(
        &CString16::try_from("db").unwrap(),
        &VariableVendor::IMAGE_SECURITY_DATABASE,
        attrs,
        db_var,
    )
    .expect("failed to write db");

    info!("writing KEK var");
    rt.set_variable(
        &CString16::try_from("KEK").unwrap(),
        &VariableVendor::GLOBAL_VARIABLE,
        attrs,
        pk_and_kek_var,
    )
    .expect("failed to write KEK");

    info!("writing PK var");
    rt.set_variable(
        &CString16::try_from("PK").unwrap(),
        &VariableVendor::GLOBAL_VARIABLE,
        attrs,
        pk_and_kek_var,
    )
    .expect("failed to write PK");

    info!("Successfully set custom db, KEK, and PK variables");

    let delay_in_s = 10;
    info!("shutting down in {} seconds", delay_in_s);

    let bt = st.boot_services();
    bt.stall(delay_in_s * 1_000_000);

    rt.reset(ResetType::Shutdown, Status::SUCCESS, None);
}
