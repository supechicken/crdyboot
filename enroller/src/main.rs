#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

use alloc::vec::Vec;
use core::mem;
use log::info;
use uefi::prelude::*;
use uefi::table::runtime::{ResetType, VariableAttributes, GLOBAL_VARIABLE};
use uefi::{CStr16, Guid};

// TODO: once a version of uefi-rs with 58ae6a401 is released, drop this
// struct and use the upstream version.
struct CString16(Vec<u16>);

impl CString16 {
    fn from_str(input: &str) -> CString16 {
        let mut v: Vec<u16> = input.encode_utf16().collect();
        v.push(0);
        CString16(v)
    }

    fn as_cstr16(&self) -> &CStr16 {
        match CStr16::from_u16_with_nul(&self.0) {
            Ok(s) => s,
            Err(_) => panic!("invalid string"),
        }
    }
}

#[entry]
fn efi_main(_image: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st)
        .expect_success("failed to initialize utilities");

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

    // TODO: this was added to uefi-rs in 4811caba3, once that's in a
    // release can drop this and use the upstream version.
    let image_security_database_guid = Guid::from_values(
        0xd719b2cb,
        0x3d3a,
        0x4596,
        0xa3bc,
        [0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
    );

    let attrs = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS
        | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

    info!("writing db var");
    rt.set_variable(
        CString16::from_str("db").as_cstr16(),
        &image_security_database_guid,
        attrs,
        db_var,
    )
    .expect_success("failed to write db");

    info!("writing KEK var");
    rt.set_variable(
        CString16::from_str("KEK").as_cstr16(),
        &GLOBAL_VARIABLE,
        attrs,
        pk_and_kek_var,
    )
    .expect_success("failed to write KEK");

    info!("writing PK var");
    rt.set_variable(
        CString16::from_str("PK").as_cstr16(),
        &GLOBAL_VARIABLE,
        attrs,
        pk_and_kek_var,
    )
    .expect_success("failed to write PK");

    info!("Successfully set custom db, KEK, and PK variables");

    let delay_in_s = 10;
    info!("shutting down in {} seconds", delay_in_s);

    let bt = st.boot_services();
    bt.stall(delay_in_s * 1_000_000);

    rt.reset(ResetType::Shutdown, Status::SUCCESS, None);
}
