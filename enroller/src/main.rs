#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

use alloc::vec::Vec;
use log::info;
use uefi::prelude::*;
use uefi::table::runtime::{VariableAttributes, GLOBAL_VARIABLE};
use uefi::{CStr16, Guid};

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

    let pk_and_kek_var = include_bytes!(
        "../../workspace/secure_boot_root_key/key.pk_and_kek.var"
    );
    let db_var =
        include_bytes!("../../workspace/secure_boot_root_key/key.db.var");

    let rt = st.runtime_services();

    // TODO: add this to uefi-rs
    let image_security_database_guid = Guid::from_values(
        0xd719b2cb,
        0x3d3a,
        0x4596,
        0xa3bc,
        [0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
    );

    rt.set_variable(
        CString16::from_str("db").as_cstr16(),
        &image_security_database_guid,
        VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        db_var,
    )
    .expect_success("failed to write db");

    rt.set_variable(
        CString16::from_str("KEK").as_cstr16(),
        &GLOBAL_VARIABLE,
        VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        pk_and_kek_var,
    )
    .expect_success("failed to write KEK");

    rt.set_variable(
        CString16::from_str("PK").as_cstr16(),
        &GLOBAL_VARIABLE,
        VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        pk_and_kek_var,
    )
    .expect_success("failed to write PK");

    info!("Successfully set custom db, KEK, and PK variables");

    let bt = st.boot_services();
    bt.stall(20_000_000);

    Status::SUCCESS
}
