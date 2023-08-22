// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]

use core::mem;
use log::info;
use uefi::guid;
use uefi::prelude::*;
use uefi::table::runtime::{ResetType, VariableAttributes, VariableVendor};

#[cfg(not(target_os = "uefi"))]
use libcrdy::uefi_services;

#[entry]
fn efi_main(_image: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("failed to initialize utilities");

    match mem::size_of::<usize>() {
        4 => info!("32-bit UEFI"),
        8 => info!("64-bit UEFI"),
        size => info!("Weird UEFI: usize is {size} bytes"),
    }

    let pk_and_kek_var = include_bytes!("../../workspace/secure_boot_root_key/key.pk_and_kek.var");
    let db_var = include_bytes!("../../workspace/secure_boot_root_key/key.db.var");

    let rt = st.runtime_services();

    let attrs = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS
        | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

    info!("writing db var");
    rt.set_variable(
        cstr16!("db"),
        &VariableVendor::IMAGE_SECURITY_DATABASE,
        attrs,
        db_var,
    )
    .expect("failed to write db");

    info!("writing KEK var");
    rt.set_variable(
        cstr16!("KEK"),
        &VariableVendor::GLOBAL_VARIABLE,
        attrs,
        pk_and_kek_var,
    )
    .expect("failed to write KEK");

    info!("writing PK var");
    rt.set_variable(
        cstr16!("PK"),
        &VariableVendor::GLOBAL_VARIABLE,
        attrs,
        pk_and_kek_var,
    )
    .expect("failed to write PK");

    info!("Successfully set custom db, KEK, and PK variables");

    if cfg!(feature = "shim_verbose") {
        info!("writing SHIM_VERBOSE var");
        rt.set_variable(
            cstr16!("SHIM_VERBOSE"),
            &VariableVendor(guid!("605dab50-e046-4300-abb6-3dd810dd8b23")),
            VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS,
            b"1",
        )
        .expect("failed to write SHIM_VERBOSE");
    }

    rt.reset(ResetType::SHUTDOWN, Status::SUCCESS, None);
}
