// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]
// TODO(nicholasbishop): temporarily allow dead_code to make it easier
// to split up changes into separate CLs.
#![allow(dead_code)]

extern crate alloc;

mod fs;
mod relocation;
mod sbat_revocation;

use libcrdy::embed_section;
use log::info;
use uefi::prelude::*;
use uefi::table::runtime::VariableVendor;

#[cfg(not(target_os = "uefi"))]
use libcrdy::uefi_services;

#[allow(clippy::doc_markdown)]
/// Check whether secure boot is enabled or not.
///
/// The firmware communicates secure boot status with a global
/// "SecureBoot" UEFI variable containing a `u8` value. If the value is
/// 0, secure boot is disabled. If the value is 1, secure boot is
/// enabled.
///
/// If the variable cannot be read, or if the value is anything other
/// than 0 or 1, log an error and treat it as secure boot being
/// disabled.
fn is_secure_boot_enabled(runtime_services: &RuntimeServices) -> bool {
    let mut buf: [u8; 1] = [0];
    match runtime_services.get_variable(
        cstr16!("SecureBoot"),
        &VariableVendor::GLOBAL_VARIABLE,
        &mut buf,
    ) {
        Ok(([0], _)) => false,
        Ok(([1], _)) => true,
        Ok((val, _)) => {
            // Only the values 0 and 1 are valid per the spec. If the
            // variable contains some other number, treat it as secure
            // boot being disabled.
            info!("unexpected SecureBoot value: {val:x?}");
            false
        }
        Err(err) => {
            // If the variable cannot be read, treat it as secure boot
            // being disabled.
            info!("failed to read SecureBoot variable: {}", err.status());
            false
        }
    }
}

#[entry]
fn efi_main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("failed to initialize uefi_services");

    todo!()
}

// Add `.sbat` section to the binary.
//
// See https://github.com/rhboot/shim/blob/main/SBAT.md for details of what
// this section is used for.
embed_section!(SBAT, ".sbat", "../sbat.csv");
