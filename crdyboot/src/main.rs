// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]

use libcrdy::{
    embed_section, load_and_execute_kernel, self_revocation_check, set_log_level, CrdybootError,
};
use uefi::prelude::*;

#[cfg(not(target_os = "uefi"))]
use libcrdy::uefi_services;

fn run(mut st: SystemTable<Boot>) -> Result<(), CrdybootError> {
    uefi_services::init(&mut st).expect("failed to initialize uefi_services");
    set_log_level(st.boot_services());

    // The self-revocation check should happen as early as possible, so
    // do it right after setting the log level.
    self_revocation_check(st.runtime_services()).map_err(CrdybootError::Revocation)?;

    load_and_execute_kernel(st)
}

#[entry]
fn efi_main(image: Handle, st: SystemTable<Boot>) -> Status {
    match run(st) {
        Ok(()) => unreachable!("kernel did not take control"),
        Err(err) => {
            panic!("boot failed: {err}");
        }
    }
}

// Add `.sbat` section to the binary.
//
// See https://github.com/rhboot/shim/blob/main/SBAT.md for details of what
// this section is used for.
embed_section!(SBAT, ".sbat", "../sbat.csv");

// Add `.vbpubk` section to the binary.
//
// The data in this section is loaded by libcrdy to get the public key
// used for kernel partition verification.
//
// By default this contains a test key with padding so that the section
// can also hold larger keys. The real key is filled in during image
// signing using `objcopy --update-section`.
embed_section!(
    KERNEL_VERIFICATION_KEY,
    ".vbpubk",
    concat!(env!("OUT_DIR"), "/padded_vbpubk")
);
