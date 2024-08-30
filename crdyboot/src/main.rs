// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]

extern crate alloc;

mod disk;
mod firmware;
mod linux;
mod revocation;
mod sbat;
mod vbpubk;

use firmware::update_firmware;
use libcrdy::{embed_section, set_log_level};
use linux::{load_and_execute_kernel, CrdybootError};
use revocation::self_revocation_check;
use uefi::prelude::*;

fn run(st: SystemTable<Boot>) -> Result<(), CrdybootError> {
    uefi::helpers::init().expect("failed to initialize uefi::helpers");
    set_log_level();

    // The self-revocation check should happen as early as possible, so
    // do it right after setting the log level.
    self_revocation_check().map_err(CrdybootError::Revocation)?;

    // For debugging purposes, conditionally copy SBAT revocations to a
    // runtime-accessible UEFI variable.
    sbat::maybe_copy_sbat_revocations();

    // Install firmware update capsules if needed. This may reset the
    // system.
    update_firmware();

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
