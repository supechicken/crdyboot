// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::pedantic)]
#![expect(clippy::module_name_repetitions)]
#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]

extern crate alloc;

#[cfg(feature = "android")]
mod avb;
mod disk;
mod firmware;
#[cfg(feature = "android")]
mod initramfs;
mod linux;
mod revocation;
mod sbat;
mod vbpubk;

use firmware::update_firmware;
use libcrdy::{embed_section, fail_with_fatal_error, sbat_revocation, set_log_level};
use linux::{load_and_execute_kernel, CrdybootError};
use log::info;
use revocation::self_revocation_check;
use uefi::prelude::*;

fn run() -> Result<(), CrdybootError> {
    // The self-revocation check should happen as early as possible, so
    // do it right after setting the log level.
    self_revocation_check().map_err(CrdybootError::Revocation)?;

    // Update SBAT revocations if necessary.
    if let Err(err) = sbat_revocation::update_and_get_revocations() {
        // Log the error but otherwise ignore it.
        info!("failed to update SBAT revocations: {err:?}");
    }

    // For debugging purposes, conditionally copy SBAT revocations to a
    // runtime-accessible UEFI variable.
    sbat::maybe_copy_sbat_revocations();

    // Install firmware update capsules if needed. This may reset the
    // system.
    update_firmware();

    load_and_execute_kernel()
}

#[entry]
fn efi_main() -> Status {
    uefi::helpers::init().expect("failed to initialize uefi::helpers");
    set_log_level();

    match run() {
        Ok(()) => unreachable!("kernel did not take control"),
        Err(err) => {
            fail_with_fatal_error!(err);
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
