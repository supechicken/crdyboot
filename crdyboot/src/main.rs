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
use libcrdy::sbat_revocation::{self, RevocationError};
use libcrdy::{embed_section, fail_with_fatal_error, set_log_level};
use linux::{load_and_execute_kernel, CrdybootError};
use log::info;
use revocation::self_revocation_check;
use uefi::prelude::*;

/// Represents the high-level flow of the crdyboot application. Crdyboot
/// has a very linear flow, so control just goes through these methods
/// in order.
///
/// This is implemented as a trait to allow for mocking.
#[cfg_attr(test, mockall::automock)]
trait Crdyboot {
    fn self_revocation_check(&self) -> Result<(), CrdybootError>;

    fn update_sbat_revocations(&self) -> Result<(), RevocationError>;

    fn maybe_copy_sbat_revocations(&self);

    fn update_firmware(&self);

    fn load_and_execute_kernel(&self) -> Result<(), CrdybootError>;
}

/// The real implementation of the `Crdyboot` trait used at runtime.
struct CrdybootImpl;

impl Crdyboot for CrdybootImpl {
    fn self_revocation_check(&self) -> Result<(), CrdybootError> {
        self_revocation_check().map_err(CrdybootError::Revocation)
    }

    fn update_sbat_revocations(&self) -> Result<(), RevocationError> {
        sbat_revocation::update_and_get_revocations().map(|_| ())
    }

    fn maybe_copy_sbat_revocations(&self) {
        sbat::maybe_copy_sbat_revocations();
    }

    fn update_firmware(&self) {
        update_firmware();
    }

    fn load_and_execute_kernel(&self) -> Result<(), CrdybootError> {
        load_and_execute_kernel()
    }
}

fn run(crdyboot: &dyn Crdyboot) -> Result<(), CrdybootError> {
    // The self-revocation must happen as early as possible.
    crdyboot.self_revocation_check()?;

    // Update SBAT revocations if necessary.
    if let Err(err) = crdyboot.update_sbat_revocations() {
        // Log the error but otherwise ignore it.
        info!("failed to update SBAT revocations: {err:?}");
    }

    // For debugging purposes, conditionally copy SBAT revocations to a
    // runtime-accessible UEFI variable.
    crdyboot.maybe_copy_sbat_revocations();

    // Install firmware update capsules if needed. This may reset the
    // system.
    crdyboot.update_firmware();

    crdyboot.load_and_execute_kernel()
}

#[entry]
fn efi_main() -> Status {
    uefi::helpers::init().expect("failed to initialize uefi::helpers");
    set_log_level();

    match run(&CrdybootImpl) {
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
