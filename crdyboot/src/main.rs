// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::pedantic)]
#![no_std]
#![no_main]
#![feature(abi_efiapi)]

use libcrdy::{load_and_execute_kernel, self_revocation_check, set_log_level, Error, Result};
use uefi::prelude::*;

fn run(mut st: SystemTable<Boot>) -> Result<()> {
    uefi_services::init(&mut st).map_err(|err| Error::UefiServicesInitFailed(err.status()))?;
    set_log_level(st.boot_services());

    // The self-revocation check should happen as early as possible, so
    // do it right after setting the log level.
    self_revocation_check(st.runtime_services())?;

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
include!(concat!(env!("OUT_DIR"), "/sbat_section.rs"));

// Add `.vbpubk` section to the binary.
//
// The data in this section is loaded by libcrdy to get the public key
// used for kernel partition verification.
//
// By default this contains a test key with padding so that the section
// can also hold larger keys. The real key is filled in during image
// signing using `objcopy --update-section`.
include!(concat!(env!("OUT_DIR"), "/vbpubk_section.rs"));
