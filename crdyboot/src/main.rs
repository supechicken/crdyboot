// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::pedantic)]
#![no_std]
#![no_main]
#![feature(abi_efiapi)]

use libcrdy::{load_and_execute_kernel, set_log_level, Error, Result};
use uefi::prelude::*;

fn run(mut st: SystemTable<Boot>) -> Result<()> {
    uefi_services::init(&mut st).map_err(|err| Error::UefiServicesInitFailed(err.status()))?;
    set_log_level(st.boot_services());

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
