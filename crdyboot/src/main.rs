// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::pedantic)]
#![no_std]
#![no_main]
#![feature(abi_efiapi)]

use libcrdy::{load_and_execute_kernel, Error, Result};
use log::LevelFilter;
use uefi::prelude::*;

fn set_log_level() {
    #[cfg(feature = "verbose")]
    let level = LevelFilter::Debug;
    #[cfg(not(feature = "verbose"))]
    let level = LevelFilter::Warn;

    log::set_max_level(level);
}

/// Get the public key used to verify the kernel. By default the key is read
/// from `keys/kernel_key.vbpubk`. If the `use_test_key` feature is enabled
/// then the key is read from a test file in the repo instead.
fn get_kernel_verification_key() -> &'static [u8] {
    let key;

    #[cfg(feature = "use_test_key")]
    {
        log::warn!("using test key for kernel verification");
        key = include_bytes!("../../third_party/vboot_reference/tests/devkeys/kernel_subkey.vbpubk");
    }

    #[cfg(not(feature = "use_test_key"))]
    {
        key = include_bytes!("../../keys/kernel_key.vbpubk");
    }

    key
}

fn run(mut st: SystemTable<Boot>) -> Result<()> {
    uefi_services::init(&mut st)
        .map_err(|err| Error::UefiServicesInitFailed(err.status()))?;
    set_log_level();

    load_and_execute_kernel(st, get_kernel_verification_key())
}

#[entry]
fn efi_main(image: Handle, st: SystemTable<Boot>) -> Status {
    match run(st) {
        Ok(()) => unreachable!("kernel did not take control"),
        Err(err) => {
            panic!("boot failed: {}", err);
        }
    }
}

// Add `.sbat` section to the binary.
//
// See https://github.com/rhboot/shim/blob/main/SBAT.md for details of what
// this section is used for.
include!(concat!(env!("OUT_DIR"), "/sbat_section.rs"));
