// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::ptr_as_ptr)]

extern crate alloc;

use libcrdy::{execute_linux_kernel, load_kernel, Error, Result};
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
        key = include_bytes!("../../workspace/test_kernel_key/key.vbpubk");
    }

    #[cfg(not(feature = "use_test_key"))]
    {
        key = include_bytes!("../../keys/kernel_key.vbpubk");
    }

    key
}

fn run(crdyboot_image: Handle, mut st: SystemTable<Boot>) -> Result<()> {
    uefi_services::init(&mut st)
        .map_err(|err| Error::UefiServicesInitFailed(err.status()))?;
    set_log_level();

    let kernel_verification_key = get_kernel_verification_key();
    let kernel = load_kernel(
        crdyboot_image,
        st.boot_services(),
        kernel_verification_key,
    )?;
    execute_linux_kernel(&kernel, crdyboot_image, st)?;

    Err(Error::KernelDidNotTakeControl)
}

#[entry]
fn efi_main(image: Handle, st: SystemTable<Boot>) -> Status {
    match run(image, st) {
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
