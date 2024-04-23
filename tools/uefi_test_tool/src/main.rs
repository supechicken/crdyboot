// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]

use uefi::table::{Boot, SystemTable};
use uefi::{entry, Handle, Status};

#[cfg(not(target_os = "uefi"))]
use libcrdy::uefi_services;

#[entry]
fn efi_main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("failed to initialize uefi_services");

    Status::SUCCESS
}
