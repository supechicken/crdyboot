// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Stub `uefi_services` interface for use when compiling tests for the
//! host arch. The real `uefi_services` cannot be used in that case
//! because it enables the `global_allocator` feature of the `uefi`
//! crate, which conflicts with std's global allocator.

#![cfg(not(target_os = "uefi"))]

use uefi::table::{Boot, SystemTable};
use uefi::Result;

pub fn init(_st: &mut SystemTable<Boot>) -> Result {
    Ok(())
}
