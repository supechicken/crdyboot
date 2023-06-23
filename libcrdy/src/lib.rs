// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::pedantic)]
#![allow(clippy::enum_glob_use)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]

mod arch;
mod disk;
mod launch;
mod linux;
mod logging;
mod nx;
mod page_alloc;
mod pe;
mod result;
mod revocation;
mod tpm;

pub use linux::load_and_execute_kernel;
pub use logging::set_log_level;
pub use result::{Error, Result};
pub use revocation::self_revocation_check;

/// On the targets we care about, `usize` is always at least as large as `u32`.
fn u32_to_usize(v: u32) -> usize {
    v.try_into().expect("size of usize is smaller than u32")
}
