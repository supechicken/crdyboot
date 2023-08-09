// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]

mod arch;
mod disk;
mod entry_point;
mod launch;
mod linux;
mod logging;
mod nx;
mod page_alloc;
mod revocation;
mod tpm;
pub mod uefi_services;
mod util;
mod vbpubk;

pub use linux::{load_and_execute_kernel, CrdybootError};
pub use logging::set_log_level;
pub use revocation::self_revocation_check;
