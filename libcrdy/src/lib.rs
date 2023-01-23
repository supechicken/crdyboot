// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::pedantic)]
#![allow(clippy::enum_glob_use)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]
#![feature(abi_efiapi)]

mod disk;
mod linux;
mod logging;
mod page_alloc;
mod pe;
mod result;
mod revocation;
mod tpm;

pub use linux::load_and_execute_kernel;
pub use logging::set_log_level;
pub use result::{Error, Result};
pub use revocation::self_revocation_check;
