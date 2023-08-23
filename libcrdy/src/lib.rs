// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]

pub mod arch;
pub mod entry_point;
pub mod launch;
mod logging;
pub mod nx;
pub mod page_alloc;
pub mod tpm;
pub mod uefi_services;
pub mod util;

pub use logging::set_log_level;
