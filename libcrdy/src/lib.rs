// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::pedantic)]
#![expect(clippy::missing_errors_doc)]
#![expect(clippy::module_name_repetitions)]
#![cfg_attr(target_os = "uefi", no_std)]

extern crate alloc;

pub mod arch;
pub mod entry_point;
mod error;
pub mod fs;
pub mod launch;
pub mod logging;
pub mod nx;
pub mod page_alloc;
pub mod relocation;
pub mod sbat_revocation;
pub mod tpm;
pub mod uefi;
pub mod util;

pub use error::fail_with_fatal_error_impl;
pub use logging::set_log_level;
