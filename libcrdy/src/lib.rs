// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]
#![feature(abi_efiapi)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::ptr_as_ptr)]

mod disk;
mod linux;
mod pe;
mod result;

pub use linux::{execute_linux_kernel, load_kernel};
pub use pe::PeError;
pub use result::{Error, Result};
