// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The avb crate is a `no_std` library that handles loading and verifying
//! the avb partitions.
//!
//! This crate can be built for the host target so that tests can run.

#![deny(missing_docs)]
#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]
// Needed by the printf module.
#![feature(c_variadic)]

extern crate alloc;

pub mod avb_ops;
mod avb_sysdeps;

/// Bindgen wrappers for parts of avb.
#[allow(clippy::pub_underscore_fields)]
#[allow(clippy::unreadable_literal)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod avb_sys {
    include!(concat!(env!("OUT_DIR"), "/avb_bindgen.rs"));
}

// The UEFI targets don't have the C library. Force the inclusion
// of `cmem` which has malloc/calloc/free wrappers that
// delegate to Rust's allocator.
extern crate cmem as _;
