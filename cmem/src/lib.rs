// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! UEFI targets don't have the C library. This module provides
//! malloc/calloc/free wrappers that delegate to Rust's allocator.
//! This crate is limited to `cfg(target_os = "uefi")` to avoid conflicting
//! with the existing malloc/calloc/free symbols provided by the C stdlib in
//! other enviroments.
//!
//! Functions are exported with `extern "C"` and do not need to be directly
//! referenced. To ensure this crate is linked use `extern crate`, for example
//! `extern crate cmem as _;`[1]
//!
//! [1]: https://doc.rust-lang.org/reference/items/extern-crates.html#extern-crate-declarations
#![cfg(target_os = "uefi")]
#![no_std]

extern crate alloc;

include!("../../third_party/malloc.rs");

#[no_mangle]
unsafe extern "C" fn calloc(elem_count: usize, elem_size: usize) -> *mut u8 {
    if let Some(bytes) = elem_count.checked_mul(elem_size) {
        let ptr = malloc(bytes);
        if !ptr.is_null() {
            ptr.write_bytes(0, bytes);
        }
        ptr
    } else {
        core::ptr::null_mut()
    }
}
