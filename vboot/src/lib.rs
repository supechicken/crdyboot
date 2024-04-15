// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The vboot crate is a `no_std` library that handles loading and verifying
//! the kernel. Internally it uses the `LoadKernel` function from
//! `third_party/vboot_reference`.
//!
//! This crate can be built for the host target so that tests can run.

#![deny(missing_docs)]
#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]
// Needed by the printf module.
#![feature(c_variadic)]

extern crate alloc;

mod disk;
mod load_kernel;
mod printf;
mod return_codes;
mod stubs;

// The UEFI targets don't have the C library. This module provides
// malloc/calloc/free wrappers that delegate to Rust's allocator.
#[cfg(not(target_env = "gnu"))]
mod malloc {
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
}

/// Bindgen wrappers for parts of vboot_reference.
#[allow(dead_code)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(clippy::pedantic)]
mod vboot_sys {
    include!(concat!(env!("OUT_DIR"), "/vboot_bindgen.rs"));
}

pub use disk::DiskIo;
pub use load_kernel::{load_kernel, LoadKernelError, LoadKernelInputs, LoadedKernel};
pub use return_codes::return_code_to_str;
pub use vboot_sys::vb2_return_code as ReturnCode;
