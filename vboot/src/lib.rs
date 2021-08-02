//! The vboot crate is a `no_std` library that handles loading and verifying
//! the kernel. Internally it uses the `LoadKernel` function from
//! `third_party/vboot_reference`.
//!
//! This crate can be built for the host target so that tests can run.

#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::ptr_as_ptr)]
#![deny(missing_docs)]
// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]
// Needed by the printf module.
#![feature(c_variadic)]

extern crate alloc;

mod disk;
mod load_kernel;
mod printf;
mod stubs;

// The UEFI targets don't have the C library. This module provides
// malloc/free wrappers that delegate to Rust's `alloc`.
#[cfg(not(target_env = "gnu"))]
mod malloc;

/// Bindgen wrappers for parts of vboot_reference.
#[allow(clippy::missing_safety_doc)]
#[allow(clippy::ptr_as_ptr)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod vboot_sys {
    // ctypes
    type c_char = i8;
    type c_void = core::ffi::c_void;

    include!(concat!(env!("OUT_DIR"), "/vboot_bindgen.rs"));
    include!(concat!(env!("OUT_DIR"), "/vboot_return_codes.rs"));
}

pub use disk::DiskIo;
pub use load_kernel::{load_kernel, LoadKernelError, LoadedKernel};
pub use vboot_sys::return_code_to_str;
pub use vboot_sys::vb2_return_code as ReturnCode;

/// Get an &T backed by a byte slice. The slice is checked to make sure it's
/// at least as large as the size of T.
///
/// # Safety
///
/// This can only be called safely on `repr(C, packed)` structs whose fields
/// are either numeric or structures that also meet these restrictions
/// (recursively).
pub unsafe fn struct_from_bytes<T>(buf: &[u8]) -> Option<&T> {
    if buf.len() < core::mem::size_of::<T>() {
        return None;
    }

    let ptr = buf.as_ptr().cast::<T>();

    Some(&*ptr)
}
