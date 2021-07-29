//! The vboot crate is a `no_std` library that handles loading and verifying
//! the kernel. Internally it uses the `LoadKernel` function from
//! `third_party/vboot_reference`.
//!
//! This crate can be built for the host target so that tests can run.

// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]
#![feature(c_variadic)]

extern crate alloc;

mod disk;
mod load_kernel;
mod printf;
mod stubs;

#[cfg(not(target_env = "gnu"))]
mod malloc;

#[allow(clippy::missing_safety_doc)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod vboot_sys {
    // The signedness of vb2_return_code created by bindgen differs
    // depending on the target
    #[cfg(target_arch = "x86")]
    type vb2_error_t = u32;
    #[cfg(target_arch = "x86_64")]
    type vb2_error_t = i32;

    include!(concat!(env!("OUT_DIR"), "/vboot_bindgen.rs"));

    // ctypes
    type c_char = i8;
    type c_int = i32;
    type c_void = core::ffi::c_void;
}

pub use disk::DiskIo;
pub use load_kernel::{load_kernel, LoadedKernel};
pub use vboot_sys::vb2_return_code as return_code;

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

    let ptr = buf.as_ptr() as *const T;

    Some(&*ptr)
}
