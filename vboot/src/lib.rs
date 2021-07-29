#![no_std]

extern crate alloc;

mod gpt;
mod kernel;

#[allow(clippy::missing_safety_doc)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod vboot_sys {
    include!(concat!(env!("OUT_DIR"), "/vboot_bindgen.rs"));

    // ctypes
    type c_char = i8;
    type c_int = i32;
}

pub use gpt::CgptAttributes;
pub use kernel::{verify_kernel, PublicKey};

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
