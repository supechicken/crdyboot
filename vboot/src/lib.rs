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
pub use kernel::{struct_from_bytes, verify_kernel, PublicKey};
