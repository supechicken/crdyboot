// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Implement [avb_sysdeps.h](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_sysdeps.h) libavb usage.
use core::ffi::{c_char, c_int, c_void};

#[no_mangle]
unsafe extern "C" fn avb_memcmp(_src1: *const c_void, _src2: *const c_void, _n: usize) -> c_int {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn avb_strcmp(_s1: *const c_char, _s2: *const c_char) -> c_int {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn avb_strncmp(_s1: *const c_char, _s2: *const c_char, _n: usize) -> c_int {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn avb_memcpy(_dest: *mut c_void, _src: *const c_void, _n: usize) -> *mut c_void {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn avb_memset(_dest: *mut c_void, _c: c_int, _n: usize) -> *mut c_void {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn avb_print(_message: *const c_char) {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn avb_printv(_message: *const c_char, mut _args: ...) {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn avb_printf(_fmt: *const c_char, mut _args: ...) {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn avb_abort() {
    panic!("abort called")
}

// Declare the extern C functions that avb_malloc and avb_free
// will delegate to.
// These will need to be included elsewhere either via
// the mallocalloc crate or available from the libc as
// is provided when running tests.
extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

#[no_mangle]
unsafe extern "C" fn avb_malloc_(size: usize) -> *mut c_void {
    // Pass the call to the extern C function for malloc.
    // This is either included with libc (on the host) or expected
    // to be defined by `cmem` for the uefi target.
    malloc(size)
}

#[no_mangle]
unsafe extern "C" fn avb_free(ptr: *mut c_void) {
    // Pass the call to the extern C function for free.
    // This is either included with libc (on the host) or expected
    // to be defined by `cmem` for the uefi target.
    free(ptr);
}

#[no_mangle]
unsafe extern "C" fn avb_strlen(_str_: *const c_char) -> usize {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn avb_div_by_10(_dividend: *mut u64) -> u32 {
    todo!()
}
