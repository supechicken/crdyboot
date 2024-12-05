// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::ffi::c_char;

#[no_mangle]
extern "C" fn vb2ex_abort() {
    panic!("vb2ex_abort called");
}

#[no_mangle]
extern "C" fn vb2ex_mtime() -> u32 {
    // This is only used to time how long operations take. We don't use
    // that functionality, so no need to return a real value.
    0
}

#[no_mangle]
extern "C" fn vb2ex_read_resource() {
    panic!("vb2ex_read_resource called");
}

#[no_mangle]
extern "C" fn vb2ex_tpm_clear_owner() {
    panic!("vb2ex_tpm_clear_owner called");
}

#[no_mangle]
extern "C" fn vb2ex_tpm_set_mode() {
    panic!("vb2ex_tpm_set_mode called");
}

#[no_mangle]
extern "C" fn strcpy(_dst: *mut c_char, _src: *const c_char) -> *mut c_char {
    panic!("strcpy called");
}
