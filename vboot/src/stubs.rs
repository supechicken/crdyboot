// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use cty::c_char;

#[no_mangle]
extern "C" fn vb2ex_abort() {
    panic!("vb2ex_abort called");
}

#[no_mangle]
extern "C" fn vb2ex_mtime() -> u32 {
    // TODO: I think this is only used for timing how long stuff takes, in
    // which case it's fine to keep this as a stub.
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
