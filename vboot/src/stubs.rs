// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::vboot_sys::*;

#[no_mangle]
extern "C" fn vb2ex_abort() {
    panic!("vb2ex_abort");
}

// This is needed so that `vb2_hwcrypto_allowed` can return false.
#[no_mangle]
extern "C" fn vb2_secdata_kernel_get(
    _ctx: *const vb2_context,
    _param: *const vb2_secdata_kernel_param,
) -> u32 {
    0
}

#[no_mangle]
extern "C" fn vb2ex_mtime() -> u32 {
    // TODO: I think this is only used for timing how long stuff takes, in
    // which case it's fine to keep this as a stub.
    0
}

#[no_mangle]
extern "C" fn vb2api_fail(_ctx: *const vb2_context, reason: u8, subcode: u8) {
    panic!("vb2api_fail: reason={}, subcode={}", reason, subcode);
}

#[no_mangle]
extern "C" fn vb2_nv_get(
    _ctx: *const vb2_context,
    _param: *const vb2_nv_param,
) -> u32 {
    panic!("vb2_nv_get");
}

#[no_mangle]
extern "C" fn vb2ex_tpm_set_mode(_mode_val: vb2_tpm_mode) -> vb2_error_t {
    panic!("vb2ex_tpm_set_mode");
}
