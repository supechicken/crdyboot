// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use alloc::borrow::Cow;
use alloc::string::String;
use core::{slice, str};
use cty::c_char;
use log::info;
use printf_compat as printf;

unsafe fn c_str_len(mut s: *const c_char) -> usize {
    let mut len = 0;
    while *s != 0 {
        len += 1;
        s = s.add(1);
    }
    len
}

unsafe fn str_from_c_str<'a>(s: *const c_char) -> Cow<'a, str> {
    let bytes = slice::from_raw_parts(s.cast::<u8>(), c_str_len(s));
    String::from_utf8_lossy(bytes)
}

/// Write a printf-style message to the log at the info level. Called
/// by `vboot_reference` for printing.
#[no_mangle]
unsafe extern "C" fn vb2ex_printf(
    func: *const c_char,
    fmt: *const c_char,
    mut args: ...
) {
    // TODO: could set the function into the log record directly
    // instead of formatting it as part of the message.
    let mut output = String::new();

    let func = str_from_c_str(func);
    printf::format(
        fmt,
        args.as_va_list(),
        printf::output::fmt_write(&mut output),
    );
    // Strip the trailing newline if present since the logger will add
    // one for us. If the input doesn't end in a newline the log
    // output will be split onto a new line anyway, which isn't
    // desired but is OK since this is just for debug output.
    let stripped = output.strip_suffix('\n').unwrap_or(&output);

    info!("{} {}", func, stripped);
}
