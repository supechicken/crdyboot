// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use alloc::borrow::Cow;
use alloc::string::String;
use core::cmp::min;
use core::ffi::{c_char, c_int};
use core::{slice, str};
use log::{Level, Record};
use printf_compat as printf;

// `core::ffi::c_size_t` is not yet stabilized:
// https://github.com/rust-lang/rust/issues/88345
#[allow(non_camel_case_types)]
type c_size_t = usize;

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
unsafe extern "C" fn vb2ex_printf(func: *const c_char, fmt: *const c_char, mut args: ...) {
    let func = str_from_c_str(func);

    let mut output = String::new();
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

    // No logger is enabled during unit tests, so to aid with debugging
    // print to stdout when compiled in test mode.
    #[cfg(test)]
    println!("{stripped}");

    // The log format we're using (from uefi-rs) prints the file, but
    // vboot just tells us the function name. The function name is more
    // useful than outputing "printf.rs", so place the function name
    // into the file path here. Only send this log if the runtime log
    // level is high enough.
    let level = Level::Info;
    if level <= log::max_level() {
        log::logger().log(
            &Record::builder()
                .args(format_args!("{stripped}"))
                .level(level)
                .file(Some(&func))
                .build(),
        );
    }
}

/// Implement the C `snprintf` function.
#[no_mangle]
unsafe extern "C" fn snprintf(
    buffer: *mut c_char,
    bufsz: c_size_t,
    fmt: *const c_char,
    mut args: ...
) -> c_int {
    if buffer.is_null() || fmt.is_null() || bufsz == 0 {
        return 0;
    }

    let buffer = slice::from_raw_parts_mut(buffer, bufsz);

    // Format into a temporary buffer.
    let mut tmp = String::new();
    printf::format(fmt, args.as_va_list(), printf::output::fmt_write(&mut tmp));

    // Convert the formatted output to a slice of `c_char`.
    let formatted_bytes = tmp.as_bytes();
    let formatted_bytes = slice::from_raw_parts(
        formatted_bytes.as_ptr().cast::<c_char>(),
        formatted_bytes.len(),
    );

    // Get the length to copy. This is the size of the formatted output,
    // capped to one less than the buffer length (to leave room for a
    // trailing null).
    let copy_len = min(formatted_bytes.len(), buffer.len().checked_sub(1).unwrap());

    // Copy the formatted output and null terminate.
    buffer[..copy_len].copy_from_slice(&formatted_bytes[..copy_len]);
    buffer[copy_len] = 0;

    // Return the size of the formatted bytes (excluding the trailing
    // null), even if not enough space was available.
    formatted_bytes.len().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_snprintf() {
        unsafe {
            let mut buf = [0; 4];

            // Format a string that will fit in the buffer.
            assert_eq!(
                snprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    b"%d %d\0".as_ptr().cast(),
                    1,
                    2
                ),
                3
            );
            assert_eq!(
                slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len()),
                b"1 2\0"
            );

            // Try to format a string that is too long for the buffer.
            assert_eq!(
                snprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    b"%d %d %d\0".as_ptr().cast(),
                    1,
                    2,
                    3
                ),
                5
            );
            assert_eq!(
                slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len()),
                b"1 2\0"
            );
        }
    }
}
