// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Implement [avb_sysdeps.h](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_sysdeps.h) libavb usage.
use alloc::string::String;
use core::ffi::{c_char, c_int, c_void, CStr};
use log::{Level, Record};
use printf_compat as printf;

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
    // avb_print doesn't seem to be used in libavb.
    // Assume it it is deprecated and leave unimplemented.
    panic!("avb_print is not implemented")
}

#[no_mangle]
unsafe extern "C" fn avb_printv(_message: *const c_char, mut _args: ...) {
    // avb_printv is not used by libavb with AVB_USE_PRINTF_LOGS defined. build.rs defines
    // AVB_USE_PRINTF_LOGS.
    panic!("avb_printv is not implemented")
}

// Split the full avb_println log entry from libavb.
// Calls through avb_println are expected to have the format:
// filename:lineno: <rest of message>
// Split out the filename and line number so the logger entry
// can have the right filename and line number.
// If the string does not have the expected format just leave the full line as-is.
fn split_avb_log_line(full_log: &str) -> (Option<&str>, Option<u32>, &str) {
    // Expect filename:fileno: <rest of message>
    let mut s = full_log.splitn(3, ':');

    let file = s.next();
    let line_number = s.next();
    let tail = s.next();

    // If there aren't 3 items return the full string.
    if file.is_none() || line_number.is_none() || tail.is_none() {
        return (None, None, full_log);
    }
    // unwrap is safe as none was checked above.
    let line_number = line_number.unwrap();
    let tail = tail.unwrap();

    // Strip the extra space after the line number that is
    // included in the avb_printf message.
    // If the space isn't there leave it as-is.
    let tail = tail.strip_prefix(' ').unwrap_or(tail);

    // It's split in an expected way.
    (file, line_number.parse().ok(), tail)
}

#[no_mangle]
unsafe extern "C" fn avb_printf(fmt: *const c_char, mut args: ...) {
    // Used when AVB_USE_PRINTF_LOGS is defined.
    // AVB_USE_PRINTF_LOGS is defined in build.rs.
    let mut full = String::new();
    printf::format(fmt, args.as_va_list(), printf::output::fmt_write(&mut full));
    let output = full.strip_suffix('\n').unwrap_or(&full);

    #[cfg(test)]
    println!("{output}");

    // Parse the formatted output so that the filename and lineno of the
    // log entry can use the .c filename from libavb instead of
    // this module's filename/line.
    // Sample output looks like the following if the rust filename
    // isn't stripped:
    // [ INFO]: avb/src/avb_sysdeps.rs@141: avb_slot_verify.c:722: \
    // DEBUG: Loading vbmeta struct from partition 'vbmeta_a'.
    // Splitting leads to the logged output:
    // [ INFO]: avb_slot_verify.c@722: \
    // DEBUG: Loading vbmeta struct from partition 'vbmeta_a'.
    let (file, line, tail) = split_avb_log_line(output);

    let level = Level::Info;
    if level <= log::max_level() {
        log::logger().log(
            &Record::builder()
                .args(format_args!("{tail}"))
                .level(level)
                .line(line)
                .file(file)
                .build(),
        );
    }
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
unsafe extern "C" fn avb_strlen(s: *const c_char) -> usize {
    CStr::from_ptr(s).count_bytes()
}

#[no_mangle]
unsafe extern "C" fn avb_div_by_10(_dividend: *mut u64) -> u32 {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_avb_printf_split_log_ok() {
        assert_eq!(
            // Successful normal split.
            split_avb_log_line(
                "avb_slot_verify.c:722: DEBUG: Loading vbmeta struct from partition 'vbmeta_a'."
            ),
            (
                Some("avb_slot_verify.c"),
                Some(722),
                "DEBUG: Loading vbmeta struct from partition 'vbmeta_a'."
            )
        );
    }

    #[test]
    fn test_avb_printf_split_log_space_ok() {
        assert_eq!(
            // Missing a ' ' before DEBUG:
            split_avb_log_line("example.c:42:DEBUG: Loading"),
            (Some("example.c"), Some(42), "DEBUG: Loading")
        );
    }

    #[test]
    fn test_avb_printf_split_log_bad_num() {
        assert_eq!(
            // Missing a proper number.
            split_avb_log_line("example.c:xx:DEBUG: Loading"),
            (Some("example.c"), None, "DEBUG: Loading")
        );
    }

    #[test]
    fn test_avb_printf_split_log_unexpected_format() {
        assert_eq!(
            // Only has 1 ':'
            split_avb_log_line("example.c:755 DEBUG Loading"),
            (None, None, "example.c:755 DEBUG Loading"),
        );
        assert_eq!(
            // No ':'
            split_avb_log_line("example.c 755 DEBUG Loading"),
            (None, None, "example.c 755 DEBUG Loading"),
        );
        assert_eq!(
            // More than 2 ':'
            split_avb_log_line("example.c:755:DEBUG: Loading"),
            (Some("example.c"), Some(755), "DEBUG: Loading"),
        );
    }

    #[test]
    fn test_avb_strlen() {
        let s = CString::new("123456").unwrap();
        assert_eq!(unsafe { avb_strlen(s.as_ptr()) }, 6);

        let s = CString::new("").unwrap();
        assert_eq!(unsafe { avb_strlen(s.as_ptr()) }, 0);

        assert_eq!(unsafe { avb_strlen(b"1234\0678\0".as_ptr().cast()) }, 4);
    }
}
