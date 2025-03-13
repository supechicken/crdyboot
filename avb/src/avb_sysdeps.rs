// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Implement [avb_sysdeps.h](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_sysdeps.h) libavb usage.
use alloc::string::String;
use core::ffi::{c_char, c_int, c_void, CStr};
use core::slice;
use log::{Level, Record};
use printf_compat as printf;

#[no_mangle]
/// Compares `src1` with `src2` as an array of `u8` up to a length of `n`.
///
/// Both buffers must be non-null and valid for at least the length of `n`.
///
/// Returns 0 if the buffers are the same up to `n`.
/// Returns -1, 1 if the first differing `u8` in `src1` is is less than, or greater than
/// the value in `src2` respectively.
unsafe extern "C" fn avb_memcmp(src1: *const c_void, src2: *const c_void, n: usize) -> c_int {
    assert!(!src1.is_null());
    assert!(!src2.is_null());
    let src1: &[u8] = slice::from_raw_parts(src1.cast(), n);
    let src2: &[u8] = slice::from_raw_parts(src2.cast(), n);
    src1.cmp(src2) as c_int
}

// compare chars for strncmp and strcmp
// see man strncmp, man strcmp
unsafe fn stroncmp(mut a: *const c_char, mut b: *const c_char, n: Option<usize>) -> c_int {
    assert!(!a.is_null());
    assert!(!b.is_null());

    let mut count = 0;

    loop {
        // Stop if count is specified and has
        // been reached.
        if let Some(n) = n {
            if count >= n {
                break;
            }
        }

        if *a != *b {
            // man strncmp claims that most implementations
            // return the difference of the last compared bytes.
            return (*a - *b).into();
        }

        if *a == 0 {
            break;
        }

        count += 1;
        a = a.add(1);
        b = b.add(1);
    }
    0
}

#[no_mangle]
unsafe extern "C" fn avb_strcmp(s1: *const c_char, s2: *const c_char) -> c_int {
    stroncmp(s1, s2, None)
}

#[no_mangle]
/// strncmp, see man strncmp
unsafe extern "C" fn avb_strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int {
    stroncmp(s1, s2, Some(n))
}

#[no_mangle]
unsafe extern "C" fn avb_memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    assert!(!dest.is_null());
    assert!(!src.is_null());
    // memcpy states these destinations should never
    // overlap. Trust that libavb does not pass overlapping
    // buffers.
    core::ptr::copy_nonoverlapping(src, dest, n);
    dest
}

#[no_mangle]
unsafe extern "C" fn avb_memset(dest: *mut c_void, value: c_int, count: usize) -> *mut c_void {
    assert!(!dest.is_null());
    // OK: The `as` truncation conversion of the c_int to the u8 is the expected behavior.
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    dest.write_bytes(value as u8, count);
    dest
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
    // TODO(b/403257806): cast the format string to unsigned on
    // aarch64. This is needed because printf-compat-0.1.1 uses cty for
    // C definitions, and cty diverges slightly from core::ffi.
    #[cfg(target_arch = "aarch64")]
    let fmt: *const core::ffi::c_uchar = fmt.cast();

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
/// Divides `dividend` by 10.
/// Sets `dividend` to the quotient and returns the remainder.
unsafe extern "C" fn avb_div_by_10(dividend: *mut u64) -> u32 {
    let q = *dividend / 10;
    // unwrap is ok: the result will always will be < 10.
    let r: u32 = (*dividend % 10).try_into().unwrap();
    *dividend = q;
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_avb_div_by_10() {
        let mut d: u64 = 250;
        let r = unsafe { avb_div_by_10(&mut d) };
        assert_eq!((d, r), (25, 0));

        // A number greater than u32 max will return something OK.
        let mut d: u64 = (u64::from(u32::MAX) * 10) + 5;
        let r = unsafe { avb_div_by_10(&mut d) };
        assert_eq!((d, r), (u64::from(u32::MAX), 5));
    }

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

    fn call_strncmp(a: &[u8], b: &[u8], len: usize) -> c_int {
        unsafe { avb_strncmp(a.as_ptr().cast(), b.as_ptr().cast(), len) }
    }

    #[test]
    fn test_avb_strncmp() {
        let a = b"test\0\0\0\0";
        let b = b"test\0x\0\0";

        assert_eq!(call_strncmp(a, b, a.len()), 0);
        assert_eq!(call_strncmp(b, a, b.len()), 0);
        assert_eq!(call_strncmp(a, b, 5), 0);
        assert_eq!(call_strncmp(b, a, 5), 0);

        let b = b"tesv";
        assert_eq!(call_strncmp(a, b, a.len()), -2);
        assert_eq!(call_strncmp(b, a, b.len()), 2);
        assert_eq!(call_strncmp(a, b, 3), 0);

        // Length of 0 is always 0 (equal).
        assert_eq!(call_strncmp(b"a", b"b", 0), 0);
    }

    fn call_strcmp(a: &[u8], b: &[u8]) -> c_int {
        unsafe { avb_strcmp(a.as_ptr().cast(), b.as_ptr().cast()) }
    }

    #[test]
    fn test_avb_strcmp() {
        let a = b"test\0\0\0\0";
        let b = b"test\0test\0";
        assert_eq!(call_strcmp(a, b), 0);
        assert_eq!(call_strcmp(b, a), 0);

        let b = b"test\0";
        assert_eq!(call_strcmp(a, b), 0);
        assert_eq!(call_strcmp(b, a), 0);

        let b = b"tesv";
        assert_eq!(call_strcmp(a, b), -2);
        assert_eq!(call_strcmp(b, a), 2);
    }

    fn call_memcmp(a: &[u8], b: &[u8], len: usize) -> c_int {
        unsafe { avb_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), len) }
    }

    #[test]
    fn test_avb_memcmp() {
        let a = b"test\0test\0";
        let b = b"test\0test\0";
        assert_eq!(call_memcmp(a, b, a.len()), 0);
        assert_eq!(call_memcmp(a, b, a.len() - 2), 0);

        let a = b"0123\0abcd\0";
        let b = b"0123\0adcd\0";
        // Continue checking past any NUL (0) values.
        assert_eq!(call_memcmp(a, b, 5), 0);
        assert_eq!(call_memcmp(b, a, 5), 0);
        // 7th value differs by more than 1 but
        // -1/1 is returned.
        assert_eq!(call_memcmp(a, b, 7), -1);
        assert_eq!(call_memcmp(b, a, 7), 1);

        // Length of 0 is always 0 (equal).
        assert_eq!(call_memcmp(b"abc", b"cba", 0), 0);

        // Length of 0 is always 0 (equal).
        assert_eq!(call_memcmp(b"", b"", 0), 0);
    }

    #[test]
    fn test_avb_memcpy() {
        let src: [u8; 25] = [u8::MAX - 3; 25];
        let mut dst: [u8; 25] = [15; 25];

        let destp: *mut c_void = dst.as_mut_ptr().cast();

        let result = unsafe { avb_memcpy(destp, src.as_ptr().cast(), 25) };
        assert_eq!(destp, result);
        assert_eq!(src, dst);

        for c in dst.each_mut() {
            *c = 33;
        }
        let destp: *mut c_void = dst.as_mut_ptr().cast();

        // Copy only a length of 15.
        let result = unsafe { avb_memcpy(destp, src.as_ptr().cast(), 15) };
        assert_eq!(destp, result);
        assert_eq!(src[..15], dst[..15]);
        // Confirm the trailing 10 values are unchanged.
        assert_eq!(dst[15..], [33; 10]);
    }

    #[test]
    fn test_avb_memset() {
        let mut dst: [u8; 25] = [15; 25];

        let destp: *mut c_void = dst.as_mut_ptr().cast();

        let result = unsafe { avb_memset(destp, 33, 25) };
        assert_eq!(destp, result);
        assert_eq!(dst, [33; 25]);

        for c in dst.each_mut() {
            *c = 15;
        }
        let destp: *mut c_void = dst.as_mut_ptr().cast();

        // Only set a length of 15.
        let result = unsafe { avb_memset(destp, 33, 15) };
        assert_eq!(destp, result);
        assert_eq!(dst[..15], [33; 15]);
        // Confirm the trailing 10 values are unchanged.
        assert_eq!(dst[15..], [15; 10]);
    }
}
