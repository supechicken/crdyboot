// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Convert a `u32` to a `usize`.
///
/// On the targets we care about, `usize` is always at least as large as `u32`.
pub fn u32_to_usize(v: u32) -> usize {
    v.try_into().expect("size of usize is smaller than u32")
}

/// Embed data in a section of the executable.
///
/// This macro takes three arguments:
/// * `static_ident`: Name of the `static` item associated with the data.
/// * `section_name`: Name of the section in the executable.
/// * `path`: Path of the file containing the raw data to be included.
#[macro_export]
macro_rules! embed_section {
    ($static_ident:ident, $section_name:literal, $path:expr) => {
        #[no_mangle]
        #[link_section = $section_name]
        pub static $static_ident: [u8; include_bytes!($path).len()] = *include_bytes!($path);
    };
}
