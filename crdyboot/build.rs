// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;
use std::{env, fs};

/// Write Rust code to a file that, when included in a binary, will add
/// a `.sbat` section. The section contains the `sbat.csv` file in this
/// directory.
///
/// The file is written to `sbat_section.rs` in the target output
/// directory, and can be included like this:
///
/// ```no_compile
/// include!(concat!(env!("OUT_DIR"), "/sbat_section.rs"));
/// ```
fn main() {
    let csv = include_str!("sbat.csv");

    let code = format!(
        r#"#[no_mangle]
#[link_section = ".sbat"]
static SBAT: [u8; {}] = *b"{}";
"#,
        csv.len(),
        csv
    );

    let dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = dir.join("sbat_section.rs");

    fs::write(&out_path, &code).unwrap();
}
