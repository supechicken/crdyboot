// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;
use std::{env, fs};

/// Write Rust code to a file that, when included in the source, will
/// add a new section to the final binary.
///
/// The file is written to `<section_base_name>_section.rs` in the
/// target output directory. For example, if `section_base_name` is
/// "foo", the section can be included like this:
///
/// ```no_compile
/// include!(concat!(env!("OUT_DIR"), "/foo_section.rs"));
/// ```
///
/// The actual section name will be prefixed with a period. You can see
/// the resulting sections by running `objdump -h <binary>`.
fn write_section_file(section_base_name: &str, size_in_bytes: usize, formatted_value: &str) {
    let code = format!(
        r#"#[no_mangle]
#[link_section = ".{section_base_name}"]
static {section_base_name}: [u8; {size_in_bytes}] = {formatted_value};
"#
    );

    let dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = dir.join(format!("{section_base_name}_section.rs"));
    fs::write(out_path, code).unwrap();
}

/// Generate the SBAT section. The data for this section comes from
/// `sbat.csv`.
fn generate_sbat_section() {
    let csv = include_str!("sbat.csv");
    write_section_file("sbat", csv.len(), &format!("*b\"{csv}\""));
}

/// Generate the vbpubk section. The data for this section comes from a
/// test key in vboot_reference. During image signing the real pubkey
/// will overwrite this data. In order to allow for a bigger key in the
/// image signer, the size of this section is padded out to an
/// arbitrarily-chosen size of 8192 bytes.
fn generate_vbpubk_section() {
    let padded_len = 8192;

    let mut pubkey =
        include_bytes!("../third_party/vboot_reference/tests/devkeys/kernel_subkey.vbpubk")
            .to_vec();
    assert!(pubkey.len() < padded_len);
    pubkey.resize(padded_len, 0);

    // Format the bytes as an array literal.
    let formatted_pubkey = format!(
        "[{}]",
        pubkey
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    write_section_file("vbpubk", padded_len, &formatted_pubkey);
}

/// Generate the `sbat_section.rs` and `vbpubk_section.rs` files
/// included by `src/main.rs`.
fn main() {
    generate_sbat_section();
    generate_vbpubk_section();
}
