// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;
use std::{env, fs};

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

    let dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = dir.join("padded_vbpubk");
    fs::write(out_path, pubkey).unwrap();
}

/// Generate `vbpubk_section.rs` file included by `src/main.rs`.
fn main() {
    generate_vbpubk_section();
}
