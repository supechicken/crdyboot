// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let bootimg_path = Path::new("../third_party/mkbootimg/rust/bootimg.rs");

    println!(
        "cargo:rerun-if-changed={}",
        bootimg_path.to_str().expect("path needs to be valid")
    );

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bootimg.rs");

    let contents = fs::read_to_string(bootimg_path).expect("failed to read source file");

    // bootimg.rs can't simply be included directly because it contains an inner (//!)
    // comment which will break rustc with error E0753.
    // See https://github.com/rust-lang/rust/issues/66920 for the status and discussions
    // around this particular issue.
    // Remove the first //! comment so that it will compile.
    let contents = contents.replacen("//! The public", "// The public", 1);

    let mut outfile = fs::File::create(out_path).expect("couldn't open destination file");
    outfile
        .write_all(contents.as_bytes())
        .expect("couldn't write to destination file");
}
