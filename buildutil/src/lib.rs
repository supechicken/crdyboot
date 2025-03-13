// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Target {
    UefiI686,
    UefiX86_64,
    Host,
}

impl Target {
    /// Read the target from the `TARGET` env var.
    pub fn from_env() -> Target {
        let target = env::var("TARGET").unwrap();
        match target.as_str() {
            "i686-unknown-uefi" => Self::UefiI686,
            "x86_64-unknown-uefi" => Self::UefiX86_64,
            // For everything else, assume it's a host build
            // (e.g. "cargo test").
            _ => Self::Host,
        }
    }

    /// True if this is a UEFI target, false if it's a host target.
    pub fn is_uefi(self) -> bool {
        match self {
            Self::UefiI686 | Self::UefiX86_64 => true,
            Self::Host => false,
        }
    }

    /// Get a target triple to override the default C compiler
    /// target. Returns None if this is a host build so that the default
    /// target is used in that case.
    ///
    /// The targets chosen here match those in the `cc` crate:
    /// https://github.com/rust-lang/cc-rs/pull/623/files
    pub fn c_target_override(self) -> Option<&'static str> {
        match self {
            Self::UefiI686 => Some("i686-unknown-windows-gnu"),
            Self::UefiX86_64 => Some("x86_64-unknown-windows-gnu"),
            Self::Host => None,
        }
    }

    pub fn build_subdir(self) -> &'static str {
        self.c_target_override().unwrap_or("host")
    }
}

/// Convert a `Path` to a `str`, or panic if the path isn't UTF-8.
pub fn path_to_str(path: &Path) -> &str {
    if let Some(s) = path.to_str() {
        s
    } else {
        panic!("{} is not a UTF-8 path", path.display());
    }
}

pub fn rerun_if_changed<P: AsRef<Path>>(path: P) {
    println!("cargo:rerun-if-changed={}", path_to_str(path.as_ref()));
}
