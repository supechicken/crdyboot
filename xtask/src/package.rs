// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Packages in the root workspace.
#[expect(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Package {
    Crdyboot,
    Crdyshim,
    Enroller,
    Libcrdy,
    UefiTestTool,
    Vboot,
    Xtask,
}

impl Package {
    /// Get the package's crate name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Crdyboot => "crdyboot",
            Self::Crdyshim => "crdyshim",
            Self::Enroller => "enroller",
            Self::Libcrdy => "libcrdy",
            Self::UefiTestTool => "uefi_test_tool",
            Self::Vboot => "vboot",
            Self::Xtask => "xtask",
        }
    }
}
