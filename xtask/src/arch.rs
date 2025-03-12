// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arch {
    Aarch64,
    Ia32,
    X64,
}

impl Arch {
    pub fn all() -> [Arch; 3] {
        [Arch::Aarch64, Arch::Ia32, Arch::X64]
    }

    pub fn all_targets() -> [&'static str; 3] {
        let targets: Vec<_> = Arch::all().iter().map(Arch::uefi_target).collect();
        targets.try_into().unwrap()
    }

    pub fn uefi_target(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64-unknown-uefi",
            Arch::Ia32 => "i686-unknown-uefi",
            Arch::X64 => "x86_64-unknown-uefi",
        }
    }

    pub fn efi_file_name(&self, base_name: &str) -> String {
        let arch_name = match self {
            Arch::Aarch64 => "aa64",
            Arch::Ia32 => "ia32",
            Arch::X64 => "x64",
        };
        format!("{base_name}{arch_name}.efi")
    }
}
