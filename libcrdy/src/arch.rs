// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Build architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Allow unused code since the variant used depends on the target.
#[allow(dead_code)]
pub enum Arch {
    Aarch64,
    Ia32,
    X86_64,
}

impl Arch {
    /// Get the architecture of the currently-running executable.
    ///
    /// This will fail to compile on unsupported targets.
    #[must_use]
    pub fn get_current_exe_arch() -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            Arch::Aarch64
        }

        #[cfg(target_arch = "x86")]
        {
            Arch::Ia32
        }

        #[cfg(target_arch = "x86_64")]
        {
            Arch::X86_64
        }
    }
}

// The PE layout is different between the 32-bit and 64-bit targets.
// Expose a type alias for a PE file appropriate for the arch of the
// currently-running executable.
#[cfg(target_pointer_width = "32")]
pub type PeFileForCurrentArch<'a> = object::read::pe::PeFile32<'a>;
#[cfg(target_pointer_width = "64")]
pub type PeFileForCurrentArch<'a> = object::read::pe::PeFile64<'a>;
