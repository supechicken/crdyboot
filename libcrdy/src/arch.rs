// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Build architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Allow unused code since the variant used depends on the target.
#[allow(dead_code)]
pub enum Arch {
    Ia32,
    X86_64,
}

impl Arch {
    /// Get the architecture of the currently-running executable.
    ///
    /// This will fail to compile on unsupported targets.
    pub fn get_current_exe_arch() -> Self {
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
