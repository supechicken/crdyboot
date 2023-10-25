// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::{Config, EfiExe};
use anyhow::{bail, Result};
use fs_err as fs;
use object::pe::{ImageNtHeaders32, ImageNtHeaders64, IMAGE_DLLCHARACTERISTICS_NX_COMPAT};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};

/// Ensure that the NX-compat bit is set in a crdyboot executable.
fn ensure_nx_compat_impl<Pe: ImageNtHeaders>(bin_data: &[u8]) -> Result<()> {
    let pe = PeFile::<Pe>::parse(bin_data)?;
    let characteristics = pe.nt_headers().optional_header().dll_characteristics();
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) == 0 {
        bail!("nx-compat is not set")
    }
    Ok(())
}

/// Ensure that the NX-compat bit is set in all executables.
fn ensure_nx_compat(conf: &Config) -> Result<()> {
    for arch in Arch::all() {
        for exe in EfiExe::all() {
            let bin_data = fs::read(conf.target_exec_path(arch, *exe))?;
            match arch {
                Arch::Ia32 => ensure_nx_compat_impl::<ImageNtHeaders32>(&bin_data)?,
                Arch::X64 => ensure_nx_compat_impl::<ImageNtHeaders64>(&bin_data)?,
            }
        }
    }
    Ok(())
}

/// Run static checks on the bootloader binaries.
pub fn run_bin_checks(conf: &Config) -> Result<()> {
    ensure_nx_compat(conf)
}
