// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::{Config, EfiExe};
use anyhow::{anyhow, bail, Result};
use fs_err as fs;
use object::pe::{ImageNtHeaders32, ImageNtHeaders64, IMAGE_DLLCHARACTERISTICS_NX_COMPAT};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use object::{Object, ObjectSection};
use sbat::ImageSbat;

/// Ensure that the NX-compat bit is set in an executable.
fn ensure_nx_compat<N: ImageNtHeaders>(pe: &PeFile<N>) -> Result<()> {
    let characteristics = pe.nt_headers().optional_header().dll_characteristics();
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) == 0 {
        bail!("nx-compat is not set");
    }
    Ok(())
}

/// Check that the SBAT data in a binary looks correct.
///
/// This checks the following:
/// * There is exactly one `.sbat` section in the binary
/// * That section contains the expected CSV data
/// * The CSV data can be parsed as SBAT image data
/// * The SBAT package entry version matches the version in Cargo.toml
fn check_sbat<N: ImageNtHeaders>(conf: &Config, exe: EfiExe, pe: &PeFile<N>) -> Result<()> {
    // The tools do not have SBAT data.
    if exe.is_tool() {
        return Ok(());
    }

    // Get the `.sbat` section. Ensure there is exactly one.
    let section_name = ".sbat";
    let mut section_iter = pe
        .sections()
        .filter(|section| section.name() == Ok(section_name));
    let section = section_iter
        .next()
        .ok_or_else(|| anyhow!("missing {section_name} section"))?;
    if section_iter.next().is_some() {
        bail!("multiple {section_name} sections");
    }
    let section_data = section.data()?;

    // Load the SBAT CSV file.
    let package_name = exe.package().name();
    let package_path = conf.repo_path().join(package_name);
    let sbat_csv_path = package_path.join("sbat.csv");
    let sbat_csv = fs::read(sbat_csv_path)?;

    // Validate the section data matches the CSV file.
    if sbat_csv != section_data {
        bail!("SBAT mismatch: {sbat_csv:?} != {section_data:?}");
    }

    // Check that the CSV parses.
    let sbat = ImageSbat::parse(&sbat_csv)?;

    // Get the package's version from Cargo.toml.
    let package_cargo = fs::read_to_string(package_path.join("Cargo.toml"))?;
    let package_version = package_cargo
        .lines()
        .find_map(|line| line.strip_prefix("version = "))
        .ok_or(anyhow!("failed to find version for package {package_name}"))?
        .replace('"', "");

    // Check that the SBAT version matches the package version.
    let entry = sbat
        .entries()
        .find(|entry| entry.component.name == package_name)
        .ok_or_else(|| anyhow!("missing package {package_name} in SBAT"))?;
    let entry_version = entry
        .vendor
        .version
        .map(|s| s.to_string())
        .unwrap_or_default();
    if entry_version != package_version {
        bail!("mismatch in package {package_name} version: {entry_version} != {package_version}");
    }

    Ok(())
}

// Run static checks on a single binary.
fn bin_check_impl<N: ImageNtHeaders>(conf: &Config, exe: EfiExe, bin_data: &[u8]) -> Result<()> {
    let pe = PeFile::<N>::parse(bin_data)?;

    ensure_nx_compat(&pe)?;
    check_sbat(conf, exe, &pe)?;

    Ok(())
}

/// Run static checks on the bootloader binaries.
pub fn run_bin_checks(conf: &Config) -> Result<()> {
    for arch in Arch::all() {
        for exe in EfiExe::all() {
            let bin_data = fs::read(conf.target_exec_path(arch, *exe))?;
            match arch {
                Arch::Ia32 => bin_check_impl::<ImageNtHeaders32>(conf, *exe, &bin_data)?,
                Arch::Aarch64 | Arch::X64 => {
                    bin_check_impl::<ImageNtHeaders64>(conf, *exe, &bin_data)?
                }
            }
        }
    }
    println!("all bin checks passed");
    Ok(())
}
