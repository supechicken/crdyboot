// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::Config;
use crate::network::HttpsResource;
use crate::{copy_file, gen_disk};
use anyhow::Result;
use command_run::Command;
use fs_err as fs;
use gen_disk::SignAndUpdateBootloader;

/// Current version of the shim build. Note that this does not
/// correspond to the shim version number, but rather to the current
/// version of how we build shim in this file.
///
/// Bump this version to force a shim rebuild.
const SHIM_BUILD_VERSION: u32 = 1;

/// Read the currently-built version.
fn read_shim_build_version(conf: &Config) -> Option<u32> {
    let data = fs::read_to_string(conf.shim_build_version_path()).ok()?;
    let version: u32 = data.trim().parse().ok()?;
    Some(version)
}

/// Write the current shim build version out to the target directory.
fn write_shim_build_version(conf: &Config) -> Result<()> {
    let data = format!("{SHIM_BUILD_VERSION}\n");
    fs::write(conf.shim_build_version_path(), data)?;
    Ok(())
}

// TODO
fn build_shim(conf: &Config) -> Result<()> {
    let shim_dir = conf.shim_build_path();

    // Create the directory. Delete and re-create it if it already
    // exists, to ensure we get an entirely fresh build.
    if shim_dir.exists() {
        fs::remove_dir_all(&shim_dir)?;
    }
    fs::create_dir(&shim_dir)?;

    // The rest of this is a simplified version of
    // https://chromium.googlesource.com/chromiumos/shim-review/+/HEAD/Dockerfile
    //
    // Applying patches and setting sbat.csv are skipped as they aren't
    // important for the tests in this repo.

    // Download and extract the shim source tarball.
    let src_tarball_path = shim_dir.join("shim.tar.bz2");
    let mut remote_src_tarball = HttpsResource::new(
        "https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2",
    );
    remote_src_tarball
        .set_expected_sha256("87cdeb190e5c7fe441769dde11a1b507ed7328e70a178cd9858c7ac7065cfade");
    remote_src_tarball.download_to_file(&src_tarball_path)?;
    Command::with_args("tar", ["-jxpf", src_tarball_path.as_str()])
        .set_dir(&shim_dir)
        .run()?;

    let shim_dir = shim_dir.join("shim-15.7");

    // Build for each UEFI arch.
    for arch in Arch::all() {
        let arch_name = match arch {
            Arch::Ia32 => "ia32",
            Arch::X64 => "x86_64",
        };

        // Build the arch in its own subdirectory.
        let build_subdir = shim_dir.join(format!("build-{arch_name}"));
        fs::create_dir(&build_subdir)?;

        // Run the build.
        Command::with_args(
            "make",
            [
                // Run within the build subdirectory.
                "-C",
                build_subdir.as_str(),
                // Set various env vars used by the build.
                &format!("ARCH={arch_name}"),
                &format!("DEFAULT_LOADER=\\\\{}", arch.efi_file_name("crdyboot")),
                &format!(
                    "VENDOR_CERT_FILE={}",
                    conf.secure_boot_shim_key_paths().pub_der(),
                ),
                "DISABLE_EBS_PROTECTION=y",
                "TOPDIR=..",
                // Set makefile path.
                "-f",
                "../Makefile",
                // Make the output silent to avoid a weird error:
                // "write error: stdout"
                "--silent",
                // Build with an appropriate number of jobs.
                "-j",
                &std::thread::available_parallelism()?.to_string(),
            ],
        )
        .run()?;

        // Copy the resulting shim executable upwards a couple
        // directories to make it easier to get the path in
        // `SignAndUpdateBootloader` below.
        let efi_file_name = arch.efi_file_name("shim");
        copy_file(
            build_subdir.join(&efi_file_name),
            conf.shim_build_path().join(&efi_file_name),
        )?;
    }

    Ok(())
}

/// Build shim, sign it, and copy into the disk image.
pub fn update_shim(conf: &Config) -> Result<()> {
    if read_shim_build_version(conf) == Some(SHIM_BUILD_VERSION) {
        println!(
            "skipping shim build; delete {} to force rebuild",
            conf.shim_build_version_path()
        );
    } else {
        build_shim(conf)?;
        write_shim_build_version(conf)?;
    }

    SignAndUpdateBootloader {
        disk_path: conf.disk_path(),
        key_paths: conf.secure_boot_root_key_paths(),
        mapping: Arch::all()
            .iter()
            .map(|arch| {
                (
                    conf.shim_build_path().join(arch.efi_file_name("shim")),
                    arch.efi_file_name("boot"),
                )
            })
            .collect(),
    }
    .run()
}
