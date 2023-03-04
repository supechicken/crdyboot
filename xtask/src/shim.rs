// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::Config;
use crate::{copy_file, gen_disk};
use anyhow::Result;
use command_run::Command;
use fs_err as fs;
use gen_disk::SignAndUpdateBootloader;

fn build_shim(conf: &Config) -> Result<()> {
    let shim_dir = conf.shim_build_path();
    let shim_url = "https://chromium.googlesource.com/chromiumos/shim-review";
    let shim_rev = "6d201a645d8b5169ea844ddafa7ba7659c3f356c";

    if shim_dir.exists() {
        // Remove local modifications so that the Dockerfile
        // modification below doesn't keep inserting the same change,
        // and so that the checked-out revision can be changed without
        // conflicts.
        Command::with_args("git", ["-C", shim_dir.as_str(), "checkout", "-f"]).run()?;
    }

    crate::update_local_repo(&shim_dir, shim_url, shim_rev)?;

    copy_file(
        conf.secure_boot_shim_key_paths().pub_der(),
        shim_dir.join("chromeos_reven.cer"),
    )?;

    // Apply some modifications to the Dockerfile:
    //
    // Disable EBS protection. This is a shim feature that hooks the
    // ExitBootServices function so that shim can verify that the
    // 2nd-stage bootloader properly used shim's verification protocol
    // to check the signature of the next stage. In our case though,
    // we verify the signature of the entire kernel partition through
    // a different mechanism than what shim provides, so the EBS check
    // would fail if enabled.
    //
    // Change the second-stage bootloader name from grub to crdyboot.
    let dockerfile_path = shim_dir.join("Dockerfile");
    let dockerfile = fs::read_to_string(&dockerfile_path)?;

    let orig_str = "TOPDIR=.. -f ../Makefile";
    let new_str = format!("DISABLE_EBS_PROTECTION=y {orig_str}");
    let dockerfile = dockerfile.replace(orig_str, &new_str);

    let default_loader_prefix = r"DEFAULT_LOADER=\\\\crdyboot";

    let orig_str = "ARCH=x86_64";
    let new_str = format!("{default_loader_prefix}x64.efi {orig_str}");
    let dockerfile = dockerfile.replace(orig_str, &new_str);

    let orig_str = "ARCH=ia32";
    let new_str = format!("{default_loader_prefix}ia32.efi {orig_str}");
    let dockerfile = dockerfile.replace(orig_str, &new_str);

    fs::write(&dockerfile_path, dockerfile)?;

    Command::with_args("make", ["build"])
        .set_dir(&shim_dir)
        .run()?;
    Command::with_args("make", ["copy"])
        .set_dir(&shim_dir)
        .run()?;

    Ok(())
}

/// Build shim, sign it, and copy into the disk image.
pub fn update_shim(conf: &Config) -> Result<()> {
    build_shim(conf)?;

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
