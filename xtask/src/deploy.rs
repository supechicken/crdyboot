// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::{Config, EfiExe};
use crate::DeployAction;
use anyhow::Result;
use camino::Utf8PathBuf;
use command_run::Command;

struct MountOpts {
    /// SSH remote.
    ssh_target: String,

    /// Source to mount from, e.g. "/dev/sda12".
    source: String,

    /// Path of the directory to mount at. The directory must exist
    /// before mounting.
    mount_point: Utf8PathBuf,
}

/// Scoped remount mount. The mount will be automatically unmounted on
/// drop.
struct RemoteMount {
    opts: MountOpts,
}

impl RemoteMount {
    fn mount(opts: MountOpts) -> Result<Self> {
        Command::with_args(
            "ssh",
            [
                &opts.ssh_target,
                "mount",
                &opts.source,
                opts.mount_point.as_str(),
            ],
        )
        .run()?;

        Ok(Self { opts })
    }
}

impl Drop for RemoteMount {
    fn drop(&mut self) {
        if let Err(err) = Command::with_args(
            "ssh",
            [
                &self.opts.ssh_target,
                "umount",
                self.opts.mount_point.as_str(),
            ],
        )
        .run()
        {
            eprintln!("failed to unmount on remote: {err}");
        }
    }
}

/// Get the remote's rootdev, e.g. "/dev/sda" or "/dev/nvme0n1".
fn get_rootdev(target: &str) -> Result<String> {
    let output = Command::with_args("ssh", [target, "rootdev", "-s", "-d"])
        .enable_capture()
        .run()?;

    let path = std::str::from_utf8(&output.stdout)?;
    Ok(path.trim().to_owned())
}

fn get_partition_path(root_dev: &str, partition_num: u32) -> String {
    // If the root_dev ends in a number, insert a "p" before the
    // partition number.
    let separator = if root_dev
        .chars()
        .last()
        .expect("root_dev must not be empty")
        .is_numeric()
    {
        "p"
    } else {
        ""
    };

    format!("{root_dev}{separator}{partition_num}")
}

fn scp(target: &str, src: Utf8PathBuf, dst: Utf8PathBuf) -> Result<()> {
    let dst = format!("{target}:{dst}");
    Command::with_args("scp", [src.as_str(), dst.as_str()]).run()?;
    Ok(())
}

pub fn run_deploy(conf: &Config, action: &DeployAction) -> Result<()> {
    let remote_mount_dir = "/tmp/crdy-deploy-mount";

    // Create the mount directory. Allow this to fail, since the
    // directory might already exist.
    Command::with_args("ssh", [&action.target, "mkdir", remote_mount_dir])
        .disable_check()
        .run()?;

    let rootdev = get_rootdev(&action.target)?;
    let esp_path = get_partition_path(&rootdev, 12);

    let mount = RemoteMount::mount(MountOpts {
        ssh_target: action.target.clone(),
        source: esp_path,
        mount_point: Utf8PathBuf::from(remote_mount_dir),
    })?;

    let dst_dir = mount.opts.mount_point.join("efi/boot");

    for arch in Arch::all() {
        if action.crdyshim {
            // Copy the signed crdyshim executable.
            scp(
                &action.target,
                conf.crdyshim_signed_path(arch),
                dst_dir.join(arch.efi_file_name("boot")),
            )?;
        }

        // Copy the crdyboot executable.
        scp(
            &action.target,
            conf.target_exec_path(arch, EfiExe::Crdyboot),
            dst_dir.join(arch.efi_file_name("crdyboot")),
        )?;

        // Copy the crdyboot signature.
        scp(
            &action.target,
            conf.crdyboot_signature_path(arch),
            dst_dir
                .join(arch.efi_file_name("crdyboot"))
                .with_extension("sig"),
        )?;
    }

    // If requested, create or delete the file that controls verbose
    // logging.
    let verbose_path = dst_dir.join("crdyboot_verbose");
    if action.enable_verbose_logs {
        Command::with_args("ssh", [&action.target, "touch", verbose_path.as_str()]).run()?;
    } else if action.disable_verbose_logs {
        // Allow this to fail, since the file might not exist.
        Command::with_args("ssh", [&action.target, "rm", verbose_path.as_str()])
            .disable_check()
            .run()?;
    }

    // Drop the mount now since it can't be done after sending the
    // reboot command.
    drop(mount);

    // If requested, reboot the device.
    if action.reboot {
        // Allow this to fail, since the ssh server is going down.
        Command::with_args("ssh", [&action.target, "reboot"])
            .disable_check()
            .run()?;
    }

    Ok(())
}
