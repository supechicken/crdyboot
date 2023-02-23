// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::qemu::OvmfPaths;
use crate::secure_boot::SecureBootKeyPaths;
use crate::vboot::VbootKeyPaths;
use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use fs_err as fs;

pub struct Config {
    disk_path: Utf8PathBuf,

    /// Absolute path of the crdyboot repo.
    repo: Utf8PathBuf,
}

impl Config {
    pub fn new(repo_root: Utf8PathBuf) -> Self {
        Self {
            disk_path: repo_root.join("workspace/disk.bin"),
            repo: repo_root,
        }
    }

    pub fn repo_path(&self) -> &Utf8Path {
        &self.repo
    }

    /// Get the build output directory.
    pub fn target_path(&self) -> Utf8PathBuf {
        self.repo.join("target")
    }

    /// Get the path of an EFI executable in the build output.
    ///
    /// For example, this might return a path like:
    ///
    ///     <repo>/target/x86_64-unknown-uefi/release/enroller.efi
    pub fn target_exec_path(&self, arch: Arch, exe: EfiExe) -> Utf8PathBuf {
        self.target_path()
            .join(arch.uefi_target())
            .join("release")
            .join(exe.as_str())
    }

    pub fn workspace_path(&self) -> Utf8PathBuf {
        self.repo.join("workspace")
    }

    /// Path of the setup-version file in the workspace. This file is
    /// used to automatically re-run the setup operations when needed.
    fn setup_version_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("setup_version")
    }

    /// Read the current setup version. Returns version 0 if any error
    /// occurs (such as the version file not existing).
    pub fn read_setup_version(&self) -> u32 {
        let default = 0;
        if let Ok(version) = fs::read_to_string(self.setup_version_path()) {
            version.trim().parse().unwrap_or(default)
        } else {
            default
        }
    }

    /// Write out the setup-version file.
    pub fn write_setup_version(&self, version: u32) -> Result<()> {
        Ok(fs::write(
            self.setup_version_path(),
            format!("{version}\n"),
        )?)
    }

    pub fn vboot_reference_path(&self) -> Utf8PathBuf {
        self.repo.join("third_party/vboot_reference")
    }

    pub fn futility_executable_path(&self) -> Utf8PathBuf {
        self.vboot_reference_path().join("build/futility/futility")
    }

    fn vboot_devkeys_path(&self) -> Utf8PathBuf {
        self.vboot_reference_path().join("tests/devkeys")
    }

    pub fn disk_path(&self) -> &Utf8Path {
        &self.disk_path
    }

    pub fn enroller_disk_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("enroller.bin")
    }

    pub fn vboot_test_disk_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("vboot_test_disk.bin")
    }

    pub fn ovmf_paths(&self, arch: Arch) -> OvmfPaths {
        let subdir = match arch {
            Arch::Ia32 => "uefi32",
            Arch::X64 => "uefi64",
        };
        OvmfPaths::new(self.workspace_path().join(subdir))
    }

    /// Key used to sign the kernel keyblock which contains the public
    /// part of the kernel_data_key.
    pub fn kernel_key_paths(&self) -> VbootKeyPaths {
        let devkeys = self.vboot_devkeys_path();
        VbootKeyPaths {
            vbprivk: devkeys.join("kernel_subkey.vbprivk"),
            vbpubk: devkeys.join("kernel_subkey.vbpubk"),
            keyblock: None,
        }
    }

    /// Key used to sign the kernel data.
    pub fn kernel_data_key_paths(&self) -> VbootKeyPaths {
        let devkeys = self.vboot_devkeys_path();
        VbootKeyPaths {
            vbprivk: devkeys.join("kernel_data_key.vbprivk"),
            vbpubk: devkeys.join("kernel_data_key.vbpubk"),
            keyblock: Some(devkeys.join("kernel.keyblock")),
        }
    }

    /// This cert will be enrolled as the PK, first KEK, and first DB
    /// entry. The private key is used to sign shim.
    pub fn secure_boot_root_key_paths(&self) -> SecureBootKeyPaths {
        SecureBootKeyPaths::new(self.workspace_path().join("secure_boot_root_key"))
    }

    /// This cert is embedded in shim and the private key is used to
    /// sign crdyboot.
    pub fn secure_boot_shim_key_paths(&self) -> SecureBootKeyPaths {
        SecureBootKeyPaths::new(self.workspace_path().join("secure_boot_shim_key"))
    }

    pub fn shim_build_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("shim_build")
    }

    /// SSH port for VMs.
    pub fn ssh_port() -> u16 {
        9322
    }
}

#[derive(Clone, Copy)]
pub enum EfiExe {
    Crdyboot,
    Enroller,
}

impl EfiExe {
    fn as_str(self) -> &'static str {
        match self {
            EfiExe::Crdyboot => "crdyboot.efi",
            EfiExe::Enroller => "enroller.efi",
        }
    }
}
