// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::build_mode::BuildMode;
use crate::package::Package;
use crate::qemu::OvmfPaths;
use crate::secure_boot::SecureBootKeyPaths;
use crate::vboot::VbootKeyPaths;
use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use fs_err as fs;
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    enable_verbose_logging: bool,
    use_test_key: bool,
    disk_path: Utf8PathBuf,

    /// Absolute path of the crdyboot repo. This is passed in to
    /// [`Config::load`], not part of the input config file.
    #[serde(skip)]
    repo: Utf8PathBuf,
}

/// Path of the config file relative to the repo root directory.
pub fn config_path(repo_root: &Utf8Path) -> Utf8PathBuf {
    repo_root.join("crdyboot.toml")
}

impl Config {
    pub fn load(repo_root: &Utf8Path) -> Result<Config> {
        let src = fs::read_to_string(config_path(repo_root))?;
        Config::parse(&src, repo_root)
    }

    fn parse(src: &str, repo: &Utf8Path) -> Result<Config> {
        let mut config: Self = toml::de::from_str(src)?;
        config.repo = repo.into();
        Ok(config)
    }

    /// Get all cargo features to enable while building a package.
    pub fn get_package_features(&self, package: Package) -> Vec<&'static str> {
        use Package::*;

        let mut features = Vec::new();

        match package {
            Crdyboot => {
                if self.enable_verbose_logging {
                    features.push("verbose");
                }
                if self.use_test_key {
                    features.push("use_test_key");
                }
            }
            Enroller | Libcrdy | Vboot | Xtask => {}
        }

        features
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
    pub fn target_exec_path(&self, arch: Arch, file_name: &str) -> Utf8PathBuf {
        self.target_path()
            .join(arch.uefi_target())
            .join(self.build_mode().dir_name())
            .join(file_name)
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
            format!("{}\n", version),
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
        SecureBootKeyPaths::new(
            self.workspace_path().join("secure_boot_root_key"),
        )
    }

    /// This cert is embedded in shim and the private key is used to
    /// sign crdyboot.
    pub fn secure_boot_shim_key_paths(&self) -> SecureBootKeyPaths {
        SecureBootKeyPaths::new(
            self.workspace_path().join("secure_boot_shim_key"),
        )
    }

    pub fn shim_build_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("shim_build")
    }

    pub fn build_mode(&self) -> BuildMode {
        BuildMode::Release
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() -> Result<()> {
        let repo = &Utf8PathBuf::new();

        // Default config parses OK.
        let default_cfg = include_str!("../default.toml");
        Config::parse(default_cfg, repo)?;

        // Config with unknown key is invalid.
        let unknown_key = format!("{}\n unknown_key = true", default_cfg);
        assert!(Config::parse(&unknown_key, repo).is_err());

        // Partial config is invalid.
        let partial = default_cfg.replace("use_test_key = true", "");
        assert!(Config::parse(&partial, repo).is_err());

        Ok(())
    }
}
