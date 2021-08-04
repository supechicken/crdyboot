use crate::arch::Arch;
use crate::build_mode::BuildMode;
use crate::qemu::OvmfPaths;
use crate::sign::KeyPaths;
use anyhow::{anyhow, bail, Error};
use camino::{Utf8Path, Utf8PathBuf};
use fehler::throws;
use fs_err as fs;

pub struct Config {
    pub enable_verbose_logging: bool,
    pub use_test_key: bool,

    /// Absolute path of the crdyboot repo.
    pub repo: Utf8PathBuf,
}

/// Path of the config file relative to the repo root directory.
pub fn config_path(repo_root: &Utf8Path) -> Utf8PathBuf {
    repo_root.join("crdyboot.conf")
}

impl Config {
    #[throws]
    pub fn load(repo_root: &Utf8Path) -> Config {
        let ini = fs::read_to_string(config_path(repo_root))?;
        Config::parse(&ini, repo_root)?
    }

    #[throws]
    fn parse(ini: &str, repo: &Utf8Path) -> Config {
        let mut enable_verbose_logging = None;
        let mut use_test_key = None;

        for (index, line) in ini.lines().enumerate() {
            let line_no = index + 1;
            let line = line.trim();

            // Ignore empty lines and comments.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<_> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                bail!(
                    "invalid config: line {}: expected 'option = value'",
                    line_no
                );
            }

            let key = parts[0].trim();
            let val = parts[1].trim();

            let parse_bool = || -> Result<Option<bool>, Error> {
                val.parse()
                    .map_err(|_| {
                        anyhow!(
                            "invalid config: line {}: expected bool value",
                            line_no
                        )
                    })
                    .map(Some)
            };

            match key {
                "enable_verbose_logging" => {
                    enable_verbose_logging = parse_bool()?
                }
                "use_test_key" => use_test_key = parse_bool()?,
                _ => println!("warning: unknown config option: {}", key),
            }
        }

        Config {
            enable_verbose_logging: enable_verbose_logging.unwrap_or(true),
            use_test_key: use_test_key.unwrap_or(false),
            repo: repo.to_path_buf(),
        }
    }

    /// Get all cargo features to enable while building crdyboot.
    pub fn get_crdyboot_features(&self) -> Vec<&'static str> {
        let mut features = Vec::new();
        if self.enable_verbose_logging {
            features.push("verbose");
        }
        if self.use_test_key {
            features.push("use_test_key");
        }
        features
    }

    pub fn crdyboot_path(&self) -> Utf8PathBuf {
        self.repo.join("crdyboot")
    }

    pub fn enroller_path(&self) -> Utf8PathBuf {
        self.repo.join("enroller")
    }

    pub fn workspace_path(&self) -> Utf8PathBuf {
        self.repo.join("workspace")
    }

    pub fn tools_path(&self) -> Utf8PathBuf {
        self.repo.join("tools")
    }

    pub fn vboot_path(&self) -> Utf8PathBuf {
        self.repo.join("vboot")
    }

    pub fn project_paths(&self) -> Vec<Utf8PathBuf> {
        vec![
            self.crdyboot_path(),
            self.enroller_path(),
            self.tools_path(),
            self.vboot_path(),
        ]
    }

    pub fn vboot_reference_path(&self) -> Utf8PathBuf {
        self.repo.join("third_party/vboot_reference")
    }

    pub fn futility_executable_path(&self) -> Utf8PathBuf {
        self.vboot_reference_path().join("build/futility/futility")
    }

    pub fn disk_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("disk.bin")
    }

    pub fn enroller_disk_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("enroller.bin")
    }

    pub fn vboot_test_disk_path(&self) -> Utf8PathBuf {
        self.repo.join("vboot/test_data/disk.bin")
    }

    pub fn ovmf_paths(&self, arch: Arch) -> OvmfPaths {
        let subdir = match arch {
            Arch::Ia32 => "uefi32",
            Arch::X64 => "uefi64",
        };
        OvmfPaths::new(self.workspace_path().join(subdir))
    }

    /// This cert will be enrolled as the PK, first KEK, and first DB
    /// entry. The private key is used to sign shim.
    pub fn secure_boot_root_key_paths(&self) -> KeyPaths {
        KeyPaths::new(self.workspace_path().join("secure_boot_root_key"))
    }

    /// This cert is embedded in shim and the private key is used to
    /// sign crdyboot.
    pub fn secure_boot_shim_key_paths(&self) -> KeyPaths {
        KeyPaths::new(self.workspace_path().join("secure_boot_shim_key"))
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
    #[throws]
    fn test_parse() {
        let path = Utf8PathBuf::from("path");

        // An empty config is OK.
        let conf = Config::parse("", &path)?;
        assert!(conf.enable_verbose_logging);

        // Parse a bool.
        let conf = Config::parse("enable_verbose_logging=false", &path)?;
        assert!(!conf.enable_verbose_logging);

        // Invalid bool.
        assert!(Config::parse("enable_verbose_logging=asdf", &path).is_err());

        // An unknown key is allowed.
        assert!(Config::parse("asdf=true", &path).is_ok());
    }
}
