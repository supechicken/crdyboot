// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::Config;
use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fs_err as fs;
use std::collections::BTreeMap;

pub struct SecureBootKeyPaths {
    dir: Utf8PathBuf,
}

impl SecureBootKeyPaths {
    pub fn new(dir: Utf8PathBuf) -> Self {
        Self { dir }
    }

    /// Create the directory if it doesn't exist.
    pub fn create_dir(&self) -> Result<()> {
        if !self.dir.exists() {
            fs::create_dir(&self.dir)?;
        }
        Ok(())
    }

    pub fn priv_pem(&self) -> Utf8PathBuf {
        self.dir.join("key.priv.pem")
    }

    pub fn pub_pem(&self) -> Utf8PathBuf {
        self.dir.join("key.pub.pem")
    }

    pub fn pub_der(&self) -> Utf8PathBuf {
        self.dir.join("key.pub.der")
    }

    pub fn pk_and_kek_var(&self) -> Utf8PathBuf {
        self.dir.join("key.pk_and_kek.var")
    }

    pub fn db_var(&self) -> Utf8PathBuf {
        self.dir.join("key.db.var")
    }

    pub fn priv_ed25519_pem(&self) -> Utf8PathBuf {
        self.dir.join("key_ed25519.priv.pem")
    }
}

pub fn generate_rsa_key(paths: &SecureBootKeyPaths, name: &str) -> Result<()> {
    paths.create_dir()?;

    if paths.priv_pem().exists() && paths.pub_pem().exists() && paths.pub_der().exists() {
        println!("using existing rsa {} key", paths.dir);
        return Ok(());
    }

    #[rustfmt::skip]
    Command::with_args("openssl", [
        "req", "-x509",
        "-newkey", "rsa:2048",
        "-keyout", paths.priv_pem().as_str(),
        "-out", paths.pub_pem().as_str(),
        "-subj", &format!("/CN={name}/"),
        // Don't encrypt the key. This avoids needing to set a password.
        "-nodes",
    ]).run()?;

    convert_pem_to_der(&paths.pub_pem(), &paths.pub_der())
}

/// Set up the Ed25519 key used for signing the second-stage bootloader
/// so that crdyshim can verify it.
///
/// This uses the test key from the vboot repo rather than generating a
/// new one.
pub fn prepare_ed25519_key(conf: &Config) -> Result<()> {
    let paths = conf.secure_boot_shim_key_paths();

    paths.create_dir()?;
    let devkeys_dir = conf.vboot_devkeys_path();

    // Copy the private key.
    fs::copy(
        devkeys_dir.join("uefi/crdyshim.priv.pem"),
        paths.priv_ed25519_pem(),
    )?;

    Ok(())
}

pub fn generate_signed_vars(paths: &SecureBootKeyPaths, var_name: &str) -> Result<()> {
    let tmp_dir = tempfile::tempdir()?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();
    let unsigned_var = tmp_path.join("unsigned_var");
    let signed_var = if var_name == "PK" || var_name == "KEK" {
        paths.pk_and_kek_var()
    } else if var_name == "db" {
        paths.db_var()
    } else {
        panic!("invalid var_name");
    };

    // Skip generation if the signed file already exists.
    if signed_var.exists() {
        return Ok(());
    }

    // These two tools are in the efitools package. Might be fun to port them
    // to Rust at some point...
    Command::with_args(
        "cert-to-efi-sig-list",
        [paths.pub_pem().as_str(), unsigned_var.as_str()],
    )
    .run()?;

    #[rustfmt::skip]
    Command::with_args("sign-efi-sig-list", [
        "-k", paths.priv_pem().as_str(),
        "-c", paths.pub_pem().as_str(),
        // The var name is used to pick the appropriate vendor GUID
        // (EFI_GLOBAL_VARIABLE for PK/KEK, or EFI_IMAGE_SECURITY_DATABASE_GUID
        // for db).
        var_name,
        unsigned_var.as_str(),
        signed_var.as_str(),
    ]).run()?;

    Ok(())
}

fn convert_pem_to_der(input: &Utf8Path, output: &Utf8Path) -> Result<()> {
    #[rustfmt::skip]
    Command::with_args("openssl", [
        "x509",
        "-outform", "der",
        "-in", input.as_str(),
        "-out", output.as_str()
    ]).run()?;

    Ok(())
}

/// Sign the file at `src` using the keys provided by `key_paths`. The
/// signed result is written to `dst` (and the `src` is never modified).
pub fn sign(src: &Utf8Path, dst: &Utf8Path, key_paths: &SecureBootKeyPaths) -> Result<()> {
    #[rustfmt::skip]
    Command::with_args("sbsign", [
        "--key", key_paths.priv_pem().as_str(),
        "--cert", key_paths.pub_pem().as_str(),
        src.as_str(),
        "--output", dst.as_str(),
    ]).run()?;

    // Created a detached Ed25519 signature for the file using
    // openssl. An Ed25519 is not always available (the first-stage
    // bootloader is only signed with an RSA key), so skip if the key
    // does not exist.
    //
    // Args based on https://cendyne.dev/posts/2022-03-06-ed25519-signatures.html
    let priv_ed25519_pem = key_paths.priv_ed25519_pem();
    if priv_ed25519_pem.exists() {
        let sig_dst = dst.with_extension("sig");
        #[rustfmt::skip]
        Command::with_args("openssl", [
            "pkeyutl", "-sign",
            "-rawin",
            "-in", dst.as_str(),
            "-inkey", priv_ed25519_pem.as_str(),
            "-out", sig_dst.as_str(),
        ]).run()?;
    }

    Ok(())
}

type Defines<'a> = BTreeMap<&'a str, &'a str>;

/// Parse `#defines` into a map.
fn parse_defines(cpp_output: &str) -> Defines {
    cpp_output
        .lines()
        .filter_map(|line| line.strip_prefix("#define ")?.split_once(' '))
        .collect()
}

/// Get the value of a specific define, and strip the surrounding quotes
/// from the value.
fn get_define_string_val<'a>(defines: &Defines<'a>, name: &str) -> Result<&'a str> {
    let value = defines
        .get(name)
        .with_context(|| format!("missing define {name}"))?;
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .context("define value is unquoted: {value}")
}

/// Parse SBAT revocation `#define`s and format as CSV.
fn sbat_defines_to_csv(cpp_output: &str) -> Result<String> {
    let defines = parse_defines(cpp_output);

    let date = get_define_string_val(&defines, "SBAT_VAR_LATEST_DATE")?;
    let revocations = get_define_string_val(&defines, "SBAT_VAR_LATEST_REVOCATIONS")?;

    let revocations = revocations.replace("\\n", "\n");

    Ok(format!("sbat,1,{date}\n{revocations}"))
}

pub fn update_sbat_revocations() -> Result<()> {
    // Clone latest shim into a temporary directory.
    let tmp_dir = tempfile::tempdir()?;
    let repo_path = tmp_dir.path();
    let repo_url = "https://github.com/rhboot/shim.git";
    Command::with_args("git", ["clone", repo_url])
        .add_arg(repo_path)
        .run()?;

    // Build the header file containing revocations.
    let header_name = "generated_sbat_var_defs.h";
    Command::with_args("make", [header_name])
        .set_dir(repo_path)
        .run()?;

    // Use `cpp` to evaluate and print the `#defines`.
    let output = Command::with_args(
        "cpp",
        [
            // This option tells `cpp` to print `#defines`.
            "-dM",
            header_name,
        ],
    )
    .set_dir(repo_path)
    .enable_capture()
    .run()?;

    // Parse the output and create a CSV file.
    let stdout = std::str::from_utf8(&output.stdout)?;
    let csv = sbat_defines_to_csv(stdout)?;

    // Write out the CSV. The operator can then examine the result and
    // commit it if necessary.
    let output_path = "libcrdy/sbat_revocations.csv";
    fs::write(output_path, csv)?;
    println!("revocations written to {output_path}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_defines() {
        assert_eq!(
            parse_defines("#define K1 V1\n#define K2 V2\n"),
            [("K1", "V1"), ("K2", "V2")].into()
        );

        // Lines that don't start with "#define" are ignored.
        assert_eq!(parse_defines("blah"), [].into());

        // Lines that don't have a value are ignored.
        assert_eq!(parse_defines("#define A"), [].into());
    }

    #[test]
    fn test_get_define_string_val() {
        // Successfully strip quotes.
        assert_eq!(
            get_define_string_val(&[("NAME", "\"VAL\"")].into(), "NAME").unwrap(),
            "VAL"
        );

        // Error: value is not quoted.
        assert!(get_define_string_val(&[("NAME", "VAL")].into(), "NAME").is_err());
    }

    #[test]
    fn test_sbat_defines_to_csv() {
        // A real example from shim, but with most of the defines
        // stripped out. Note that `SBAT_AUTOMATIC_DATE` is not used,
        // just serves to test that unused defines are ignored.
        let cpp_output = r#"
#define SBAT_AUTOMATIC_DATE 2023012900
#define SBAT_VAR_LATEST_DATE "2024040900"
#define SBAT_VAR_LATEST_REVOCATIONS "shim,4\ngrub,4\ngrub.peimage,2\n"
"#;

        let expected_csv = "sbat,1,2024040900
shim,4
grub,4
grub.peimage,2
";

        assert_eq!(sbat_defines_to_csv(cpp_output).unwrap(), expected_csv);
    }
}
