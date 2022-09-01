// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fs_err as fs;

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
}

pub fn generate_key(paths: &SecureBootKeyPaths, name: &str) -> Result<()> {
    paths.create_dir()?;

    if paths.priv_pem().exists()
        && paths.pub_pem().exists()
        && paths.pub_der().exists()
    {
        println!("using existing {} key", paths.dir);
        return Ok(());
    }

    #[rustfmt::skip]
    Command::with_args("openssl", &[
        "req", "-x509",
        "-newkey", "rsa:2048",
        "-keyout", paths.priv_pem().as_str(),
        "-out", paths.pub_pem().as_str(),
        "-subj", &format!("/CN={}/", name),
        // Don't encrypt the key. This avoids needing to set a password.
        "-nodes",
    ]).run()?;

    convert_pem_to_der(&paths.pub_pem(), &paths.pub_der())
}

pub fn generate_signed_vars(
    paths: &SecureBootKeyPaths,
    var_name: &str,
) -> Result<()> {
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
        &[paths.pub_pem().as_str(), unsigned_var.as_str()],
    )
    .run()?;

    #[rustfmt::skip]
    Command::with_args("sign-efi-sig-list", &[
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
    Command::with_args("openssl", &[
        "x509",
        "-outform", "der",
        "-in", input.as_str(),
        "-out", output.as_str()
    ]).run()?;

    Ok(())
}

/// Sign the file at `src` using the keys provided by `key_paths`. The
/// signed result is written to `dst` (and the `src` is never modified).
pub fn sign(
    src: &Utf8Path,
    dst: &Utf8Path,
    key_paths: &SecureBootKeyPaths,
) -> Result<()> {
    #[rustfmt::skip]
    Command::with_args("sbsign", &[
        "--key", key_paths.priv_pem().as_str(),
        "--cert", key_paths.pub_pem().as_str(),
        src.as_str(),
        "--output", dst.as_str(),
    ]).run()?;

    Ok(())
}
