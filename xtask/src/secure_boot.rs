// Copyright 2022 The ChromiumOS Authors
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

    pub fn priv_ed25519_pem(&self) -> Utf8PathBuf {
        self.dir.join("key_ed25519.priv.pem")
    }

    pub fn pub_ed25519_pem(&self) -> Utf8PathBuf {
        self.dir.join("key_ed25519.pub.pem")
    }

    pub fn pub_ed25519_raw(&self) -> Utf8PathBuf {
        self.dir.join("key_ed25519.pub.raw")
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

pub fn generate_ed25519_key(paths: &SecureBootKeyPaths) -> Result<()> {
    paths.create_dir()?;

    if paths.priv_ed25519_pem().exists()
        && paths.pub_ed25519_pem().exists()
        && paths.pub_ed25519_raw().exists()
    {
        println!("using existing ed25519 {} key", paths.dir);
        return Ok(());
    }

    // Generate private key.
    #[rustfmt::skip]
    Command::with_args("openssl", [
        "genpkey",
        "-algorithm", "ed25519",
        "-out", paths.priv_ed25519_pem().as_str(),
    ]).run()?;

    // Extract the public key.
    #[rustfmt::skip]
    Command::with_args("openssl", [
        "pkey",
        "-in", paths.priv_ed25519_pem().as_str(),
        "-outform", "PEM",
        "-pubout",
        "-out", paths.pub_ed25519_pem().as_str(),
    ]).run()?;

    // Create a raw version of the pubkey that can be loaded with
    // `ed25519_compact::PublicKey::from_slice`.
    let pub_pem = fs::read_to_string(paths.pub_ed25519_pem())?;
    let pub_key = ed25519_compact::PublicKey::from_pem(&pub_pem)?;
    let pub_raw: &[u8] = &*pub_key;
    fs::write(paths.pub_ed25519_raw(), pub_raw)?;

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
