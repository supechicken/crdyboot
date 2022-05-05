use crate::config::Config;
use crate::sign::KeyPaths;
use anyhow::{Context, Error};
use camino::Utf8Path;
use command_run::Command;
use fehler::throws;

#[throws]
fn gen_key(key_paths: &KeyPaths) {
    let path = key_paths.priv_pem();
    // Key generation takes a while, so don't do it if the key
    // already exists.
    if !path.exists() {
        Command::with_args(
            "openssl",
            &["genrsa", "-F4", "-out", path.as_str(), "8192"],
        )
        .run()?;
    }
    // Also generate the public key in PEM format. This isn't used by
    // vboot utilities, but is used in the Rust tests.
    Command::with_args(
        "openssl",
        &[
            "rsa",
            "-pubout",
            "-in",
            path.as_str(),
            "-out",
            key_paths.pub_pem().as_str(),
        ],
    )
    .run()?;
}

/// Generate .vbprivk and .vbpubk files from a .pem file.
#[throws]
fn gen_keypair(futility_path: &Utf8Path, key_paths: &KeyPaths) {
    Command::with_args(
        futility_path,
        &[
            "--vb1",
            "create",
            key_paths.priv_pem().as_str(),
            key_paths.base_name_path().as_str(),
        ],
    )
    .run()?;
}

#[throws]
fn gen_keyblock(
    futility_path: &Utf8Path,
    kernel_key: &KeyPaths,
    kernel_data_key: &KeyPaths,
) {
    // Copied from vboot_reference/firmware/2lib/include/2struct.h
    const VB2_KEYBLOCK_FLAG_DEVELOPER_0: u32 = 0x1;
    const VB2_KEYBLOCK_FLAG_RECOVERY_0: u32 = 0x4;
    const VB2_KEYBLOCK_FLAG_MINIOS_0: u32 = 0x10;
    let flags = VB2_KEYBLOCK_FLAG_DEVELOPER_0
        | VB2_KEYBLOCK_FLAG_RECOVERY_0
        | VB2_KEYBLOCK_FLAG_MINIOS_0;

    Command::with_args(
        futility_path,
        &[
            "--vb1",
            "sign",
            "--signprivate",
            kernel_key.vbprivk().as_str(),
            "--flags",
            &flags.to_string(),
            kernel_data_key.vbpubk().as_str(),
            kernel_data_key.keyblock().as_str(),
        ],
    )
    .run()?;
}

#[throws]
pub fn generate_test_keys(conf: &Config) {
    let futility_path = &conf.futility_executable_path();
    let kernel_key = &conf.kernel_key_paths();
    let kernel_data_key = &conf.kernel_data_key_paths();

    kernel_key.create_dir()?;
    kernel_data_key.create_dir()?;

    gen_key(kernel_key)?;
    gen_key(kernel_data_key)?;

    gen_keypair(futility_path, kernel_key).context("gen kernel_key failed")?;
    gen_keypair(futility_path, kernel_data_key)
        .context("gen kernel_data_key failed")?;
    gen_keyblock(futility_path, kernel_key, kernel_data_key)
        .context("gen_keyblock failed")?;
}
