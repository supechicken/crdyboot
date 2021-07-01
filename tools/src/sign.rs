use anyhow::Error;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fehler::throws;
use fs_err as fs;

pub struct KeyPaths {
    dir: Utf8PathBuf,
}

impl KeyPaths {
    pub fn new(dir: Utf8PathBuf) -> KeyPaths {
        KeyPaths { dir }
    }

    pub fn enroll_data(&self) -> Utf8PathBuf {
        self.dir.join("key.oemstr")
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

#[throws]
pub fn generate_key(paths: &KeyPaths, name: &str) {
    if !paths.dir.exists() {
        fs::create_dir(&paths.dir)?;
    }

    if paths.priv_pem().exists()
        && paths.pub_pem().exists()
        && paths.pub_der().exists()
    {
        println!("using existing {} key", paths.dir);
        return;
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

    convert_pem_to_der(&paths.pub_pem(), &paths.pub_der())?;
}

#[throws]
pub fn generate_signed_vars(paths: &KeyPaths, var_name: &str) {
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
        return;
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
}

#[throws]
fn convert_pem_to_der(input: &Utf8Path, output: &Utf8Path) {
    #[rustfmt::skip]
    Command::with_args("openssl", &[
        "x509",
        "-outform", "der",
        "-in", input.as_str(),
        "-out", output.as_str()
    ]).run()?;
}

#[throws]
pub fn sign_all(efi: &Utf8Path, key_paths: &KeyPaths, file_names: &[String]) {
    let tmp_dir = tempfile::tempdir()?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

    let tmp_unsigned = tmp_path.join("unsigned.efi");
    let tmp_signed = tmp_path.join("signed.efi");
    let tmp_db = tmp_path.join("db");

    fs::create_dir(&tmp_db)?;

    for file_name in file_names {
        let file_path = efi.join("efi/boot").join(file_name);
        fs::copy(&file_path, &tmp_unsigned)?;

        #[rustfmt::skip]
        Command::with_args("sbsign", &[
            "--key", key_paths.priv_pem().as_str(),
            "--cert", key_paths.pub_pem().as_str(),
            tmp_unsigned.as_str(),
            "--output", tmp_signed.as_str(),
        ])
        .run()?;

        Command::with_args("sbverify", &["--list", tmp_signed.as_str()])
            .run()?;

        Command::with_args(
            "sudo",
            &["cp", tmp_signed.as_str(), file_path.as_str()],
        )
        .run()?;

        fs::remove_file(&tmp_unsigned)?;
        fs::remove_file(&tmp_signed)?;
    }
}
