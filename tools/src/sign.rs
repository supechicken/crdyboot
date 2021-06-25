use crate::Opt;
use anyhow::{anyhow, Error};
use camino::Utf8Path;
use command_run::Command;
use fehler::{throw, throws};
use fs_err as fs;

const CERT_NICKNAME: &str = "testsbcert";
const PASSWORD: &str = "fakepassword";

#[throws]
fn convert_der_to_pem(input: &Utf8Path, output: &Utf8Path) {
    #[rustfmt::skip]
    Command::with_args("openssl", &[
        "x509",
        "-inform", "der",
        "-in", input.as_str(),
        "-out", output.as_str()
    ]).run()?;
}

#[throws]
fn convert_pem_to_pkcs12(
    pub_pem: &Utf8Path,
    priv_pem: &Utf8Path,
    output: &Utf8Path,
) {
    #[rustfmt::skip]
    Command::with_args("openssl", &[
        "pkcs12", "-export",
        "-passin", &format!("pass:{}", PASSWORD),
        "-passout", &format!("pass:{}", PASSWORD),
        "-name", CERT_NICKNAME,
        "-out", output.as_str(),
        "-inkey", priv_pem.as_str(),
        "-in", pub_pem.as_str(),
    ]).run()?;
}

#[throws]
fn make_pk12_db(db_path: &Utf8Path, p12: &Utf8Path) {
    #[rustfmt::skip]
    Command::with_args("pk12util", &[
        "-i", p12.as_str(),
        "-d", db_path.as_str(),
        "-K", PASSWORD,
        "-W", PASSWORD,
        "-v",
    ]).run()?;
}

fn run_pesign(
    db_path: &Utf8Path,
    input: &Utf8Path,
    output: &Utf8Path,
) -> rexpect::errors::Result<()> {
    #[rustfmt::skip]
    let cmd = Command::with_args("pesign", &[
        "--in", input.as_str(),
        "--out", output.as_str(),
        "--certficate", CERT_NICKNAME,
        "--certdir", db_path.as_str(),
        "--sign",
        "--verbose",
    ]);

    let cmd = cmd.command_line_lossy();
    println!("{}", cmd);

    let timeout_seconds = 5;
    let mut p = rexpect::spawn(&cmd, Some(timeout_seconds * 1000))?;
    p.exp_string("Enter Password or Pin for \"NSS Certificate DB\":")?;
    p.send_line(PASSWORD)?;
    let output = p.exp_eof()?;
    println!("{}", output);

    let status = p.process.wait()?;
    if let rexpect::process::wait::WaitStatus::Exited(_, code) = status {
        if code == 0 {
            return Ok(());
        }
    }
    eprintln!("pesign failed: {:?}", status);
    Err(rexpect::errors::Error::from_kind(
        rexpect::errors::ErrorKind::Msg("pesign failed".into()),
    ))
}

#[throws]
pub fn sign_all(opt: &Opt, efi: &Utf8Path, file_names: &[String]) {
    let tmp_dir = tempfile::tempdir()?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

    let pubkey_pem_path = tmp_path.join("sb.pub.pem");
    let p12_path = tmp_path.join("sb.p12");
    let tmp_unsigned = tmp_path.join("unsigned.efi");
    let tmp_signed = tmp_path.join("signed.efi");
    let tmp_db = tmp_path.join("db");

    fs::create_dir(&tmp_db)?;

    convert_der_to_pem(&opt.secure_boot_pub_der(), &pubkey_pem_path)?;
    convert_pem_to_pkcs12(
        &pubkey_pem_path,
        &opt.secure_boot_priv_pem(),
        &p12_path,
    )?;

    make_pk12_db(&tmp_db, &p12_path)?;

    for file_name in file_names {
        let file_path = efi.join("efi/boot").join(file_name);
        fs::copy(&file_path, &tmp_unsigned)?;

        if let Err(err) = run_pesign(&tmp_db, &tmp_unsigned, &tmp_signed) {
            throw!(anyhow!("pesign: {}", err));
        }

        Command::with_args(
            "sudo",
            &["cp", tmp_signed.as_str(), file_path.as_str()],
        )
        .run()?;

        fs::remove_file(&tmp_unsigned)?;
        fs::remove_file(&tmp_signed)?;
    }
}
