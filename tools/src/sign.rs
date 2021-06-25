use crate::Opt;
use anyhow::Error;
use camino::Utf8Path;
use command_run::Command;
use fehler::throws;
use fs_err as fs;

#[throws]
pub fn convert_pem_to_der(input: &Utf8Path, output: &Utf8Path) {
    #[rustfmt::skip]
    Command::with_args("openssl", &[
        "x509",
        "-outform", "der",
        "-in", input.as_str(),
        "-out", output.as_str()
    ]).run()?;
}

#[throws]
pub fn sign_all(opt: &Opt, efi: &Utf8Path, file_names: &[String]) {
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
            "--key", opt.secure_boot_priv_pem().as_str(),
            "--cert", opt.secure_boot_pub_pem().as_str(),
            tmp_unsigned.as_str(),
            "--output", tmp_signed.as_str(),
        ])
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
