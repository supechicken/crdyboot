use crate::loopback::PartitionPaths;
use crate::mount::Mount;
use crate::{Arch, Opt};
use anyhow::Error;
use camino::Utf8Path;
use command_run::Command;
use fehler::throws;
use fs_err as fs;

const CERT_NICKNAME: &str = "testsbcert";
const PASSWORD: &str = "fakepassword";

#[throws]
pub fn build_shim(opt: &Opt) {
    let shim_dir = opt.volatile_path().join("shim_build");
    let shim_url = "https://github.com/rhboot/shim.git";
    let shim_rev = "9f973e4e95b1136b8c98051dbbdb1773072cc998";

    crate::update_local_repo(&shim_dir, shim_url, shim_rev)?;

    let shim_cert = "shim.cer";
    fs::copy(opt.secure_boot_pub_der(), shim_dir.join(shim_cert))?;

    let arches = [(Arch::X64, "x86_64"), (Arch::Ia32, "ia32")];

    for (arch, shim_arch) in arches {
        let file_name = format!("shim{}.efi", arch.as_str());
        let dst_path = opt.volatile_path().join(&file_name);
        if dst_path.exists() {
            println!("skipping build: {} already exists", dst_path);
            continue;
        }

        let build_dir = shim_dir.join(shim_arch);
        if !build_dir.exists() {
            fs::create_dir(&build_dir)?;
        }

        #[rustfmt::skip]
        Command::with_args("make", &[
            "-C", build_dir.as_str(),
            &format!("ARCH={}", shim_arch),
            &format!("VENDOR_CERT_FILE=../{}", shim_cert),
            "TOPDIR=..",
            "-f", "../Makefile"
        ]).run()?;

        fs::copy(build_dir.join(&file_name), dst_path)?;
    }
}

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

/// Sign shim with the custom secure boot key.
#[throws]
pub fn sign_shim(opt: &Opt, partitions: &PartitionPaths) {
    let efi_mount = Mount::new(&partitions.efi)?;
    let efi = efi_mount.mount_point();

    let shims = ["bootx64.efi", "bootia32.efi"];

    let tmp_dir = tempfile::tempdir()?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

    let pubkey_pem_path = tmp_path.join("sb.pub.pem");
    let p12_path = tmp_path.join("sb.p12");
    let tmp_shim_unsigned = tmp_path.join("shim-unsigned.efi");
    let tmp_shim_signed = tmp_path.join("shim-signed.efi");
    let tmp_db = tmp_path.join("db");

    fs::create_dir(&tmp_db)?;

    convert_der_to_pem(&opt.secure_boot_pub_der(), &pubkey_pem_path)?;
    convert_pem_to_pkcs12(
        &pubkey_pem_path,
        &opt.secure_boot_priv_pem(),
        &p12_path,
    )?;

    make_pk12_db(&tmp_db, &p12_path)?;

    for shim in shims {
        let real_shim = efi.join("efi/boot").join(shim);
        fs::copy(&real_shim, &tmp_shim_unsigned)?;

        run_pesign(&tmp_db, &tmp_shim_unsigned, &tmp_shim_signed).unwrap();

        Command::with_args(
            "sudo",
            &["cp", tmp_shim_signed.as_str(), real_shim.as_str()],
        )
        .run()?;

        fs::remove_file(&tmp_shim_signed)?;
    }
}
