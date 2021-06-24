use crate::loopback::PartitionPaths;
use crate::mount::Mount;
use crate::Opt;
use anyhow::Error;
use camino::Utf8Path;
use command_run::Command;
use fehler::throws;
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

/// Replace both grub executables with crdyboot.
#[throws]
pub fn copy_in_crdyboot(opt: &Opt, partitions: &PartitionPaths) {
    let efi_mount = Mount::new(&partitions.efi)?;
    let efi = efi_mount.mount_point();

    let targets = [
        ("x86_64-unknown-uefi", "grubx64.efi"),
        ("i686-unknown-uefi", "grubia32.efi"),
    ];

    for (target, dstname) in targets {
        let src = opt
            .crdyboot_path()
            .join("target")
            .join(target)
            .join("release/crdyboot.efi");
        let dst = efi.join("efi/boot").join(dstname);
        Command::with_args("sudo", &["cp"])
            .add_arg(src.as_str())
            .add_arg(dst.as_str())
            .run()?;
    }
}

#[throws]
pub fn sign_kernel_partition(opt: &Opt, partition_device_path: &Utf8Path) {
    let tmp_dir = tempfile::tempdir()?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

    let futility = opt.futility_executable_path();
    let futility = futility.as_str();

    // TODO: for now just use a pregenerated test keys.
    let test_data = opt.vboot_path().join("test_data");
    let kernel_key_public = test_data.join("kernel_key.vbpubk");
    let kernel_data_key_private = test_data.join("kernel_data_key.vbprivk");
    let kernel_data_key_keyblock = test_data.join("kernel_data_key.keyblock");

    let unsigned_kernel_partition = tmp_path.join("kernel_partition");
    let vmlinuz = tmp_path.join("vmlinuz");
    let bootloader = tmp_path.join("bootloader");
    let config = tmp_path.join("config");
    let signed_kernel_partition = tmp_path.join("kernel_partition.signed");

    // The bootloader isn't actually used, so just write an
    // placeholder file. (Can't be empty as futility
    // rejects it.)
    fs::write(&bootloader, "not a real bootloader")?;

    // Copy the whole partition to a temporary file.
    Command::with_args(
        "sudo",
        &[
            "cp",
            partition_device_path.as_str(),
            unsigned_kernel_partition.as_str(),
        ],
    )
    .run()?;

    // Get the kernel command line and write it to a file.
    let output = Command::with_args(
        "sudo",
        &[
            futility,
            "vbutil_kernel",
            "--verify",
            unsigned_kernel_partition.as_str(),
            "--verbose",
        ],
    )
    .enable_capture()
    .run()?;
    let stdout = output.stdout_string_lossy();
    let command_line = stdout.lines().last().unwrap();
    fs::write(&config, command_line)?;

    // Extract vmlinuz.
    Command::with_args(
        "sudo",
        &[
            futility,
            "vbutil_kernel",
            "--get-vmlinuz",
            unsigned_kernel_partition.as_str(),
            "--vmlinuz-out",
            vmlinuz.as_str(),
        ],
    )
    .run()?;

    // TODO: give it a fake version for now.
    let version = 0x1988;

    // Sign it.
    #[rustfmt::skip]
    Command::with_args("sudo", &[futility, "vbutil_kernel",
        "--pack", signed_kernel_partition.as_str(),
        "--keyblock", kernel_data_key_keyblock.as_str(),
        "--signprivate", kernel_data_key_private.as_str(),
        "--version", &version.to_string(),
        "--vmlinuz", vmlinuz.as_str(),
        "--bootloader", bootloader.as_str(),
        "--config", config.as_str(),
        // TODO: the kernel is actually amd64, but pass in
        // arm64 so that vbutil won't do all the kernel
        // munging stuff it wants to.
        "--arch", "arm64"]).run()?;

    // Verify it.
    Command::with_args(
        "sudo",
        &[
            futility,
            "vbutil_kernel",
            "--verify",
            signed_kernel_partition.as_str(),
            "--signpubkey",
            kernel_key_public.as_str(),
        ],
    )
    .run()?;

    // Copy it back to the partition.
    Command::with_args(
        "sudo",
        &[
            "cp",
            signed_kernel_partition.as_str(),
            partition_device_path.as_str(),
        ],
    )
    .run()?;
}
