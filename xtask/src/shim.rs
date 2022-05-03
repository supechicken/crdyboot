use crate::arch::Arch;
use crate::config::Config;
use crate::copy_file;
use crate::loopback::PartitionPaths;
use crate::mount::Mount;
use crate::sign;
use anyhow::Error;
use command_run::Command;
use fehler::throws;
use fs_err as fs;

#[throws]
fn build_shim(conf: &Config) {
    let shim_dir = conf.shim_build_path();
    let shim_url = "https://chromium.googlesource.com/chromiumos/shim-review";
    let shim_rev = "aba1fb2b7bffa4af651a40e667bde0dfdfc4ab0a";

    crate::update_local_repo(&shim_dir, shim_url, shim_rev)?;

    // Remove local modifications so that the Dockerfile modification below
    // doesn't keep inserting the same change.
    Command::with_args("git", &["-C", shim_dir.as_str(), "checkout", "-f"])
        .run()?;

    copy_file(
        conf.secure_boot_shim_key_paths().pub_der(),
        shim_dir.join("chromeos_reven.cer"),
    )?;

    // Disable EBS protection. This is a shim feature that hooks the
    // ExitBootServices function so that shim can verify that the
    // 2nd-stage bootloader properly used shim's verification protocol
    // to check the signature of the next stage. In our case though,
    // we verify the signature of the entire kernel partition through
    // a different mechanism than what shim provides, so the EBS check
    // would fail if enabled.
    let dockerfile_path = shim_dir.join("Dockerfile");
    let orig_dockerfile = fs::read_to_string(&dockerfile_path)?;
    let orig_str = "TOPDIR=.. -f ../Makefile";
    let new_str = format!("DISABLE_EBS_PROTECTION=y {}", orig_str);
    let new_dockerfile = orig_dockerfile.replace(orig_str, &new_str);
    fs::write(&dockerfile_path, new_dockerfile)?;

    Command::with_args("make", &["build"])
        .set_dir(&shim_dir)
        .run()?;
    Command::with_args("make", &["copy"])
        .set_dir(&shim_dir)
        .run()?;
}

#[throws]
pub fn update_shim(conf: &Config, partitions: &PartitionPaths) {
    build_shim(conf)?;

    let efi_mount = Mount::new(&partitions.efi)?;
    let efi = efi_mount.mount_point();

    let mut to_sign = Vec::new();

    for arch in Arch::all() {
        let src = conf.shim_build_path().join(arch.efi_file_name("shim"));

        let dst_file_name = arch.efi_file_name("boot");
        let dst = efi.join("efi/boot").join(&dst_file_name);

        Command::with_args("sudo", &["cp", src.as_str(), dst.as_str()])
            .run()?;

        to_sign.push(dst_file_name);
    }

    sign::sign_all(efi, &conf.secure_boot_root_key_paths(), &to_sign)?;
}
