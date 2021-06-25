use crate::loopback::PartitionPaths;
use crate::mount::Mount;
use crate::sign;
use crate::{Arch, Opt};
use anyhow::Error;
use command_run::Command;
use fehler::throws;
use fs_err as fs;
use std::env;

#[throws]
fn build_shim(opt: &Opt) {
    let shim_dir = opt.shim_build_path();
    let shim_url = "https://github.com/neverware/shim-build.git";
    let shim_rev = "f91f23e3ce3f93fe8532d8bbcfe90ace755a5fed";

    crate::update_local_repo(&shim_dir, shim_url, shim_rev)?;

    fs::copy(
        opt.secure_boot_shim_key_paths().pub_der(),
        shim_dir.join("neverware.cer"),
    )?;

    Command::with_args("make", &["build"])
        .set_dir(&shim_dir)
        .run()?;
    Command::with_args("make", &["copy"])
        .set_dir(&shim_dir)
        .run()?;

    // For some reason the files get dumped to the CWD instead of the
    // CWD passed into set_dir above. Super confused as to why.
    Command::with_args(
        "sudo",
        &["chown", "-R", &env::var("USER").unwrap(), "install"],
    )
    .run()?;
    fs::rename("install/shimia32.efi", shim_dir.join("shimia32.efi"))?;
    fs::rename("install/shimx64.efi", shim_dir.join("shimx64.efi"))?;
    fs::remove_dir("install")?;
}

#[throws]
pub fn update_shim(opt: &Opt, partitions: &PartitionPaths) {
    build_shim(opt)?;

    let efi_mount = Mount::new(&partitions.efi)?;
    let efi = efi_mount.mount_point();

    let mut to_sign = Vec::new();

    for arch in Arch::all() {
        let src = opt
            .shim_build_path()
            .join(format!("shim{}.efi", arch.as_str()));

        let dst_file_name = format!("boot{}.efi", arch.as_str());
        let dst = efi.join("efi/boot").join(&dst_file_name);

        Command::with_args("sudo", &["cp", src.as_str(), dst.as_str()])
            .run()?;

        to_sign.push(dst_file_name);
    }

    sign::sign_all(efi, &opt.secure_boot_root_key_paths(), &to_sign)?;
}
