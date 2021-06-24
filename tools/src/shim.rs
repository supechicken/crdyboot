use crate::loopback::PartitionPaths;
use crate::pesign;
use crate::{Arch, Opt};
use anyhow::Error;
use command_run::Command;
use fehler::throws;
use fs_err as fs;

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

/// Sign shim with the custom secure boot key.
#[throws]
pub fn sign_shim(opt: &Opt, partitions: &PartitionPaths) {
    let shims = ["bootx64.efi", "bootia32.efi"];
    pesign::sign_all(opt, partitions, &shims)?;
}
