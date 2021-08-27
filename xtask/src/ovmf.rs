use crate::arch::Arch;
use crate::config::Config;
use crate::{copy_file, update_local_repo};
use anyhow::Error;
use camino::Utf8Path;
use command_run::Command;
use fehler::throws;

#[throws]
fn build_ovmf(arch_flags: &[&str], edk2_dir: &Utf8Path) {
    // See edk2/OvmfPkg/README for details of these build flags.
    let mut cmd = Command::new("OvmfPkg/build.sh");
    cmd.add_args(arch_flags);
    // Enable secure boot and require SMM. The latter requires a
    // pflash-backed variable store.
    cmd.add_args(&["-D", "SECURE_BOOT_ENABLE"]);
    cmd.add_args(&["-D", "SMM_REQUIRE"]);
    cmd.set_dir(edk2_dir);
    cmd.run()?;
}

#[throws]
pub fn run_build_ovmf(conf: &Config) {
    let edk2_dir = conf.workspace_path().join("edk2");
    let edk2_url = "https://github.com/tianocore/edk2.git";
    // Known-working commit.
    let edk2_rev = "75e9154f818a58ffc3a28db9f8c97279e723f02d";

    update_local_repo(&edk2_dir, edk2_url, edk2_rev)?;

    let arch_flags = [
        // 64-bit UEFI for a 64-bit CPU.
        vec!["-a", "X64"],
        // 32-bit UEFI for a 32-bit CPU. OVMF also allows building 32-bit UEFI
        // for a 64-bit CPU, but this doesn't actually give the 32-bit UEFI
        // interfaces we want to test against.
        vec!["-a", "IA32"],
    ];

    for arf in arch_flags {
        build_ovmf(&arf, &edk2_dir)?;
    }

    // Copy the outputs to a more convenient location.
    let compiler = "DEBUG_GCC5";
    for arch in Arch::all() {
        let (src_name, efi_dir_name) = match arch {
            Arch::Ia32 => ("OvmfIa32", "IA32"),
            Arch::X64 => ("OvmfX64", "X64"),
        };

        let src_dir = edk2_dir.join("Build").join(src_name).join(compiler);
        let fv_dir = src_dir.join("FV");
        let efi_dir = src_dir.join(efi_dir_name);

        let dst = conf.ovmf_paths(arch);
        copy_file(fv_dir.join("OVMF_CODE.fd"), dst.code())?;
        copy_file(fv_dir.join("OVMF_VARS.fd"), dst.original_vars())?;
        copy_file(
            efi_dir.join("EnrollDefaultKeys.efi"),
            dst.enroll_executable(),
        )?;
    }
}
