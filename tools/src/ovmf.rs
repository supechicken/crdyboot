use crate::{copy_file, update_local_repo, Arch, Opt};
use anyhow::Error;
use camino::Utf8Path;
use command_run::Command;
use fehler::throws;

#[throws]
fn build_ovmf(arch_flags: &[&str], edk2_dir: &Utf8Path) {
    // See edk2/OvmfPkg/README for details of these build flags.
    let mut cmd = Command::new("OvmfPkg/build.sh");
    cmd.add_args(arch_flags);
    // Write debug messages to the serial port.
    cmd.add_args(&["-D", "DEBUG_ON_SERIAL_PORT"]);
    // Enable secure boot and require SMM. The latter requires a
    // pflash-backed variable store.
    cmd.add_args(&["-D", "SECURE_BOOT_ENABLE"]);
    cmd.add_args(&["-D", "SMM_REQUIRE"]);
    cmd.set_dir(edk2_dir);
    cmd.run()?;
}

#[throws]
pub fn run_build_ovmf(opt: &Opt) {
    let edk2_dir = opt.volatile_path().join("edk2");
    let edk2_url = "https://github.com/tianocore/edk2.git";
    // Known-working commit.
    let edk2_rev = "75e9154f818a58ffc3a28db9f8c97279e723f02d";

    update_local_repo(&edk2_dir, edk2_url, edk2_rev)?;

    let arch_flags = [
        // 64-bit UEFI for a 64-bit CPU.
        vec!["-a", "X64"],
        // 32-bit UEFI for a 64-bit CPU.
        vec!["-a", "IA32", "-a", "X64"],
    ];

    for arf in arch_flags {
        build_ovmf(&arf, &edk2_dir)?;
    }

    // Copy the outputs to a more convenient location.
    let compiler = "DEBUG_GCC5";
    let outputs = [("Ovmf3264", Arch::Ia32), ("OvmfX64", Arch::X64)];
    for (src_name, arch) in outputs {
        let src_dir = edk2_dir.join("Build").join(src_name).join(compiler);
        let fv_dir = src_dir.join("FV");
        let efi_dir = src_dir.join("X64");

        let dst = opt.ovmf_paths(arch);
        copy_file(fv_dir.join("OVMF_CODE.fd"), dst.code())?;
        copy_file(fv_dir.join("OVMF_VARS.fd"), dst.original_vars())?;
        copy_file(
            efi_dir.join("EnrollDefaultKeys.efi"),
            dst.enroll_executable(),
        )?;
    }
}
