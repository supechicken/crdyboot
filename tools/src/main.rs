mod gen_disk;
mod loopback;
mod mount;
mod qemu;

use anyhow::Error;
use argh::FromArgs;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fehler::throws;
use fs_err as fs;
use loopback::LoopbackDevice;
use qemu::{OvmfPaths, Qemu};
use std::env;

/// Tools for crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
pub struct Opt {
    /// absolute path of the crdyboot repo
    #[argh(option)]
    repo: Utf8PathBuf,

    /// action to run
    #[argh(subcommand)]
    action: Action,
}

impl Opt {
    fn crdyboot_path(&self) -> Utf8PathBuf {
        self.repo.join("crdyboot")
    }

    // TODO: consider moving this to repo root.
    fn volatile_path(&self) -> Utf8PathBuf {
        self.crdyboot_path().join("volatile")
    }

    fn tools_path(&self) -> Utf8PathBuf {
        self.repo.join("tools")
    }

    fn vboot_path(&self) -> Utf8PathBuf {
        self.repo.join("vboot")
    }

    fn project_paths(&self) -> Vec<Utf8PathBuf> {
        vec![self.crdyboot_path(), self.tools_path(), self.vboot_path()]
    }

    fn vboot_reference_path(&self) -> Utf8PathBuf {
        self.repo.join("third_party/vboot_reference")
    }

    fn futility_executable_path(&self) -> Utf8PathBuf {
        self.vboot_reference_path().join("build/futility/futility")
    }

    fn disk_path(&self) -> Utf8PathBuf {
        self.volatile_path().join("disk.bin")
    }

    fn ovmf_paths(&self, arch: Arch) -> OvmfPaths {
        let subdir = match arch {
            Arch::Ia32 => "uefi32",
            Arch::X64 => "uefi64",
        };
        OvmfPaths::new(self.volatile_path().join(subdir))
    }
}

enum Arch {
    Ia32,
    X64,
}

impl Arch {
    fn all() -> [Arch; 2] {
        [Arch::Ia32, Arch::X64]
    }
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Action {
    Check(CheckAction),
    Format(FormatAction),
    Lint(LintAction),
    Test(TestAction),
    Build(BuildAction),
    GenDisk(GenDiskAction),
    BuildOvmf(BuildOvmfAction),
    SecureBootSetup(SecureBootSetupAction),
    Qemu(QemuAction),
}

/// Build crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build")]
struct BuildAction {}

/// Build OVMF.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build-ovmf")]
struct BuildOvmfAction {}

/// Format, lint, test, and build.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "check")]
struct CheckAction {}

/// Run "cargo fmt" on all the code.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "fmt")]
struct FormatAction {}

/// Modify an existing CloudReady build to insert crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "gen-disk")]
struct GenDiskAction {}

/// Run "cargo clippy" on all the code.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "lint")]
struct LintAction {}

/// Set up secure boot keys.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "secure-boot-setup")]
struct SecureBootSetupAction {
    /// print output from QEMU
    #[argh(switch)]
    verbose: bool,
}

/// Run "cargo test" in the vboot project.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "test")]
struct TestAction {}

/// Run crdyboot under qemu.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "qemu")]
struct QemuAction {
    /// use 32-bit UEFI instead of 64-bit
    #[argh(switch)]
    ia32: bool,
}

const RUSTFLAGS_ENV_VAR: &str = "RUSTFLAGS";

fn update_rustflags_path_prefix(project_dir: &Utf8Path) -> String {
    let mut val = env::var(RUSTFLAGS_ENV_VAR).unwrap_or_else(|_| String::new());
    val += &format!(" --remap-path-prefix=src={}/src", project_dir);
    val
}

fn modify_cmd_for_path_prefix(cmd: &mut Command, project_dir: &Utf8Path) {
    cmd.env.insert(
        RUSTFLAGS_ENV_VAR.into(),
        update_rustflags_path_prefix(project_dir).into(),
    );
}

#[throws]
fn run_check(opt: &Opt) {
    run_rustfmt(opt)?;
    run_clippy(opt)?;
    run_tests(opt)?;
    run_build(opt)?;
}

#[throws]
fn run_build(opt: &Opt) {
    let targets = ["x86_64-unknown-uefi", "i686-unknown-uefi"];
    let crdyboot_dir = opt.crdyboot_path();

    for target in targets {
        let mut cmd = Command::with_args(
            "cargo",
            &[
                "+nightly",
                "build",
                // TODO: for now always use release mode to avoid this
                // error: "LLVM ERROR: Do not know how to split the result
                // of this operator!"
                "--release",
                "-Zbuild-std=core,compiler_builtins,alloc",
                "-Zbuild-std-features=compiler-builtins-mem",
                "--target",
                target,
            ],
        );
        modify_cmd_for_path_prefix(&mut cmd, &crdyboot_dir);
        cmd.set_dir(&crdyboot_dir);
        cmd.run()?;
    }
}

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
fn run_build_ovmf(opt: &Opt) {
    let edk2_dir = opt.volatile_path().join("edk2");
    let edk2_url = "https://github.com/tianocore/edk2.git";

    // Clone edk2 if not already cloned, otherwise just fetch.
    if edk2_dir.exists() {
        Command::with_args("git", &["-C", edk2_dir.as_str(), "fetch"]).run()?;
    } else {
        Command::with_args("git", &["clone", edk2_url, edk2_dir.as_str()])
            .run()?;
    }

    // Check out a known-working commit.
    Command::with_args(
        "git",
        &[
            "-C",
            edk2_dir.as_str(),
            "checkout",
            "75e9154f818a58ffc3a28db9f8c97279e723f02d",
        ],
    )
    .run()?;

    // Init/update submodules.
    Command::with_args(
        "git",
        &["-C", edk2_dir.as_str(), "submodule", "update", "--init"],
    )
    .run()?;

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
        fs::copy(fv_dir.join("OVMF_CODE.fd"), dst.code())?;
        fs::copy(fv_dir.join("OVMF_VARS.fd"), dst.original_vars())?;
        fs::copy(
            efi_dir.join("EnrollDefaultKeys.efi"),
            dst.enroll_executable(),
        )?;
    }
}

#[throws]
fn run_rustfmt(opt: &Opt) {
    for project in opt.project_paths() {
        let cargo_path = project.join("Cargo.toml");
        Command::with_args(
            "cargo",
            &["fmt", "--manifest-path", cargo_path.as_str()],
        )
        .run()?;
    }
}

#[throws]
fn run_gen_disk(opt: &Opt) {
    let disk = opt.disk_path();

    let lo_dev = LoopbackDevice::new(&disk)?;
    let partitions = lo_dev.partition_paths();

    gen_disk::copy_in_crdyboot(opt, &partitions)?;

    // Sign both kernel partitions.
    gen_disk::sign_kernel_partition(opt, &partitions.kern_a)?;
    gen_disk::sign_kernel_partition(opt, &partitions.kern_b)?;
}

#[throws]
fn run_clippy(opt: &Opt) {
    for project in opt.project_paths() {
        println!("{}:", project);
        let mut cmd = Command::with_args("cargo", &["+nightly", "clippy"]);
        modify_cmd_for_path_prefix(&mut cmd, &project);
        cmd.set_dir(&project);
        cmd.run()?;
    }
}

#[throws]
fn run_tests(opt: &Opt) {
    let vboot_dir = opt.vboot_path();
    let mut cmd = Command::with_args("cargo", &["test"]);
    modify_cmd_for_path_prefix(&mut cmd, &vboot_dir);
    cmd.set_dir(&vboot_dir);
    cmd.run()?;
}

#[throws]
fn generate_secure_boot_key(opt: &Opt) -> Utf8PathBuf {
    let volatile = opt.volatile_path();

    let conf_path = volatile.join("openssl.conf");
    let pubkey_path = volatile.join("sb.key.pub");
    let privkey_path = volatile.join("sb.key.priv");
    let oemstr_path = volatile.join("sb.key.oemstr");

    if pubkey_path.exists() && privkey_path.exists() {
        println!("using existing secure boot key");
        return oemstr_path;
    }

    let conf = "
        [req]
        distinguished_name = req_distinguished_name
        prompt = no
        output_password = fakepassword

        [req_distinguished_name]
        O = secure boot test cert";

    fs::write(&conf_path, conf)?;

    #[rustfmt::skip]
    Command::with_args("openssl", &[
        "req", "-x509",
        "-newkey", "rsa:2048",
        "-outform", "DER",
        "-keyout", privkey_path.as_str(),
        "-out", pubkey_path.as_str(),
        "-config", conf_path.as_str()]).run()?;

    // Remove no-longer-needed config.
    fs::remove_file(&conf_path)?;

    let der = fs::read(&pubkey_path)?;

    // Defined in edk2/OvmfPkg/Include/Guid/OvmfPkKek1AppPrefix.h
    let uuid = "4e32566d-8e9e-4f52-81d3-5bb9715f9727";

    let oemstr = format!("{}:{}", uuid, base64::encode(der));

    fs::write(&oemstr_path, oemstr)?;

    oemstr_path
}

#[throws]
fn run_secure_boot_setup(opt: &Opt, action: &SecureBootSetupAction) {
    let po = if action.verbose {
        qemu::PrintOutput::Yes
    } else {
        qemu::PrintOutput::No
    };

    let oemstr_path = generate_secure_boot_key(opt)?;

    for arch in Arch::all() {
        let ovmf = opt.ovmf_paths(arch);

        fs::copy(ovmf.original_vars(), ovmf.secure_boot_vars())?;

        let qemu = Qemu::new(ovmf);
        qemu.enroll(&oemstr_path, po)?;
    }
}

#[throws]
fn run_qemu(opt: &Opt, action: &QemuAction) {
    let disk = opt.disk_path();

    let ovmf = if action.ia32 {
        opt.ovmf_paths(Arch::Ia32)
    } else {
        opt.ovmf_paths(Arch::X64)
    };

    let qemu = Qemu::new(ovmf);
    qemu.run_disk_image(&disk)?;
}

#[throws]
fn main() {
    let opt: Opt = argh::from_env();

    Command::with_args(
        "git",
        &["-C", opt.repo.as_str(), "submodule", "update", "--init"],
    )
    .run()?;

    match &opt.action {
        Action::Build(_) => run_build(&opt),
        Action::BuildOvmf(_) => run_build_ovmf(&opt),
        Action::Check(_) => run_check(&opt),
        Action::Format(_) => run_rustfmt(&opt),
        Action::GenDisk(_) => run_gen_disk(&opt),
        Action::Lint(_) => run_clippy(&opt),
        Action::SecureBootSetup(action) => run_secure_boot_setup(&opt, action),
        Action::Test(_) => run_tests(&opt),
        Action::Qemu(action) => run_qemu(&opt, action),
    }?;
}
