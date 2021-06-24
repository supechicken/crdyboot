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
use mount::Mount;
use qemu::Qemu;
use std::env;

/// Tools for crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
struct Opt {
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
    let outputs = [("Ovmf3264", "uefi32"), ("OvmfX64", "uefi64")];
    for (src_name, dst_dir_name) in outputs {
        let src_dir = edk2_dir
            .join("Build")
            .join(src_name)
            .join(compiler)
            .join("FV");
        let dst_dir = opt.volatile_path().join(dst_dir_name);
        let file_names = ["OVMF_CODE.fd", "OVMF_VARS.fd"];
        for name in file_names {
            let src = src_dir.join(name);
            let dst = dst_dir.join(name);
            fs::copy(src, dst)?;
        }
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
fn sign_kernel_partition(opt: &Opt, partition_device_path: &Utf8Path) {
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

#[throws]
fn run_gen_disk(opt: &Opt) {
    // TODO: dedup
    let volatile = opt.volatile_path();
    let disk = volatile.join("disk.bin");

    let lo_dev = LoopbackDevice::new(&disk)?;
    let partitions = lo_dev.partition_paths();

    {
        // Replace both grub executables with crdyboot.
        let efi_mount = Mount::new(&partitions.efi)?;
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
            let dst = efi_mount.mount_point().join("efi/boot").join(dstname);
            Command::with_args("sudo", &["cp"])
                .add_arg(src.as_str())
                .add_arg(dst.as_str())
                .run()?;
        }
    }

    // Sign both kernel partitions.
    sign_kernel_partition(opt, &partitions.kern_a)?;
    sign_kernel_partition(opt, &partitions.kern_b)?;
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
fn run_qemu(opt: &Opt, action: &QemuAction) {
    let volatile = opt.volatile_path();
    let disk = volatile.join("disk.bin");

    let ovmf_dir = if action.ia32 {
        volatile.join("uefi32")
    } else {
        volatile.join("uefi64")
    };

    let qemu = Qemu::new(&disk, &ovmf_dir);
    qemu.run()?;
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
        Action::Test(_) => run_tests(&opt),
        Action::Qemu(action) => run_qemu(&opt, action),
    }?;
}
