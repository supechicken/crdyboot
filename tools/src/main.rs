mod arch;
mod build_mode;
mod gen_disk;
mod loopback;
mod mount;
mod ovmf;
mod qemu;
mod shim;
mod sign;

use anyhow::Error;
use arch::Arch;
use argh::FromArgs;
use build_mode::BuildMode;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fehler::throws;
use fs_err as fs;
use loopback::LoopbackDevice;
use qemu::{OvmfPaths, Qemu};
use sign::KeyPaths;
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

    fn enroller_path(&self) -> Utf8PathBuf {
        self.repo.join("enroller")
    }

    fn workspace_path(&self) -> Utf8PathBuf {
        self.repo.join("workspace")
    }

    fn tools_path(&self) -> Utf8PathBuf {
        self.repo.join("tools")
    }

    fn vboot_path(&self) -> Utf8PathBuf {
        self.repo.join("vboot")
    }

    fn project_paths(&self) -> Vec<Utf8PathBuf> {
        vec![
            self.crdyboot_path(),
            self.enroller_path(),
            self.tools_path(),
            self.vboot_path(),
        ]
    }

    fn vboot_reference_path(&self) -> Utf8PathBuf {
        self.repo.join("third_party/vboot_reference")
    }

    fn futility_executable_path(&self) -> Utf8PathBuf {
        self.vboot_reference_path().join("build/futility/futility")
    }

    fn disk_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("disk.bin")
    }

    fn enroller_disk_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("enroller.bin")
    }

    fn vboot_test_disk_path(&self) -> Utf8PathBuf {
        self.repo.join("vboot/test_data/disk.bin")
    }

    fn ovmf_paths(&self, arch: Arch) -> OvmfPaths {
        let subdir = match arch {
            Arch::Ia32 => "uefi32",
            Arch::X64 => "uefi64",
        };
        OvmfPaths::new(self.workspace_path().join(subdir))
    }

    /// This cert will be enrolled as the PK, first KEK, and first DB
    /// entry. The private key is used to sign shim.
    fn secure_boot_root_key_paths(&self) -> KeyPaths {
        KeyPaths::new(self.workspace_path().join("secure_boot_root_key"))
    }

    /// This cert is embedded in shim and the private key is used to
    /// sign crdyboot.
    fn secure_boot_shim_key_paths(&self) -> KeyPaths {
        KeyPaths::new(self.workspace_path().join("secure_boot_shim_key"))
    }

    fn shim_build_path(&self) -> Utf8PathBuf {
        self.workspace_path().join("shim_build")
    }

    fn build_mode(&self) -> BuildMode {
        BuildMode::Release
    }
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Action {
    Check(CheckAction),
    Clean(CleanAction),
    Format(FormatAction),
    Lint(LintAction),
    Test(TestAction),
    Build(BuildAction),
    PrepDisk(PrepDiskAction),
    UpdateDisk(UpdateDiskAction),
    BuildOvmf(BuildOvmfAction),
    SecureBootSetup(SecureBootSetupAction),
    Qemu(QemuAction),
    BuildEnroller(BuildEnrollerAction),
    BuildVbootTestDisk(BuildVbootTestDiskAction),
}

/// Build crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build")]
struct BuildAction {
    /// build crdyboot with the "verbose" feature
    #[argh(switch)]
    enable_verbose_feature: bool,
}

/// Build enroller.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build-enroller")]
struct BuildEnrollerAction {}

/// Build OVMF.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build-ovmf")]
struct BuildOvmfAction {}

/// Build vboot test disk.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build-vboot-test-disk")]
struct BuildVbootTestDiskAction {}

/// Format, lint, test, and build.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "check")]
struct CheckAction {
    /// build crdyboot with the "verbose" feature
    #[argh(switch)]
    enable_verbose_feature: bool,
}

/// Clean out all the target directories.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "clean")]
struct CleanAction {}

/// Run "cargo fmt" on all the code.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "fmt")]
struct FormatAction {}

/// Modify an existing CloudReady build to insert crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "update-disk")]
struct UpdateDiskAction {}

/// Run "cargo clippy" on all the code.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "lint")]
struct LintAction {}

/// Sign shim and the kernel partitions.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prep-disk")]
struct PrepDiskAction {}

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

    /// enable secure boot
    #[argh(switch)]
    secure_boot: bool,
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
fn run_check(opt: &Opt, action: &CheckAction) {
    run_rustfmt(opt)?;
    run_clippy(opt)?;
    run_tests(opt)?;
    run_crdyboot_build(
        opt,
        &BuildAction {
            enable_verbose_feature: action.enable_verbose_feature,
        },
    )?;
}

#[throws]
fn run_clean(opt: &Opt) {
    for project in opt.project_paths() {
        println!("{}:", project);
        let mut cmd = Command::with_args("cargo", &["clean"]);
        modify_cmd_for_path_prefix(&mut cmd, &project);
        cmd.set_dir(&project);
        cmd.run()?;
    }
}

#[throws]
fn run_uefi_build(
    project_dir: &Utf8Path,
    build_mode: BuildMode,
    features: &[&str],
) {
    for target in Arch::all_targets() {
        let mut cmd = Command::with_args(
            "cargo",
            &[
                "+nightly",
                "build",
                "-Zbuild-std=core,compiler_builtins,alloc",
                "-Zbuild-std-features=compiler-builtins-mem",
                "--target",
                target,
            ],
        );
        if !features.is_empty() {
            cmd.add_args(&["--features", &features.join(",")]);
        }
        cmd.add_args(build_mode.cargo_args());
        modify_cmd_for_path_prefix(&mut cmd, project_dir);
        cmd.set_dir(project_dir);
        cmd.run()?;
    }
}

#[throws]
fn run_crdyboot_build(opt: &Opt, action: &BuildAction) {
    let mut features = Vec::new();
    if action.enable_verbose_feature {
        features.push("verbose");
    }
    run_uefi_build(&opt.crdyboot_path(), opt.build_mode(), &features)?;
}

#[throws]
pub fn update_local_repo(path: &Utf8Path, url: &str, rev: &str) {
    // Clone repo if not already cloned, otherwise just fetch.
    if path.exists() {
        Command::with_args("git", &["-C", path.as_str(), "fetch"]).run()?;
    } else {
        Command::with_args("git", &["clone", url, path.as_str()]).run()?;
    }

    // Check out a known-working commit.
    Command::with_args("git", &["-C", path.as_str(), "checkout", rev]).run()?;

    // Init/update submodules.
    Command::with_args(
        "git",
        &["-C", path.as_str(), "submodule", "update", "--init"],
    )
    .run()?;
}

#[throws]
fn run_build_enroller(opt: &Opt) {
    run_uefi_build(&opt.enroller_path(), opt.build_mode(), &[])?;

    gen_disk::gen_enroller_disk(opt)?;
}

#[throws]
fn copy_file<S, D>(src: S, dst: D)
where
    S: AsRef<Utf8Path>,
    D: AsRef<Utf8Path>,
{
    let src = src.as_ref();
    let dst = dst.as_ref();
    println!("copy {} to {}", src, dst);
    fs::copy(src, dst)?;
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
fn run_prep_disk(opt: &Opt) {
    let disk = opt.disk_path();

    let lo_dev = LoopbackDevice::new(&disk)?;
    let partitions = lo_dev.partition_paths();

    shim::update_shim(opt, &partitions)?;

    // Sign both kernel partitions.
    gen_disk::sign_kernel_partition(opt, &partitions.kern_a)?;
    gen_disk::sign_kernel_partition(opt, &partitions.kern_b)?;
}

#[throws]
fn run_update_disk(opt: &Opt) {
    let disk = opt.disk_path();

    let lo_dev = LoopbackDevice::new(&disk)?;
    let partitions = lo_dev.partition_paths();

    gen_disk::copy_in_crdyboot(opt, &partitions)?;
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
    let mut cmd = Command::with_args("cargo", &["+nightly", "test"]);
    modify_cmd_for_path_prefix(&mut cmd, &vboot_dir);
    cmd.set_dir(&vboot_dir);
    cmd.run()?;
}

#[throws]
fn generate_secure_boot_keys(opt: &Opt) {
    sign::generate_key(
        &opt.secure_boot_root_key_paths(),
        "SecureBootRootTestKey",
    )?;
    sign::generate_key(
        &opt.secure_boot_shim_key_paths(),
        "SecureBootShimTestKey",
    )?;

    let root_key_paths = opt.secure_boot_root_key_paths();

    // Generate the PK/KEK and db vars for use with the non-VM enroller.
    sign::generate_signed_vars(&root_key_paths, "PK")?;
    sign::generate_signed_vars(&root_key_paths, "db")?;

    // Generate the oemstr for use wit the VM enroller.

    let der = fs::read(root_key_paths.pub_der())?;

    // Defined in edk2/OvmfPkg/Include/Guid/OvmfPkKek1AppPrefix.h
    let uuid = "4e32566d-8e9e-4f52-81d3-5bb9715f9727";

    let oemstr = format!("{}:{}", uuid, base64::encode(der));

    fs::write(root_key_paths.enroll_data(), oemstr)?;
}

#[throws]
fn run_secure_boot_setup(opt: &Opt, action: &SecureBootSetupAction) {
    let po = if action.verbose {
        qemu::PrintOutput::Yes
    } else {
        qemu::PrintOutput::No
    };

    for arch in Arch::all() {
        let ovmf = opt.ovmf_paths(arch);

        copy_file(ovmf.original_vars(), ovmf.secure_boot_vars())?;

        let qemu = Qemu::new(ovmf);
        let oemstr_path = opt.secure_boot_root_key_paths().enroll_data();
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

    let mut qemu = Qemu::new(ovmf);
    qemu.secure_boot = action.secure_boot;
    qemu.run_disk_image(&disk)?;
}

#[throws]
fn initial_setup(opt: &Opt) {
    Command::with_args(
        "git",
        &["-C", opt.repo.as_str(), "submodule", "update", "--init"],
    )
    .run()?;

    generate_secure_boot_keys(opt)?;
}

#[throws]
fn main() {
    let opt: Opt = argh::from_env();

    initial_setup(&opt)?;

    match &opt.action {
        Action::Build(action) => run_crdyboot_build(&opt, action),
        Action::BuildEnroller(_) => run_build_enroller(&opt),
        Action::BuildOvmf(_) => ovmf::run_build_ovmf(&opt),
        Action::BuildVbootTestDisk(_) => gen_disk::gen_vboot_test_disk(&opt),
        Action::Check(action) => run_check(&opt, action),
        Action::Clean(_) => run_clean(&opt),
        Action::Format(_) => run_rustfmt(&opt),
        Action::UpdateDisk(_) => run_update_disk(&opt),
        Action::Lint(_) => run_clippy(&opt),
        Action::PrepDisk(_) => run_prep_disk(&opt),
        Action::SecureBootSetup(action) => run_secure_boot_setup(&opt, action),
        Action::Test(_) => run_tests(&opt),
        Action::Qemu(action) => run_qemu(&opt, action),
    }?;
}
