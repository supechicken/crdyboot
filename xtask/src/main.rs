mod arch;
mod build_mode;
mod config;
mod gen_disk;
mod gen_keys;
mod package;
mod qemu;
mod shim;
mod sign;

use anyhow::{anyhow, Error};
use arch::Arch;
use argh::FromArgs;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use config::Config;
use fehler::throws;
use fs_err as fs;
use package::Package;
use qemu::{Display, Qemu, VarAccess};
use std::{env, process};

const NIGHTLY_TC: &str = "nightly-2022-02-06";

/// Get a toolchain arg for compiling with nightly Rust. This just
/// prepends a `+` to `NIGHTLY_TC`.
fn nightly_tc_arg() -> String {
    format!("+{}", NIGHTLY_TC)
}

/// Tools for crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
pub struct Opt {
    /// action to run
    #[argh(subcommand)]
    action: Action,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Action {
    Setup(SetupAction),
    Check(CheckAction),
    Format(FormatAction),
    Lint(LintAction),
    Test(TestAction),
    Build(BuildAction),
    PrepDisk(PrepDiskAction),
    UpdateDisk(UpdateDiskAction),
    Qemu(QemuAction),
    BuildEnroller(BuildEnrollerAction),
    Writedisk(WritediskAction),
    InstallToolchain(InstallToolchainAction),
}

/// Build crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build")]
struct BuildAction {}

/// Build enroller.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build-enroller")]
struct BuildEnrollerAction {}

/// Check formating, lint, test, and build.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "check")]
struct CheckAction {}

/// Run "cargo fmt" on all the code.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "fmt")]
struct FormatAction {
    /// don't format the code, just check if it's already formatted
    #[argh(switch)]
    check: bool,
}

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

/// Initialize the workspace.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "setup")]
struct SetupAction {
    /// path of the reven disk image to copy.
    #[argh(positional)]
    disk_image: Option<Utf8PathBuf>,
}

struct Miri(bool);

fn default_miri_usage() -> bool {
    true
}
/// Run "cargo test" in the vboot project.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "test")]
struct TestAction {
    /// enable or disable miri tests: true, false (default=true)
    #[argh(option, default="default_miri_usage()")]
    miri: bool,
}

impl Default for TestAction {
    fn default() -> Self {
        TestAction {
            miri: default_miri_usage(),
        }
    }
}

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

    /// type of qemu display to use none, gtk, sdl (default=sdl)
    #[argh(option, default = "Display::Sdl")]
    display: Display,
}

/// Write the disk binary to a USB with `writedisk`.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "writedisk")]
struct WritediskAction {}

/// Install the appropriate Rust nightly toolchain.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "install-toolchain")]
struct InstallToolchainAction {}

#[throws]
fn run_cargo_deny() {
    // Check if cargo-deny is installed, and install it if not.
    if Command::with_args("cargo", &["deny", "--version"])
        .enable_capture()
        .run()
        .is_err()
    {
        Command::with_args("cargo", &["install", "--locked", "cargo-deny"])
            .run()?;
    }

    // Run cargo-deny. This uses the config in `.deny.toml`.
    Command::with_args("cargo", &["deny", "check"]).run()?;
}

#[throws]
fn run_check(conf: &Config) {
    run_cargo_deny()?;
    run_rustfmt(&FormatAction { check: true })?;
    run_tests(&Default::default())?;
    run_crdyboot_build(conf)?;
    run_clippy(conf)?;
}

/// Add cargo features to a command. Does nothing if `features` is empty.
fn add_cargo_features_args(cmd: &mut Command, features: &[&str]) {
    if !features.is_empty() {
        cmd.add_args(&["--features", &features.join(",")]);
    }
}

#[throws]
fn run_uefi_build(conf: &Config, package: Package) {
    let features = conf.get_package_features(package);
    let build_mode = conf.build_mode();

    for target in Arch::all_targets() {
        let mut cmd = Command::with_args(
            "cargo",
            &[
                &nightly_tc_arg(),
                "build",
                "--package",
                package.name(),
                "-Zbuild-std=core,compiler_builtins,alloc",
                "-Zbuild-std-features=compiler-builtins-mem",
                "--target",
                target,
            ],
        );
        add_cargo_features_args(&mut cmd, &features);
        cmd.add_args(build_mode.cargo_args());
        cmd.run()?;
    }
}

#[throws]
fn run_crdyboot_build(conf: &Config) {
    run_uefi_build(conf, Package::Crdyboot)?;
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
fn run_build_enroller(conf: &Config) {
    run_uefi_build(conf, Package::Enroller)?;

    gen_disk::gen_enroller_disk(conf)?;
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
fn run_rustfmt(action: &FormatAction) {
    let mut cmd = Command::with_args("cargo", &["fmt", "--all"]);
    if action.check {
        cmd.add_args(&["--", "--check"]);
    }
    cmd.run()?;
}

#[throws]
fn run_prep_disk(conf: &Config) {
    shim::update_shim(conf)?;

    // Sign both kernel partitions.
    gen_disk::sign_kernel_partition(conf, "KERN-A")?;
    gen_disk::sign_kernel_partition(conf, "KERN-B")?;
}

#[throws]
fn run_clippy(conf: &Config) {
    for package in Package::all() {
        let mut cmd = Command::with_args(
            "cargo",
            &[&nightly_tc_arg(), "clippy", "--package", package.name()],
        );
        add_cargo_features_args(&mut cmd, &conf.get_package_features(package));
        cmd.run()?;
    }
}

#[throws]
fn run_tests_for_package(package: Package, miri: Miri) {
    let mut cmd = Command::with_args("cargo", &[nightly_tc_arg()]);
    if miri.0 {
        cmd.add_arg("miri");
    }
    cmd.add_args(&["test", "--package", package.name()]);
    cmd.run()?;
}

#[throws]
fn run_tests(action: &TestAction) {
    run_tests_for_package(Package::Xtask, Miri(false))?;
    run_tests_for_package(Package::Vboot, Miri(false))?;
    run_tests_for_package(Package::Libcrdy, Miri(false))?;

    if action.miri {
        run_tests_for_package(Package::Vboot, Miri(true))?;
        run_tests_for_package(Package::Libcrdy, Miri(true))?;
    }
}

#[throws]
fn generate_secure_boot_keys(conf: &Config) {
    sign::generate_key(
        &conf.secure_boot_root_key_paths(),
        "SecureBootRootTestKey",
    )?;
    sign::generate_key(
        &conf.secure_boot_shim_key_paths(),
        "SecureBootShimTestKey",
    )?;

    let root_key_paths = conf.secure_boot_root_key_paths();
    // Generate the PK/KEK and db vars for use with the enroller.
    sign::generate_signed_vars(&root_key_paths, "PK")?;
    sign::generate_signed_vars(&root_key_paths, "db")?;
}

#[throws]
fn init_submodules(conf: &Config) {
    Command::with_args(
        "git",
        &[
            "-C",
            conf.repo_path().as_str(),
            "submodule",
            "update",
            "--init",
        ],
    )
    .run()?;
}

/// Run the enroller in a VM to set up UEFI variables for secure boot.
#[throws]
fn enroll_secure_boot_keys(conf: &Config) {
    for arch in Arch::all() {
        let ovmf = conf.ovmf_paths(arch);

        // Copy the system OVMF files to a local directory.
        // TODO: move these hardcoded paths to the config.
        let system_ovmf_dir = Utf8Path::new("/usr/share/OVMF/");
        let (system_code, system_vars) = match arch {
            Arch::Ia32 => ("OVMF32_CODE_4M.secboot.fd", "OVMF32_VARS_4M.fd"),
            Arch::X64 => ("OVMF_CODE_4M.secboot.fd", "OVMF_VARS_4M.fd"),
        };
        copy_file(system_ovmf_dir.join(system_code), ovmf.code())?;
        copy_file(system_ovmf_dir.join(system_vars), ovmf.original_vars())?;

        // Keep a copy of the original vars for running QEMU in
        // non-secure-boot mode.
        copy_file(ovmf.original_vars(), ovmf.secure_boot_vars())?;

        // Run the enroller in QEMU to set up secure boot UEFI variables.
        let qemu = Qemu::new(ovmf);
        qemu.run_disk_image(
            &conf.enroller_disk_path(),
            VarAccess::ReadWrite,
            Display::None,
        )?;
    }
}

/// Fix build errors caused by a vboot upgrade.
#[throws]
fn clean_futility_build(conf: &Config) {
    Command::with_args(
        "make",
        &["-C", conf.vboot_reference_path().as_str(), "clean"],
    )
    .run()?;
}

/// Build futility, the firmware utility executable that is part of
/// vboot_reference.
#[throws]
fn build_futility(conf: &Config) {
    let mut cmd = Command::with_args(
        "make",
        &[
            "-C",
            conf.vboot_reference_path().as_str(),
            conf.futility_executable_path().as_str(),
        ],
    );
    // For compatiblity with openssl3, allow use of deprecated
    // functions.
    cmd.env
        .insert("CFLAGS".into(), "-Wno-deprecated-declarations".into());
    cmd.run()?;
}

// Run various setup operations. This must be run once before running
// any other xtask commands.
#[throws]
fn run_setup(conf: &Config, action: &SetupAction) {
    init_submodules(conf)?;

    if let Some(disk_image) = &action.disk_image {
        copy_file(disk_image, conf.disk_path())?;
    }

    if !conf.disk_path().exists() {
        println!("A disk image is needed to continue. Rerun this command");
        println!("with the path of a reven disk image, which will be copied");
        println!("to a local path.");
        process::exit(1);
    }

    build_futility(conf)?;

    gen_keys::generate_test_keys(conf)?;

    generate_secure_boot_keys(conf)?;
    run_build_enroller(conf)?;
    enroll_secure_boot_keys(conf)?;

    // Build and install shim, and sign the kernel partitions with a
    // local key.
    run_prep_disk(conf)?;

    // Generate a disk image used by the `test_load_kernel` vboot test.
    gen_disk::gen_vboot_test_disk(conf)?;
}

#[throws]
fn run_qemu(conf: &Config, action: &QemuAction) {
    let disk = conf.disk_path();

    let ovmf = if action.ia32 {
        conf.ovmf_paths(Arch::Ia32)
    } else {
        conf.ovmf_paths(Arch::X64)
    };

    let mut qemu = Qemu::new(ovmf);
    qemu.secure_boot = action.secure_boot;
    qemu.run_disk_image(disk, VarAccess::ReadOnly, action.display)?;
}

#[throws]
fn run_writedisk(conf: &Config) {
    Command::with_args("writedisk", &[conf.disk_path()]).run()?;
}

#[throws]
fn run_install_toolchain() {
    Command::with_args("rustup", &["install", NIGHTLY_TC]).run()?;
    Command::with_args(
        "rustup",
        &["component", "add", "rust-src", "miri", "--toolchain", NIGHTLY_TC],
    )
    .run()?;
}

#[throws]
fn rerun_setup_if_needed(action: &Action, conf: &Config) {
    // Bump this version any time the setup step needs to be re-run.
    let current_version = 2;

    // Don't run setup if the user is already doing it.
    if matches!(action, Action::Setup(_)) {
        return;
    }

    // Don't run setup if the user is installing the toolchain.
    if matches!(action, Action::InstallToolchain(_)) {
        return;
    }

    // Don't try to run setup if the workspace doesn't exist yet.
    if !conf.workspace_path().exists() {
        return;
    }

    // Nothing to do if the version is already high enough.
    let existing_version = conf.read_setup_version();
    if existing_version >= current_version {
        return;
    }

    println!(
        "Re-running setup: upgrading from {} to {}",
        existing_version, current_version
    );

    // Put any version-specific cleanup operations here.

    if conf.read_setup_version() < 2 {
        clean_futility_build(conf)?;
    }

    // End version-specific cleanup operations.

    run_setup(conf, &SetupAction { disk_image: None })?;
    conf.write_setup_version(current_version)?;
}

/// Get the repo root path. This assumes this executable is located at
/// <repo>/target/<buildmode>/<exe>.
#[throws]
fn get_repo_path() -> Utf8PathBuf {
    let exe_path = env::current_exe()?;
    let repo_path = exe_path
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .ok_or_else(|| anyhow!("repo path: not enough parents"))?;
    Utf8Path::from_path(repo_path)
        .ok_or_else(|| anyhow!("repo path: not utf-8"))?
        .to_path_buf()
}

#[throws]
fn main() {
    let opt: Opt = argh::from_env();
    let repo_root = get_repo_path()?;

    // Create the config file from the default if it doesn't already exist.
    let conf_path = config::config_path(&repo_root);
    let default_conf_path = repo_root.join("xtask/default.toml");
    if !conf_path.exists() {
        copy_file(&default_conf_path, &conf_path)?;
    }
    let conf = Config::load(&repo_root)?;

    // Re-run setup if something has changed that requires it.
    rerun_setup_if_needed(&opt.action, &conf)?;

    match &opt.action {
        Action::Build(_) => run_crdyboot_build(&conf),
        Action::BuildEnroller(_) => run_build_enroller(&conf),
        Action::Check(_) => run_check(&conf),
        Action::Format(action) => run_rustfmt(action),
        Action::UpdateDisk(_) => gen_disk::copy_in_crdyboot(&conf),
        Action::Lint(_) => run_clippy(&conf),
        Action::PrepDisk(_) => run_prep_disk(&conf),
        Action::Setup(action) => run_setup(&conf, action),
        Action::Test(action) => run_tests(action),
        Action::Qemu(action) => run_qemu(&conf, action),
        Action::Writedisk(_) => run_writedisk(&conf),
        Action::InstallToolchain(_) => run_install_toolchain(),
    }?;
}
