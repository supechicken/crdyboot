// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod arch;
mod config;
mod gen_disk;
mod package;
mod qemu;
mod secure_boot;
mod shim;
mod swtpm;
mod util;
mod vboot;

use anyhow::{anyhow, bail, Result};
use arch::Arch;
use argh::FromArgs;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use config::{Config, EfiExe};
use fs_err as fs;
use gen_disk::VerboseRuntimeLogs;
use object::pe::{ImageNtHeaders32, ImageNtHeaders64, IMAGE_DLLCHARACTERISTICS_NX_COMPAT};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use package::Package;
use qemu::{Display, QemuOpts};
use std::{env, process};
use swtpm::TpmVersion;

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
    Qemu(QemuAction),
    BuildEnroller(BuildEnrollerAction),
    Writedisk(WritediskAction),
    GenVbootReturnCodeStrings(GenVbootReturnCodeStringsAction),
}

/// Build crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build")]
struct BuildAction {
    /// only log warnings and errors
    #[argh(switch)]
    disable_verbose_logs: bool,
}

impl BuildAction {
    fn verbose(&self) -> VerboseRuntimeLogs {
        VerboseRuntimeLogs(!self.disable_verbose_logs)
    }
}

/// Build enroller.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build-enroller")]
struct BuildEnrollerAction {}

/// Check formating, lint, test, and build.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "check")]
struct CheckAction {
    /// only log warnings and errors
    #[argh(switch)]
    disable_verbose_logs: bool,
}

impl CheckAction {
    fn verbose(&self) -> VerboseRuntimeLogs {
        VerboseRuntimeLogs(!self.disable_verbose_logs)
    }
}

/// Run "cargo fmt" on all the code.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "fmt")]
struct FormatAction {
    /// don't format the code, just check if it's already formatted
    #[argh(switch)]
    check: bool,
}

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

/// Run "cargo test" in the vboot project.
#[derive(FromArgs, PartialEq, Debug, Default)]
#[argh(subcommand, name = "test")]
struct TestAction {
    /// disable miri tests
    #[argh(switch)]
    no_miri: bool,
}

/// Run crdyboot under qemu.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "qemu")]
struct QemuAction {
    /// use 32-bit UEFI instead of 64-bit
    #[argh(switch)]
    ia32: bool,

    /// disable secure boot
    #[argh(switch)]
    no_secure_boot: bool,

    /// type of qemu display to use none, gtk, sdl (default=sdl)
    #[argh(option, default = "Display::Sdl")]
    display: Display,

    /// enable emulated TPM v1.2
    #[argh(switch)]
    tpm1: bool,

    /// enable emulated TPM v2.0
    #[argh(switch)]
    tpm2: bool,
}

impl QemuAction {
    fn tpm_version(&self) -> Option<TpmVersion> {
        match (self.tpm1, self.tpm2) {
            (true, true) => {
                // QEMU doesn't support connecting to multiple TPMs at
                // the same time.
                println!("cannot enable both --tpm1 and --tpm2 at the same time");
                process::exit(1);
            }
            (true, false) => Some(TpmVersion::V1),
            (false, true) => Some(TpmVersion::V2),
            (false, false) => None,
        }
    }
}

/// Write the disk binary to a USB with `writedisk`.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "writedisk")]
struct WritediskAction {}

/// Regenerate vboot/src/return_codes.rs.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "gen-vboot-return-code-strings")]
struct GenVbootReturnCodeStringsAction {}

fn run_cargo_deny() -> Result<()> {
    // Check if cargo-deny is installed, and install it if not.
    if Command::with_args("cargo", ["deny", "--version"])
        .enable_capture()
        .run()
        .is_err()
    {
        Command::with_args("cargo", ["install", "--locked", "cargo-deny"]).run()?;
    }

    // Run cargo-deny. This uses the config in `.deny.toml`.
    Command::with_args("cargo", ["deny", "check"]).run()?;

    Ok(())
}

fn run_check(conf: &Config, verbose: VerboseRuntimeLogs) -> Result<()> {
    run_cargo_deny()?;
    run_rustfmt(&FormatAction { check: true })?;
    run_tests(&Default::default())?;
    run_crdyboot_build(conf, verbose)?;
    run_clippy()
}

fn run_uefi_build(package: Package) -> Result<()> {
    for target in Arch::all_targets() {
        Command::with_args(
            "cargo",
            [
                "build",
                "--release",
                "--package",
                package.name(),
                "--target",
                target,
            ],
        )
        .run()?;
    }

    Ok(())
}

/// Ensure that the NX-compat bit is set in a crdyboot executable.
fn ensure_nx_compat_impl<Pe: ImageNtHeaders>(bin_data: &[u8]) -> Result<()> {
    let pe = PeFile::<Pe>::parse(bin_data)?;
    let characteristics = pe.nt_headers().optional_header().dll_characteristics();
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) == 0 {
        bail!("nx-compat is not set")
    }
    Ok(())
}

/// Ensure that the NX-compat bit is set in all crdyboot executables.
fn ensure_nx_compat(conf: &Config) -> Result<()> {
    for arch in Arch::all() {
        let bin_data = fs::read(conf.target_exec_path(arch, EfiExe::Crdyboot))?;
        match arch {
            Arch::Ia32 => ensure_nx_compat_impl::<ImageNtHeaders32>(&bin_data)?,
            Arch::X64 => ensure_nx_compat_impl::<ImageNtHeaders64>(&bin_data)?,
        }
    }
    Ok(())
}

fn run_crdyboot_build(conf: &Config, verbose: VerboseRuntimeLogs) -> Result<()> {
    run_uefi_build(Package::Crdyboot)?;

    // Ensure that the NX-compat bit is set in all crdyboot executables.
    ensure_nx_compat(conf)?;

    // Update the disk image with the new executable.
    gen_disk::copy_in_crdyboot(conf)?;

    // Add or remove the `crdyboot_verbose` file.
    gen_disk::update_verbose_boot_file(conf, verbose)
}

pub fn update_local_repo(path: &Utf8Path, url: &str, rev: &str) -> Result<()> {
    // Clone repo if not already cloned, otherwise just fetch.
    if path.exists() {
        Command::with_args("git", ["-C", path.as_str(), "fetch"]).run()?;
    } else {
        Command::with_args("git", ["clone", url, path.as_str()]).run()?;
    }

    // Check out a known-working commit.
    Command::with_args("git", ["-C", path.as_str(), "checkout", rev]).run()?;

    // Init/update submodules.
    Command::with_args(
        "git",
        ["-C", path.as_str(), "submodule", "update", "--init"],
    )
    .run()?;

    Ok(())
}

fn run_build_enroller(conf: &Config) -> Result<()> {
    run_uefi_build(Package::Enroller)?;

    gen_disk::gen_enroller_disk(conf)
}

fn copy_file<S, D>(src: S, dst: D) -> Result<()>
where
    S: AsRef<Utf8Path>,
    D: AsRef<Utf8Path>,
{
    let src = src.as_ref();
    let dst = dst.as_ref();
    println!("copy {src} to {dst}");
    fs::copy(src, dst)?;

    Ok(())
}

fn run_rustfmt(action: &FormatAction) -> Result<()> {
    let mut cmd = Command::with_args("cargo", ["fmt", "--all"]);
    if action.check {
        cmd.add_args(["--", "--check"]);
    }
    cmd.run()?;

    Ok(())
}

fn run_prep_disk(conf: &Config) -> Result<()> {
    shim::update_shim(conf)?;

    // Sign both kernel partitions.
    gen_disk::sign_kernel_partition(conf, "KERN-A")?;
    gen_disk::sign_kernel_partition(conf, "KERN-B")
}

fn run_clippy_for_package(package: Package) -> Result<()> {
    let mut cmd = Command::with_args("cargo", ["clippy", "--package", package.name()]);

    // Use a UEFI target for everything but xtask. This gives slightly
    // better coverage (for example, third_party/malloc.rs is not
    // included on the host target), and is required in newer versions
    // of uefi-rs due to `eh_personality` no longer being set.
    if package != Package::Xtask {
        cmd.add_args([
            "--target",
            // Arbitrarily choose the 64-bit target.
            Arch::X64.uefi_target(),
        ]);
    }
    cmd.run()?;

    Ok(())
}

fn run_clippy() -> Result<()> {
    for package in Package::all() {
        run_clippy_for_package(package)?;
    }

    Ok(())
}

fn run_tests_for_package(package: Package, miri: Miri) -> Result<()> {
    let mut cmd = Command::new("cargo");
    if miri.0 {
        cmd.add_arg("miri");
    }
    cmd.add_args(["test", "--package", package.name()]);
    cmd.run()?;

    Ok(())
}

fn run_tests(action: &TestAction) -> Result<()> {
    run_tests_for_package(Package::Xtask, Miri(false))?;
    run_tests_for_package(Package::Vboot, Miri(false))?;
    run_tests_for_package(Package::Libcrdy, Miri(false))?;

    if !action.no_miri {
        run_tests_for_package(Package::Vboot, Miri(true))?;
        run_tests_for_package(Package::Libcrdy, Miri(true))?;
    }

    Ok(())
}

fn generate_secure_boot_keys(conf: &Config) -> Result<()> {
    secure_boot::generate_key(&conf.secure_boot_root_key_paths(), "SecureBootRootTestKey")?;
    secure_boot::generate_key(&conf.secure_boot_shim_key_paths(), "SecureBootShimTestKey")?;

    let root_key_paths = conf.secure_boot_root_key_paths();
    // Generate the PK/KEK and db vars for use with the enroller.
    secure_boot::generate_signed_vars(&root_key_paths, "PK")?;
    secure_boot::generate_signed_vars(&root_key_paths, "db")
}

fn init_submodules(conf: &Config) -> Result<()> {
    Command::with_args(
        "git",
        [
            "-C",
            conf.repo_path().as_str(),
            "submodule",
            "update",
            "--init",
        ],
    )
    .run()?;

    Ok(())
}

/// Run the enroller in a VM to set up UEFI variables for secure boot.
fn enroll_secure_boot_keys(conf: &Config) -> Result<()> {
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
        let qemu = QemuOpts {
            capture_output: false,
            display: Display::None,
            image_path: conf.enroller_disk_path(),
            ovmf,
            secure_boot: true,
            timeout: None,
            tpm_version: None,
        };
        qemu.run_disk_image(conf)?;
    }

    Ok(())
}

/// Fix build errors caused by a vboot upgrade.
fn clean_futility_build(conf: &Config) -> Result<()> {
    Command::with_args(
        "make",
        ["-C", conf.vboot_reference_path().as_str(), "clean"],
    )
    .run()?;

    Ok(())
}

/// Build futility, the firmware utility executable that is part of
/// vboot_reference.
fn build_futility(conf: &Config) -> Result<()> {
    let mut cmd = Command::with_args(
        "make",
        [
            "-C",
            conf.vboot_reference_path().as_str(),
            "USE_FLASHROM=0",
            conf.futility_executable_path().as_str(),
        ],
    );
    // For compatiblity with openssl3, allow use of deprecated
    // functions.
    cmd.env
        .insert("CFLAGS".into(), "-Wno-deprecated-declarations".into());
    cmd.run()?;

    Ok(())
}

// Run various setup operations. This must be run once before running
// any other xtask commands.
fn run_setup(conf: &Config, action: &SetupAction) -> Result<()> {
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

    generate_secure_boot_keys(conf)?;
    run_build_enroller(conf)?;
    enroll_secure_boot_keys(conf)?;

    // Build and install shim, and sign the kernel partitions with a
    // local key.
    run_prep_disk(conf)?;

    // Generate a disk image used by the `test_load_kernel` vboot test.
    gen_disk::gen_vboot_test_disk(conf)
}

fn run_qemu(conf: &Config, action: &QemuAction) -> Result<()> {
    let ovmf = if action.ia32 {
        conf.ovmf_paths(Arch::Ia32)
    } else {
        conf.ovmf_paths(Arch::X64)
    };

    let qemu = QemuOpts {
        capture_output: false,
        display: action.display,
        image_path: conf.disk_path().to_path_buf(),
        ovmf,
        secure_boot: !action.no_secure_boot,
        timeout: None,
        tpm_version: action.tpm_version(),
    };
    qemu.run_disk_image(conf)
}

fn run_writedisk(conf: &Config) -> Result<()> {
    Command::with_args("writedisk", [conf.disk_path()]).run()?;
    Ok(())
}

fn rerun_setup_if_needed(action: &Action, conf: &Config) -> Result<()> {
    // Bump this version any time the setup step needs to be re-run.
    let current_version = 5;

    // Don't run setup if the user is already doing it.
    if matches!(action, Action::Setup(_)) {
        return Ok(());
    }

    // Don't try to run setup if the workspace doesn't exist yet.
    if !conf.workspace_path().exists() {
        return Ok(());
    }

    // Nothing to do if the version is already high enough.
    let existing_version = conf.read_setup_version();
    if existing_version >= current_version {
        return Ok(());
    }

    println!("Re-running setup: upgrading from {existing_version} to {current_version}");

    // Put any version-specific cleanup operations here.

    if conf.read_setup_version() < 4 {
        clean_futility_build(conf)?;
    }

    // End version-specific cleanup operations.

    run_setup(conf, &SetupAction { disk_image: None })?;
    conf.write_setup_version(current_version)
}

/// Get the repo root path. This assumes this executable is located at
/// <repo>/target/<buildmode>/<exe>.
fn get_repo_path() -> Result<Utf8PathBuf> {
    let exe_path = env::current_exe()?;
    let repo_path = exe_path
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .ok_or_else(|| anyhow!("repo path: not enough parents"))?;
    Ok(Utf8Path::from_path(repo_path)
        .ok_or_else(|| anyhow!("repo path: not utf-8"))?
        .to_path_buf())
}

fn main() -> Result<()> {
    let opt: Opt = argh::from_env();
    let repo_root = get_repo_path()?;

    let conf = Config::new(repo_root);

    // Re-run setup if something has changed that requires it.
    rerun_setup_if_needed(&opt.action, &conf)?;

    match &opt.action {
        Action::Build(action) => run_crdyboot_build(&conf, action.verbose()),
        Action::BuildEnroller(_) => run_build_enroller(&conf),
        Action::Check(action) => run_check(&conf, action.verbose()),
        Action::Format(action) => run_rustfmt(action),
        Action::Lint(_) => run_clippy(),
        Action::PrepDisk(_) => run_prep_disk(&conf),
        Action::Setup(action) => run_setup(&conf, action),
        Action::Test(action) => run_tests(action),
        Action::Qemu(action) => run_qemu(&conf, action),
        Action::Writedisk(_) => run_writedisk(&conf),
        Action::GenVbootReturnCodeStrings(_) => vboot::gen_return_code_strings(&conf),
    }
}
