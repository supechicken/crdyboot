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
mod vm_test;

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
use tempfile::TempDir;

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

    /// disable miri tests
    #[argh(switch)]
    no_miri: bool,

    /// enable slow VM tests
    #[argh(switch)]
    vm_tests: bool,
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
#[derive(FromArgs, PartialEq, Debug, Default)]
#[argh(subcommand, name = "setup")]
struct SetupAction {
    /// path of the reven disk image to copy.
    #[argh(positional)]
    disk_image: Option<Utf8PathBuf>,

    /// OVMF 64-bit code file.
    #[argh(option)]
    ovmf64_code: Option<Utf8PathBuf>,

    /// OVMF 64-bit vars file.
    #[argh(option)]
    ovmf64_vars: Option<Utf8PathBuf>,

    /// OVMF 32-bit code file.
    #[argh(option)]
    ovmf32_code: Option<Utf8PathBuf>,

    /// OVMF 32-bit vars file.
    #[argh(option)]
    ovmf32_vars: Option<Utf8PathBuf>,
}

struct Miri(bool);

/// Run tests.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "test")]
struct TestAction {
    /// disable miri tests
    #[argh(switch)]
    no_miri: bool,

    /// enable slow VM tests
    #[argh(switch)]
    vm_tests: bool,
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

fn run_check(conf: &Config, action: &CheckAction) -> Result<()> {
    run_cargo_deny()?;
    run_rustfmt(&FormatAction { check: true })?;
    run_clippy()?;
    run_tests(
        conf,
        &TestAction {
            no_miri: action.no_miri,
            vm_tests: action.vm_tests,
        },
    )?;
    run_crdyboot_build(conf, action.verbose())?;

    Ok(())
}

fn run_uefi_build(package: Package, features: Vec<&str>) -> Result<()> {
    for target in Arch::all_targets() {
        let mut cmd = Command::with_args(
            "cargo",
            [
                "build",
                "--release",
                "--package",
                package.name(),
                "--target",
                target,
            ],
        );
        if !features.is_empty() {
            cmd.add_arg("--features");
            cmd.add_arg(features.join(","));
        }
        cmd.run()?;
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
    run_uefi_build(Package::Crdyboot, vec![])?;

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
    let features = if conf.workspace_path().join("shim_verbose").exists() {
        vec!["shim_verbose"]
    } else {
        vec![]
    };

    run_uefi_build(Package::Enroller, features)?;

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

fn run_tests(conf: &Config, action: &TestAction) -> Result<()> {
    run_tests_for_package(Package::Xtask, Miri(false))?;
    run_tests_for_package(Package::Vboot, Miri(false))?;
    run_tests_for_package(Package::Libcrdy, Miri(false))?;

    if !action.no_miri {
        run_tests_for_package(Package::Vboot, Miri(true))?;
        run_tests_for_package(Package::Libcrdy, Miri(true))?;
    }

    if action.vm_tests {
        vm_test::run_vm_tests(conf)?;
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
fn enroll_secure_boot_keys(conf: &Config, action: &SetupAction) -> Result<()> {
    for arch in Arch::all() {
        let ovmf = conf.ovmf_paths(arch);

        // Get the system path of the OVMF files installed via apt.
        let system_ovmf_dir = Utf8Path::new("/usr/share/OVMF/");
        let (system_code, system_vars) = match arch {
            Arch::Ia32 => ("OVMF32_CODE_4M.secboot.fd", "OVMF32_VARS_4M.fd"),
            Arch::X64 => ("OVMF_CODE_4M.secboot.fd", "OVMF_VARS_4M.fd"),
        };
        let system_code = system_ovmf_dir.join(system_code);
        let system_vars = system_ovmf_dir.join(system_vars);

        let (args_code, args_vars) = match arch {
            Arch::Ia32 => (action.ovmf32_code.as_ref(), action.ovmf32_vars.as_ref()),
            Arch::X64 => (action.ovmf64_code.as_ref(), action.ovmf64_vars.as_ref()),
        };

        // Copy the OVMF files to a local directory.
        let src_code_path = args_code.unwrap_or(&system_code);
        let src_vars_path = args_vars.unwrap_or(&system_vars);
        copy_file(src_code_path, ovmf.code())?;
        copy_file(src_vars_path, ovmf.original_vars())?;

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
            snapshot: false,
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
    let cflags = [
        // For compatiblity with openssl3, allow use of deprecated
        // functions.
        "-Wno-deprecated-declarations",
        // Disable this error to match the default chromeos build
        // flags. See b/231987783.
        "-Wno-int-conversion",
    ];

    cmd.env.insert("CFLAGS".into(), cflags.join(" ").into());
    cmd.run()?;

    Ok(())
}

fn download_latest_reven(conf: &Config) -> Result<()> {
    let gsutil = "gsutil";
    let bucket = "chromeos-image-archive";
    let board_dir = "reven-release";

    // Find the latest version using the LATEST-main file, which
    // contains a string like "R114-15410.0.0".
    let latest_main_path = format!("gs://{bucket}/{board_dir}/LATEST-main");
    let output = Command::with_args(gsutil, ["cat", &latest_main_path])
        .enable_capture()
        .run()?;
    let latest_version = String::from_utf8(output.stdout)?;

    // Download the compressed test image to a temporary directory.
    let tmp_dir = TempDir::new()?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();
    let compressed_name = "chromiumos_test_image.tar.xz";
    let download_path = tmp_path.join(compressed_name);
    let test_image_path = format!("gs://{bucket}/{board_dir}/{latest_version}/{compressed_name}");
    Command::with_args(gsutil, ["cp", &test_image_path, download_path.as_str()]).run()?;

    // Extract the image.
    Command::with_args(
        "tar",
        [
            "xf",
            download_path.as_str(),
            // Change directory to the temporary directory.
            "-C",
            tmp_path.as_str(),
        ],
    )
    .run()?;

    // Move the image to the workspace.
    Command::with_args(
        "mv",
        [
            &tmp_path.join("chromiumos_test_image.bin"),
            conf.disk_path(),
        ],
    )
    .run()?;

    Ok(())
}

// Run various setup operations. This must be run once before running
// any other xtask commands.
fn run_setup(conf: &Config, action: &SetupAction) -> Result<()> {
    init_submodules(conf)?;

    // If the user has provided their own disk image on the command
    // line, use that.
    if let Some(disk_image) = &action.disk_image {
        copy_file(disk_image, conf.disk_path())?;
    }

    // If we don't have a disk image, download one from GS.
    if !conf.disk_path().exists() {
        download_latest_reven(conf)?;
    }

    build_futility(conf)?;

    generate_secure_boot_keys(conf)?;
    run_build_enroller(conf)?;
    enroll_secure_boot_keys(conf, action)?;

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
        snapshot: true,
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
    let current_version = 6;

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

    run_setup(conf, &SetupAction::default())?;
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
        Action::Check(action) => run_check(&conf, action),
        Action::Format(action) => run_rustfmt(action),
        Action::Lint(_) => run_clippy(),
        Action::PrepDisk(_) => run_prep_disk(&conf),
        Action::Setup(action) => run_setup(&conf, action),
        Action::Test(action) => run_tests(&conf, action),
        Action::Qemu(action) => run_qemu(&conf, action),
        Action::Writedisk(_) => run_writedisk(&conf),
        Action::GenVbootReturnCodeStrings(_) => vboot::gen_return_code_strings(&conf),
    }
}
