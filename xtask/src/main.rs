// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod arch;
mod config;
mod gen_disk;
mod package;
mod qemu;
mod secure_boot;
mod setup;
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
use sha2::{Digest, Sha256};
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
    Qemu(QemuAction),
    BuildEnroller(BuildEnrollerAction),
    Writedisk(WritediskAction),
    GenTestDataTarball(GenTestDataTarballAction),
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

/// Generate a tarball of test data for upload to GS.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "gen-test-data-tarball")]
struct GenTestDataTarballAction {}

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

/// Ensure that the NX-compat bit is set in all executables.
fn ensure_nx_compat(conf: &Config) -> Result<()> {
    for arch in Arch::all() {
        for exe in EfiExe::all() {
            let bin_data = fs::read(conf.target_exec_path(arch, *exe))?;
            match arch {
                Arch::Ia32 => ensure_nx_compat_impl::<ImageNtHeaders32>(&bin_data)?,
                Arch::X64 => ensure_nx_compat_impl::<ImageNtHeaders64>(&bin_data)?,
            }
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

fn run_clippy() -> Result<()> {
    // Use a UEFI target for everything but xtask. This gives slightly
    // better coverage (for example, third_party/malloc.rs is not
    // included on the host target), and is required in newer versions
    // of uefi-rs due to `eh_personality` no longer being set.
    Command::with_args(
        "cargo",
        [
            "clippy",
            "--workspace",
            "--exclude",
            Package::Xtask.name(),
            // Arbitrarily choose the 64-bit UEFI target.
            "--target",
            Arch::X64.uefi_target(),
        ],
    )
    .run()?;

    // Use the default host target for xtask since it requires `std`.
    Command::with_args("cargo", ["clippy", "--package", Package::Xtask.name()]).run()?;

    Ok(())
}

fn run_tests(conf: &Config, action: &TestAction) -> Result<()> {
    Command::new("cargo").add_arg("test").run()?;

    if !action.no_miri {
        Command::new("cargo").add_args(["miri", "test"]).run()?;
    }

    if action.vm_tests {
        vm_test::run_vm_tests(conf)?;
    }

    Ok(())
}

/// Generate a tarball in the current directory named
/// `crdyboot_test_data_<hash>.tar.xz`, where `<hash>` is a truncated
/// sha256 hash of the tarball.
///
/// The file is not uploaded by this action since new files should be
/// tested before upload.
///
/// Once the file is tested, upload it to
/// `gs://chromeos-localmirror/distfiles/` as described here:
/// https://chromium.googlesource.com/chromiumos/docs/+/HEAD/archive_mirrors.md
fn gen_test_data_tarball(conf: &Config) -> Result<()> {
    gen_disk::gen_vboot_test_disk(conf)?;

    let tmp_dir = TempDir::new()?;
    let tmp_dir = Utf8Path::from_path(tmp_dir.path()).unwrap();

    let data_dir_name = "crdyboot_test_data";
    let data_dir = tmp_dir.join(data_dir_name);

    let orig_tarball_name = "tmp.tar.xz";
    let orig_tarball_path = tmp_dir.join(orig_tarball_name);

    // Create and fill the directory that will be in the tarball.
    fs::create_dir(&data_dir)?;
    fs::copy(
        conf.vboot_test_disk_path(),
        data_dir.join("vboot_test_disk.bin"),
    )?;

    // Create the tarball.
    Command::with_args(
        "tar",
        [
            // Set an arbitrary but consistent time to make the output
            // reproducible.
            "--mtime=UTC 2020-01-01",
            "-C",
            tmp_dir.as_str(),
            "-cJf",
            orig_tarball_path.as_str(),
            data_dir_name,
        ],
    )
    .run()?;

    // Get the sha256 hash of the tarball.
    let digest = Sha256::digest(fs::read(&orig_tarball_path)?);
    let digest = format!("{digest:x}");

    // Rename the tarball to include the abbreviated hash and place it
    // in the current directory.
    let new_tarball_path = format!("{data_dir_name}_{}.tar.xz", &digest[..8]);
    fs::copy(orig_tarball_path, &new_tarball_path)?;

    println!("created {new_tarball_path}");

    Ok(())
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
    setup::rerun_setup_if_needed(&opt.action, &conf)?;

    match &opt.action {
        Action::Build(action) => run_crdyboot_build(&conf, action.verbose()),
        Action::BuildEnroller(_) => run_build_enroller(&conf),
        Action::Check(action) => run_check(&conf, action),
        Action::Format(action) => run_rustfmt(action),
        Action::Lint(_) => run_clippy(),
        Action::Setup(action) => setup::run_setup(&conf, action),
        Action::Test(action) => run_tests(&conf, action),
        Action::Qemu(action) => run_qemu(&conf, action),
        Action::Writedisk(_) => run_writedisk(&conf),
        Action::GenTestDataTarball(_) => gen_test_data_tarball(&conf),
        Action::GenVbootReturnCodeStrings(_) => vboot::gen_return_code_strings(&conf),
    }
}
