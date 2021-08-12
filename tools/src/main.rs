mod arch;
mod build_mode;
mod config;
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
use config::Config;
use fehler::throws;
use fs_err as fs;
use loopback::LoopbackDevice;
use qemu::Qemu;

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
    Writedisk(WritediskAction),
}

/// Build crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build")]
struct BuildAction {}

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

/// Check formating, lint, test, and build.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "check")]
struct CheckAction {}

/// Clean out all the target directories.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "clean")]
struct CleanAction {}

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

/// Write the disk binary to a USB with `writedisk`.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "writedisk")]
struct WritediskAction {}

const RUSTFLAGS_ENV_VAR: &str = "RUSTFLAGS";

fn update_rustflags_path_prefix(project_dir: &Utf8Path) -> String {
    // TODO: update the variable rather than overwriting it. It's important
    // to avoid having multiple remap-path-prefixes though, that can cause
    // unwanted rebuilds of the tools project.
    format!("--remap-path-prefix=src={}/src", project_dir)
}

fn modify_cmd_for_path_prefix(cmd: &mut Command, project_dir: &Utf8Path) {
    cmd.env.insert(
        RUSTFLAGS_ENV_VAR.into(),
        update_rustflags_path_prefix(project_dir).into(),
    );
}

#[throws]
fn run_check(conf: &Config) {
    run_rustfmt(conf, &FormatAction { check: true })?;
    run_tests(conf)?;
    run_crdyboot_build(conf)?;
    run_clippy(conf)?;
}

#[throws]
fn run_clean(conf: &Config) {
    for project in conf.project_paths() {
        println!("{}:", project);
        let mut cmd = Command::with_args("cargo", &["clean"]);
        modify_cmd_for_path_prefix(&mut cmd, &project);
        cmd.set_dir(&project);
        cmd.run()?;
    }
}

/// Add cargo features to a command. Does nothing if `features` is empty.
fn add_cargo_features_args(cmd: &mut Command, features: &[&str]) {
    if !features.is_empty() {
        cmd.add_args(&["--features", &features.join(",")]);
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
        add_cargo_features_args(&mut cmd, features);
        cmd.add_args(build_mode.cargo_args());
        modify_cmd_for_path_prefix(&mut cmd, project_dir);
        cmd.set_dir(project_dir);
        cmd.run()?;
    }
}

#[throws]
fn run_crdyboot_build(conf: &Config) {
    run_uefi_build(
        &conf.crdyboot_path(),
        conf.build_mode(),
        &conf.get_crdyboot_features(),
    )?;
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
    generate_secure_boot_keys(conf)?;

    run_uefi_build(&conf.enroller_path(), conf.build_mode(), &[])?;

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
fn run_rustfmt(conf: &Config, action: &FormatAction) {
    for project in conf.project_paths() {
        let cargo_path = project.join("Cargo.toml");
        let mut cmd = Command::with_args(
            "cargo",
            &["fmt", "--manifest-path", cargo_path.as_str()],
        );
        if action.check {
            cmd.add_args(&["--", "--check"]);
        }
        cmd.run()?;
    }
}

#[throws]
fn run_prep_disk(conf: &Config) {
    generate_secure_boot_keys(conf)?;

    let disk = conf.disk_path();

    let lo_dev = LoopbackDevice::new(disk)?;
    let partitions = lo_dev.partition_paths();

    shim::update_shim(conf, &partitions)?;

    // Sign both kernel partitions.
    gen_disk::sign_kernel_partition(conf, &partitions.kern_a)?;
    gen_disk::sign_kernel_partition(conf, &partitions.kern_b)?;
}

#[throws]
fn run_update_disk(conf: &Config) {
    generate_secure_boot_keys(conf)?;

    let disk = conf.disk_path();

    let lo_dev = LoopbackDevice::new(disk)?;
    let partitions = lo_dev.partition_paths();

    gen_disk::copy_in_crdyboot(conf, &partitions)?;
}

#[throws]
fn run_clippy(conf: &Config) {
    for project in conf.project_paths() {
        println!("{}:", project);
        let mut cmd = Command::with_args("cargo", &["+nightly", "clippy"]);
        if project.ends_with("crdyboot") {
            add_cargo_features_args(&mut cmd, &conf.get_crdyboot_features());
        }
        modify_cmd_for_path_prefix(&mut cmd, &project);
        cmd.set_dir(&project);
        cmd.run()?;
    }
}

#[throws]
fn run_tests_in_dir(dir: &Utf8Path, nightly: bool) {
    let mut cmd = Command::new("cargo");
    if nightly {
        cmd.add_arg("+nightly");
    }
    cmd.add_arg("test");
    modify_cmd_for_path_prefix(&mut cmd, dir);
    cmd.set_dir(dir);
    cmd.run()?;
}

#[throws]
fn run_tests(conf: &Config) {
    run_tests_in_dir(&conf.tools_path(), /* nightly=*/ false)?;
    run_tests_in_dir(&conf.vboot_path(), /* nightly=*/ true)?;
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

    // Generate the PK/KEK and db vars for use with the non-VM enroller.
    sign::generate_signed_vars(&root_key_paths, "PK")?;
    sign::generate_signed_vars(&root_key_paths, "db")?;

    // Generate the oemstr for use with the VM enroller.

    let der = fs::read(root_key_paths.pub_der())?;

    // Defined in edk2/OvmfPkg/Include/Guid/OvmfPkKek1AppPrefix.h
    let uuid = "4e32566d-8e9e-4f52-81d3-5bb9715f9727";

    let oemstr = format!("{}:{}", uuid, base64::encode(der));

    fs::write(root_key_paths.enroll_data(), oemstr)?;
}

#[throws]
fn run_secure_boot_setup(conf: &Config, action: &SecureBootSetupAction) {
    generate_secure_boot_keys(conf)?;

    let po = if action.verbose {
        qemu::PrintOutput::Yes
    } else {
        qemu::PrintOutput::No
    };

    for arch in Arch::all() {
        let ovmf = conf.ovmf_paths(arch);

        copy_file(ovmf.original_vars(), ovmf.secure_boot_vars())?;

        let qemu = Qemu::new(ovmf);
        let oemstr_path = conf.secure_boot_root_key_paths().enroll_data();
        qemu.enroll(&oemstr_path, po)?;
    }
}

#[throws]
fn run_qemu(conf: &Config, action: &QemuAction) {
    generate_secure_boot_keys(conf)?;

    let disk = conf.disk_path();

    let ovmf = if action.ia32 {
        conf.ovmf_paths(Arch::Ia32)
    } else {
        conf.ovmf_paths(Arch::X64)
    };

    let mut qemu = Qemu::new(ovmf);
    qemu.secure_boot = action.secure_boot;
    qemu.run_disk_image(disk)?;
}

#[throws]
fn run_writedisk(conf: &Config) {
    Command::with_args("writedisk", &[conf.disk_path()]).run()?;
}

#[throws]
fn initial_setup(conf: &Config) {
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

#[throws]
fn main() {
    let opt: Opt = argh::from_env();
    let repo_root = &opt.repo;

    // Create the config file from the default if it doesn't already exist.
    let conf_path = config::config_path(repo_root);
    let default_conf_path = repo_root.join("tools/default.conf");
    if !conf_path.exists() {
        copy_file(&default_conf_path, &conf_path)?;
    }
    let conf = Config::load(repo_root)?;

    initial_setup(&conf)?;

    match &opt.action {
        Action::Build(_) => run_crdyboot_build(&conf),
        Action::BuildEnroller(_) => run_build_enroller(&conf),
        Action::BuildOvmf(_) => ovmf::run_build_ovmf(&conf),
        Action::BuildVbootTestDisk(_) => gen_disk::gen_vboot_test_disk(&conf),
        Action::Check(_) => run_check(&conf),
        Action::Clean(_) => run_clean(&conf),
        Action::Format(action) => run_rustfmt(&conf, action),
        Action::UpdateDisk(_) => run_update_disk(&conf),
        Action::Lint(_) => run_clippy(&conf),
        Action::PrepDisk(_) => run_prep_disk(&conf),
        Action::SecureBootSetup(action) => run_secure_boot_setup(&conf, action),
        Action::Test(_) => run_tests(&conf),
        Action::Qemu(action) => run_qemu(&conf, action),
        Action::Writedisk(_) => run_writedisk(&conf),
    }?;
}
