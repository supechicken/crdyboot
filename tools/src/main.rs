use anyhow::Error;
use argh::FromArgs;
use camino::Utf8PathBuf;
use command_run::Command;
use fehler::throws;
use fs_err as fs;

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

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Action {
    Check(CheckAction),
    Format(FormatAction),
    Lint(LintAction),
    Test(TestAction),
    Build(BuildAction),
    GenDisk(GenDiskAction),
    Qemu(QemuAction),
}

/// Build crdyboot.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build")]
struct BuildAction {}

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

fn get_projects(opt: &Opt) -> Vec<Utf8PathBuf> {
    vec![
        opt.repo.join("crdyboot"),
        opt.repo.join("tools"),
        opt.repo.join("vboot"),
    ]
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

    for target in targets {
        Command::with_args(
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
        )
        .set_dir(opt.repo.join("crdyboot"))
        .run()?;
    }
}

#[throws]
fn run_rustfmt(opt: &Opt) {
    for project in get_projects(opt) {
        let cargo_path = project.join("Cargo.toml");
        Command::with_args(
            "cargo",
            &["fmt", "--manifest-path", cargo_path.as_str()],
        )
        .run()?;
    }
}

#[throws]
fn run_gen_disk(_opt: &Opt) {
    println!("todo");
}

#[throws]
fn run_clippy(opt: &Opt) {
    for project in get_projects(opt) {
        println!("{}:", project);
        Command::with_args("cargo", &["+nightly", "clippy"])
            .set_dir(project)
            .run()?;
    }
}

#[throws]
fn run_tests(opt: &Opt) {
    let vboot_cargo = opt.repo.join("vboot/Cargo.toml");
    Command::with_args(
        "cargo",
        &["test", "--manifest-path", vboot_cargo.as_str()],
    )
    .run()?;
}

#[throws]
fn run_qemu(opt: &Opt, action: &QemuAction) {
    let volatile = opt.repo.join("crdyboot/volatile");
    let disk = volatile.join("disk.bin");

    let ovmf_dir = if action.ia32 {
        volatile.join("uefi32")
    } else {
        volatile.join("uefi64")
    };
    let ovmf_code = ovmf_dir.join("OVMF_CODE.fd");
    let orig_ovmf_vars = ovmf_dir.join("OVMF_VARS.fd");
    let new_ovmf_vars = ovmf_dir.join("OVMF_VARS.copy.fd");
    fs::copy(orig_ovmf_vars, &new_ovmf_vars)?;

    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.add_arg("-enable-kvm");
    cmd.add_arg("-nodefaults");
    cmd.add_args(&["-vga", "virtio"]);
    cmd.add_args(&["-serial", "stdio"]);

    // Give it a small but reasonable amount of memory (the
    // default of 128M is too small).
    cmd.add_args(&["-m", "1G"]);

    // These options are needed for SMM as described in
    // edk2/OvmfPkg/README.
    cmd.add_args(&["-machine", "q35,smm=on,accel=kvm"]);
    cmd.add_args(&["-global", "ICH9-LPC.disable_s3=1"]);

    cmd.add_args(&["-global", "driver=cfi.pflash01,property=secure,value=on"]);
    cmd.add_args(&[
        "-drive",
        &format!("if=pflash,format=raw,unit=0,readonly=on,file={}", ovmf_code),
    ]);
    cmd.add_args(&[
        "-drive",
        &format!(
            "if=pflash,format=raw,unit=1,readonly=on,file={}",
            new_ovmf_vars
        ),
    ]);
    cmd.add_args(&["-drive", &format!("format=raw,file={}", disk)]);

    cmd.run()?;
}

#[throws]
fn main() {
    let opt: Opt = argh::from_env();

    match &opt.action {
        Action::Build(_) => run_build(&opt),
        Action::Check(_) => run_check(&opt),
        Action::Format(_) => run_rustfmt(&opt),
        Action::GenDisk(_) => run_gen_disk(&opt),
        Action::Lint(_) => run_clippy(&opt),
        Action::Test(_) => run_tests(&opt),
        Action::Qemu(action) => run_qemu(&opt, action),
    }?;
}
