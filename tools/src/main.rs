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
    Format(FormatAction),
    Lint(LintAction),
    Qemu(QemuAction),
}

/// Run "cargo fmt" on all the code.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "fmt")]
struct FormatAction {}

/// Run "cargo clippy" on all the code.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "lint")]
struct LintAction {}

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
fn run_clippy(opt: &Opt) {
    for project in get_projects(opt) {
        println!("{}:", project);
        Command::with_args("cargo", &["+nightly", "clippy"])
            .set_dir(project)
            .run()?;
    }
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
        Action::Format(_) => run_rustfmt(&opt),
        Action::Lint(_) => run_clippy(&opt),
        Action::Qemu(action) => run_qemu(&opt, action),
    }?;
}
