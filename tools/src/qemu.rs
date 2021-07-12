use crate::copy_file;
use anyhow::Error;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fehler::throws;
use fs_err as fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{self, Stdio};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrintOutput {
    No,
    Yes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VarAccess {
    ReadOnly,
    ReadWrite,
}

pub struct OvmfPaths {
    pub dir: Utf8PathBuf,
}

impl OvmfPaths {
    pub fn new(dir: Utf8PathBuf) -> OvmfPaths {
        OvmfPaths { dir }
    }

    pub fn code(&self) -> Utf8PathBuf {
        self.dir.join("OVMF_CODE.fd")
    }

    pub fn original_vars(&self) -> Utf8PathBuf {
        self.dir.join("OVMF_VARS.fd.orig")
    }

    pub fn secure_boot_vars(&self) -> Utf8PathBuf {
        self.dir.join("OVMF_VARS.fd.secure_boot")
    }

    pub fn enroll_executable(&self) -> Utf8PathBuf {
        self.dir.join("enroll.efi")
    }

    /// Path to which OVMF debugging log messages are sent.
    pub fn qemu_log(&self) -> Utf8PathBuf {
        self.dir.join("qemu.log")
    }
}

pub struct Qemu {
    ovmf: OvmfPaths,
    pub secure_boot: bool,
}

impl Qemu {
    pub fn new(ovmf: OvmfPaths) -> Qemu {
        Qemu {
            ovmf,
            secure_boot: true,
        }
    }

    fn create_command(&self, var_access: VarAccess) -> Command {
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

        // Send OVMF debug logging to a file.
        cmd.add_args(&[
            "-debugcon",
            &format!("file:{}", self.ovmf.qemu_log()),
            "-global",
            "isa-debugcon.iobase=0x402",
        ]);

        cmd.add_args(&[
            "-global",
            "driver=cfi.pflash01,property=secure,value=on",
        ]);
        cmd.add_args(&[
            "-drive",
            &format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                self.ovmf.code()
            ),
        ]);
        cmd.add_args(&[
            "-drive",
            &format!(
                "if=pflash,format=raw,unit=1,readonly={},file={}",
                if var_access == VarAccess::ReadWrite {
                    "off"
                } else {
                    "on"
                },
                if self.secure_boot {
                    self.ovmf.secure_boot_vars()
                } else {
                    self.ovmf.original_vars()
                }
            ),
        ]);

        cmd
    }

    #[throws]
    pub fn run_disk_image(&self, image_path: &Utf8Path) {
        let mut cmd = self.create_command(VarAccess::ReadOnly);

        cmd.add_args(&["-drive", &format!("format=raw,file={}", image_path)]);
        cmd.run()?;
    }

    #[throws]
    pub fn enroll(&self, oemstr_path: &Utf8Path, po: PrintOutput) {
        let mut cmd = self.create_command(VarAccess::ReadWrite);

        let tmp_dir = tempfile::tempdir()?;
        let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

        let boot_dir = tmp_path.join("efi/boot");
        fs::create_dir_all(&boot_dir)?;

        let dst_name = "enroll.efi";

        cmd.add_args(&[
            "-drive",
            &format!("format=raw,file=fat:rw:{}", tmp_path),
        ]);

        cmd.add_args(&["-smbios", &format!("type=11,path={}", oemstr_path)]);

        copy_file(self.ovmf.enroll_executable(), boot_dir.join(dst_name))?;

        // Convert to an std Command, command_run doesn't
        // support the interactive session needed here.
        let mut cmd = process::Command::from(&cmd);

        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());

        let mut child = cmd.spawn()?;
        let stdout = child.stdout.take().unwrap();
        let mut stdin = child.stdin.take().unwrap();

        let mut reader = BufReader::new(stdout);

        // Wait for the shell to start.
        wait_for_line_containing(&mut reader, "UEFI Interactive Shell", po)?;

        // Send an escape to skip the five second delay before
        // the shell starts.
        write!(stdin, "\x1b")?;
        // Send a return so that we get an actual shell prompt.
        write!(stdin, "\r\n")?;

        // Wait for the shell prompt.
        wait_for_line_containing(&mut reader, "Shell> ", po)?;

        // Send the enroll command. Passing in "--no-default" changes
        // what certificates get enrolled in the db. The default, for
        // some reason, is to enroll the Microsoft certs rather than
        // the cert we have passed in. Now, the cert we passed in does
        // get enrolled as the PK and first KEK, and in theory it
        // being in the KEK should allow our custom-signed shim to
        // boot, but that doesn't seem to work in practice with OVMF.
        write!(stdin, "enroll --no-default\r\n")?;

        // Wait again for the shell prompt.
        wait_for_line_containing(&mut reader, "Shell> ", po)?;

        // Send the shutdown command.
        write!(stdin, "reset -s\r\n")?;

        child.wait()?;
    }
}

#[throws]
fn wait_for_line_containing(
    reader: &mut dyn BufRead,
    substr: &str,
    po: PrintOutput,
) {
    for line in reader.lines() {
        let line = line?;
        if po == PrintOutput::Yes {
            println!("{}", line);
        }
        // Can't use "starts_with" because of the color
        // escape codes.
        if line.contains(substr) {
            break;
        }
    }
}
