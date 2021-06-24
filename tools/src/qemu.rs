use anyhow::Error;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fehler::throws;
use fs_err as fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{self, Stdio};

pub struct Qemu {
    ovmf_dir: Utf8PathBuf,
}

impl Qemu {
    pub fn new(ovmf_dir: Utf8PathBuf) -> Qemu {
        Qemu { ovmf_dir }
    }

    #[throws]
    fn create_command(&self) -> Command {
        let ovmf_code = self.ovmf_dir.join("OVMF_CODE.fd");
        let orig_ovmf_vars = self.ovmf_dir.join("OVMF_VARS.fd");
        let new_ovmf_vars = self.ovmf_dir.join("OVMF_VARS.copy.fd");
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

        cmd.add_args(&[
            "-global",
            "driver=cfi.pflash01,property=secure,value=on",
        ]);
        cmd.add_args(&[
            "-drive",
            &format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                ovmf_code
            ),
        ]);
        cmd.add_args(&[
            "-drive",
            &format!(
                "if=pflash,format=raw,unit=1,readonly=on,file={}",
                new_ovmf_vars
            ),
        ]);

        cmd
    }

    #[throws]
    pub fn run_disk_image(&self, image_path: &Utf8Path) {
        let mut cmd = self.create_command()?;

        cmd.add_args(&["-drive", &format!("format=raw,file={}", image_path)]);
        cmd.run()?;
    }

    #[throws]
    pub fn enroll(&self, executable_path: &Utf8Path) {
        let mut cmd = self.create_command()?;

        let tmp_dir = tempfile::tempdir()?;
        let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

        let boot_dir = tmp_path.join("efi/boot");
        fs::create_dir_all(&boot_dir)?;

        let dst_name = "enroll.efi";

        cmd.add_args(&[
            "-drive",
            &format!("format=raw,file=fat:rw:{}", tmp_path),
        ]);

        fs::copy(executable_path, boot_dir.join(dst_name))?;

        // Convert to an std Command, command_run doesn't
        // support the interactive session needed here.
        let mut cmd = process::Command::from(&cmd);

        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());

        let mut child = cmd.spawn()?;
        let stdout = child.stdout.take().unwrap();
        let mut stdin = child.stdin.take().unwrap();

        let mut reader = BufReader::new(stdout);

        // Wait for the shell to start.
        wait_for_line_containing(&mut reader, "UEFI Interactive Shell")?;

        // Send an escape to skip the five second delay before
        // the shell starts.
        write!(stdin, "\x1b")?;
        // Send a return so that we get an actual shell prompt.
        write!(stdin, "\r\n")?;

        wait_for_line_containing(&mut reader, "Shell> ")?;

        // Send the enroll command.
        write!(stdin, "enroll\r\n")?;

        child.wait()?;
    }
}

#[throws]
fn wait_for_line_containing(reader: &mut dyn BufRead, substr: &str) {
    for line in reader.lines() {
        let line = line?;
        println!("{}", line);
        // Can't use "starts_with" because of the color
        // escape codes.
        if line.contains(substr) {
            break;
        }
    }
}
