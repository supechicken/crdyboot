use anyhow::Error;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fehler::throws;
use fs_err as fs;

pub struct Qemu {
    image_path: Utf8PathBuf,
    ovmf_dir: Utf8PathBuf,
}

impl Qemu {
    pub fn new(image_path: &Utf8Path, ovmf_dir: &Utf8Path) -> Qemu {
        Qemu {
            image_path: image_path.into(),
            ovmf_dir: ovmf_dir.into(),
        }
    }

    #[throws]
    pub fn run(&self) {
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
        cmd.add_args(&[
            "-drive",
            &format!("format=raw,file={}", self.image_path),
        ]);

        cmd.run()?;
    }
}
