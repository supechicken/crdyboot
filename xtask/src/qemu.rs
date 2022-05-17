// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{anyhow, Error};
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fehler::throws;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VarAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Display {
    None,
    Gtk,
    Sdl,
}

impl FromStr for Display {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "none" => Ok(Self::None),
            "gtk" => Ok(Self::Gtk),
            "sdl" => Ok(Self::Sdl),
            _ => Err(anyhow!("invalid display type: {s}")),
        }
    }
}

impl Display {
    fn as_arg_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gtk => "gtk,gl=on,show-cursor=on",
            Self::Sdl => "sdl,gl=on,show-cursor=on",
        }
    }
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

    fn create_command(
        &self,
        var_access: VarAccess,
        display: Display,
    ) -> Command {
        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.add_arg("-enable-kvm");
        cmd.add_arg("-nodefaults");
        cmd.add_args(&["-vga", "virtio"]);
        cmd.add_args(&["-serial", "stdio"]);
        cmd.add_args(&["-display", display.as_arg_str()]);

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
    pub fn run_disk_image(
        &self,
        image_path: &Utf8Path,
        var_access: VarAccess,
        display: Display,
    ) {
        let mut cmd = self.create_command(var_access, display);

        cmd.add_args(&["-drive", &format!("format=raw,file={}", image_path)]);
        cmd.run()?;
    }
}
