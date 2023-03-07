// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::swtpm::{Swtpm, TpmVersion};
use crate::util::ScopedChild;
use crate::Config;
use anyhow::{anyhow, Error, Result};
use camino::Utf8PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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

pub struct QemuProcess {
    pub qemu: Arc<Mutex<ScopedChild>>,
    timeout_thread_handle: Option<thread::JoinHandle<()>>,
    _swtpm: Option<Swtpm>,
}

impl QemuProcess {
    // If the process is still running after the `timeout` duration has
    // elapsed, kill the process and panic.
    fn kill_child_after_timeout(timeout: Duration, process: Arc<Mutex<ScopedChild>>) {
        let start_time = Instant::now();

        // Wait up to `timeout` for the child to exit.
        while start_time.elapsed() < timeout {
            let exit_status = process.lock().unwrap().try_wait().unwrap();
            if exit_status.is_some() {
                // Child has already exited.
                return;
            }
            // Sleep a half second before checking again.
            thread::sleep(Duration::from_millis(500));
        }

        // Kill the child and panic.
        let _ = process.lock().unwrap().kill();
        panic!("timeout occurred, VM killed");
    }
}

impl Drop for QemuProcess {
    fn drop(&mut self) {
        if let Some(handle) = self.timeout_thread_handle.take() {
            handle.join().unwrap();
        }
    }
}

pub struct QemuOpts {
    pub capture_output: bool,
    pub display: Display,
    pub image_path: Utf8PathBuf,
    pub ovmf: OvmfPaths,
    pub secure_boot: bool,
    pub snapshot: bool,
    pub timeout: Option<Duration>,
    pub tpm_version: Option<TpmVersion>,
}

impl QemuOpts {
    fn create_command(&self) -> Command {
        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.arg("-enable-kvm");
        cmd.arg("-nodefaults");
        cmd.args(["-vga", "virtio"]);
        cmd.args(["-serial", "stdio"]);
        cmd.args(["-display", self.display.as_arg_str()]);

        if self.snapshot {
            cmd.arg("-snapshot");
        }

        // Give it a small but reasonable amount of memory (the
        // default of 128M is too small).
        cmd.args(["-m", "1G"]);

        // These options are needed for SMM as described in
        // edk2/OvmfPkg/README.
        cmd.args(["-machine", "q35,smm=on,accel=kvm"]);
        cmd.args(["-global", "ICH9-LPC.disable_s3=1"]);

        // Send OVMF debug logging to a file.
        cmd.args([
            "-debugcon",
            &format!("file:{}", self.ovmf.qemu_log()),
            "-global",
            "isa-debugcon.iobase=0x402",
        ]);

        cmd.args(["-global", "driver=cfi.pflash01,property=secure,value=on"]);
        cmd.args([
            "-drive",
            &format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                self.ovmf.code()
            ),
        ]);
        cmd.args([
            "-drive",
            &format!(
                "if=pflash,format=raw,unit=1,readonly=off,file={}",
                if self.secure_boot {
                    self.ovmf.secure_boot_vars()
                } else {
                    self.ovmf.original_vars()
                }
            ),
        ]);

        cmd.args([
            "-net",
            "nic,model=virtio",
            "-net",
            &format!("user,hostfwd=tcp::{}-:22", Config::ssh_port()),
        ]);

        if self.capture_output {
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }

        // Disconnect the input stream. This prevents QEMU from messing
        // with the TTY. Normally it doesn't matter, but if QEMU is
        // terminated without shutting down cleanly it may leave the TTY
        // with echo turned off.
        cmd.stdin(Stdio::null());

        cmd
    }

    pub fn spawn_disk_image(&self, conf: &Config) -> Result<QemuProcess> {
        let swtpm = if let Some(tpm_version) = self.tpm_version {
            Some(Swtpm::spawn(conf, tpm_version)?)
        } else {
            None
        };

        let mut cmd = self.create_command();

        cmd.args(["-drive", &format!("format=raw,file={}", self.image_path)]);
        if let Some(swtpm) = &swtpm {
            cmd.args(swtpm.qemu_args());
        }
        let process = Arc::new(Mutex::new(ScopedChild::new(cmd.spawn()?)));

        // If a timeout is set, launch a background thread to kill the
        // VM when the timeout is reached.
        let timeout_thread_handle = if let Some(timeout) = self.timeout {
            let process = process.clone();
            Some(thread::spawn(move || {
                QemuProcess::kill_child_after_timeout(timeout, process)
            }))
        } else {
            None
        };

        Ok(QemuProcess {
            qemu: process,
            timeout_thread_handle,
            _swtpm: swtpm,
        })
    }

    pub fn run_disk_image(&self, conf: &Config) -> Result<()> {
        let vm = self.spawn_disk_image(conf)?;
        let status = vm.qemu.lock().unwrap().wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(anyhow!("qemu exited non-zero: {status:?}"))
        }
    }
}
