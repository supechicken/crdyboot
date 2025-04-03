// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::util::ScopedChild;
use crate::Config;
use anyhow::Result;
use fs_err as fs;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// TPM version.
#[derive(Clone, Copy, PartialEq)]
pub enum TpmVersion {
    /// V1 TPM.
    V1,

    /// V2 TPM.
    V2,
}

/// Wrapper for running `swtpm`, a software TPM emulator.
///
/// <https://github.com/stefanberger/swtpm>
///
/// The process is killed on drop.
pub struct Swtpm {
    tmp_dir: TempDir,
    _child: ScopedChild,
}

impl Swtpm {
    /// Run `swtpm` in a new process.
    pub fn spawn(conf: &Config, version: TpmVersion) -> Result<Self> {
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path().to_str().unwrap();

        let log_path = conf.workspace_path().join("tpm.log");

        // Remove the log if it already exists. Otherwise, new logs will
        // be appended to the existing log, making it harder to read.
        let _ = fs::remove_file(&log_path);

        // Adapted from https://qemu.readthedocs.io/en/latest/specs/tpm.html
        let mut cmd = Command::new("swtpm");
        cmd.args([
            "socket",
            "--tpmstate",
            &format!("dir={tmp_path}"),
            "--ctrl",
            &format!("type=unixio,path={tmp_path}/swtpm-sock"),
            // Terminate when the connection drops. If for any reason
            // this fails, the process will be killed on drop.
            "--terminate",
            // Send verbose logs to a file.
            "--log",
            &format!("file={},level=10", log_path),
        ]);

        if version == TpmVersion::V2 {
            cmd.arg("--tpm2");
        }

        // Print the command before spawning it.
        println!(
            "launching swtpm: {}",
            format!("{:?}", cmd).replace('\"', "")
        );
        let child = ScopedChild::new(cmd.spawn()?);

        // Add an artificial short delay here to give the swtpm time to
        // launch before qemu runs. This is a speculative fix for
        // b/407787282, where the TPM tests sometimes fail in the CoP
        // container.
        thread::sleep(Duration::from_secs_f32(0.5));

        Ok(Self {
            tmp_dir,
            _child: child,
        })
    }

    /// Get the QEMU args needed to connect to the TPM emulator.
    pub fn qemu_args(&self) -> Vec<String> {
        let socket_path = self.tmp_dir.path().join("swtpm-sock");
        vec![
            "-chardev".into(),
            format!("socket,id=chrtpm0,path={}", socket_path.to_str().unwrap()),
            "-tpmdev".into(),
            "emulator,id=tpm0,chardev=chrtpm0".into(),
            "-device".into(),
            "tpm-tis,tpmdev=tpm0".into(),
        ]
    }
}
