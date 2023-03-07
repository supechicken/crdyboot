// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::Config;
use crate::gen_disk::{corrupt_kern_a, VerboseRuntimeLogs};
use crate::qemu::{Display, QemuOpts};
use crate::{copy_file, run_crdyboot_build};
use anyhow::{bail, Result};
use camino::Utf8Path;
use command_run::Command;
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};
use std::{env, thread};

/// Make sure the SSH key is the expected test key.
fn validate_test_key(key_path: &Utf8Path) -> Result<()> {
    let output = Command::with_args(
        "ssh-keygen",
        [
            // Show the fingerprint.
            "-l",
            // Set the file path.
            "-f",
            key_path.as_str(),
        ],
    )
    .enable_capture()
    .run()?;
    let stdout = String::from_utf8(output.stdout)?;
    let expected = "Fp1qWjFLyK1cTpiI5rdk7iEJwoK9lcnYAgbQtGC3jzU";
    if !stdout.contains(expected) {
        bail!("incorrect key; expected {expected}, got {}", stdout.trim());
    }
    Ok(())
}

/// Wait for SSH to come up on the VM (indicating a successful
/// boot). Times out after one minute.
fn wait_for_ssh() -> Result<()> {
    // Get the standard testing key. Fail early with an error if it
    // doesn't exist.
    let identity_path = Utf8Path::new(&env::var("HOME").unwrap()).join(".ssh/testing_rsa");
    if let Err(err) = validate_test_key(&identity_path) {
        bail!("missing or invalid test key in {identity_path}; copy it from https://chromium.googlesource.com/chromiumos/chromite/+/HEAD/ssh_keys/testing_rsa and set the permissions with `chmod 600` ({err})");
    }

    println!("waiting for SSH");
    let mut cmd = Command::with_args(
        "ssh",
        [
            "-oStrictHostKeyChecking=no",
            "-oUserKnownHostsFile=/dev/null",
            // Enable batch mode to prevent password prompts if the SSH
            // key is misconfigured.
            "-oBatchMode=yes",
            "-i",
            identity_path.as_str(),
            "-p",
            &Config::ssh_port().to_string(),
            "root@localhost",
            "true",
        ],
    );
    cmd.check = false;
    cmd.capture = true;
    cmd.log_command = false;

    // Wait up to one minute for SSH to come up.
    let start_time = Instant::now();
    while start_time.elapsed() < Duration::from_secs(60) {
        let output = cmd.run()?;
        if output.status.success() {
            return Ok(());
        }

        thread::sleep(Duration::from_secs(1));
    }

    bail!("SSH didn't come up");
}

/// Test successful boots on both ia32 and x64.
fn test_successful_boot(conf: &Config) -> Result<()> {
    for arch in Arch::all() {
        println!("test successful boot with arch={arch:?}");
        let opts = QemuOpts {
            capture_output: true,
            display: Display::None,
            // No need to copy the disk for this test since we aren't
            // modifying it.
            image_path: conf.disk_path().to_path_buf(),
            ovmf: conf.ovmf_paths(arch),
            secure_boot: true,
            snapshot: true,
            timeout: None,
            tpm_version: None,
        };
        let _vm = opts.spawn_disk_image(conf)?;

        // Check that SSH comes up, indicating a successful boot.
        wait_for_ssh()?;
    }

    Ok(())
}

/// Make a copy of the original disk image so that we can modify it for
/// the test.
fn create_test_disk(conf: &Config) -> Result<()> {
    copy_file(conf.disk_path(), conf.test_disk_path())
}

/// Test failed boot due to corrupt KERN-A.
///
/// This test generates an intentionally corrupt disk, where a single
/// byte in the kernel data has been changed so that the signature is no
/// longer valid.
///
/// The test checks that vboot rejects that kernel with a specific
/// error, and that crdyboot fails to boot.
fn test_corrupt_kern_a(conf: &Config) -> Result<()> {
    println!("test if boot correctly fails when KERN-A is corrupt");

    create_test_disk(conf)?;

    corrupt_kern_a(&conf.test_disk_path())?;

    let opts = QemuOpts {
        capture_output: true,
        display: Display::None,
        image_path: conf.test_disk_path(),
        ovmf: conf.ovmf_paths(Arch::X64),
        secure_boot: true,
        snapshot: true,
        timeout: Some(Duration::from_secs(30)),
        tpm_version: None,
    };
    let vm = opts.spawn_disk_image(conf)?;

    let stdout = vm.qemu.lock().unwrap().stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut confirmed_kernel_data_error = false;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            // EOF reached,
            bail!("QEMU no longer running");
        }

        if line.contains("Kernel data verification failed") {
            confirmed_kernel_data_error = true;
        } else if line.contains("boot failed: failed to load kernel") {
            if confirmed_kernel_data_error {
                // The expected failure occurred, test is
                // successful. Kill the VM.
                vm.qemu.lock().unwrap().kill().unwrap();
                return Ok(());
            } else {
                bail!("missing the kernel data verification error");
            }
        }
    }
}

pub fn run_vm_tests(conf: &Config) -> Result<()> {
    run_crdyboot_build(conf, VerboseRuntimeLogs(true))?;

    test_corrupt_kern_a(conf)?;
    test_successful_boot(conf)?;

    Ok(())
}
