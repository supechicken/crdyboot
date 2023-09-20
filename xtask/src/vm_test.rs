// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::Config;
use crate::gen_disk::{
    corrupt_kern_a, corrupt_pubkey_section, SignAfterCorrupt, VerboseRuntimeLogs,
};
use crate::network::HttpsResource;
use crate::qemu::{Display, QemuOpts};
use crate::{copy_file, run_crdyboot_build};
use anyhow::{bail, Result};
use command_run::Command;
use fs_err as fs;
use std::fs::Permissions;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::{Duration, Instant};

/// Timeout used for error tests.
///
/// This can be relatively short since error tests fail early in boot
/// (we don't have to wait for SSH to come up like in the success
/// tests).
const VM_ERROR_TIMEOUT: Duration = Duration::from_secs(30);

/// Download the well-known testing_rsa key for ChromeOS test images.
fn download_test_key(conf: &Config) -> Result<()> {
    let mut resource = HttpsResource::new("https://chromium.googlesource.com/chromiumos/chromite/+/HEAD/ssh_keys/testing_rsa?format=TEXT");
    resource.enable_base64_decode();
    let key = resource.download_to_vec()?;
    fs::write(conf.ssh_key_path(), key)?;

    // Set key permissions.
    fs::set_permissions(conf.ssh_key_path(), Permissions::from_mode(0o600)).unwrap();

    Ok(())
}

/// Wait for SSH to come up on the VM (indicating a successful
/// boot). Times out after one minute.
fn wait_for_ssh(conf: &Config) -> Result<()> {
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
            conf.ssh_key_path().as_str(),
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
    while start_time.elapsed() < Duration::from_secs(120) {
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
        wait_for_ssh(conf)?;
    }

    Ok(())
}

/// Make a copy of the original disk image so that we can modify it for
/// the test.
fn create_test_disk(conf: &Config) -> Result<()> {
    copy_file(conf.disk_path(), conf.test_disk_path())
}

/// Helper for testing vboot errors.
///
/// This launches the test disk in a VM and monitors the output, looking
/// for each error string in `expected_errors` (in order). Once all
/// expected errors have been output by the VM, the VM is killed and
/// `Ok` is returned.
///
/// If the expected errors do not occur within `VM_ERROR_TIMEOUT`, the
/// VM is killed and an error is returned.
fn launch_test_disk_and_expect_errors(conf: &Config, expected_errors: &[&str]) -> Result<()> {
    // At least one expected error is required.
    assert!(!expected_errors.is_empty());

    let opts = QemuOpts {
        capture_output: true,
        display: Display::None,
        image_path: conf.test_disk_path(),
        ovmf: conf.ovmf_paths(Arch::X64),
        secure_boot: true,
        snapshot: true,
        timeout: Some(VM_ERROR_TIMEOUT),
        tpm_version: None,
    };
    let vm = opts.spawn_disk_image(conf)?;

    let stdout = vm.qemu.lock().unwrap().stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut expected_errors = expected_errors.to_vec();

    while let Some(next_expected_error) = expected_errors.first() {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            // EOF reached, which means the VM has stopped.
            bail!("QEMU no longer running");
        }
        print!(">>> {line}");

        if line.contains(next_expected_error) {
            expected_errors.remove(0);
        }
    }

    // The expected errors have all occurred, test is successful. Kill
    // the VM.
    vm.qemu.lock().unwrap().kill().unwrap();
    Ok(())
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

    let expected_errors = &[
        "Kernel data verification failed",
        "boot failed: failed to load kernel",
    ];
    launch_test_disk_and_expect_errors(conf, expected_errors)
}

/// Wrapper that prints `text` when dropped if `print` is true. This is
/// used for printing test output when a panic occurs.
struct PrintOutputOnDrop {
    text: String,
    print: bool,
}

impl PrintOutputOnDrop {
    fn new() -> Self {
        Self {
            text: String::new(),
            print: true,
        }
    }
}

impl Drop for PrintOutputOnDrop {
    fn drop(&mut self) {
        if self.print {
            println!("start output ---");
            println!("{}", self.text);
            println!("--- end output");
        }
    }
}

/// This test modifies a byte in the `.vbpubk` section of the
/// bootloader, then verifies that shim refuses to launch crdyboot due
/// to the executable's signature no longer being valid.
///
/// This validates that the `.vbpubk` section is properly included in
/// the authenticode hash, and shim is correctly validating the
/// signature.
fn test_vbpubk_mod_breaks_signature(conf: &Config) -> Result<()> {
    println!("test that modifying the vbpubk section prevents crdyboot from launching");

    create_test_disk(conf)?;

    corrupt_pubkey_section(conf, &conf.test_disk_path(), SignAfterCorrupt(false))?;

    let opts = QemuOpts {
        capture_output: true,
        display: Display::None,
        image_path: conf.test_disk_path(),
        ovmf: conf.ovmf_paths(Arch::X64),
        secure_boot: true,
        snapshot: true,
        timeout: Some(VM_ERROR_TIMEOUT),
        tpm_version: None,
    };
    let vm = opts.spawn_disk_image(conf)?;
    let mut stdout = vm.qemu.lock().unwrap().stdout.take().unwrap();
    let mut output = PrintOutputOnDrop::new();
    loop {
        // Read one byte at a time since there's no newline character
        // after the message we are looking for.
        let mut byte = [0];
        if stdout.read(&mut byte)? == 0 {
            // EOF reached.
            bail!("QEMU no longer running");
        }
        output.text.push(char::try_from(byte[0]).unwrap());

        if output
            .text
            .contains("Verification failed: (0x1A) Security Violation")
        {
            // The expected failure occurred, test is successful. Kill
            // the VM.
            output.print = false;
            vm.qemu.lock().unwrap().kill().unwrap();
            return Ok(());
        }
    }
}

/// This test modifies a byte in the `.vbpubk` section of crdyboot and
/// then re-signs crdyboot. It then verifies that crdyboot refuses to
/// launch the kernel since the pubkey is no longer valid.
///
/// This validates two things:
/// 1. Crdyboot is reading the pubkey from the expected place in the binary.
/// 2. Vboot will not load a kernel if the pubkey is invalid.
fn test_signed_vbpubk_mod_breaks_vboot(conf: &Config) -> Result<()> {
    println!(
        "test that modifying the vbpubk section and re-signing prevents the kernel from launching"
    );

    create_test_disk(conf)?;

    corrupt_pubkey_section(conf, &conf.test_disk_path(), SignAfterCorrupt(true))?;

    let expected_errors = &[
        "vb2api_inject_kernel_subkey failed",
        "boot failed: failed to load kernel",
    ];
    launch_test_disk_and_expect_errors(conf, expected_errors)
}

pub fn run_vm_tests(conf: &Config) -> Result<()> {
    run_crdyboot_build(conf, VerboseRuntimeLogs(true))?;
    download_test_key(conf)?;

    test_signed_vbpubk_mod_breaks_vboot(conf)?;
    test_vbpubk_mod_breaks_signature(conf)?;
    test_corrupt_kern_a(conf)?;
    test_successful_boot(conf)?;

    Ok(())
}
