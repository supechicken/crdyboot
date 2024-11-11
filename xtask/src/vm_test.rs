// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Directly include the `Operation` enum from `uefi_test_tool`.
mod operation {
    include!("../../tools/uefi_test_tool/src/operation.rs");
}
pub use operation::Operation;

use crate::arch::Arch;
use crate::config::Config;
use crate::gen_disk::{
    copy_partition_from_disk_to_disk, corrupt_crdyboot_signatures, corrupt_kern_a,
    corrupt_pubkey_section, delete_crdyboot_signatures, install_uefi_test_tool, SignAfterCorrupt,
    VerboseRuntimeLogs,
};
use crate::network::HttpsResource;
use crate::qemu::{Display, QemuOpts};
use crate::swtpm::TpmVersion;
use crate::{copy_file, run_bootloader_build, BuildAndroid};
use anyhow::{bail, Result};
use command_run::Command;
use fs_err as fs;
use regex::Regex;
use std::fs::Permissions;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::process::ChildStdout;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Timeout used for short VM tests. The short tests are all the tests
/// that don't need to wait for SSH.
const VM_TIMEOUT_SHORT: Duration = Duration::from_secs(30);

/// Timeout used for tests that need to wait for SSH.
const VM_TIMEOUT_LONG: Duration = Duration::from_secs(240);

/// Download the well-known testing_rsa key for ChromeOS test images.
fn download_test_key(conf: &Config) -> Result<()> {
    let mut resource = HttpsResource::new("https://chromium.googlesource.com/chromiumos/chromite/+/HEAD/ssh_keys/testing_rsa?format=TEXT");
    resource.enable_base64_decode();
    resource
        .set_expected_sha256("ebd33984c3b671f8aa82f73ab12dd1fe5af6af7080bd6361e3ec814f60c335be");
    let key = resource.download_to_vec()?;
    fs::write(conf.ssh_key_path(), key)?;

    // Set key permissions.
    fs::set_permissions(conf.ssh_key_path(), Permissions::from_mode(0o600)).unwrap();

    Ok(())
}

/// Default QEMU options.
fn default_qemu_opts(conf: &Config) -> QemuOpts {
    QemuOpts {
        capture_output: true,
        display: Display::None,
        image_path: conf.test_disk_path(),
        ovmf: conf.ovmf_paths(Arch::X64),
        secure_boot: true,
        snapshot: true,
        timeout: Some(VM_TIMEOUT_SHORT),
        tpm_version: None,
        network: false,
    }
}

/// Wait for SSH to come up on the VM (indicating a successful
/// boot). Times out after `VM_TIMEOUT_LONG`.
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

    // Wait for SSH to come up.
    let start_time = Instant::now();
    while start_time.elapsed() < VM_TIMEOUT_LONG {
        let output = cmd.run()?;
        if output.status.success() {
            return Ok(());
        }

        thread::sleep(Duration::from_secs(1));
    }

    bail!("SSH didn't come up");
}

/// Create a thread that captures stdout from a child process. The
/// thread will end when EOF is reached (i.e. when the child process has
/// terminated).
///
/// The output is returned a `Vec` of lines when the thread is joined.
fn create_output_capture_thread(stdout: ChildStdout) -> JoinHandle<Vec<String>> {
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut output = Vec::new();

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(len) => {
                    // EOF reached, which mean the VM has stopped. Exit
                    // the thread.
                    if len == 0 {
                        break;
                    }

                    output.push(line.clone());
                }
                // Unexpected error. Exit the thread.
                Err(_) => {
                    break;
                }
            }
        }
        output
    })
}

/// Test successful boots on both ia32 and x64.
fn test_successful_boot(conf: &Config) -> Result<()> {
    for arch in Arch::all() {
        // TODO(b/330536482): Skip 32-bit for now; the ia32 OVMF
        // firmware is broken.
        if arch == Arch::Ia32 {
            continue;
        }

        println!("test successful boot with arch={arch:?}");
        let opts = QemuOpts {
            // No need to copy the disk for this test since we aren't
            // modifying it.
            image_path: conf.disk_path().to_path_buf(),
            ovmf: conf.ovmf_paths(arch),
            timeout: None,
            network: true,
            ..default_qemu_opts(conf)
        };
        let vm = opts.spawn_disk_image(conf)?;

        // Launch a background thread to read stdout.
        let stdout = vm.qemu.lock().unwrap().stdout.take().unwrap();
        let output_thread = create_output_capture_thread(stdout);

        // Check that SSH comes up, indicating a successful boot. If
        // not, print the VM log.
        if let Err(err) = wait_for_ssh(conf) {
            println!("error: SSH didn't come up");

            // Kill QEMU, which will also cause the output thread to end.
            vm.qemu.lock().unwrap().kill().unwrap();

            // Print the VM output.
            let vm_output = output_thread.join().unwrap();
            for line in vm_output {
                print!(">>> {line}");
            }

            return Err(err);
        }
    }

    Ok(())
}

/// Make a copy of the original disk image so that we can modify it for
/// the test.
fn create_test_disk(conf: &Config) -> Result<()> {
    copy_file(conf.disk_path(), conf.test_disk_path())
}

/// Reset test disk partitions that may have been modified by a test.
///
/// This copies the KERN-A and EFI-SYSTEM partitions from the original
/// disk to the test disk. If any tests are added in the future that
/// alter other parts of the disk, they must be added here.
///
/// Note that during the QEMU portion of a test, the disk is never
/// modified due to the `-snapshot` arg.
fn reset_test_disk(conf: &Config) -> Result<()> {
    let test_disk = conf.test_disk_path();
    let orig_disk = conf.disk_path();

    for part in ["KERN-A", "EFI-SYSTEM"] {
        copy_partition_from_disk_to_disk(&test_disk, orig_disk, part)?;
    }

    Ok(())
}

/// Launch the test disk in a VM and monitor the output, looking for
/// each string in `expected_output` (in order). Once all expected
/// strings have been output by the VM, the VM is killed and `Ok` is
/// returned.
///
/// If the expected output does not occur within `VM_TIMEOUT_SHORT`, the
/// VM is killed and an error is returned.
fn launch_test_disk_and_expect_output(
    conf: &Config,
    opts: QemuOpts,
    expected_output: &[&str],
) -> Result<()> {
    // At least one expected error is required.
    assert!(!expected_output.is_empty());

    let vm = opts.spawn_disk_image(conf)?;

    let stdout = vm.qemu.lock().unwrap().stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut expected_output = expected_output.to_vec();

    while let Some(next_expected_error) = expected_output.first() {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            // EOF reached, which means the VM has stopped.
            bail!("QEMU no longer running");
        }
        print!(">>> {line}");

        let regex = Regex::new(next_expected_error).unwrap();
        if regex.is_match(&line) {
            expected_output.remove(0);
        }
    }

    // The expected errors have all occurred, test is successful. Kill
    // the VM.
    vm.qemu.lock().unwrap().kill().unwrap();
    Ok(())
}

/// Test successful boot with an active V1 TPM.
fn test_tpm1_success(conf: &Config) -> Result<()> {
    println!("test successful boot with an active v1 tpm");
    let expected_output = &[
        // Crdyshim measures crdyboot.
        "bytes to PCR 4 of a v1 TPM",
        // Crdyboot measures the kernel.
        "bytes to PCR 8 of a v1 TPM",
        "EFI stub: UEFI Secure Boot is enabled.",
    ];
    launch_test_disk_and_expect_output(
        conf,
        QemuOpts {
            tpm_version: Some(TpmVersion::V1),
            ..default_qemu_opts(conf)
        },
        expected_output,
    )
}

/// Test successful boot with an active V2 TPM.
fn test_tpm2_success(conf: &Config) -> Result<()> {
    println!("test successful boot with an active v2 tpm");
    let expected_output = &[
        // Crdyshim measures crdyboot.
        "bytes to PCR 4 of a v2 TPM",
        // Crdyboot measures the kernel.
        "bytes to PCR 8 of a v2 TPM",
        "EFI stub: UEFI Secure Boot is enabled.",
    ];
    launch_test_disk_and_expect_output(
        conf,
        QemuOpts {
            tpm_version: Some(TpmVersion::V2),
            ..default_qemu_opts(conf)
        },
        expected_output,
    )
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

    corrupt_kern_a(&conf.test_disk_path())?;

    let expected_output = &[
        "Kernel data verification failed",
        "boot failed: failed to load kernel",
    ];
    launch_test_disk_and_expect_output(conf, default_qemu_opts(conf), expected_output)
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

    corrupt_pubkey_section(conf, &conf.test_disk_path(), SignAfterCorrupt(false))?;

    let expected_output = &["boot failed: signature verification failed"];
    launch_test_disk_and_expect_output(conf, default_qemu_opts(conf), expected_output)
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

    corrupt_pubkey_section(conf, &conf.test_disk_path(), SignAfterCorrupt(true))?;

    let expected_output = &[
        "vb2api_inject_kernel_subkey failed",
        "boot failed: failed to load kernel",
    ];
    launch_test_disk_and_expect_output(conf, default_qemu_opts(conf), expected_output)
}

/// Test that crdyshim refuses to launch crdyboot if the signature file
/// is missing.
fn test_missing_signature_prevents_crdyboot_launch(conf: &Config) -> Result<()> {
    println!("test that if the crdyboot signature is missing, crdyshim refuses to launch it");

    delete_crdyboot_signatures(&conf.test_disk_path())?;

    let expected_output =
        &["boot failed: failed to read the next stage signature: file open failed: NOT_FOUND"];
    launch_test_disk_and_expect_output(conf, default_qemu_opts(conf), expected_output)
}

/// Test that crdyshim refuses to launch crdyboot if the signature file
/// is invalid.
fn test_invalid_signature_prevents_crdyboot_launch(conf: &Config) -> Result<()> {
    println!("test that if the crdyboot signature is invalid, crdyshim refuses to launch it");

    corrupt_crdyboot_signatures(&conf.test_disk_path())?;

    let expected_output = &["boot failed: signature verification failed"];
    launch_test_disk_and_expect_output(conf, default_qemu_opts(conf), expected_output)
}

/// Test that a deactivated v1 TPM is correctly ignored.
fn test_tpm1_deactivated_success(conf: &Config) -> Result<()> {
    println!("test that a deactivated v1 TPM is correctly ignored");

    install_uefi_test_tool(conf, Operation::Tpm1Deactivated)?;

    let expected_output = &[
        // Expect this message twice, first crdyshim then crdyboot:
        "TPMv1 protocol exists, but TPM is deactivated",
        "TPMv1 protocol exists, but TPM is deactivated",
        // Indicates the kernel has launched:
        "EFI stub: UEFI Secure Boot is enabled.",
    ];
    launch_test_disk_and_expect_output(conf, default_qemu_opts(conf), expected_output)
}

/// Test that an error from extending a v1 TPM PCR is correctly ignored.
fn test_tpm1_extend_error_success(conf: &Config) -> Result<()> {
    println!("test that an error from extending a v1 TPM PCR is correctly ignored");

    install_uefi_test_tool(conf, Operation::Tpm1ExtendFail)?;

    let expected_output = &[
        // Expect this message twice, first crdyshim then crdyboot:
        "failed to extend PCR: TPMv1 hash_log_extend_event failed: DEVICE_ERROR",
        "failed to extend PCR: TPMv1 hash_log_extend_event failed: DEVICE_ERROR",
        // Indicates the kernel has launched:
        "EFI stub: UEFI Secure Boot is enabled.",
    ];
    launch_test_disk_and_expect_output(conf, default_qemu_opts(conf), expected_output)
}

pub fn run_vm_tests(conf: &Config) -> Result<()> {
    run_bootloader_build(conf, BuildAndroid(false), VerboseRuntimeLogs(true))?;
    download_test_key(conf)?;

    create_test_disk(conf)?;

    let tests = [
        test_tpm1_deactivated_success,
        test_tpm1_extend_error_success,
        test_missing_signature_prevents_crdyboot_launch,
        test_invalid_signature_prevents_crdyboot_launch,
        test_signed_vbpubk_mod_breaks_vboot,
        test_vbpubk_mod_breaks_signature,
        test_corrupt_kern_a,
        test_tpm1_success,
        test_tpm2_success,
        test_successful_boot,
    ];

    for test in tests {
        test(conf)?;

        reset_test_disk(conf)?;
    }

    Ok(())
}
