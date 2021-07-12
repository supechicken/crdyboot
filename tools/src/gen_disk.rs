use crate::arch::Arch;
use crate::loopback::{LoopbackDevice, PartitionPaths};
use crate::mount::Mount;
use crate::{sign, Opt};
use anyhow::Error;
use camino::Utf8Path;
use command_run::Command;
use fehler::throws;
use fs_err as fs;

#[throws]
pub fn gen_enroller_disk(opt: &Opt) {
    let disk = opt.enroller_disk_path();

    // Generate empty image.
    Command::with_args("truncate", &["--size", "4MiB", disk.as_str()]).run()?;

    // Make GPT table.
    Command::with_args(
        "parted",
        &["--script", disk.as_str(), "mktable", "GPT"],
    )
    .run()?;

    // Create a single partition.
    Command::with_args(
        "parted",
        &[
            "--script",
            disk.as_str(),
            "mkpart",
            "primary",
            "2048s",
            "100%",
        ],
    )
    .run()?;

    // Mark the partition bootable.
    Command::with_args(
        "parted",
        &["--script", disk.as_str(), "set", "1", "esp", "on"],
    )
    .run()?;

    let lo_dev = LoopbackDevice::new(&disk)?;

    // Format the partition.
    Command::with_args(
        "sudo",
        &["mkfs.fat", lo_dev.partition_device(1).as_str()],
    )
    .run()?;

    // Mount the partition.
    let esp_mount = Mount::new(&lo_dev.partition_device(1))?;
    let esp = esp_mount.mount_point();

    // Create the standard boot directory.
    let boot_dir = esp.join("efi/boot");
    Command::with_args("sudo", &["mkdir", "-p", boot_dir.as_str()]).run()?;

    // Copy in the two enroller executables.
    for arch in Arch::all() {
        let src = opt
            .enroller_path()
            .join("target")
            .join(arch.as_target())
            .join("release/enroller.efi");
        let dst = boot_dir.join(format!("boot{}.efi", arch.as_str()));
        Command::with_args("sudo", &["cp", src.as_str(), dst.as_str()])
            .run()?;
    }
}

/// Replace both grub executables with crdyboot.
#[throws]
pub fn copy_in_crdyboot(opt: &Opt, partitions: &PartitionPaths) {
    let efi_mount = Mount::new(&partitions.efi)?;
    let efi = efi_mount.mount_point();

    let targets = [
        ("x86_64-unknown-uefi", "grubx64.efi"),
        ("i686-unknown-uefi", "grubia32.efi"),
    ];

    for (target, dstname) in targets {
        let src = opt
            .crdyboot_path()
            .join("target")
            .join(target)
            .join("release/crdyboot.efi");
        let dst = efi.join("efi/boot").join(dstname);
        Command::with_args("sudo", &["cp"])
            .add_arg(src.as_str())
            .add_arg(dst.as_str())
            .run()?;
    }

    sign::sign_all(
        efi,
        &opt.secure_boot_shim_key_paths(),
        &["grubx64.efi".into(), "grubia32.efi".into()],
    )?;
}

#[throws]
pub fn sign_kernel_partition(opt: &Opt, partition_device_path: &Utf8Path) {
    let tmp_dir = tempfile::tempdir()?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

    let futility = opt.futility_executable_path();
    let futility = futility.as_str();

    // TODO: for now just use a pregenerated test keys.
    let test_data = opt.vboot_path().join("test_data");
    let kernel_key_public = test_data.join("kernel_key.vbpubk");
    let kernel_data_key_private = test_data.join("kernel_data_key.vbprivk");
    let kernel_data_key_keyblock = test_data.join("kernel_data_key.keyblock");

    let unsigned_kernel_partition = tmp_path.join("kernel_partition");
    let vmlinuz = tmp_path.join("vmlinuz");
    let bootloader = tmp_path.join("bootloader");
    let config = tmp_path.join("config");
    let signed_kernel_partition = tmp_path.join("kernel_partition.signed");

    // The bootloader isn't actually used, so just write an
    // placeholder file. (Can't be empty as futility
    // rejects it.)
    fs::write(&bootloader, "not a real bootloader")?;

    // Copy the whole partition to a temporary file.
    Command::with_args(
        "sudo",
        &[
            "cp",
            partition_device_path.as_str(),
            unsigned_kernel_partition.as_str(),
        ],
    )
    .run()?;

    // Get the kernel command line and write it to a file.
    let output = Command::with_args(
        "sudo",
        &[
            futility,
            "vbutil_kernel",
            "--verify",
            unsigned_kernel_partition.as_str(),
            "--verbose",
        ],
    )
    .enable_capture()
    .run()?;
    let stdout = output.stdout_string_lossy();
    let command_line = stdout.lines().last().unwrap();
    fs::write(&config, command_line)?;

    // Extract vmlinuz.
    Command::with_args(
        "sudo",
        &[
            futility,
            "vbutil_kernel",
            "--get-vmlinuz",
            unsigned_kernel_partition.as_str(),
            "--vmlinuz-out",
            vmlinuz.as_str(),
        ],
    )
    .run()?;

    // TODO: give it a fake version for now.
    let version = 0x1988;

    // Sign it.
    #[rustfmt::skip]
    Command::with_args("sudo", &[futility, "vbutil_kernel",
        "--pack", signed_kernel_partition.as_str(),
        "--keyblock", kernel_data_key_keyblock.as_str(),
        "--signprivate", kernel_data_key_private.as_str(),
        "--version", &version.to_string(),
        "--vmlinuz", vmlinuz.as_str(),
        "--bootloader", bootloader.as_str(),
        "--config", config.as_str(),
        // TODO: the kernel is actually amd64, but pass in
        // arm64 so that vbutil won't do all the kernel
        // munging stuff it wants to.
        "--arch", "arm64"]).run()?;

    // Verify it.
    Command::with_args(
        "sudo",
        &[
            futility,
            "vbutil_kernel",
            "--verify",
            signed_kernel_partition.as_str(),
            "--signpubkey",
            kernel_key_public.as_str(),
        ],
    )
    .run()?;

    // Copy it back to the partition.
    Command::with_args(
        "sudo",
        &[
            "cp",
            signed_kernel_partition.as_str(),
            partition_device_path.as_str(),
        ],
    )
    .run()?;
}
