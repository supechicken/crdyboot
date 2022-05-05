use crate::arch::Arch;
use crate::config::Config;
use crate::loopback::{LoopbackDevice, PartitionPaths};
use crate::mount::Mount;
use crate::sign;
use anyhow::Error;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fehler::throws;
use fs_err as fs;
use std::fmt;

enum GptPartitionType {
    EfiSystem,
    ChromeOsKernel,
}

impl fmt::Display for GptPartitionType {
    #[throws(fmt::Error)]
    fn fmt(&self, f: &mut fmt::Formatter) {
        match self {
            GptPartitionType::EfiSystem => {
                write!(f, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b")?;
            }
            GptPartitionType::ChromeOsKernel => {
                write!(f, "fe3a2a5d-4f32-41a7-b725-accc3285a309")?;
            }
        }
    }
}

struct PartitionSettings {
    label: &'static str,
    start: &'static str,
    end: &'static str,
    type_guid: Option<GptPartitionType>,
    partition_guid: Option<&'static str>,
    set_successful_boot_bit: bool,
    // 15: highest, 1: lowest, 0: not bootable.
    priority: Option<u8>,
}

struct Disk {
    path: Utf8PathBuf,
    num_partitions: u32,
}

impl Disk {
    #[throws]
    fn create(path: Utf8PathBuf, size: &str) -> Disk {
        // Delete the file if it already exists.
        if path.exists() {
            fs::remove_file(&path)?;
        }

        // Generate empty image.
        Command::with_args("truncate", &["--size", size, path.as_str()])
            .run()?;

        Disk {
            path,
            num_partitions: 0,
        }
    }

    #[throws]
    fn add_partition(&mut self, settings: PartitionSettings) -> u32 {
        // Get the partition number (starts at one, not zero).
        let part_num = self.num_partitions + 1;

        // Create a single partition.
        Command::with_args(
            "sgdisk",
            &[
                &format!(
                    "--new={}:{}:{}",
                    part_num, settings.start, settings.end
                ),
                self.path.as_str(),
            ],
        )
        .run()?;

        self.num_partitions += 1;

        // Set the partition label.
        Command::with_args(
            "sgdisk",
            &[
                &format!("--change-name={}:{}", part_num, settings.label),
                self.path.as_str(),
            ],
        )
        .run()?;

        // Set partition type.
        if let Some(guid) = settings.type_guid {
            Command::with_args(
                "sgdisk",
                &[
                    &format!("--typecode={}:{}", part_num, guid),
                    self.path.as_str(),
                ],
            )
            .run()?;
        }

        // Set partition GUID.
        if let Some(guid) = settings.partition_guid {
            Command::with_args(
                "sgdisk",
                &[
                    &format!("--partition-guid={}:{}", part_num, guid),
                    self.path.as_str(),
                ],
            )
            .run()?;
        }

        #[throws]
        fn set_bit(disk: &Disk, part_num: u32, bit_num: u8) {
            Command::with_args(
                "sgdisk",
                &[
                    "-A",
                    &format!("{}:set:{}", part_num, bit_num),
                    disk.path.as_str(),
                ],
            )
            .run()?;
        }

        if settings.set_successful_boot_bit {
            set_bit(self, part_num, 56)?;
        }

        if let Some(priority) = settings.priority {
            // Only priority 1 supported for now.
            assert_eq!(priority, 1);
            set_bit(self, part_num, 48)?;
        }

        part_num
    }
}

#[throws]
pub fn gen_vboot_test_disk(conf: &Config) {
    // 16MiB kernel partition, plus some extra space for GPT.
    let mut disk = Disk::create(conf.vboot_test_disk_path(), "18MiB")?;

    // Create kernel partition.
    let part_num = disk.add_partition(PartitionSettings {
        label: "KERN-A",
        start: "1MiB",
        end: "17MiB",
        type_guid: Some(GptPartitionType::ChromeOsKernel),
        // The specific value doesn't matter here, but must match the
        // partition GUID in the vboot test `test_load_kernel`.
        partition_guid: Some("c6fbb888-1b6d-4988-a66e-ace443df68f4"),
        set_successful_boot_bit: true,
        priority: Some(1),
    })?;

    let vboot_disk_lo_dev = LoopbackDevice::new(&disk.path)?;
    let cloudready_lo_dev = LoopbackDevice::new(conf.disk_path())?;

    // Copy a kernel partition from the cloudready disk to the new disk.
    Command::with_args(
        "sudo",
        &[
            "cp",
            cloudready_lo_dev.partition_paths().kern_a.as_str(),
            vboot_disk_lo_dev.partition_device(part_num).as_str(),
        ],
    )
    .run()?;
}

#[throws]
pub fn gen_enroller_disk(conf: &Config) {
    let mut disk = Disk::create(conf.enroller_disk_path(), "4MiB")?;

    // Create a single bootable partition.
    let part_num = disk.add_partition(PartitionSettings {
        label: "boot",
        start: "2048s",
        end: "-2048s",
        type_guid: Some(GptPartitionType::EfiSystem),
        partition_guid: None,
        set_successful_boot_bit: false,
        priority: None,
    })?;

    let lo_dev = LoopbackDevice::new(&disk.path)?;

    // Format the partition.
    Command::with_args(
        "sudo",
        &["mkfs.fat", lo_dev.partition_device(part_num).as_str()],
    )
    .run()?;

    // Mount the partition.
    let esp_mount = Mount::new(&lo_dev.partition_device(part_num))?;
    let esp = esp_mount.mount_point();

    // Create the standard boot directory.
    let boot_dir = esp.join("efi/boot");
    Command::with_args("sudo", &["mkdir", "-p", boot_dir.as_str()]).run()?;

    // Copy in the two enroller executables.
    for arch in Arch::all() {
        let src = conf.target_exec_path(arch, "enroller.efi");
        let dst = boot_dir.join(arch.efi_file_name("boot"));
        Command::with_args("sudo", &["cp", src.as_str(), dst.as_str()])
            .run()?;
    }
}

/// Replace both grub executables with crdyboot.
#[throws]
pub fn copy_in_crdyboot(conf: &Config, partitions: &PartitionPaths) {
    let efi_mount = Mount::new(&partitions.efi)?;
    let efi = efi_mount.mount_point();

    let mut dst_names = Vec::new();

    for arch in Arch::all() {
        let src = conf.target_exec_path(arch, "crdyboot.efi");

        let dst_name = arch.efi_file_name("grub");
        dst_names.push(dst_name.clone());

        let dst = efi.join("efi/boot").join(dst_name);

        Command::with_args("sudo", &["cp"])
            .add_arg(src.as_str())
            .add_arg(dst.as_str())
            .run()?;
    }

    sign::sign_all(efi, &conf.secure_boot_shim_key_paths(), &dst_names)?;
}

#[throws]
pub fn build_futility(conf: &Config) {
    Command::with_args(
        "make",
        &[
            "-C",
            conf.vboot_reference_path().as_str(),
            conf.futility_executable_path().as_str(),
        ],
    )
    .run()?;
}

#[throws]
pub fn sign_kernel_partition(conf: &Config, partition_device_path: &Utf8Path) {
    let tmp_dir = tempfile::tempdir()?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

    let futility = conf.futility_executable_path();
    let futility = futility.as_str();

    // TODO: for now just use a pregenerated test keys.
    let test_data = conf.vboot_path().join("test_data");
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

    build_futility(conf)?;

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
