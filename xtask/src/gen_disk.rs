// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::{Config, EfiExe};
use crate::mount::Mount;
use crate::secure_boot::{self, SecureBootKeyPaths};
use crate::vm_test::Operation;
use anyhow::{bail, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fatfs::{FileSystem, FormatVolumeOptions, FsOptions, ReadWriteSeek};
use fs_err::{self as fs, File, OpenOptions};
use gpt_disk_types::{guid, BlockSize, GptPartitionType, Guid, Lba, LbaRangeInclusive};
use gptman::{GPTPartitionEntry, GPT};
use object::read::pe::PeFile64;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::{Range, RangeInclusive};
use tempfile::TempDir;

const SECTOR_SIZE: u64 = 512;

/// Create an empty file with the given size (using the `truncate`
/// command). This will delete the file first if it already exists.
fn create_empty_file_with_size(path: &Utf8Path, size: &str) -> Result<()> {
    // Delete the file if it already exists.
    if path.exists() {
        fs::remove_file(path)?;
    }

    // Generate empty image.
    Command::with_args("truncate", ["--size", size, path.as_str()]).run()?;

    Ok(())
}

struct PartitionSettings<'a> {
    label: &'a str,
    data_range: PartitionDataRange,
    type_guid: GptPartitionType,
    guid: Guid,
    set_successful_boot_bit: bool,
    // 15: highest, 1: lowest, 0: not bootable.
    priority: Option<u8>,
    // Contents of the partition.
    data: &'a [u8],
}

impl<'a> PartitionSettings<'a> {
    fn attribute_bits(&self) -> u64 {
        let mut attribute_bits: u64 = 0;

        // ChromeOS-specific attributes.
        if self.set_successful_boot_bit {
            attribute_bits |= 1 << 56;
        }
        if let Some(priority) = self.priority {
            assert!((1..=15).contains(&priority));
            let priority: u64 = priority.into();
            attribute_bits |= priority << 48;
        }

        attribute_bits
    }
}

/// Open `path` in read+write mode, without truncating the existing
/// file. This will return an error if the file doesn't exist.
fn open_rw(path: &Utf8Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?)
}

struct DiskSettings<'a> {
    path: &'a Utf8Path,
    size: &'a str,
    guid: Guid,
    partitions: &'a [PartitionSettings<'a>],
}

impl<'a> DiskSettings<'a> {
    fn create(&self) -> Result<()> {
        create_empty_file_with_size(self.path, self.size)?;

        let mut disk_file = open_rw(self.path)?;

        let mut gpt = GPT::new_from(&mut disk_file, SECTOR_SIZE, self.guid.to_bytes())?;

        for (i, part) in self.partitions.iter().enumerate() {
            // GPT partitions start at 1.
            let part_num: u32 = (i + 1).try_into().unwrap();

            // Create the partition entry.
            gpt[part_num] = gptman::GPTPartitionEntry {
                partition_type_guid: part.type_guid.0.to_bytes(),
                unique_partition_guid: part.guid.to_bytes(),
                starting_lba: part.data_range.0.start().0,
                ending_lba: part.data_range.0.end().0,
                attribute_bits: part.attribute_bits(),
                partition_name: part.label.into(),
            };

            // Write out the partition data.
            part.data_range
                .write_bytes_to_file(&mut disk_file, part.data)?;
        }

        // Write out the protective MBR and GPT headers.
        GPT::write_protective_mbr_into(&mut disk_file, SECTOR_SIZE)?;
        gpt.write_into(&mut disk_file)?;

        Ok(())
    }
}

/// Convert from MiB to bytes.
fn mib_to_byte(val: u64) -> u64 {
    val * 1024 * 1024
}

#[derive(Debug, Eq, PartialEq)]
struct PartitionDataRange(LbaRangeInclusive);

impl PartitionDataRange {
    fn new(partition: &GPTPartitionEntry) -> Self {
        Self(
            LbaRangeInclusive::new(Lba(partition.starting_lba), Lba(partition.ending_lba)).unwrap(),
        )
    }

    fn from_byte_range(byte_range: Range<u64>) -> Self {
        Self(
            LbaRangeInclusive::from_byte_range(
                byte_range.start..=byte_range.end - 1,
                BlockSize::BS_512,
            )
            .unwrap(),
        )
    }

    fn to_byte_range(&self) -> RangeInclusive<u64> {
        self.0.to_byte_range(BlockSize::BS_512).unwrap()
    }

    fn num_bytes(&self) -> usize {
        self.0
            .num_bytes(BlockSize::BS_512)
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn read_bytes_from_file(&self, f: &mut File) -> Result<Vec<u8>> {
        let mut v = vec![0; self.num_bytes()];
        f.seek(SeekFrom::Start(*self.to_byte_range().start()))?;
        f.read_exact(&mut v)?;
        Ok(v)
    }

    fn write_bytes_to_file(&self, f: &mut File, data: &[u8]) -> Result<()> {
        assert!(data.len() <= self.num_bytes());
        f.seek(SeekFrom::Start(*self.to_byte_range().start()))?;
        Ok(f.write_all(data)?)
    }
}

/// Read data from a reven kernel partition.
fn read_real_kernel_partition(conf: &Config) -> Result<Vec<u8>> {
    let mut f = File::open(conf.disk_path())?;
    let gpt = gptman::GPT::find_from(&mut f)?;

    let kern_a = &gpt[2];
    assert_eq!(kern_a.partition_name.as_str(), "KERN-A");

    let kern_a_data_range = PartitionDataRange::new(kern_a);
    kern_a_data_range.read_bytes_from_file(&mut f)
}

pub fn copy_partition_from_disk_to_disk(
    dst_disk: &Utf8Path,
    src_disk: &Utf8Path,
    partition_name: &str,
) -> Result<()> {
    let mut dst_disk = open_rw(dst_disk)?;
    let mut src_disk = File::open(src_disk)?;
    let dst_gpt = gptman::GPT::find_from(&mut dst_disk)?;
    let src_gpt = gptman::GPT::find_from(&mut src_disk)?;

    let src_part = src_gpt
        .iter()
        .map(|(_, entry)| entry)
        .find(|entry| entry.partition_name.as_str() == partition_name)
        .context(format!("failed to find partition {partition_name} in src"))?;
    let dst_part = dst_gpt
        .iter()
        .map(|(_, entry)| entry)
        .find(|entry| entry.partition_name.as_str() == partition_name)
        .context(format!("failed to find partition {partition_name} in dst"))?;

    let src_range = PartitionDataRange::new(src_part);
    let dst_range = PartitionDataRange::new(dst_part);

    if src_range != dst_range {
        bail!("src and dst partitions have different ranges");
    }

    let data = src_range.read_bytes_from_file(&mut src_disk)?;
    dst_range.write_bytes_to_file(&mut dst_disk, &data)?;

    Ok(())
}

pub fn gen_vboot_test_disk(conf: &Config) -> Result<()> {
    let kern_a = read_real_kernel_partition(conf)?;

    let kernel_partition_size_in_mib = 64;

    let disk = DiskSettings {
        path: &conf.vboot_test_disk_path(),
        // Kernel partition size plus extra space for GPT headers.
        size: &format!("{}MiB", kernel_partition_size_in_mib + 2),
        // Arbitrary GUID.
        guid: guid!("d24199e7-33f0-4409-b677-1c04683552c5"),
        partitions: &[PartitionSettings {
            label: "KERN-A",
            data_range: PartitionDataRange::from_byte_range(
                mib_to_byte(1)..mib_to_byte(kernel_partition_size_in_mib + 1),
            ),
            type_guid: GptPartitionType::CHROME_OS_KERNEL,
            // Arbitrary, but must match the partition GUID in the vboot
            // test `test_load_kernel`.
            guid: guid!("c6fbb888-1b6d-4988-a66e-ace443df68f4"),
            set_successful_boot_bit: true,
            // Must be set to something between 1 and 15, but otherwise
            // arbitrary.
            priority: Some(1),
            data: &kern_a,
        }],
    };
    disk.create()
}

/// Generate a simple EFI system partition FAT file system
/// of size `mib_size` with the EFI/BOOT directories created.
fn gen_base_esp_fs(mib_size: u64) -> Result<Vec<u8>> {
    let mut esp_part_data = vec![0; mib_to_byte(mib_size).try_into().unwrap()];

    {
        let esp_part_cursor = Cursor::new(&mut esp_part_data);
        fatfs::format_volume(esp_part_cursor, FormatVolumeOptions::new())?;
    }

    {
        let sys_part_cursor = Cursor::new(&mut esp_part_data);
        let sys_part_fs = FileSystem::new(sys_part_cursor, FsOptions::new())?;
        let root_dir = sys_part_fs.root_dir();
        root_dir.create_dir("EFI")?.create_dir("BOOT")?;
    }

    Ok(esp_part_data)
}

// Create a disk image that recreates disk state of a device after running the
// FRD agent. It contains 2 partitions:
// * EFI System Partition - to hold crdyshim, crdyboot.
// * Basic Data Partition - to hold flexor_vmlinuz, ChromeOS flex image.
// Note: This function only creates the partitions and the `EFI/BOOT` directories.
pub fn gen_flexor_disk_image(conf: &Config) -> Result<()> {
    let esp_part_data = gen_base_esp_fs(90)?;

    // Generate FAT file system for the basic data partition.
    let mut basic_part_data = vec![0; mib_to_byte(108).try_into().unwrap()];
    let basic_part_cursor = Cursor::new(&mut basic_part_data);
    fatfs::format_volume(basic_part_cursor, FormatVolumeOptions::new())?;

    let disk = DiskSettings {
        path: &conf.flexor_disk_path(),
        // 200 MiB should be sufficient to store the bootloaders and the flexor kernel.
        size: "200MiB",
        // Arbitrary GUID.
        guid: guid!("a2d46164-7684-4423-b165-5f6188732b93"),
        partitions: &[
            PartitionSettings {
                label: "EFI System Partition",
                data_range: PartitionDataRange::from_byte_range(mib_to_byte(1)..mib_to_byte(91)),
                type_guid: GptPartitionType::EFI_SYSTEM,
                // Arbitrary GUID.
                guid: guid!("67f80b17-ae26-471c-83c5-2424f9f12874"),
                set_successful_boot_bit: false,
                priority: None,
                data: &esp_part_data,
            },
            PartitionSettings {
                label: "Basic Data Partition",
                data_range: PartitionDataRange::from_byte_range(mib_to_byte(91)..mib_to_byte(199)),
                type_guid: GptPartitionType::BASIC_DATA,
                // Arbitrary GUID.
                guid: guid!("73908410-c876-4ba9-b0ef-136baf49f21a"),
                set_successful_boot_bit: false,
                priority: None,
                data: &basic_part_data,
            },
        ],
    };
    disk.create()?;

    Ok(())
}

pub fn gen_stateful_test_partition(conf: &Config) -> Result<()> {
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();

    // Create the empty filesystem.
    create_empty_file_with_size(&conf.stateful_test_partition_path(), "1MiB")?;
    Command::with_args(
        "mkfs.ext4",
        [
            // Set ownership in the filesystem to match the current user
            // instead of root. Mounting still requires root, but
            // unprivileged `std::fs` operations can be used to edit the
            // filesystem.
            "-E",
            &format!("root_owner={uid}:{gid}"),
            conf.stateful_test_partition_path().as_str(),
        ],
    )
    .run()?;

    let mount = Mount::new(&conf.stateful_test_partition_path())?;

    // Create the capsule directory.
    let capsules_path = mount
        .mount_point()
        .join("unencrypted/uefi_capsule_updates/EFI/chromeos/fw");
    fs::create_dir_all(&capsules_path)?;
    fs::write(
        capsules_path.join("fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523.cap"),
        "test capsule data",
    )?;

    Ok(())
}

/// Generate the EFI system partition FAT file system containing the
/// enroller executables.
fn gen_enroller_fs(conf: &Config) -> Result<Vec<u8>> {
    let mut sys_part_data = vec![0; mib_to_byte(2).try_into().unwrap()];

    {
        let sys_part_cursor = Cursor::new(&mut sys_part_data);
        fatfs::format_volume(sys_part_cursor, FormatVolumeOptions::new())?;
    }

    {
        let sys_part_cursor = Cursor::new(&mut sys_part_data);
        let sys_part_fs = FileSystem::new(sys_part_cursor, FsOptions::new())?;
        let root_dir = sys_part_fs.root_dir();
        let efi_dir = root_dir.create_dir("EFI")?;
        let boot_dir = efi_dir.create_dir("BOOT")?;

        // Copy in the two enroller executables.
        for arch in Arch::all() {
            let src_path = conf.target_exec_path(arch, EfiExe::Enroller);
            let src_data = fs::read(src_path)?;

            let dst_file_name = arch.efi_file_name("boot");
            let mut dst_file = boot_dir.create_file(&dst_file_name)?;

            dst_file.write_all(&src_data)?;
        }
    }

    Ok(sys_part_data)
}

pub fn gen_enroller_disk(conf: &Config) -> Result<()> {
    let part_data = gen_enroller_fs(conf)?;

    let disk = DiskSettings {
        path: &conf.enroller_disk_path(),
        // 2MiB system partition, plus extra space for GPT headers.
        size: "4MiB",
        // Arbitrary GUID.
        guid: guid!("4345f688-5dac-4ab0-a596-ad5bcaf30163"),
        partitions: &[PartitionSettings {
            label: "boot",
            data_range: PartitionDataRange::from_byte_range(mib_to_byte(1)..mib_to_byte(3)),
            type_guid: GptPartitionType::EFI_SYSTEM,
            // Arbitrary GUID.
            guid: guid!("21049f0f-75a3-4fba-beff-569ba248a19d"),
            set_successful_boot_bit: false,
            priority: None,
            data: &part_data,
        }],
    };
    disk.create()
}

/// Read a file from the EFI System Partition of a disk.
///
/// `file_path` is the path to the file inside the ESP. The file content is
/// returned as a vector.
fn read_file_from_esp(disk_path: &Utf8Path, file_path: &str) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    modify_system_partition(disk_path, |root_dir| {
        let mut file_handle = root_dir.open_file(file_path).unwrap();
        file_handle.read_to_end(&mut buffer)?;
        Ok(())
    })?;

    Ok(buffer)
}

type FatDirOnVec<'a, 'b> = fatfs::Dir<'a, Cursor<&'b mut Vec<u8>>>;

/// Modify a fat filesystem stored in the backing vector.
fn modify_filesystem<F>(data: &mut Vec<u8>, mut modify: F) -> Result<()>
where
    F: FnMut(FatDirOnVec) -> Result<()>,
{
    let sys_part_cursor = Cursor::new(data);
    let sys_part_fs = FileSystem::new(sys_part_cursor, FsOptions::new())?;
    let root_dir = sys_part_fs.root_dir();
    modify(root_dir)
}

/// Modify data in the EFI system partition FAT file system.
///
/// This loads the partition into memory and opens it with `fatfs`. The
/// root directory handle is then passed to the `modify` function, and
/// the caller can update the contents as desired. Then the partition is
/// written back out to disk.
fn modify_system_partition<F>(disk_path: &Utf8Path, mut modify: F) -> Result<()>
where
    F: FnMut(FatDirOnVec) -> Result<()>,
{
    let mut disk_file = open_rw(disk_path)?;
    let gpt = GPT::read_from(&mut disk_file, SECTOR_SIZE)?;
    let partition_type = GptPartitionType::EFI_SYSTEM.0.to_bytes();
    let sys_part = gpt
        .iter()
        .find(|(_, part)| part.partition_type_guid == partition_type)
        .expect("system partition not found")
        .1;
    let sys_data_range = PartitionDataRange::new(sys_part);

    // Load the entire partition into memory.
    let mut sys_part_data = sys_data_range.read_bytes_from_file(&mut disk_file)?;

    modify_filesystem(&mut sys_part_data, &mut modify)?;

    // Write the entire partition back out.
    sys_data_range.write_bytes_to_file(&mut disk_file, &sys_part_data)
}

/// Create a file named `file_name` to a FAT filesystem in `dir`.
///
/// If the file already exists, it will be deleted before writing the
/// new file.
fn fat_write_file<T: ReadWriteSeek>(
    dir: &fatfs::Dir<T>,
    file_name: &str,
    data: &[u8],
) -> Result<()> {
    // Delete the file if it already exists.
    let _ = dir.remove(file_name);

    // Write out the new data.
    let mut f = dir.create_file(file_name)?;
    f.write_all(data)?;

    Ok(())
}

/// Copy all the files in `src_dir` to the `EFI/BOOT` directory on the
/// system partition in the disk image at `disk_path`.
pub fn update_boot_files(disk_path: &Utf8Path, src_dir: &Utf8Path) -> Result<()> {
    modify_system_partition(disk_path, |root_dir| {
        let dst_efi_dir = root_dir.open_dir("EFI")?;
        let dst_boot_dir = dst_efi_dir.open_dir("BOOT")?;

        for entry in fs::read_dir(src_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_str().unwrap();

            println!("copying {} to EFI/BOOT", entry.path().display());

            let src = fs::read(entry.path())?;

            fat_write_file(&dst_boot_dir, file_name, &src)?;
        }

        Ok(())
    })
    .context("failed to update boot files")
}

/// Copy all the files in `src_dir` to the `EFI/BOOT` directory on the EFI
/// system partition in the disk image at `flexor_disk_path`.
pub fn update_flexor_boot_files(flexor_disk_path: &Utf8PathBuf, src_dir: &Utf8Path) -> Result<()> {
    modify_system_partition(flexor_disk_path, |root_dir| {
        let dst_efi_dir = root_dir.open_dir("EFI")?;
        let dst_boot_dir = dst_efi_dir.open_dir("BOOT")?;

        for entry in fs::read_dir(src_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_str().unwrap();

            println!(
                "copying {} to EFI/BOOT in the flexor disk image.",
                entry.path().display()
            );

            let src = fs::read(entry.path())?;

            fat_write_file(&dst_boot_dir, file_name, &src)?;
        }
        Ok(())
    })
    .context("failed to update flexor boot files")
}

/// Copy `vmlinuz.A` from `disk_path` to `flexor_disk_path` with the name
/// `flexor_vmlinuz`.
pub fn update_flexor_disk_with_test_kernel(
    disk_path: &Utf8Path,
    flexor_disk_path: &Utf8PathBuf,
) -> Result<()> {
    modify_system_partition(flexor_disk_path, |root_dir| {
        let vmlinuz_a = read_file_from_esp(disk_path, r"/syslinux/vmlinuz.A")?;

        // Write `vmlinuz.A` as `flexor_vmlinuz`, for testing purposes.
        fat_write_file(&root_dir, "flexor_vmlinuz", &vmlinuz_a)?;

        Ok(())
    })
    .context("failed to update flexor disk image with the test kernel.")
}

pub struct SignAndUpdateBootloader<'a> {
    /// Path to a reven disk image.
    pub disk_path: &'a Utf8Path,

    /// Path to flexor disk image.
    pub flexor_disk_path: Utf8PathBuf,

    /// Keys to sign with.
    pub key_paths: SecureBootKeyPaths,

    /// Mapping from source file path (an unsigned bootloader
    /// executable) to the destination file name (within the EFI/BOOT
    /// subdirectory of the system partition).
    pub mapping: Vec<(Utf8PathBuf, String)>,
}

impl<'a> SignAndUpdateBootloader<'a> {
    /// Sign each source file (in a temporary directory, source files
    /// are not modified), then copy the signed files into the system
    /// partition of the disk image.
    pub fn run(&self) -> Result<()> {
        let tmp_dir = TempDir::new()?;
        let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

        for (src, dst_name) in &self.mapping {
            let signed_src = tmp_path.join(dst_name);
            secure_boot::sign(src, &signed_src, &self.key_paths)?;
        }

        update_boot_files(self.disk_path, tmp_path)?;
        update_flexor_boot_files(&self.flexor_disk_path, tmp_path)
    }
}

/// Whether to enable verbose runtime logs in crdyboot.
pub struct VerboseRuntimeLogs(pub bool);

/// Add or remove the `crdyboot_verbose` file from the ESP.
pub fn update_verbose_boot_file(disk_path: &Utf8Path, verbose: VerboseRuntimeLogs) -> Result<()> {
    modify_system_partition(disk_path, |root_dir| {
        let efi_dir = root_dir.open_dir("EFI")?;
        let boot_dir = efi_dir.open_dir("BOOT")?;
        let verbose_name = "crdyboot_verbose";

        // Unconditionally delete the file (ignore any errors since it
        // might not exist).
        let _ = boot_dir.remove(verbose_name);
        // Create the file if needed.
        if verbose.0 {
            boot_dir.create_file(verbose_name)?;
        }
        Ok(())
    })
}

/// Sign the bootloaders (both crdyshim and crdyboot) and copy them into
/// the disk image.
pub fn sign_and_copy_bootloaders(conf: &Config) -> Result<()> {
    SignAndUpdateBootloader {
        disk_path: conf.disk_path(),
        flexor_disk_path: conf.flexor_disk_path(),
        key_paths: conf.secure_boot_root_key_paths(),
        mapping: Arch::all()
            .iter()
            .map(|arch| {
                (
                    conf.target_exec_path(*arch, EfiExe::Crdyshim),
                    arch.efi_file_name("boot"),
                )
            })
            .collect(),
    }
    .run()?;

    SignAndUpdateBootloader {
        disk_path: conf.disk_path(),
        flexor_disk_path: conf.flexor_disk_path(),
        key_paths: conf.secure_boot_shim_key_paths(),
        mapping: Arch::all()
            .iter()
            .map(|arch| {
                (
                    conf.target_exec_path(*arch, EfiExe::Crdyboot),
                    arch.efi_file_name("crdyboot"),
                )
            })
            .collect(),
    }
    .run()
}

pub fn sign_kernel_partition(conf: &Config, partition_name: &str) -> Result<()> {
    let mut disk_file = open_rw(conf.disk_path())?;
    let gpt = GPT::read_from(&mut disk_file, SECTOR_SIZE)?;
    let kern_part = gpt
        .iter()
        .find(|part| part.1.partition_name.as_str() == partition_name)
        .unwrap()
        .1;
    let kern_data_range = PartitionDataRange::new(kern_part);

    let tmp_dir = tempfile::tempdir()?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

    let futility = conf.futility_executable_path();
    let futility = futility.as_str();

    // Use test keys from vboot_reference.
    let kernel_key = &conf.kernel_key_paths();
    let kernel_data_key = &conf.kernel_data_key_paths();

    let unsigned_kernel_partition = tmp_path.join("kernel_partition");
    let vmlinuz = tmp_path.join("vmlinuz");
    let config = tmp_path.join("config");
    let signed_kernel_partition = tmp_path.join("kernel_partition.signed");

    // Copy the whole partition to a temporary file.
    let orig_kern_data = kern_data_range.read_bytes_from_file(&mut disk_file)?;
    fs::write(&unsigned_kernel_partition, orig_kern_data)?;

    // Get the kernel command line and write it to a file.
    let output = Command::with_args(
        futility,
        [
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
    // Reven builds enable the `quiet` arg so that the EFI stub doesn't
    // print messages. However, for VM tests in this repo it's useful to
    // show those messages so we can assert the EFI stub has started
    // (the alternative is to wait for SSH to fully come up, which would
    // make tests take much longer).
    let command_line = command_line.replace("quiet ", "");
    fs::write(&config, command_line)?;

    // Extract vmlinuz.
    Command::with_args(
        futility,
        [
            "vbutil_kernel",
            "--get-vmlinuz",
            unsigned_kernel_partition.as_str(),
            "--vmlinuz-out",
            vmlinuz.as_str(),
        ],
    )
    .run()?;

    // Arbitrary version.
    let version = 0x1;

    // Sign it.
    #[rustfmt::skip]
    Command::with_args(futility, ["vbutil_kernel",
        "--pack", signed_kernel_partition.as_str(),
        "--keyblock", kernel_data_key.keyblock.as_ref().unwrap().as_str(),
        "--signprivate", kernel_data_key.vbprivk.as_str(),
        "--version", &version.to_string(),
        "--vmlinuz", vmlinuz.as_str(),
        "--config", config.as_str(),
        "--arch", "amd64"]).run()?;

    // Verify it.
    Command::with_args(
        futility,
        [
            "vbutil_kernel",
            "--verify",
            signed_kernel_partition.as_str(),
            "--signpubkey",
            kernel_key.vbpubk.as_str(),
        ],
    )
    .run()?;

    // Write the updated kernel partition back to the disk image.
    let signed_kern_data = fs::read(signed_kernel_partition)?;
    kern_data_range.write_bytes_to_file(&mut disk_file, &signed_kern_data)
}

/// Intentionally corrupt one byte in a disk's KERN-A kernel data so
/// that the kernel data signature is no longer valid.
pub fn corrupt_kern_a(disk_path: &Utf8Path) -> Result<()> {
    let mut disk_file = open_rw(disk_path)?;
    let kern_data_range = {
        let gpt = GPT::read_from(&mut disk_file, SECTOR_SIZE)?;
        let kern_part = gpt
            .iter()
            .find(|part| part.1.partition_name.as_str() == "KERN-A")
            .unwrap()
            .1;
        PartitionDataRange::new(kern_part).to_byte_range()
    };

    // Get the offset within the partition of the byte to modify. The
    // exact byte doesn't matter much, but we want it far enough in the
    // partition so that we're modifying actual kernel data, not the
    // kernel partition headers.
    let offset = mib_to_byte(1);

    // Read the byte's current value.
    disk_file.seek(SeekFrom::Start(kern_data_range.start() + offset))?;
    let mut byte = [0];
    disk_file.read_exact(&mut byte)?;

    // Flip all the bits.
    byte[0] = !byte[0];

    // Write out the new value.
    disk_file.seek(SeekFrom::Start(kern_data_range.start() + offset))?;
    disk_file.write_all(&byte)?;
    disk_file.sync_all()?;

    Ok(())
}

/// Parameter used in `corrupt_pubkey_section`. If true, the bootloader
/// will be re-signed after it is modified.
pub struct SignAfterCorrupt(pub bool);

/// Modify one byte at the start of crdyboot's `.vbpubk` section in a
/// disk image. If `sign_after_corrupt` is true, crdyboot will be
/// re-signed after this modification.
pub fn corrupt_pubkey_section(
    conf: &Config,
    disk_path: &Utf8Path,
    sign_after_corrupt: SignAfterCorrupt,
) -> Result<()> {
    // Get the expected section data for the vbpubk. This matches the
    // data produced by crdyboot's build.rs.
    let mut expected_pubkey = fs::read(conf.kernel_key_paths().vbpubk)?;
    expected_pubkey.resize(8192, 0);

    modify_system_partition(disk_path, |root_dir| {
        let efi_dir = root_dir.open_dir("EFI")?;
        let boot_dir = efi_dir.open_dir("BOOT")?;

        let file_name = "crdybootx64.efi";
        let mut data = Vec::new();
        {
            let mut f = boot_dir.open_file(file_name)?;
            f.read_to_end(&mut data)?;
        }

        // Find the offset and size of the `.vbpubk` section.
        let pe = PeFile64::parse(&*data)?;
        let section = pe
            .section_table()
            .iter()
            .find(|section| section.raw_name() == b".vbpubk")
            .unwrap();
        let (offset, size) = section.pe_file_range();

        // Verify the section contains the expected data.
        let section_data = &mut data[offset as usize..(offset + size) as usize];
        assert_eq!(section_data, expected_pubkey);

        // Modify a single byte at the start of the section. Panic if
        // the byte is already the new value.
        assert_ne!(section_data[0], 1);
        section_data[0] = 1;

        // If requested, re-sign crdyboot so that the first-stage
        // bootloader can still validate it successfully.
        if sign_after_corrupt.0 {
            let tmp_dir = tempfile::tempdir()?;
            let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();
            let unsigned = tmp_path.join("unsigned");
            let signed = tmp_path.join("signed");
            fs::write(&unsigned, data)?;

            secure_boot::sign(&unsigned, &signed, &conf.secure_boot_shim_key_paths())?;

            data = fs::read(signed)?;

            // Write the modified signature out.
            let sig_data = fs::read(tmp_path.join("signed.sig"))?;
            fat_write_file(&boot_dir, &file_name.replace(".efi", ".sig"), &sig_data)?;
        }

        // Write the modified file out.
        fat_write_file(&boot_dir, file_name, &data)?;

        Ok(())
    })
}

/// Delete the crdyboot signatures from the disk (for testing).
pub fn delete_crdyboot_signatures(disk_path: &Utf8Path) -> Result<()> {
    modify_system_partition(disk_path, |root_dir| {
        let efi_dir = root_dir.open_dir("EFI")?;
        let boot_dir = efi_dir.open_dir("BOOT")?;

        boot_dir.remove("crdybootx64.sig")?;
        boot_dir.remove("crdybootia32.sig")?;

        Ok(())
    })
}

/// Corrupt the crdyboot signatures on the disk (for testing).
pub fn corrupt_crdyboot_signatures(disk_path: &Utf8Path) -> Result<()> {
    modify_system_partition(disk_path, |root_dir| {
        let efi_dir = root_dir.open_dir("EFI")?;
        let boot_dir = efi_dir.open_dir("BOOT")?;

        let sig_data = [0xff; 64];

        fat_write_file(&boot_dir, "crdybootx64.sig", &sig_data)?;
        fat_write_file(&boot_dir, "crdybootia32.sig", &sig_data)?;

        Ok(())
    })
}

/// Install the signed `uefi_test_runner` executable as the first-stage
/// bootloader (for VM testing).
pub fn install_uefi_test_tool(conf: &Config, operation: Operation) -> Result<()> {
    modify_system_partition(&conf.test_disk_path(), |root_dir| {
        let efi_dir = root_dir.open_dir("EFI")?;
        let boot_dir = efi_dir.open_dir("BOOT")?;

        // Rename the boot executables to crdyshim.
        boot_dir.rename("bootx64.efi", &boot_dir, "crdyshimx64.efi")?;
        boot_dir.rename("bootia32.efi", &boot_dir, "crdyshimia32.efi")?;

        // Create the test control file.
        fat_write_file(
            &boot_dir,
            "crdy_test_control",
            format!("{operation}\n").as_bytes(),
        )?;

        Ok(())
    })?;

    // Sign the test tool and copy it to the ESP.
    SignAndUpdateBootloader {
        disk_path: &conf.test_disk_path(),
        flexor_disk_path: conf.flexor_disk_path(),
        key_paths: conf.secure_boot_root_key_paths(),
        mapping: Arch::all()
            .iter()
            .map(|arch| {
                (
                    conf.target_exec_path(*arch, EfiExe::UefiTestTool),
                    arch.efi_file_name("boot"),
                )
            })
            .collect(),
    }
    .run()?;

    Ok(())
}

/// Size in MiB of the trivial esp that is generated.
// This must be smaller than 64MiB which is the current partition size
// in the reven layout. It must be larger than the typical bootloader
// and filesystem overhead.
// 2MiB is sufficient with a bit of slack for any dev work.
// This can be removed when the ESP is able to be generated
// at build time (b/388905930).
const TRIVIAL_ESP_MIB: u64 = 2;

/// Generate a data file `esp.img` containing a trivial ESP filesystem
/// with just the bootx86.efi binary.
pub fn gen_trivial_esp_image(conf: &Config, verbose: &VerboseRuntimeLogs) -> Result<()> {
    let mut data = gen_base_esp_fs(TRIVIAL_ESP_MIB)?;

    modify_filesystem(&mut data, |root_dir| {
        let efi_dir = root_dir.open_dir("EFI")?;
        let boot_dir = efi_dir.open_dir("BOOT")?;

        if verbose.0 {
            boot_dir.create_file("crdyboot_verbose")?;
        }
        // Force x64 for now as 32 bit EFI devices aren't used.
        let arch = Arch::X64;
        let src_path = conf.target_exec_path(arch, EfiExe::Crdyboot);
        let src_data = fs::read(src_path)?;
        fat_write_file(&boot_dir, &arch.efi_file_name("boot"), &src_data)
    })
    .context("failed to update boot files")?;

    let path = conf.workspace_path().join("esp.img");
    let mut outfile = File::create(path)?;
    if outfile.write(data.as_slice())? != data.len() {
        bail!("did not write the full ESP data");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_range() {
        let r = PartitionDataRange(LbaRangeInclusive::new(Lba(1), Lba(1)).unwrap());

        assert_eq!(r.num_bytes(), 512);
        assert_eq!(r.to_byte_range(), 512..=1023);

        let r2 = PartitionDataRange::from_byte_range(512..1024);
        assert_eq!(r, r2);
    }
}
