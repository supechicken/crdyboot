// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::Config;
use crate::secure_boot::{self, SecureBootKeyPaths};
use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fatfs::{
    FileSystem, FormatVolumeOptions, FsOptions, LossyOemCpConverter,
    NullTimeProvider, StdIoWrapper,
};
use fs_err::{self as fs, File, OpenOptions};
use gpt_disk_types::{
    guid, BlockSize, GptPartitionType, Guid, Lba, LbaRangeInclusive,
};
use gptman::{GPTPartitionEntry, GPT};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::{Range, RangeInclusive};
use tempfile::TempDir;

const SECTOR_SIZE: u64 = 512;

/// Create an empty file with the given size (using the `truncate`
/// command). This will delete the file first if it already exists.
fn create_empty_file_with_size(path: &Utf8Path, size: &str) -> Result<()> {
    // Delete the file if it already exists.
    if path.exists() {
        fs::remove_file(&path)?;
    }

    // Generate empty image.
    Command::with_args("truncate", &["--size", size, path.as_str()]).run()?;

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

        let mut gpt =
            GPT::new_from(&mut disk_file, SECTOR_SIZE, self.guid.to_bytes())?;

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
            LbaRangeInclusive::new(
                Lba(partition.starting_lba),
                Lba(partition.ending_lba),
            )
            .unwrap(),
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

pub fn gen_vboot_test_disk(conf: &Config) -> Result<()> {
    let kern_a = read_real_kernel_partition(conf)?;

    let disk = DiskSettings {
        path: &conf.vboot_test_disk_path(),
        // 16MiB kernel partition, plus extra space for GPT headers.
        size: "18MiB",
        // Arbitrary GUID.
        guid: guid!("d24199e7-33f0-4409-b677-1c04683552c5"),
        partitions: &[PartitionSettings {
            label: "KERN-A",
            data_range: PartitionDataRange::from_byte_range(
                mib_to_byte(1)..mib_to_byte(17),
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

/// Generate the EFI system partition FAT file system containing the
/// enroller executables.
fn gen_enroller_fs(conf: &Config) -> Result<Vec<u8>> {
    let mut sys_part_data = vec![0; mib_to_byte(2).try_into().unwrap()];

    {
        let mut sys_part_cursor =
            StdIoWrapper::new(Cursor::new(&mut sys_part_data));
        fatfs::format_volume(&mut sys_part_cursor, FormatVolumeOptions::new())?;
    }

    {
        let sys_part_cursor = Cursor::new(&mut sys_part_data);
        let sys_part_fs = FileSystem::new(sys_part_cursor, FsOptions::new())?;
        let root_dir = sys_part_fs.root_dir();
        let efi_dir = root_dir.create_dir("EFI")?;
        let boot_dir = efi_dir.create_dir("BOOT")?;

        // Copy in the two enroller executables.
        for arch in Arch::all() {
            let src_path = conf.target_exec_path(arch, "enroller.efi");
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
            data_range: PartitionDataRange::from_byte_range(
                mib_to_byte(1)..mib_to_byte(3),
            ),
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

/// Modify data in the EFI system partition FAT file system.
///
/// This loads the partition into memory and opens it with `fatfs`. The
/// root directory handle is then passed to the `modify` function, and
/// the caller can update the contents as desired. Then the partition is
/// written back out to disk.
fn modify_system_partition<F>(disk_path: &Utf8Path, modify: F) -> Result<()>
where
    F: Fn(
        fatfs::Dir<
            StdIoWrapper<Cursor<&mut Vec<u8>>>,
            NullTimeProvider,
            LossyOemCpConverter,
        >,
    ) -> Result<()>,
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
    let mut sys_part_data =
        sys_data_range.read_bytes_from_file(&mut disk_file)?;

    {
        let sys_part_cursor = Cursor::new(&mut sys_part_data);
        let sys_part_fs = FileSystem::new(sys_part_cursor, FsOptions::new())?;
        let root_dir = sys_part_fs.root_dir();
        modify(root_dir)?;
    }

    // Write the entire partition back out.
    sys_data_range.write_bytes_to_file(&mut disk_file, &sys_part_data)
}

/// Copy all the files in `src_dir` to the `EFI/BOOT` directory on the
/// system partition in the disk image at `disk_path`.
pub fn update_boot_files(
    disk_path: &Utf8Path,
    src_dir: &Utf8Path,
) -> Result<()> {
    modify_system_partition(disk_path, |root_dir| {
        let dst_efi_dir = root_dir.open_dir("EFI")?;
        let dst_boot_dir = dst_efi_dir.open_dir("BOOT")?;

        for entry in fs::read_dir(src_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_str().unwrap();

            let src = fs::read(entry.path())?;
            let mut dst = dst_boot_dir.open_file(file_name)?;

            // Clear out existing data, then copy in the new data.
            dst.truncate()?;
            dst.write_all(&src)?;
        }

        Ok(())
    })
    .context("failed to update boot files")
}

pub struct SignAndUpdateBootloader<'a> {
    /// Path to a reven disk image.
    pub disk_path: &'a Utf8Path,

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

        update_boot_files(self.disk_path, tmp_path)
    }
}

/// Sign crdyboot, then copy it into the disk image under the "grub"
/// name (since that's what shim currently chains to).
pub fn copy_in_crdyboot(conf: &Config) -> Result<()> {
    SignAndUpdateBootloader {
        disk_path: conf.disk_path(),
        key_paths: conf.secure_boot_shim_key_paths(),
        mapping: Arch::all()
            .iter()
            .map(|arch| {
                (
                    conf.target_exec_path(*arch, "crdyboot.efi"),
                    arch.efi_file_name("grub"),
                )
            })
            .collect(),
    }
    .run()
}

pub fn sign_kernel_partition(
    conf: &Config,
    partition_name: &str,
) -> Result<()> {
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

    // TODO: for now just use a pregenerated test keys.
    let kernel_key = &conf.kernel_key_paths();
    let kernel_data_key = &conf.kernel_data_key_paths();

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
    let orig_kern_data =
        kern_data_range.read_bytes_from_file(&mut disk_file)?;
    fs::write(&unsigned_kernel_partition, orig_kern_data)?;

    // Get the kernel command line and write it to a file.
    let output = Command::with_args(
        futility,
        &[
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
        futility,
        &[
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
    Command::with_args(futility, &["vbutil_kernel",
        "--pack", signed_kernel_partition.as_str(),
        "--keyblock", kernel_data_key.keyblock.as_ref().unwrap().as_str(),
        "--signprivate", kernel_data_key.vbprivk.as_str(),
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
        futility,
        &[
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_range() {
        let r =
            PartitionDataRange(LbaRangeInclusive::new(Lba(1), Lba(1)).unwrap());

        assert_eq!(r.num_bytes(), 512);
        assert_eq!(r.to_byte_range(), 512..=1023);

        let r2 = PartitionDataRange::from_byte_range(512..1024);
        assert_eq!(r, r2);
    }
}
