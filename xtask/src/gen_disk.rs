// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::Config;
use crate::sign::{self, KeyPaths};
use anyhow::{Context, Error, Result};
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fatfs::{FileSystem, FormatVolumeOptions, FsOptions};
use fehler::throws;
use fs_err::{self as fs, File, OpenOptions};
use gptman::{GPTPartitionEntry, GPT};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use tempfile::TempDir;

/// Standard sector size.
const SECTOR_SIZE: u64 = 512;

#[derive(Clone, Copy, Debug)]
enum GptPartitionType {
    ChromeOsKernel,
    EfiSystem,
}

impl GptPartitionType {
    fn as_guid_str(self) -> &'static str {
        match self {
            Self::ChromeOsKernel => "fe3a2a5d-4f32-41a7-b725-accc3285a309",
            Self::EfiSystem => "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        }
    }
}

/// Convert a GUID string to a byte array.
///
/// For example, "d24199e7-33f0-4409-b677-1c04683552c5" is converted to:
/// [e7, 99, 41, d2, f0, 33, 09, 44, b6, 77, 1c, 04, 68, 35, 52, c5]
///
/// Note that some bytes appear in a different order between the string
/// and byte representation; that's just how GUIDs are.
fn guid_str_to_array(guid: &str) -> [u8; 16] {
    assert_eq!(guid.len(), 36);

    let a = &guid[0..8];
    let b = &guid[9..13];
    let c = &guid[14..18];
    let d = &guid[19..23];
    let e = &guid[24..36];

    let a = u32::from_str_radix(a, 16).unwrap();
    let b = u16::from_str_radix(b, 16).unwrap();
    let c = u16::from_str_radix(c, 16).unwrap();
    let d = u16::from_str_radix(d, 16).unwrap();
    let e = u64::from_str_radix(e, 16).unwrap();

    let mut output = Vec::new();
    output.extend(a.to_le_bytes());
    output.extend(b.to_le_bytes());
    output.extend(c.to_le_bytes());
    output.extend(d.to_be_bytes());
    output.extend(&e.to_be_bytes()[2..]);

    output.try_into().unwrap()
}

/// Create an empty file with the given size (using the `truncate`
/// command). This will delete the file first if it already exists.
#[throws]
fn create_empty_file_with_size(path: &Utf8Path, size: &str) {
    // Delete the file if it already exists.
    if path.exists() {
        fs::remove_file(&path)?;
    }

    // Generate empty image.
    Command::with_args("truncate", &["--size", size, path.as_str()]).run()?;
}

struct PartitionSettings<'a> {
    label: &'a str,
    data_range: PartitionDataRange,
    type_guid: GptPartitionType,
    guid: &'a str,
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
#[throws]
fn open_rw(path: &Utf8Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?
}

struct DiskSettings<'a> {
    path: &'a Utf8Path,
    size: &'a str,
    guid: &'a str,
    partitions: &'a [PartitionSettings<'a>],
}

impl<'a> DiskSettings<'a> {
    #[throws]
    fn create(&self) {
        create_empty_file_with_size(self.path, self.size)?;

        let mut disk_file = open_rw(self.path)?;

        let mut gpt = GPT::new_from(
            &mut disk_file,
            SECTOR_SIZE,
            guid_str_to_array(self.guid),
        )?;

        for (i, part) in self.partitions.iter().enumerate() {
            // GPT partitions start at 1.
            let part_num: u32 = (i + 1).try_into().unwrap();

            // Create the partition entry.
            gpt[part_num] = gptman::GPTPartitionEntry {
                partition_type_guid: guid_str_to_array(
                    part.type_guid.as_guid_str(),
                ),
                unique_partition_guid: guid_str_to_array(part.guid),
                starting_lba: part.data_range.start_lba,
                ending_lba: part.data_range.end_lba,
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
    }
}

/// Convert from MiB to bytes.
fn mib_to_byte(val: u64) -> u64 {
    val * 1024 * 1024
}

#[derive(Debug, Eq, PartialEq)]
struct PartitionDataRange {
    // Start and end are inclusive.
    start_lba: u64,
    end_lba: u64,
}

impl PartitionDataRange {
    fn new(partition: &GPTPartitionEntry) -> Self {
        Self {
            start_lba: partition.starting_lba,
            end_lba: partition.ending_lba,
        }
    }

    fn from_byte_range(byte_range: Range<u64>) -> Self {
        let byte_to_lba = |b| {
            assert_eq!(b % SECTOR_SIZE, 0);
            b / SECTOR_SIZE
        };
        Self {
            start_lba: byte_to_lba(byte_range.start),
            end_lba: byte_to_lba(byte_range.end) - 1,
        }
    }

    fn byte_range(&self) -> Range<u64> {
        self.start_lba * SECTOR_SIZE..(self.end_lba + 1) * SECTOR_SIZE
    }

    fn num_bytes(&self) -> usize {
        let r = self.byte_range();
        let num = r.end - r.start;
        usize::try_from(num).unwrap()
    }

    #[throws]
    fn read_bytes_from_file(&self, f: &mut File) -> Vec<u8> {
        let mut v = vec![0; self.num_bytes()];
        f.seek(SeekFrom::Start(self.byte_range().start))?;
        f.read_exact(&mut v)?;
        v
    }

    #[throws]
    fn write_bytes_to_file(&self, f: &mut File, data: &[u8]) {
        assert!(data.len() <= self.num_bytes());
        f.seek(SeekFrom::Start(self.byte_range().start))?;
        f.write_all(data)?;
    }
}

/// Read data from a reven kernel partition.
#[throws]
fn read_real_kernel_partition(conf: &Config) -> Vec<u8> {
    let mut f = File::open(conf.disk_path())?;
    let gpt = gptman::GPT::find_from(&mut f)?;

    let kern_a = &gpt[2];
    assert_eq!(kern_a.partition_name.as_str(), "KERN-A");

    let kern_a_data_range = PartitionDataRange::new(kern_a);
    kern_a_data_range.read_bytes_from_file(&mut f)?
}

#[throws]
pub fn gen_vboot_test_disk(conf: &Config) {
    let kern_a = read_real_kernel_partition(conf)?;

    let disk = DiskSettings {
        path: &conf.vboot_test_disk_path(),
        // 16MiB kernel partition, plus extra space for GPT headers.
        size: "18MiB",
        // Arbitrary GUID.
        guid: "d24199e7-33f0-4409-b677-1c04683552c5",
        partitions: &[PartitionSettings {
            label: "KERN-A",
            data_range: PartitionDataRange::from_byte_range(
                mib_to_byte(1)..mib_to_byte(17),
            ),
            type_guid: GptPartitionType::ChromeOsKernel,
            // Arbitrary, but must match the partition GUID in the vboot
            // test `test_load_kernel`.
            guid: "c6fbb888-1b6d-4988-a66e-ace443df68f4",
            set_successful_boot_bit: true,
            // Must be set to something between 1 and 15, but otherwise
            // arbitrary.
            priority: Some(1),
            data: &kern_a,
        }],
    };
    disk.create()?;
}

/// Generate the EFI system partition FAT file system containing the
/// enroller executables.
#[throws]
fn gen_enroller_fs(conf: &Config) -> Vec<u8> {
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
            let src_path = conf.target_exec_path(arch, "enroller.efi");
            let src_data = fs::read(src_path)?;

            let dst_file_name = arch.efi_file_name("boot");
            let mut dst_file = boot_dir.create_file(&dst_file_name)?;

            dst_file.write_all(&src_data)?;
        }
    }

    sys_part_data
}

#[throws]
pub fn gen_enroller_disk(conf: &Config) {
    let part_data = gen_enroller_fs(conf)?;

    let disk = DiskSettings {
        path: &conf.enroller_disk_path(),
        // 2MiB system partition, plus extra space for GPT headers.
        size: "4MiB",
        // Arbitrary GUID.
        guid: "4345f688-5dac-4ab0-a596-ad5bcaf30163",
        partitions: &[PartitionSettings {
            label: "boot",
            data_range: PartitionDataRange::from_byte_range(
                mib_to_byte(1)..mib_to_byte(3),
            ),
            type_guid: GptPartitionType::EfiSystem,
            // Arbitrary GUID.
            guid: "21049f0f-75a3-4fba-beff-569ba248a19d",
            set_successful_boot_bit: false,
            priority: None,
            data: &part_data,
        }],
    };
    disk.create()?;
}

/// Modify data in the EFI system partition FAT file system.
///
/// This loads the partition into memory and opens it with `fatfs`. The
/// root directory handle is then passed to the `modify` function, and
/// the caller can update the contents as desired. Then the partition is
/// written back out to disk.
#[throws]
fn modify_system_partition<F>(disk_path: &Utf8Path, modify: F)
where
    F: Fn(fatfs::Dir<Cursor<&mut Vec<u8>>>) -> Result<()>,
{
    let mut disk_file = open_rw(disk_path)?;
    let gpt = GPT::read_from(&mut disk_file, SECTOR_SIZE)?;
    let partition_type =
        guid_str_to_array(GptPartitionType::EfiSystem.as_guid_str());
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
    sys_data_range.write_bytes_to_file(&mut disk_file, &sys_part_data)?;
}

/// Copy all the files in `src_dir` to the `EFI/BOOT` directory on the
/// system partition in the disk image at `disk_path`.
#[throws]
pub fn update_boot_files(disk_path: &Utf8Path, src_dir: &Utf8Path) {
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
    .context("failed to update boot files")?;
}

pub struct SignAndUpdateBootloader<'a> {
    /// Path to a reven disk image.
    pub disk_path: &'a Utf8Path,

    /// Keys to sign with.
    pub key_paths: KeyPaths,

    /// Mapping from source file path (an unsigned bootloader
    /// executable) to the destination file name (within the EFI/BOOT
    /// subdirectory of the system partition).
    pub mapping: Vec<(Utf8PathBuf, String)>,
}

impl<'a> SignAndUpdateBootloader<'a> {
    /// Sign each source file (in a temporary directory, source files
    /// are not modified), then copy the signed files into the system
    /// partition of the disk image.
    #[throws]
    pub fn run(&self) {
        let tmp_dir = TempDir::new()?;
        let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();

        for (src, dst_name) in &self.mapping {
            let signed_src = tmp_path.join(dst_name);
            sign::sign(src, &signed_src, &self.key_paths)?;
        }

        update_boot_files(self.disk_path, tmp_path)?;
    }
}

/// Sign crdyboot, then copy it into the disk image under the "grub"
/// name (since that's what shim currently chains to).
#[throws]
pub fn copy_in_crdyboot(conf: &Config) {
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
    .run()?;
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
pub fn sign_kernel_partition(conf: &Config, partition_name: &str) {
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
    let orig_kern_data =
        kern_data_range.read_bytes_from_file(&mut disk_file)?;
    fs::write(&unsigned_kernel_partition, orig_kern_data)?;

    build_futility(conf)?;

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
        futility,
        &[
            "vbutil_kernel",
            "--verify",
            signed_kernel_partition.as_str(),
            "--signpubkey",
            kernel_key_public.as_str(),
        ],
    )
    .run()?;

    // Write the updated kernel partition back to the disk image.
    let signed_kern_data = fs::read(signed_kernel_partition)?;
    kern_data_range.write_bytes_to_file(&mut disk_file, &signed_kern_data)?;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid() {
        assert_eq!(
            guid_str_to_array("d24199e7-33f0-4409-b677-1c04683552c5"),
            [
                0xe7, 0x99, 0x41, 0xd2, 0xf0, 0x33, 0x09, 0x44, 0xb6, 0x77,
                0x1c, 0x04, 0x68, 0x35, 0x52, 0xc5
            ]
        );
    }

    #[test]
    fn test_partition_range() {
        let r = PartitionDataRange {
            start_lba: 1,
            end_lba: 1,
        };

        assert_eq!(r.num_bytes(), 512);
        assert_eq!(r.byte_range(), 512..1024);

        let r2 = PartitionDataRange::from_byte_range(512..1024);
        assert_eq!(r, r2);
    }
}
