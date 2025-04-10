// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use alloc::vec;
use alloc::vec::Vec;
use gpt_disk_io::gpt_disk_types::{GptPartitionEntry, GptPartitionEntrySizeError};
use gpt_disk_io::{Disk, DiskError};
use libcrdy::uefi::{BlockIoError, ScopedBlockIo, ScopedDevicePath, ScopedDiskIo, Uefi};
use libcrdy::util::u32_to_usize;
use uefi::prelude::*;
use uefi::proto::device_path::media::HardDrive;
use uefi::proto::device_path::{DeviceSubType, DeviceType};
use uefi::CStr16;

#[cfg(feature = "android")]
use {gpt_disk_io::gpt_disk_types::BlockSize, uefi::Guid};

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum GptDiskError {
    /// The disk block size is zero.
    #[error("disk block size is zero")]
    InvalidBlockSize,

    /// The number of blocks cannot fit in [`u64`].
    #[error("number of blocks cannot fit in u64")]
    InvalidLastBlock,

    /// No handles support the [`BlockIO`] protocol.
    #[error("no handles support the BlockIO protocol: {0}")]
    BlockIoProtocolMissing(Status),

    /// Failed to open the [`BlockIO`] protocol.
    #[error("failed to open the BlockIO protocol: {0}")]
    OpenBlockIoProtocolFailed(Status),

    /// Failed to open the [`DevicePath`] protocol.
    #[error("failed to open the DevicePath protocol: {0}")]
    OpenDevicePathProtocolFailed(Status),

    /// Failed to open the [`UefiDiskIo`] protocol.
    #[error("failed to open the DiskIO protocol: {0}")]
    OpenDiskIoProtocolFailed(Status),

    /// Failed to open the [`LoadedImage`] protocol.
    #[error("failed to open the LoadedImage protocol: {0}")]
    OpenLoadedImageProtocolFailed(Status),

    /// The [`LoadedImage`] does not have a device handle set.
    #[error("the LoadedImage does not have a device handle set")]
    LoadedImageHasNoDevice,

    /// Failed to find the handle for the disk that the current
    /// executable was booted from.
    #[error("failed to get parent disk")]
    ParentDiskNotFound,

    /// Failed to find the handle for the named partition.
    #[error("failed to find partition handle for a named partition")]
    PartitionNotFound,

    /// The partition size is zero or cannot fit into [`u64`].
    #[cfg(feature = "android")]
    #[error("partition size is zero or too large")]
    InvalidPartitionSize,

    /// A block I/O operation failed.
    #[error("block I/O error: {0}")]
    BlockIo(DiskError<BlockIoError>),

    /// Disk does not have a valid GPT.
    #[error("disk does not have a valid GPT")]
    GptMissing,

    /// GPT partition entry array is invalid.
    #[error("invalid GPT partition entry array")]
    InvalidGptPartitionArray(GptPartitionEntrySizeError),
}

/// Open `DevicePath` protocol for `handle`.
pub fn device_path_for_handle(
    uefi: &dyn Uefi,
    handle: Handle,
) -> Result<ScopedDevicePath, GptDiskError> {
    uefi.device_path_for_handle(handle)
        .map_err(|err| GptDiskError::OpenDevicePathProtocolFailed(err.status()))
}

/// True if `potential_parent` is the handle representing the disk that
/// contains the `partition` device.
///
/// This is determined by looking at the Device Paths associated with each
/// handle. The parent device should have exactly the same set of paths, except
/// that the partition paths end with a Hard Drive Media Device Path.
fn is_parent_disk(
    uefi: &dyn Uefi,
    potential_parent: Handle,
    partition: Handle,
) -> Result<bool, GptDiskError> {
    // A partition cannot be its own parent. This is important to check
    // first, to avoid a potential panic when dropping `DevicePath`s
    // below. This can occur because the protocol is opened in
    // non-exclusive mode. If opened twice in non-exclusive mode, the
    // first drop will succeed, but the second will fail if the firmware
    // thinks the protocol is already closed. A failure in
    // close_protocol currently causes a panic in uefi-rs. b/409609580
    if partition == potential_parent {
        return Ok(false);
    }

    let potential_parent_device_path = device_path_for_handle(uefi, potential_parent)?;
    let potential_parent_device_path_node_iter = potential_parent_device_path.node_iter();
    let partition_device_path = device_path_for_handle(uefi, partition)?;
    let mut partition_device_path_node_iter = partition_device_path.node_iter();

    for (parent_path, partition_path) in
        potential_parent_device_path_node_iter.zip(&mut partition_device_path_node_iter)
    {
        if parent_path != partition_path {
            return Ok(false);
        }
    }

    // After the zip operation we expect there to be one remaining path for the
    // partition device; validate that this expectation is met.
    let Some(final_partition_path) = partition_device_path_node_iter.next() else {
        return Ok(false);
    };

    // That final path should be a Hard Drive Media Device Path.
    if final_partition_path.full_type() != (DeviceType::MEDIA, DeviceSubType::MEDIA_HARD_DRIVE) {
        return Ok(false);
    }

    Ok(true)
}

/// Search `block_io_handles` for the device that is a parent of
/// `partition_handle`. See `is_parent_disk` for details.
fn find_parent_disk(
    uefi: &dyn Uefi,
    block_io_handles: &[Handle],
    partition_handle: Handle,
) -> Result<Handle, GptDiskError> {
    for handle in block_io_handles {
        if is_parent_disk(uefi, *handle, partition_handle)? {
            return Ok(*handle);
        }
    }

    Err(GptDiskError::ParentDiskNotFound)
}

/// Find the [`Handle`] corresponding to the ESP partition that this
/// executable is running from.
pub fn find_esp_partition_handle(uefi: &dyn Uefi) -> Result<Handle, GptDiskError> {
    match uefi.find_esp_partition_handle() {
        Ok(Some(handle)) => Ok(handle),
        Ok(None) => Err(GptDiskError::LoadedImageHasNoDevice),
        Err(err) => Err(GptDiskError::OpenLoadedImageProtocolFailed(err.status())),
    }
}

/// Find the `Handle` for the disk that this executable is running from.
///
/// Note that this is the handle associated with the entire disk device,
/// not an individual partition on the disk.
fn find_boot_disk_handle(uefi: &dyn Uefi) -> Result<Handle, GptDiskError> {
    let partition_handle = find_esp_partition_handle(uefi)?;

    // Get all handles that support BlockIO. This includes both disk devices
    // and logical partition devices.
    let block_io_handles = uefi
        .find_block_io_handles()
        .map_err(|err| GptDiskError::BlockIoProtocolMissing(err.status()))?;

    // Find the parent disk device of the logical partition device.
    find_parent_disk(uefi, &block_io_handles, partition_handle)
}

pub fn find_disk_block_io(uefi: &dyn Uefi) -> Result<ScopedBlockIo, GptDiskError> {
    let disk_handle = find_boot_disk_handle(uefi)?;

    // Open the protocol with `GetProtocol` instead of `Exclusive`. On
    // the X1Cg9, opening the protocol in exclusive mode takes over
    // 800ms for some unknown reason.
    //
    // Functionally there's not much difference in safety here, since
    // crdyboot is the only code that should be running other than the
    // firmware. Grub also opens the protocol in non-exclusive mode.
    unsafe {
        uefi.open_block_io(disk_handle)
            .map_err(|err| GptDiskError::OpenBlockIoProtocolFailed(err.status()))
    }
}

/// Test if the passed in `name` matches the `partition_name` in the
/// `partition_info` struct.
/// This compares `name` with `partition_name` only up to the
/// length of `name` including the null terminator.
/// Any trailing chars in `partition_name` array after the first null
/// are ignored.
fn is_gpt_partition_entry_named(partition_info: &GptPartitionEntry, name: &CStr16) -> bool {
    // Get iterators over the characters in `partition_info.name` and
    // `name`. These iterators exclude the trailing null, if present.
    let partition_name_chars = partition_info.name.chars();
    let name_chars = name.as_slice().iter().copied();

    name_chars.eq(partition_name_chars)
}

/// Get the partition size in bytes for the GPT partition with `name`.
///
/// This finds the `name` partition by its label and excludes
/// partitions from disks other than the one this executable is running
/// from.
#[cfg(feature = "android")]
pub fn get_partition_size_in_bytes(uefi: &dyn Uefi, name: &CStr16) -> Result<u64, GptDiskError> {
    let gpt = Gpt::load_boot_disk(uefi)?;

    // Find the partition named `name`.
    let (_, entry) = gpt.find_partition_by_name(name)?;

    entry
        .lba_range()
        .ok_or(GptDiskError::InvalidPartitionSize)?
        .num_bytes(gpt.block_size)
        .ok_or(GptDiskError::InvalidPartitionSize)
}

/// Get the `Guid` of the GPT partition with `name`.
///
/// This finds the `name` partition by its label and excludes
/// partitions from disks other than the one this executable is running
/// from.
#[cfg(feature = "android")]
pub fn get_partition_unique_guid(uefi: &dyn Uefi, name: &CStr16) -> Result<Guid, GptDiskError> {
    let gpt = Gpt::load_boot_disk(uefi)?;
    let (_, entry) = gpt.find_partition_by_name(name)?;

    Ok(entry.unique_partition_guid)
}

/// Get the handle and `GptPartitionEntry` of the named GPT partition.
///
/// This finds the `name` partition by its label, and excludes
/// partitions from disks other than the one this executable is running
/// from.
fn find_partition_by_name(
    uefi: &dyn Uefi,
    name: &CStr16,
) -> Result<(Handle, GptPartitionEntry), GptDiskError> {
    // Find the boot disk and load its GPT.
    let boot_disk_handle = find_boot_disk_handle(uefi)?;
    let gpt = Gpt::load(uefi, boot_disk_handle)?;

    // Find the partition named `name`.
    let (partition_num, entry) = gpt.find_partition_by_name(name)?;

    // Get all handles that support BlockIO. This includes both disk devices
    // and logical partition devices.
    let block_io_handles = uefi
        .find_block_io_handles()
        .map_err(|err| GptDiskError::BlockIoProtocolMissing(err.status()))?;

    // Find the partition handle that matches `partition_num`. This is
    // needed so that other code can open protocols (like BlockIO)
    // targeting that specific partition.
    for handle in block_io_handles {
        // Ignore the handle if it's not a child of the boot disk.
        if is_parent_disk(uefi, boot_disk_handle, handle) != Ok(true) {
            continue;
        }

        // Get the handle's device path.
        let Ok(dp) = device_path_for_handle(uefi, handle) else {
            continue;
        };

        // Get the last node in the device path.
        let Some(last_node) = dp.node_iter().last() else {
            continue;
        };

        // Convert the node to the `HardDrive` type used for partitions.
        let Ok(last_node) = <&HardDrive>::try_from(last_node) else {
            continue;
        };

        // Check if this node's partition number matches the one we're
        // looking for.
        if last_node.partition_number() == *partition_num {
            return Ok((handle, *entry));
        }
    }

    Err(GptDiskError::PartitionNotFound)
}

/// Open the Disk IO protocol for the partition. This allows
/// byte-level access to partition data.
///
/// Returns a tuple containing the protocol and a media ID of type
/// `u32`. The ID is passed in as a parameter of the protocol's methods.
pub fn open_partition_by_name(
    uefi: &dyn Uefi,
    name: &CStr16,
) -> Result<(ScopedDiskIo, u32), GptDiskError> {
    let partition_handle = find_partition_by_name(uefi, name)?.0;
    // See comment in `find_disk_block_io` for why the non-exclusive
    // mode is used.

    // Get the disk's media ID. This value is needed when calling disk
    // IO operations.
    let media_id = unsafe {
        uefi.open_block_io(partition_handle)
            .map_err(|err| GptDiskError::OpenBlockIoProtocolFailed(err.status()))?
            .media()
            .media_id()
    };

    let disk_io = unsafe {
        uefi.open_disk_io(partition_handle)
            .map_err(|err| GptDiskError::OpenDiskIoProtocolFailed(err.status()))
    }?;

    Ok((disk_io, media_id))
}

/// Open the Disk IO protocol for the stateful partition. This allows
/// byte-level access to partition data.
///
/// Returns a tuple containing the protocol and a media ID of type
/// `u32`. The ID is passed in as a parameter of the protocol's methods.
pub fn open_stateful_partition(uefi: &dyn Uefi) -> Result<(ScopedDiskIo, u32), GptDiskError> {
    // Name of the stateful partition.
    const STATE_NAME: &CStr16 = cstr16!("STATE");
    open_partition_by_name(uefi, STATE_NAME)
}

/// 1-based index of a partition within the GPT's partition entry array.
type PartitionNum = u32;

/// Information about a disk's GPT.
///
/// This allows looking up information about partitions. Loading only
/// requires a disk `Handle`. Internally, the `BlockIO` protocol is used
/// to read data from the disk. No partition-specific UEFI protocols are
/// used.
#[derive(Debug)]
pub struct Gpt {
    #[cfg(feature = "android")]
    block_size: BlockSize,
    partitions: Vec<(PartitionNum, GptPartitionEntry)>,
}

impl Gpt {
    /// Create a `Gpt` for the disk that this executable is running from.
    #[cfg(feature = "android")]
    pub fn load_boot_disk(uefi: &dyn Uefi) -> Result<Self, GptDiskError> {
        let disk_handle = find_boot_disk_handle(uefi)?;
        Self::load(uefi, disk_handle)
    }

    /// Create a `Gpt` for the disk represented by `disk_handle`.
    fn load(uefi: &dyn Uefi, disk_handle: Handle) -> Result<Self, GptDiskError> {
        // See comment in `find_disk_block_io` for why the non-exclusive
        // mode is used.
        //
        // Safety: nothing else is using the disk for the duration of
        // this function.
        let block_io = unsafe {
            uefi.open_block_io(disk_handle)
                .map_err(|err| GptDiskError::OpenBlockIoProtocolFailed(err.status()))
        }?;

        let block_size = block_io.media().block_size();
        let mut disk = Disk::new(block_io).map_err(GptDiskError::BlockIo)?;
        let mut block_buf = vec![0; u32_to_usize(block_size)];
        let gpt_header = disk
            .read_primary_gpt_header(&mut block_buf)
            .map_err(GptDiskError::BlockIo)?;
        if !gpt_header.is_signature_valid() {
            return Err(GptDiskError::GptMissing);
        }

        let layout = gpt_header
            .get_partition_entry_array_layout()
            .map_err(GptDiskError::InvalidGptPartitionArray)?;
        let partitions: Vec<_> = disk
            .gpt_partition_entry_array_iter(layout, &mut block_buf)
            .map_err(GptDiskError::BlockIo)?
            .enumerate()
            .filter_map(|(i, entry)| {
                // Ignore invalid entries.
                let entry = entry.ok()?;

                // Ignore unused entries.
                if !entry.is_used() {
                    return None;
                }

                // Convert from the 0-based index to the 1-based partition number.
                let partition_num = PartitionNum::try_from(i).ok()?.checked_add(1)?;

                Some((partition_num, entry))
            })
            .collect();

        Ok(Self {
            #[cfg(feature = "android")]
            block_size: BlockSize::new(block_size).ok_or(GptDiskError::InvalidBlockSize)?,
            partitions,
        })
    }

    /// Find a partition entry by name.
    ///
    /// If found, returns a tuple containing both `PartitionNum` and
    /// `GptPartitionEntry`. If not found, returns `PartitionNotFound`.
    pub fn find_partition_by_name(
        &self,
        looking_for: &CStr16,
    ) -> Result<&(PartitionNum, GptPartitionEntry), GptDiskError> {
        self.partitions
            .iter()
            .find(|(_, entry)| is_gpt_partition_entry_named(entry, looking_for))
            .ok_or(GptDiskError::PartitionNotFound)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use core::ffi::c_void;
    use core::{mem, slice};
    use gpt_disk_io::gpt_disk_types::{GptPartitionAttributes, GptPartitionType, LbaLe};
    use libcrdy::uefi::MockUefi;
    use libcrdy::util::usize_to_u64;
    use uefi::data_types::chars::NUL_16;
    use uefi::proto::device_path::build::acpi::Acpi;
    use uefi::proto::device_path::build::hardware::Pci;
    use uefi::proto::device_path::build::media::{FilePath, HardDrive};
    use uefi::proto::device_path::build::messaging::{MacAddress, Scsi};
    use uefi::proto::device_path::build::{self, BuildError, BuildNode};
    use uefi::proto::device_path::media::{PartitionFormat, PartitionSignature};
    use uefi::proto::media::block::BlockIO;
    use uefi::{cstr16, guid, CStr16, Char16, Guid};
    use uefi_raw::protocol::block::{BlockIoMedia, BlockIoProtocol};
    use uefi_raw::protocol::disk::DiskIoProtocol;

    pub(crate) static VBOOT_TEST_DISK: &[u8] =
        include_bytes!("../../workspace/crdyboot_test_data/vboot_test_disk.bin");
    pub(crate) static ANDROID_TEST_DISK: &[u8] =
        include_bytes!("../../workspace/crdyboot_test_data/android_test_disk.bin");

    // All-zero data representing a disk that does not have a valid GPT.
    pub(crate) static NON_GPT_TEST_DISK: &[u8] = &[0; 1024 * 2];

    // TODO(b/397698913): temporarily hardcode the start and length of
    // the stateful test partition within `VBOOT_TEST_DISK`.
    //
    // This can be removed once we replace all use of UEFI partition
    // protocols with UEFI disk protocols.
    const STATEFUL_TEST_PARTITION_START: u64 = (1024 * 1024) * (64 + 1);
    const STATEFUL_TEST_PARTITION_LEN: u64 = 1024 * 1024;

    pub(crate) enum BootDrive {
        Hd1,

        /// Android disk with three partitions:
        /// 1. ESP
        /// 2. boot_a
        /// 3. boot_b
        Hd2,

        /// A non-GPT disk.
        Hd3,

        HdWithNoEspDeviceHandle,
        Invalid,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum DeviceKind {
        Hd1 = 0,
        Hd1Esp,
        Hd1State,

        Hd2,
        Hd2Esp,
        Hd2BootA,
        Hd2BootB,

        Hd3,

        FilePath,
        MacAddr,
    }

    impl DeviceKind {
        /// Get the handle for this device. This will always return the
        /// same handle for the given `kind`.
        fn handle(self) -> Handle {
            // A handle is basically a void pointer. We don't care what the
            // particular value of that pointer is, it just needs to
            // consistent for each `DeviceKind`.
            //
            // The easiest thing to do would be `kind as usize as *const
            // c_void`, but miri doesn't like pointers being created out of
            // thin air like that, so instead create a static array and
            // create pointers to its elements. Since the elements have a
            // non-zero size, each element is guaranteed to have a different
            // address.
            let index = self as usize;
            static H: [u8; 11] = [0; 11];
            let ptr: *const u8 = &H[index];
            let ptr: *mut _ = ptr.cast_mut().cast();
            unsafe { Handle::from_ptr(ptr) }.unwrap()
        }

        /// Get the device kind for a handle. Panics on unknown handles.
        fn from_handle(handle: Handle) -> Self {
            *DeviceKind::all()
                .iter()
                .find(|kind| handle == kind.handle())
                .expect("invalid handle")
        }

        fn all() -> &'static [Self] {
            &[
                Self::Hd1,
                Self::Hd1Esp,
                Self::Hd1State,
                Self::Hd2,
                Self::Hd2Esp,
                Self::Hd2BootA,
                Self::Hd2BootB,
                Self::Hd3,
                Self::FilePath,
                Self::MacAddr,
            ]
        }

        fn partition_number(self) -> Option<u32> {
            match self {
                Self::Hd1Esp | Self::Hd2Esp => Some(12),
                Self::Hd1State => Some(1),
                Self::Hd2BootA => Some(13),
                Self::Hd2BootB => Some(14),
                _ => None,
            }
        }

        fn partition_device_path_node(self) -> Option<HardDrive> {
            Some(HardDrive {
                partition_number: self.partition_number()?,

                // The rest of these values aren't read, so put in default values.
                partition_start: 0,
                partition_size: 0,
                partition_signature: PartitionSignature::Guid(Guid::default()),
                partition_format: PartitionFormat::GPT,
            })
        }

        fn create_device_path(self) -> Result<ScopedDevicePath, BuildError> {
            let mut nodes: Vec<&dyn BuildNode> = Vec::new();

            let hd1 = [
                &Acpi { hid: 1, uid: 2 } as &dyn BuildNode,
                &Pci {
                    function: 3,
                    device: 4,
                },
                &Scsi {
                    target_id: 5,
                    logical_unit_number: 6,
                },
            ];
            let hd2 = [
                &Acpi { hid: 10, uid: 20 } as &dyn BuildNode,
                &Pci {
                    function: 30,
                    device: 40,
                },
                &Scsi {
                    target_id: 50,
                    logical_unit_number: 60,
                },
            ];
            let hd3 = [
                &Acpi { hid: 11, uid: 22 } as &dyn BuildNode,
                &Pci {
                    function: 33,
                    device: 44,
                },
                &Scsi {
                    target_id: 55,
                    logical_unit_number: 66,
                },
            ];
            let path = FilePath {
                path_name: cstr16!("abc"),
            };

            let partition = self.partition_device_path_node();
            let partition = partition.as_ref();

            match self {
                Self::Hd1 => nodes.extend(hd1),
                Self::Hd1Esp | Self::Hd1State => {
                    nodes.extend(hd1);
                    nodes.push(partition.unwrap());
                }
                Self::Hd2 => nodes.extend(hd2),
                Self::Hd2Esp | Self::Hd2BootA | Self::Hd2BootB => {
                    nodes.extend(hd2);
                    nodes.push(partition.unwrap());
                }
                Self::Hd3 => nodes.extend(hd3),
                Self::FilePath => {
                    nodes.extend(hd1);
                    nodes.push(&path);
                }
                Self::MacAddr => nodes.push(&MacAddress {
                    mac_address: [1; 32],
                    interface_type: 2,
                }),
            }

            let mut vec = Vec::new();
            let mut builder = build::DevicePathBuilder::with_vec(&mut vec);
            for node in nodes {
                builder = builder.push(node)?;
            }
            let path = builder.finalize()?;

            Ok(ScopedDevicePath::for_test(path.to_boxed()))
        }
    }

    pub(crate) fn create_mock_uefi(boot_drive: BootDrive) -> MockUefi {
        static HD1_MEDIA: BlockIoMedia = BlockIoMedia {
            media_id: 100,
            removable_media: false,
            media_present: true,
            logical_partition: false,
            read_only: false,
            write_caching: false,
            block_size: 512,
            io_align: 0,
            last_block: usize_to_u64((VBOOT_TEST_DISK.len() / 512) - 1),
            lowest_aligned_lba: 0,
            logical_blocks_per_physical_block: 1,
            optimal_transfer_length_granularity: 1,
        };
        static HD1_STATE_MEDIA: BlockIoMedia = BlockIoMedia {
            media_id: 101,
            last_block: (STATEFUL_TEST_PARTITION_LEN / 512) - 1,
            ..HD1_MEDIA
        };
        static HD2_MEDIA: BlockIoMedia = BlockIoMedia {
            media_id: 200,
            last_block: usize_to_u64((ANDROID_TEST_DISK.len() / 512) - 1),
            ..HD1_MEDIA
        };
        static HD3_MEDIA: BlockIoMedia = BlockIoMedia {
            media_id: 300,
            last_block: usize_to_u64((NON_GPT_TEST_DISK.len() / 512) - 1),
            ..HD1_MEDIA
        };

        unsafe extern "efiapi" fn read_blocks(
            this: *const BlockIoProtocol,
            media_id: u32,
            lba: u64,
            buffer_size: usize,
            buffer: *mut c_void,
        ) -> uefi_raw::Status {
            let src = if media_id == HD1_MEDIA.media_id {
                VBOOT_TEST_DISK
            } else if media_id == HD2_MEDIA.media_id {
                ANDROID_TEST_DISK
            } else if media_id == HD3_MEDIA.media_id {
                NON_GPT_TEST_DISK
            } else {
                panic!("attempted to read blocks from {media_id}");
            };

            if lba > (*(*this).media).last_block {
                return uefi_raw::Status::INVALID_PARAMETER;
            }

            let dst: &mut [u8] = slice::from_raw_parts_mut(buffer.cast(), buffer_size);

            let offset = usize::try_from(lba * 512).unwrap();
            let src = &src[offset..offset + dst.len()];

            dst.copy_from_slice(src);

            uefi_raw::Status::SUCCESS
        }

        unsafe extern "efiapi" fn write_blocks(
            this: *mut BlockIoProtocol,
            media_id: u32,
            lba: u64,
            _buffer_size: usize,
            _buffer: *const c_void,
        ) -> uefi_raw::Status {
            assert_eq!(media_id, HD1_MEDIA.media_id);

            if lba > (*(*this).media).last_block {
                return uefi_raw::Status::INVALID_PARAMETER;
            }

            uefi_raw::Status::SUCCESS
        }

        unsafe extern "efiapi" fn reset(_: *mut BlockIoProtocol, _: bool) -> uefi_raw::Status {
            unimplemented!()
        }

        unsafe extern "efiapi" fn flush_blocks(_: *mut BlockIoProtocol) -> uefi_raw::Status {
            unimplemented!()
        }

        unsafe extern "efiapi" fn read_disk(
            _: *const DiskIoProtocol,
            media_id: u32,
            offset: u64,
            buffer_size: usize,
            buffer: *mut c_void,
        ) -> uefi_raw::Status {
            assert_eq!(media_id, HD1_STATE_MEDIA.media_id);

            let offset = usize::try_from(offset + STATEFUL_TEST_PARTITION_START).unwrap();
            let Some(src) = VBOOT_TEST_DISK.get(offset..offset + buffer_size) else {
                return uefi_raw::Status::INVALID_PARAMETER;
            };

            buffer.cast::<u8>().copy_from(src.as_ptr(), buffer_size);

            return uefi_raw::Status::SUCCESS;
        }

        unsafe extern "efiapi" fn write_disk(
            _: *mut DiskIoProtocol,
            _media_id: u32,
            _offset: u64,
            _buffer_size: usize,
            _buffer: *const c_void,
        ) -> uefi_raw::Status {
            unreachable!();
        }

        let mut uefi = MockUefi::new();
        uefi.expect_device_path_for_handle().returning(|h| {
            let kind = DeviceKind::from_handle(h);
            Ok(kind.create_device_path().unwrap())
        });
        uefi.expect_find_esp_partition_handle()
            .returning(move || match boot_drive {
                BootDrive::Hd1 => Ok(Some(DeviceKind::Hd1Esp.handle())),
                BootDrive::Hd2 => Ok(Some(DeviceKind::Hd2Esp.handle())),
                BootDrive::Hd3 => Ok(None),
                BootDrive::HdWithNoEspDeviceHandle => Ok(None),
                BootDrive::Invalid => Err(Status::INVALID_PARAMETER.into()),
            });
        uefi.expect_find_block_io_handles().returning(|| {
            Ok(vec![
                DeviceKind::Hd1.handle(),
                DeviceKind::Hd1Esp.handle(),
                DeviceKind::Hd1State.handle(),
                DeviceKind::Hd2.handle(),
                DeviceKind::Hd2Esp.handle(),
                DeviceKind::Hd2BootA.handle(),
                DeviceKind::Hd2BootB.handle(),
                DeviceKind::Hd3.handle(),
            ])
        });
        uefi.expect_open_block_io().returning(|handle| {
            let media = if handle == DeviceKind::Hd1.handle() {
                &HD1_MEDIA
            } else if handle == DeviceKind::Hd1State.handle() {
                &HD1_STATE_MEDIA
            } else if handle == DeviceKind::Hd2.handle() {
                &HD2_MEDIA
            } else if handle == DeviceKind::Hd3.handle() {
                &HD3_MEDIA
            } else {
                return Err(Status::UNSUPPORTED.into());
            };

            let bio = BlockIoProtocol {
                revision: 0,
                media,
                reset,
                read_blocks,
                write_blocks,
                flush_blocks,
            };
            let bio: BlockIO = unsafe { mem::transmute(bio) };
            Ok(ScopedBlockIo::for_test(Box::new(bio)))
        });
        uefi.expect_open_disk_io().returning(|handle| {
            assert_eq!(handle, DeviceKind::Hd1State.handle());
            let dio = DiskIoProtocol {
                revision: DiskIoProtocol::REVISION,
                read_disk,
                write_disk,
            };
            let dio: uefi::proto::media::disk::DiskIo = unsafe { mem::transmute(dio) };
            Ok(ScopedDiskIo::for_test(Box::new(dio)))
        });
        uefi
    }

    /// Test that `is_parent_disk` returns true for a valid child
    /// partition.
    #[test]
    fn test_is_parent_disk_partition() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        assert!(
            is_parent_disk(&uefi, DeviceKind::Hd1.handle(), DeviceKind::Hd1Esp.handle()).unwrap()
        );
    }

    /// Test that `is_parent_disk` returns false if the parent has nodes
    /// the child doesn't have.
    #[test]
    fn test_is_parent_disk_nonmatching() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        assert!(!is_parent_disk(
            &uefi,
            DeviceKind::MacAddr.handle(),
            DeviceKind::Hd1Esp.handle()
        )
        .unwrap());
    }

    /// Test that `is_parent_disk` returns false if the child doesn't
    /// end with a hard drive partition node.
    #[test]
    fn test_is_parent_disk_nonpartition() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        assert!(!is_parent_disk(
            &uefi,
            DeviceKind::Hd1.handle(),
            DeviceKind::FilePath.handle()
        )
        .unwrap());
    }

    /// Test that `is_parent_disk` returns false for a parent == child.
    #[test]
    fn test_is_parent_disk_harddrive() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        assert!(
            !is_parent_disk(&uefi, DeviceKind::Hd1.handle(), DeviceKind::Hd1.handle()).unwrap()
        );
    }

    /// Test that `find_parent_disk` identifies the correct handle.
    #[test]
    fn test_find_parent_disk_success() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        let all_handles: Vec<_> = DeviceKind::all().iter().map(|k| k.handle()).collect();

        assert_eq!(
            find_parent_disk(&uefi, &all_handles, DeviceKind::Hd1Esp.handle()).unwrap(),
            DeviceKind::Hd1.handle()
        );
    }

    /// Test that `find_parent_disk` returns an error if the parent is
    /// not found.
    #[test]
    fn test_find_parent_disk_not_found() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        let all_handles: Vec<_> = DeviceKind::all()
            .iter()
            .filter(|k| **k != DeviceKind::Hd1)
            .map(|k| k.handle())
            .collect();

        assert_eq!(
            find_parent_disk(&uefi, &all_handles, DeviceKind::Hd1Esp.handle()),
            Err(GptDiskError::ParentDiskNotFound)
        );
    }

    /// Test that `get_partition_size_in_bytes` succeeds.
    #[cfg(feature = "android")]
    #[test]
    fn test_get_partition_size_in_bytes() {
        let pname = cstr16!("STATE");
        let uefi = create_mock_uefi(BootDrive::Hd1);
        // The size is the block size * the number of lba for the device
        // as setup.
        assert_eq!(
            get_partition_size_in_bytes(&uefi, pname).unwrap(),
            STATEFUL_TEST_PARTITION_LEN
        );
    }

    /// Test that `get_partition_unique_guid` succeeds.
    #[cfg(feature = "android")]
    #[test]
    fn test_get_partition_unique_guid_success() {
        let pname = cstr16!("STATE");
        let uefi = create_mock_uefi(BootDrive::Hd1);
        assert_eq!(
            get_partition_unique_guid(&uefi, pname).unwrap(),
            guid!("25532186-f207-0e47-9985-cc4b8847c1ad")
        );
    }

    fn create_gpt_partition_entry(partition_name: [Char16; 36]) -> GptPartitionEntry {
        GptPartitionEntry {
            partition_type_guid: GptPartitionType(guid!("7ce8b0e4-20a9-4edd-9982-fe9c84e06e6f")),
            unique_partition_guid: guid!("1fa90113-672a-4c30-89c6-1b87fe019adc"),
            starting_lba: LbaLe::from_u64(0),
            ending_lba: LbaLe::from_u64(10000),
            attributes: GptPartitionAttributes::default(),
            // Safety: `Char16` is a `repr(transparent)` wrapper around
            // `u16`. `[u16; 36]` can be soundly transmuted to `[u8; 72]`.
            name: unsafe { mem::transmute_copy(&partition_name) },
        }
    }

    /// Test that `find_partition_by_name` succeeds with a valid
    /// sibling stateful partition.
    #[test]
    fn test_find_partition_by_name_success() {
        let pname = cstr16!("STATE");
        let uefi = create_mock_uefi(BootDrive::Hd1);
        assert_eq!(
            find_partition_by_name(&uefi, pname).unwrap().0,
            DeviceKind::Hd1State.handle()
        );
    }

    /// Test that `find_partition_by_name` fails with the name of a
    /// partition that does not exist.
    #[test]
    fn test_find_partition_by_name_error() {
        let pname = cstr16!("does not exist");
        let uefi = create_mock_uefi(BootDrive::Hd1);
        assert_eq!(
            find_partition_by_name(&uefi, pname).unwrap_err(),
            GptDiskError::PartitionNotFound
        );
    }

    /// Test that `find_partition_by_name` fails if the only
    /// stateful partition is on a different drive.
    #[test]
    fn test_find_partition_by_name_different_drive() {
        let pname = cstr16!("STATE");
        let uefi = create_mock_uefi(BootDrive::Hd2);

        assert_eq!(
            find_partition_by_name(&uefi, pname).unwrap_err(),
            GptDiskError::PartitionNotFound
        );
    }

    /// Test that `find_esp_partition_handle` handles a loaded image
    /// with no device by returning an error.
    #[test]
    fn test_find_esp_partition_handle_no_device() {
        let mut uefi = create_mock_uefi(BootDrive::HdWithNoEspDeviceHandle);
        uefi.expect_find_esp_partition_handle()
            .returning(|| Ok(None));

        assert_eq!(
            find_esp_partition_handle(&uefi),
            Err(GptDiskError::LoadedImageHasNoDevice)
        );
    }

    /// Test that `find_esp_partition_handle` maps errors correctly.
    #[test]
    fn test_find_esp_partition_handle_error() {
        let mut uefi = create_mock_uefi(BootDrive::Invalid);
        uefi.expect_find_esp_partition_handle()
            .returning(|| Err(Status::INVALID_PARAMETER.into()));

        assert_eq!(
            find_esp_partition_handle(&uefi),
            Err(GptDiskError::OpenLoadedImageProtocolFailed(
                Status::INVALID_PARAMETER
            ))
        );
    }

    /// Test that `find_block_io_handles` succeeds with valid inputs.
    #[test]
    fn test_find_disk_block_io_success() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        assert!(find_disk_block_io(&uefi).is_ok());
    }

    /// Test that `open_stateful_partition` succeeds on a valid disk.
    #[test]
    fn test_open_stateful_partition() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        open_stateful_partition(&uefi).unwrap();
    }

    /// Initialize a type matching the `partition_name` field of
    /// the `GptPartitionEntry` struct with `name`.
    /// The trailing values in the array are initialized to `NUL_16`.
    fn init_partition_name(name: &CStr16) -> [Char16; 36] {
        let mut partition_name: [Char16; 36] = [NUL_16; 36];
        let name = name.as_slice_with_nul();
        partition_name[..name.len()].copy_from_slice(name);
        partition_name
    }

    /// Test normal partition name matches.
    #[test]
    fn test_is_gpt_partition_entry_named_ok() {
        let name = cstr16!("STATE");
        let partition_info = create_gpt_partition_entry(init_partition_name(name));
        assert!(is_gpt_partition_entry_named(&partition_info, &name));
    }

    /// Test that any NUL trailing chars in the `partition_name`
    /// are ignored when comparing.
    /// This exercises the behavior if the `partition_name` happens
    /// to have this unexpected input.
    #[test]
    fn test_is_gpt_partition_entry_named_trailing_non_null() {
        let name = cstr16!("nondescript");
        let mut partition_name = init_partition_name(&name);
        // Insert a char after the null terminator.
        // If this is considered a CStr16 it would be invalid,
        // however, the data structure is [Char16] so it could
        // be possible.
        partition_name[name.as_slice_with_nul().len() + 2] = Char16::try_from('f').unwrap();
        let partition_info = create_gpt_partition_entry(partition_name);

        assert!(is_gpt_partition_entry_named(&partition_info, &name));
    }

    /// Test that if the `partition_name` does not have a
    /// null terminator the result is simply false.
    #[test]
    fn test_is_gpt_partition_entry_named_non_terminated() {
        let name = cstr16!("fff");
        // All 'f' without a null terminator.
        let partition_name = [Char16::try_from('f').unwrap(); 36];
        let partition_info = create_gpt_partition_entry(partition_name);
        // Should simply not match if the partition_name is
        // not null-terminated.
        assert!(!is_gpt_partition_entry_named(&partition_info, &name));
    }

    /// Test that a CStr16 which is exactly the right length will
    /// succeed the check.
    #[test]
    fn test_is_gpt_partition_entry_named_full_length() {
        let name = cstr16!("Anything that is  36 in length okay");
        // Self check the test name length is 36.
        assert_eq!(name.as_slice_with_nul().len(), 36);
        let partition_name = init_partition_name(&name);
        let partition_info = create_gpt_partition_entry(partition_name);
        assert!(is_gpt_partition_entry_named(&partition_info, &name));
    }

    /// Test that a CStr16 which is too long will simply return false
    /// for the match.
    #[test]
    fn test_is_gpt_partition_entry_named_too_long() {
        let name = cstr16!("abcdefghijklmnopqrstuvwxyz0123456789");
        let partial_name = cstr16!("abcdefghijklmnopqrstuvwxyz012345678");
        // Self check the lengths of the test strings.
        assert_eq!(name.as_slice_with_nul().len(), 37);
        assert_eq!(partial_name.as_slice_with_nul().len(), 36);
        let partition_info = create_gpt_partition_entry(init_partition_name(partial_name));

        // This should not match, the length of the requested name is too long.
        assert!(!is_gpt_partition_entry_named(&partition_info, &name));
    }

    /// Test successfully loading and using a `Gpt`.
    #[test]
    fn test_gpt_success() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        let gpt = Gpt::load(&uefi, DeviceKind::Hd1.handle()).unwrap();

        // Check that all expected partitions were loaded (and no unused
        // partition entries were included).
        assert_eq!(gpt.partitions.len(), 2);

        // Check that finding a nonexistent partition fails.
        assert_eq!(
            gpt.find_partition_by_name(cstr16!("invalid")),
            Err(GptDiskError::PartitionNotFound)
        );

        // Check that finding a real partition succeeds.
        let (pnum, partition) = gpt.find_partition_by_name(cstr16!("STATE")).unwrap();
        assert_eq!(*pnum, 1);
        assert_eq!(partition.name.chars().collect::<String>(), "STATE");
    }

    /// Test that `Gpt::load` fails on a non-blockio handle.
    #[test]
    fn test_gpt_load_no_block_io() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        assert_eq!(
            Gpt::load(&uefi, DeviceKind::FilePath.handle()).unwrap_err(),
            GptDiskError::OpenBlockIoProtocolFailed(Status::UNSUPPORTED)
        );
    }

    /// Test that `Gpt::load` fails on a non-gpt disk.
    #[test]
    fn test_gpt_load_no_gpt() {
        let uefi = create_mock_uefi(BootDrive::Hd3);
        assert_eq!(
            Gpt::load(&uefi, DeviceKind::Hd3.handle()).unwrap_err(),
            GptDiskError::GptMissing
        );
    }
}
