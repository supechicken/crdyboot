// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::fmt::{self, Display, Formatter};
use core::num::NonZeroU64;
use libcrdy::uefi::{PartitionInfo, ScopedBlockIo, ScopedDevicePath, ScopedDiskIo, Uefi};
use log::error;
use uefi::prelude::*;
use uefi::proto::device_path::{DeviceSubType, DeviceType};
use uefi::proto::media::partition::GptPartitionEntry;
#[cfg(feature = "android")]
use uefi::Guid;
use uefi::{CStr16, Char16};
use vboot::{DiskIo, ReturnCode};

#[derive(Debug, Eq, PartialEq)]
pub enum GptDiskError {
    /// The disk block size is zero.
    InvalidBlockSize,

    /// The number of blocks cannot fit in [`u64`].
    InvalidLastBlock,

    /// No handles support the [`BlockIO`] protocol.
    BlockIoProtocolMissing(Status),

    /// No handles support the [`PartitionInfo`] protocol.
    PartitionInfoProtocolMissing(Status),

    /// Failed to open the [`BlockIO`] protocol.
    OpenBlockIoProtocolFailed(Status),

    /// Failed to open the [`DevicePath`] protocol.
    OpenDevicePathProtocolFailed(Status),

    /// Failed to open the [`UefiDiskIo`] protocol.
    OpenDiskIoProtocolFailed(Status),

    /// Failed to open the [`LoadedImage`] protocol.
    OpenLoadedImageProtocolFailed(Status),

    /// Failed to open the [`PartitionInfo`] protocol.
    OpenPartitionInfoProtocolFailed(Status),

    /// The [`LoadedImage`] does not have a device handle set.
    LoadedImageHasNoDevice,

    /// Failed to find the handle for the disk that the current
    /// executable was booted from.
    ParentDiskNotFound,

    /// Failed to find the handle for the named partition.
    PartitionNotFound,

    /// The partition size is zero or cannot fit into [`u64`].
    #[cfg(feature = "android")]
    InvalidPartitionSize,
}

impl Display for GptDiskError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::InvalidBlockSize => {
                write!(f, "disk block size is zero")
            }
            Self::InvalidLastBlock => {
                write!(f, "number of blocks cannot fit in u64")
            }
            Self::BlockIoProtocolMissing(status) => {
                write!(f, "no handles support the BlockIO protocol: {status}")
            }
            Self::PartitionInfoProtocolMissing(status) => {
                write!(f, "no handles support the PartitionInfo protocol: {status}")
            }
            Self::OpenBlockIoProtocolFailed(status) => {
                write!(f, "failed to open the BlockIO protocol: {status}")
            }
            Self::OpenDevicePathProtocolFailed(status) => {
                write!(f, "failed to open the DevicePath protocol: {status}")
            }
            Self::OpenDiskIoProtocolFailed(status) => {
                write!(f, "failed to open the DiskIO protocol: {status}")
            }
            Self::OpenLoadedImageProtocolFailed(status) => {
                write!(f, "failed to open the LoadedImage protocol: {status}")
            }
            Self::OpenPartitionInfoProtocolFailed(status) => {
                write!(f, "failed to open the PartitionInfo protocol: {status}")
            }
            Self::LoadedImageHasNoDevice => {
                write!(f, "the LoadedImage does not have a device handle set")
            }
            Self::ParentDiskNotFound => {
                write!(f, "failed to get parent disk")
            }
            Self::PartitionNotFound => {
                write!(f, "failed to find partition handle for a named partition")
            }
            #[cfg(feature = "android")]
            Self::InvalidPartitionSize => {
                write!(f, "partition size is zero or too large")
            }
        }
    }
}

/// Open `DevicePath` protocol for `handle`.
fn device_path_for_handle(
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
fn find_esp_partition_handle(uefi: &dyn Uefi) -> Result<Handle, GptDiskError> {
    match uefi.find_esp_partition_handle() {
        Ok(Some(handle)) => Ok(handle),
        Ok(None) => Err(GptDiskError::LoadedImageHasNoDevice),
        Err(err) => Err(GptDiskError::OpenLoadedImageProtocolFailed(err.status())),
    }
}

fn find_disk_block_io(uefi: &dyn Uefi) -> Result<ScopedBlockIo, GptDiskError> {
    let partition_handle = find_esp_partition_handle(uefi)?;

    // Get all handles that support BlockIO. This includes both disk devices
    // and logical partition devices.
    let block_io_handles = uefi
        .find_block_io_handles()
        .map_err(|err| GptDiskError::BlockIoProtocolMissing(err.status()))?;

    // Find the parent disk device of the logical partition device.
    let disk_handle = find_parent_disk(uefi, &block_io_handles, partition_handle)?;

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

/// Check if `p1` and `p2` are handles of partitions on the same
/// disk. Returns `Ok(true)` if they are on the same disk, `Ok(false)`
/// otherwise.
///
/// Both handles are assumed to be partition handles. If they are not,
/// the function may fail with an error or return `Ok(false)`.
fn is_sibling_partition(uefi: &dyn Uefi, p1: Handle, p2: Handle) -> Result<bool, GptDiskError> {
    // Get the device path for both partitions.
    let p1 = device_path_for_handle(uefi, p1)?;
    let p2 = device_path_for_handle(uefi, p2)?;

    // Check that both paths have the same number of nodes.
    let count = p1.node_iter().count();
    if count != p2.node_iter().count() {
        return Ok(false);
    }

    for (i, (n1, n2)) in p1.node_iter().zip(p2.node_iter()).enumerate() {
        // `count - 1` cannot fail because if we are in this loop then
        // `count` is not zero.
        #[allow(clippy::arithmetic_side_effects)]
        if i < count - 1 {
            // Check that all nodes except the last are the same.
            if n1 != n2 {
                return Ok(false);
            }
        } else {
            // For the last node of each path, check that they are of
            // the expected type.
            let hd = (DeviceType::MEDIA, DeviceSubType::MEDIA_HARD_DRIVE);
            if n1.full_type() != hd || n2.full_type() != hd {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// Test if the passed in `name` matches the `partition_name` in the
/// `partition_info` struct.
/// This compares `name` with `partition_name` only up to the
/// length of `name` including the null terminator.
/// Any trailing chars in `partition_name` array after the first null
/// are ignored.
fn is_gpt_partition_entry_named(partition_info: &GptPartitionEntry, name: &CStr16) -> bool {
    // `PartitionInfo` is `repr(packed)`, which limits operations on
    // fields. Copy the `name` field to a local variable to work around
    // this.
    let partition_name: [Char16; 36] = partition_info.partition_name;
    // Compare including the terminating nul.
    let name = name.as_slice_with_nul();

    // Get a slice the length of name to compare.
    let Some(partition_name) = partition_name.get(..name.len()) else {
        // Name is too long to match.
        return false;
    };

    partition_name == name
}

/// Get the partition size in bytes for the GPT partition with `name`.
///
/// This finds the `name` partition by its label and excludes
/// partitions from disks other than the one this executable is running
/// from.
#[allow(unused)]
#[cfg(feature = "android")]
pub fn get_partition_size_in_bytes(uefi: &dyn Uefi, name: &CStr16) -> Result<u64, GptDiskError> {
    let (partition_handle, partition_info) = find_partition_by_name(uefi, name)?;

    let block_io = unsafe {
        uefi.open_block_io(partition_handle)
            .map_err(|err| GptDiskError::OpenBlockIoProtocolFailed(err.status()))?
    };

    let bytes_per_block = NonZeroU64::new(block_io.media().block_size().into())
        .ok_or(GptDiskError::InvalidBlockSize)?;

    partition_info
        .num_blocks()
        .ok_or(GptDiskError::InvalidBlockSize)?
        .checked_mul(bytes_per_block.get())
        .ok_or(GptDiskError::InvalidPartitionSize)
}

/// Get the `Guid` of the GPT partition with `name`.
///
/// This finds the `name` partition by its label and excludes
/// partitions from disks other than the one this executable is running
/// from.
#[allow(unused)]
#[cfg(feature = "android")]
pub fn get_partition_unique_guid(uefi: &dyn Uefi, name: &CStr16) -> Result<Guid, GptDiskError> {
    Ok(find_partition_by_name(uefi, name)?.1.unique_partition_guid)
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
    let esp_partition_handle = find_esp_partition_handle(uefi)?;

    // Get all handles that support the partition info protocol.
    let partition_info_handles = uefi
        .find_partition_info_handles()
        .map_err(|err| GptDiskError::PartitionInfoProtocolMissing(err.status()))?;

    for handle in partition_info_handles {
        let partition_info = uefi
            .partition_info_for_handle(handle)
            .map_err(|err| GptDiskError::OpenPartitionInfoProtocolFailed(err.status()))?;

        // Ignore non-GPT partitions.
        let PartitionInfo::Gpt(partition_info) = partition_info else {
            continue;
        };

        // Ignore partitions with a name other than `name`.
        if !is_gpt_partition_entry_named(&partition_info, name) {
            continue;
        }

        // Ignore partitions from a different disk. For example, if the
        // user is running from an installed system but also has an
        // installer USB plugged in, this ensures that we find the
        // partition on the internal disk.
        if is_sibling_partition(uefi, esp_partition_handle, handle)? {
            return Ok((handle, partition_info));
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

pub struct GptDisk {
    block_io: ScopedBlockIo,
    bytes_per_lba: NonZeroU64,
    lba_count: u64,
}

impl GptDisk {
    pub fn new(uefi: &dyn Uefi) -> Result<GptDisk, GptDiskError> {
        let block_io = find_disk_block_io(uefi)?;

        let bytes_per_lba = NonZeroU64::new(block_io.media().block_size().into())
            .ok_or(GptDiskError::InvalidBlockSize)?;
        let lba_count = block_io
            .media()
            .last_block()
            .checked_add(1)
            .ok_or(GptDiskError::InvalidLastBlock)?;

        Ok(GptDisk {
            block_io,
            bytes_per_lba,
            lba_count,
        })
    }
}

impl DiskIo for GptDisk {
    fn bytes_per_lba(&self) -> NonZeroU64 {
        self.bytes_per_lba
    }

    fn lba_count(&self) -> u64 {
        self.lba_count
    }

    fn read(&self, lba_start: u64, buffer: &mut [u8]) -> ReturnCode {
        let media_id = self.block_io.media().media_id();
        match self.block_io.read_blocks(media_id, lba_start, buffer) {
            Ok(()) => ReturnCode::VB2_SUCCESS,
            Err(err) => {
                error!(
                    "disk read failed: lba_start={lba_start}, size in bytes: {}, err: {err:?}",
                    buffer.len()
                );
                ReturnCode::VB2_ERROR_UNKNOWN
            }
        }
    }

    fn write(&mut self, lba_start: u64, buffer: &[u8]) -> ReturnCode {
        let media_id = self.block_io.media().media_id();
        match self.block_io.write_blocks(media_id, lba_start, buffer) {
            Ok(()) => ReturnCode::VB2_SUCCESS,
            Err(err) => {
                error!(
                    "disk write failed: lba_start={lba_start}, size in bytes: {}, err: {err:?}",
                    buffer.len()
                );
                ReturnCode::VB2_ERROR_UNKNOWN
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use core::ffi::c_void;
    use core::{mem, slice};
    use libcrdy::uefi::MockUefi;
    use uefi::data_types::chars::NUL_16;
    use uefi::proto::device_path::build::acpi::Acpi;
    use uefi::proto::device_path::build::hardware::Pci;
    use uefi::proto::device_path::build::media::{FilePath, HardDrive};
    use uefi::proto::device_path::build::messaging::{MacAddress, Scsi};
    use uefi::proto::device_path::build::{self, BuildError, BuildNode};
    use uefi::proto::device_path::media::{PartitionFormat, PartitionSignature};
    use uefi::proto::device_path::DevicePath;
    use uefi::proto::media::block::BlockIO;
    use uefi::proto::media::partition::{
        GptPartitionAttributes, GptPartitionEntry, GptPartitionType, MbrOsType, MbrPartitionRecord,
    };
    use uefi::{guid, CStr16};
    use uefi_raw::protocol::block::{BlockIoMedia, BlockIoProtocol};
    use uefi_raw::protocol::disk::DiskIoProtocol;

    pub(crate) enum BootDrive {
        Hd1,
        Hd2,
        Hd3Mbr,
        HdWithNoEspDeviceHandle,
        Invalid,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum DeviceKind {
        Hd1 = 0,
        Hd1Esp,
        Hd1State,
        Hd2Esp,
        Hd3MbrPartition,
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
            static H: [u8; 8] = [0; 8];
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
                Self::Hd2Esp,
                Self::Hd3MbrPartition,
                Self::FilePath,
                Self::MacAddr,
            ]
        }

        fn partition_info(self) -> Option<PartitionInfo> {
            match self {
                Self::Hd1Esp | Self::Hd2Esp => Some(PartitionInfo::Gpt(GptPartitionEntry {
                    partition_type_guid: GptPartitionType::EFI_SYSTEM_PARTITION,
                    unique_partition_guid: guid!("b1f85a2c-a582-1148-a677-73b11035c739"),
                    starting_lba: 300_000,
                    ending_lba: 400_000,
                    attributes: GptPartitionAttributes::empty(),
                    partition_name: init_partition_name(cstr16!("EFI-SYSTEM")),
                })),
                Self::Hd1State => Some(PartitionInfo::Gpt(GptPartitionEntry {
                    partition_type_guid: GptPartitionType(guid!(
                        "0fc63daf-8483-4772-8e79-3d69d8477de4"
                    )),
                    unique_partition_guid: guid!("1fa90113-672a-4c30-89c6-1b87fe019adc"),
                    starting_lba: 6_000_000,
                    ending_lba: 16_000_000,
                    attributes: GptPartitionAttributes::empty(),
                    partition_name: init_partition_name(cstr16!("STATE")),
                })),
                Self::Hd3MbrPartition => Some(PartitionInfo::Mbr(MbrPartitionRecord {
                    boot_indicator: 0,
                    starting_chs: [1, 2, 3],
                    os_type: MbrOsType(0),
                    ending_chs: [4, 5, 6],
                    starting_lba: 0,
                    size_in_lba: 10000,
                })),
                _ => None,
            }
        }

        fn partition_number(self) -> Option<u32> {
            match self {
                Self::Hd1Esp | Self::Hd2Esp => Some(12),
                Self::Hd1State => Some(1),
                Self::Hd3MbrPartition => Some(1),
                _ => None,
            }
        }

        fn partition_device_path_node(self) -> Option<HardDrive> {
            match self.partition_info()? {
                PartitionInfo::Gpt(gpt) => Some(HardDrive {
                    partition_number: self.partition_number().unwrap(),
                    partition_start: gpt.starting_lba,
                    partition_size: gpt.num_blocks().unwrap(),
                    partition_signature: PartitionSignature::Guid(gpt.unique_partition_guid),
                    partition_format: PartitionFormat::GPT,
                }),
                PartitionInfo::Mbr(mbr) => Some(HardDrive {
                    partition_number: self.partition_number().unwrap(),
                    partition_start: mbr.starting_lba.into(),
                    partition_size: mbr.size_in_lba.into(),
                    partition_signature: PartitionSignature::Mbr([3; 4]),
                    partition_format: PartitionFormat::MBR,
                }),
            }
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
                Self::Hd1Esp => {
                    nodes.extend(hd1);
                    nodes.push(partition.unwrap());
                }
                Self::Hd1State => {
                    nodes.extend(hd1);
                    nodes.push(partition.unwrap());
                }
                Self::Hd2Esp => {
                    nodes.extend(hd2);
                    nodes.push(partition.unwrap());
                }
                Self::Hd3MbrPartition => {
                    nodes.extend(hd3);
                    nodes.push(partition.unwrap());
                }
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
            let _ = builder.finalize()?;

            let path: Box<[u8]> = vec.into_boxed_slice();
            // TODO(b/366018844): add a way to construct Box<DevicePath>` to
            // uefi-rs.
            let path: Box<DevicePath> = unsafe { mem::transmute(path) };

            Ok(ScopedDevicePath::Boxed(path))
        }
    }

    pub(crate) fn create_mock_uefi(boot_drive: BootDrive) -> MockUefi {
        static MEDIA: BlockIoMedia = BlockIoMedia {
            media_id: 123,
            removable_media: false,
            media_present: true,
            logical_partition: false,
            read_only: false,
            write_caching: false,
            block_size: 512,
            io_align: 0,
            last_block: 9999,
            lowest_aligned_lba: 0,
            logical_blocks_per_physical_block: 1,
            optimal_transfer_length_granularity: 1,
        };

        unsafe extern "efiapi" fn read_blocks(
            this: *const BlockIoProtocol,
            _media_id: u32,
            lba: u64,
            buffer_size: usize,
            buffer: *mut c_void,
        ) -> uefi_raw::Status {
            if lba > (*(*this).media).last_block {
                return uefi_raw::Status::INVALID_PARAMETER;
            }

            let buffer: &mut [u8] = slice::from_raw_parts_mut(buffer.cast(), buffer_size);
            assert_eq!(buffer.len() % 8, 0);
            for chunk in buffer.chunks_mut(8) {
                chunk.copy_from_slice(&lba.to_le_bytes());
            }
            uefi_raw::Status::SUCCESS
        }

        unsafe extern "efiapi" fn write_blocks(
            this: *mut BlockIoProtocol,
            _media_id: u32,
            lba: u64,
            _buffer_size: usize,
            _buffer: *const c_void,
        ) -> uefi_raw::Status {
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
            _media_id: u32,
            offset: u64,
            buffer_size: usize,
            buffer: *mut c_void,
        ) -> uefi_raw::Status {
            static DATA: &[u8] =
                include_bytes!("../../workspace/crdyboot_test_data/stateful_test_partition.bin");

            let offset = usize::try_from(offset).unwrap();
            let Some(src) = DATA.get(offset..offset + buffer_size) else {
                return Status::INVALID_PARAMETER;
            };

            buffer.cast::<u8>().copy_from(src.as_ptr(), buffer_size);

            return Status::SUCCESS;
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
                BootDrive::Hd3Mbr => Ok(Some(DeviceKind::Hd3MbrPartition.handle())),
                BootDrive::HdWithNoEspDeviceHandle => Ok(None),
                BootDrive::Invalid => Err(Status::INVALID_PARAMETER.into()),
            });
        uefi.expect_find_partition_info_handles().returning(|| {
            Ok(DeviceKind::all()
                .iter()
                .filter(|kind| kind.partition_info().is_some())
                .map(|kind| kind.handle())
                .collect())
        });
        uefi.expect_find_block_io_handles().returning(|| {
            Ok(vec![
                DeviceKind::Hd1.handle(),
                DeviceKind::Hd1Esp.handle(),
                DeviceKind::Hd1State.handle(),
                DeviceKind::Hd2Esp.handle(),
            ])
        });
        uefi.expect_partition_info_for_handle()
            .returning(|handle| Ok(DeviceKind::from_handle(handle).partition_info().unwrap()));
        uefi.expect_open_block_io().returning(|_| {
            let bio = BlockIoProtocol {
                revision: 0,
                media: &MEDIA,
                reset,
                read_blocks,
                write_blocks,
                flush_blocks,
            };
            let bio: BlockIO = unsafe { mem::transmute(bio) };
            Ok(ScopedBlockIo::ForTest(bio))
        });
        uefi.expect_open_disk_io().returning(|handle| {
            assert_eq!(handle, DeviceKind::Hd1State.handle());
            let dio = DiskIoProtocol {
                revision: DiskIoProtocol::REVISION,
                read_disk,
                write_disk,
            };
            let dio: uefi::proto::media::disk::DiskIo = unsafe { mem::transmute(dio) };
            Ok(ScopedDiskIo::ForTest(dio))
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

    /// Test that `is_sibling_partition` returns true for sibling partitions.
    #[test]
    fn test_is_sibling_partition_true() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        assert!(is_sibling_partition(
            &uefi,
            DeviceKind::Hd1Esp.handle(),
            DeviceKind::Hd1State.handle(),
        )
        .unwrap());
    }

    /// Test that `is_sibling_partition` returns false for partitions on
    /// different drives.
    #[test]
    fn test_is_sibling_partition_false() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        assert!(!is_sibling_partition(
            &uefi,
            DeviceKind::Hd1Esp.handle(),
            DeviceKind::Hd2Esp.handle(),
        )
        .unwrap());
    }

    /// Test that `is_sibling_partition` returns false for device paths
    /// of different lengths.
    #[test]
    fn test_is_sibling_partition_different_lengths() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        assert!(!is_sibling_partition(
            &uefi,
            DeviceKind::Hd1Esp.handle(),
            DeviceKind::Hd1.handle(),
        )
        .unwrap());
    }

    /// Test that `is_sibling_partition` returns false for paths that
    /// end with a non-partition node.
    #[test]
    fn test_is_sibling_partition_non_partition() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        assert!(!is_sibling_partition(
            &uefi,
            DeviceKind::Hd1Esp.handle(),
            DeviceKind::FilePath.handle(),
        )
        .unwrap());
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
            (10_000_001 * 512)
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
            guid!("1fa90113-672a-4c30-89c6-1b87fe019adc")
        );
    }

    fn create_gpt_partition_entry(partition_name: [Char16; 36]) -> GptPartitionEntry {
        GptPartitionEntry {
            partition_type_guid: GptPartitionType(guid!("7ce8b0e4-20a9-4edd-9982-fe9c84e06e6f")),
            unique_partition_guid: guid!("1fa90113-672a-4c30-89c6-1b87fe019adc"),
            starting_lba: 0,
            ending_lba: 10000,
            attributes: GptPartitionAttributes::empty(),
            partition_name,
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

    /// Test that `find_partition_by_name` fails for MBR disks.
    #[test]
    fn test_find_partition_by_name_mbr_fail() {
        let uefi = create_mock_uefi(BootDrive::Hd3Mbr);

        assert_eq!(
            find_partition_by_name(&uefi, cstr16!("STATE")).unwrap_err(),
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

    /// Test that `GptDisk` accessor methods work.
    #[test]
    fn test_gpt_disk_accessors() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        let disk = GptDisk::new(&uefi).unwrap();
        assert_eq!(disk.bytes_per_lba().get(), 512);
        assert_eq!(disk.lba_count(), 10_000);
    }

    /// Test that `GptDisk` can read via the Block IO protocol.
    #[test]
    fn test_gpt_disk_read() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        let disk = GptDisk::new(&uefi).unwrap();

        fn check_block(block: &[u8], block_num: u64) {
            assert_eq!(block.len(), 512);
            let mut expected = Vec::new();
            for _ in 0..(512 / 8) {
                expected.extend(block_num.to_le_bytes());
            }
            assert_eq!(block, expected, "bad block: {block_num}");
        }

        // Valid reads.
        let mut block = vec![0; 512];
        assert_eq!(disk.read(0, &mut block), ReturnCode::VB2_SUCCESS);
        check_block(&block, 0);
        assert_eq!(disk.read(1, &mut block), ReturnCode::VB2_SUCCESS);
        check_block(&block, 1);
        assert_eq!(disk.read(9999, &mut block), ReturnCode::VB2_SUCCESS);
        check_block(&block, 9999);

        // Out of range starting block.
        assert_eq!(disk.read(10_000, &mut block), ReturnCode::VB2_ERROR_UNKNOWN);
    }

    /// Test that `GptDisk` can write via the Block IO protocol.
    #[test]
    fn test_gpt_disk_write() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        let mut disk = GptDisk::new(&uefi).unwrap();
        let block = vec![0; 512];

        // Valid write.
        assert_eq!(disk.write(0, &block), ReturnCode::VB2_SUCCESS);

        // Out of range starting block.
        assert_eq!(disk.write(10_000, &block), ReturnCode::VB2_ERROR_UNKNOWN);
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
}
