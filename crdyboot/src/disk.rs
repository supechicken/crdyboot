// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::fmt::{self, Display, Formatter};
use core::num::NonZeroU64;
use libcrdy::uefi::{PartitionInfo, ScopedDevicePath, Uefi, UefiImpl};
use log::error;
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::prelude::*;
use uefi::proto::device_path::{DeviceSubType, DeviceType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::disk::DiskIo as UefiDiskIo;
use uefi::proto::media::partition;
use uefi::Char16;
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

    /// Failed to find the handle for the stateful partition.
    StatefulPartitionNotFound,
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
            Self::StatefulPartitionNotFound => {
                write!(f, "failed to find stateful partition handle")
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
fn find_esp_partition_handle(_uefi: &dyn Uefi) -> Result<Handle, GptDiskError> {
    // Get the LoadedImage protocol for the image handle. This provides
    // a device handle which should correspond to the partition that the
    // image was loaded from.
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|err| GptDiskError::OpenLoadedImageProtocolFailed(err.status()))?;
    loaded_image
        .device()
        .ok_or(GptDiskError::LoadedImageHasNoDevice)
}

fn find_disk_block_io() -> Result<ScopedProtocol<BlockIO>, GptDiskError> {
    let uefi = &UefiImpl;

    let partition_handle = find_esp_partition_handle(uefi)?;

    // Get all handles that support BlockIO. This includes both disk devices
    // and logical partition devices.
    let block_io_handles = boot::find_handles::<BlockIO>()
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
        boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle: disk_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
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

// Turn off lint that incorrectly fires on "ChromeOS".
#[allow(clippy::doc_markdown)]
/// Use the `PartitionInfo` protocol to test if `partition_handle`
/// corresponds to a ChromeOS stateful partition.
///
/// This checks if the partition's name is "STATE".
fn is_stateful_partition(uefi: &dyn Uefi, partition_handle: Handle) -> Result<bool, GptDiskError> {
    // Name of the stateful partition.
    const STATE_NAME: &[Char16] = cstr16!("STATE").as_slice_with_nul();

    let partition_info = uefi
        .partition_info_for_handle(partition_handle)
        .map_err(|err| GptDiskError::OpenPartitionInfoProtocolFailed(err.status()))?;

    // Ignore non-GPT partitions.
    let PartitionInfo::Gpt(partition_info) = partition_info else {
        return Ok(false);
    };

    // `PartitionInfo` is `repr(packed)`, which limits operations on
    // fields. Copy the `name` field to a local variable to work around
    // this.
    let name: [Char16; 36] = partition_info.partition_name;

    // Check the partition name. Indexing cannot fail since `name` is
    // longer than `STATE_NAME`.
    #[allow(clippy::indexing_slicing)]
    Ok(name[..STATE_NAME.len()] == *STATE_NAME)
}

/// Get the handle of the stateful partition.
///
/// This finds the stateful partition by its label, and excludes
/// partitions from disks other than the one this executable is running
/// from.
fn find_stateful_partition_handle(uefi: &dyn Uefi) -> Result<Handle, GptDiskError> {
    let esp_partition_handle = find_esp_partition_handle(uefi)?;

    // Get all handles that support the partition info protocol.
    let partition_info_handles = boot::find_handles::<partition::PartitionInfo>()
        .map_err(|err| GptDiskError::PartitionInfoProtocolMissing(err.status()))?;

    for handle in partition_info_handles {
        // Ignore partitions with a name other than "STATE".
        if !is_stateful_partition(uefi, handle)? {
            continue;
        }

        // Ignore partitions from a different disk. For example, if the
        // user is running from an installed system but also has an
        // installer USB plugged in, this ensures that we find the
        // partition on the internal disk.
        if is_sibling_partition(uefi, esp_partition_handle, handle)? {
            return Ok(handle);
        }
    }

    Err(GptDiskError::StatefulPartitionNotFound)
}

/// Open the Disk IO protocol for the stateful partition. This allows
/// byte-level access to partition data.
///
/// Returns a tuple containing the protocol and a media ID of type
/// `u32`. The ID is passed in as a parameter of the protocol's methods.
pub fn open_stateful_partition() -> Result<(ScopedProtocol<UefiDiskIo>, u32), GptDiskError> {
    let uefi = &UefiImpl;

    let stateful_partition_handle = find_stateful_partition_handle(uefi)?;

    // See comment in `find_disk_block_io` for why the non-exclusive
    // mode is used.

    // Get the disk's media ID. This value is needed when calling disk
    // IO operations.
    let media_id = unsafe {
        boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle: stateful_partition_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|err| GptDiskError::OpenBlockIoProtocolFailed(err.status()))?
        .media()
        .media_id()
    };

    let disk_io = unsafe {
        boot::open_protocol::<UefiDiskIo>(
            OpenProtocolParams {
                handle: stateful_partition_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|err| GptDiskError::OpenDiskIoProtocolFailed(err.status()))
    }?;

    Ok((disk_io, media_id))
}

pub struct GptDisk {
    block_io: ScopedProtocol<BlockIO>,
    bytes_per_lba: NonZeroU64,
    lba_count: u64,
}

impl GptDisk {
    pub fn new() -> Result<GptDisk, GptDiskError> {
        let block_io = find_disk_block_io()?;

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
mod tests {
    use super::*;
    use core::mem;
    use libcrdy::uefi::MockUefi;
    use uefi::guid;
    use uefi::proto::device_path::build::acpi::Acpi;
    use uefi::proto::device_path::build::hardware::Pci;
    use uefi::proto::device_path::build::media::{FilePath, HardDrive};
    use uefi::proto::device_path::build::messaging::{MacAddress, Scsi};
    use uefi::proto::device_path::build::{self, BuildError, BuildNode};
    use uefi::proto::device_path::media::{PartitionFormat, PartitionSignature};
    use uefi::proto::device_path::DevicePath;

    #[derive(Clone, Copy, PartialEq)]
    enum DeviceKind {
        HardDrive = 0,
        Partition1,
        Partition2,
        PartitionOnAnotherDrive,
        FilePath,
        MacAddr,
    }

    impl DeviceKind {
        fn all() -> &'static [Self] {
            &[
                Self::HardDrive,
                Self::Partition1,
                Self::Partition2,
                Self::PartitionOnAnotherDrive,
                Self::FilePath,
                Self::MacAddr,
            ]
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
            let partition1 = HardDrive {
                partition_number: 12,
                partition_start: 299008,
                partition_size: 131072,
                partition_signature: PartitionSignature::Guid(guid!(
                    "99cc6f39-2fd1-4d85-b15a-543e7b023a1f"
                )),
                partition_format: PartitionFormat::GPT,
            };
            let partition2 = HardDrive {
                partition_number: 13,
                ..partition1
            };
            let path = FilePath {
                path_name: cstr16!("abc"),
            };

            match self {
                Self::HardDrive => nodes.extend(hd1),
                Self::Partition1 => {
                    nodes.extend(hd1);
                    nodes.push(&partition1);
                }
                Self::Partition2 => {
                    nodes.extend(hd1);
                    nodes.push(&partition2);
                }
                Self::PartitionOnAnotherDrive => {
                    nodes.extend(hd2);
                    // This partition is intentionally identical to the
                    // one on hd1.
                    nodes.push(&partition1);
                }
                Self::FilePath => {
                    nodes.extend(hd1);
                    nodes.push(&path);
                }
                Self::MacAddr => nodes.push(&MacAddress {
                    mac_address: [1; 32],
                    interface_type: 2,
                }),
            };

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

    /// Get a device handle. This will always return the same handle for
    /// the given `kind`.
    fn get_handle(kind: DeviceKind) -> Handle {
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
        let index = kind as usize;
        static H: [u8; 8] = [0; 8];
        let ptr: *const u8 = &H[index];
        let ptr: *mut _ = ptr.cast_mut().cast();
        unsafe { Handle::from_ptr(ptr) }.unwrap()
    }

    fn handle_to_kind(handle: Handle) -> DeviceKind {
        for kind in DeviceKind::all() {
            let kind = *kind;
            if handle == get_handle(kind) {
                return kind;
            }
        }
        panic!("invalid handle");
    }

    fn create_mock_uefi() -> MockUefi {
        let mut uefi = MockUefi::new();
        uefi.expect_device_path_for_handle().returning(|h| {
            let kind = handle_to_kind(h);
            Ok(kind.create_device_path().unwrap())
        });
        uefi
    }

    /// Test that `is_parent_disk` returns true for a valid child
    /// partition.
    #[test]
    fn test_is_parent_disk_partition() {
        let uefi = create_mock_uefi();

        assert!(is_parent_disk(
            &uefi,
            get_handle(DeviceKind::HardDrive),
            get_handle(DeviceKind::Partition1)
        )
        .unwrap());
    }

    /// Test that `is_parent_disk` returns false if the parent has nodes
    /// the child doesn't have.
    #[test]
    fn test_is_parent_disk_nonmatching() {
        let uefi = create_mock_uefi();

        assert!(!is_parent_disk(
            &uefi,
            get_handle(DeviceKind::MacAddr),
            get_handle(DeviceKind::Partition1)
        )
        .unwrap());
    }

    /// Test that `is_parent_disk` returns false if the child doesn't
    /// end with a hard drive partition node.
    #[test]
    fn test_is_parent_disk_nonpartition() {
        let uefi = create_mock_uefi();

        assert!(!is_parent_disk(
            &uefi,
            get_handle(DeviceKind::HardDrive),
            get_handle(DeviceKind::FilePath)
        )
        .unwrap());
    }

    /// Test that `is_parent_disk` returns false for a parent == child.
    #[test]
    fn test_is_parent_disk_harddrive() {
        let uefi = create_mock_uefi();

        assert!(!is_parent_disk(
            &uefi,
            get_handle(DeviceKind::HardDrive),
            get_handle(DeviceKind::HardDrive)
        )
        .unwrap());
    }

    /// Test that `find_parent_disk` identifies the correct handle.
    #[test]
    fn test_find_parent_disk_success() {
        let uefi = create_mock_uefi();

        let all_handles: Vec<_> = DeviceKind::all().iter().map(|k| get_handle(*k)).collect();

        assert_eq!(
            find_parent_disk(&uefi, &all_handles, get_handle(DeviceKind::Partition1)).unwrap(),
            get_handle(DeviceKind::HardDrive)
        );
    }

    /// Test that `find_parent_disk` returns an error if the parent is
    /// not found.
    #[test]
    fn test_find_parent_disk_not_found() {
        let uefi = create_mock_uefi();

        let all_handles: Vec<_> = DeviceKind::all()
            .iter()
            .filter(|k| **k != DeviceKind::HardDrive)
            .map(|k| get_handle(*k))
            .collect();

        assert_eq!(
            find_parent_disk(&uefi, &all_handles, get_handle(DeviceKind::Partition1)),
            Err(GptDiskError::ParentDiskNotFound)
        );
    }

    /// Test that `is_sibling_partition` returns true for sibling partitions.
    #[test]
    fn test_is_sibling_partition_true() {
        let uefi = create_mock_uefi();
        assert!(is_sibling_partition(
            &uefi,
            get_handle(DeviceKind::Partition1),
            get_handle(DeviceKind::Partition2),
        )
        .unwrap());
    }

    /// Test that `is_sibling_partition` returns false for partitions on
    /// different drives.
    #[test]
    fn test_is_sibling_partition_false() {
        let uefi = create_mock_uefi();
        assert!(!is_sibling_partition(
            &uefi,
            get_handle(DeviceKind::Partition1),
            get_handle(DeviceKind::PartitionOnAnotherDrive),
        )
        .unwrap());
    }

    /// Test that `is_sibling_partition` returns false for device paths
    /// of different lengths.
    #[test]
    fn test_is_sibling_partition_different_lengths() {
        let uefi = create_mock_uefi();
        assert!(!is_sibling_partition(
            &uefi,
            get_handle(DeviceKind::Partition1),
            get_handle(DeviceKind::HardDrive),
        )
        .unwrap());
    }

    /// Test that `is_sibling_partition` returns false for paths that
    /// end with a non-partition node.
    #[test]
    fn test_is_sibling_partition_non_partition() {
        let uefi = create_mock_uefi();
        assert!(!is_sibling_partition(
            &uefi,
            get_handle(DeviceKind::Partition1),
            get_handle(DeviceKind::FilePath),
        )
        .unwrap());
    }
}
