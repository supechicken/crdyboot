// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::fmt::{self, Display, Formatter};
use core::num::NonZeroU64;
use libcrdy::uefi::{Uefi, UefiImpl};
use log::error;
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::prelude::*;
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::disk::DiskIo as UefiDiskIo;
use uefi::proto::media::partition::PartitionInfo;
use uefi::Char16;
use vboot::{DiskIo, ReturnCode};

#[derive(Debug)]
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
fn device_path_for_handle(handle: Handle) -> Result<ScopedProtocol<DevicePath>, GptDiskError> {
    // Safety: this protocol cannot be opened in exclusive mode. This
    // should be fine here as device paths are immutable.
    let device_path = unsafe {
        boot::open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|err| GptDiskError::OpenDevicePathProtocolFailed(err.status()))
    }?;
    Ok(device_path)
}

/// True if `potential_parent` is the handle representing the disk that
/// contains the `partition` device.
///
/// This is determined by looking at the Device Paths associated with each
/// handle. The parent device should have exactly the same set of paths, except
/// that the partition paths end with a Hard Drive Media Device Path.
fn is_parent_disk(
    _uefi: &dyn Uefi,
    potential_parent: Handle,
    partition: Handle,
) -> Result<bool, GptDiskError> {
    let potential_parent_device_path = device_path_for_handle(potential_parent)?;
    let potential_parent_device_path_node_iter = potential_parent_device_path.node_iter();
    let partition_device_path = device_path_for_handle(partition)?;
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
fn find_esp_partition_handle() -> Result<Handle, GptDiskError> {
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

    let partition_handle = find_esp_partition_handle()?;

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
fn is_sibling_partition(_uefi: &dyn Uefi, p1: Handle, p2: Handle) -> Result<bool, GptDiskError> {
    // Get the device path for both partitions.
    let p1 = device_path_for_handle(p1)?;
    let p2 = device_path_for_handle(p2)?;

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
fn is_stateful_partition(partition_handle: Handle) -> Result<bool, GptDiskError> {
    // Name of the stateful partition.
    const STATE_NAME: &[Char16] = cstr16!("STATE").as_slice_with_nul();

    // See comment in `find_disk_block_io` for why the non-exclusive
    // mode is used.
    let partition_info = unsafe {
        boot::open_protocol::<PartitionInfo>(
            OpenProtocolParams {
                handle: partition_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|err| GptDiskError::OpenPartitionInfoProtocolFailed(err.status()))
    }?;

    // Ignore non-GPT partitions.
    let Some(partition_info) = partition_info.gpt_partition_entry() else {
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
fn find_stateful_partition_handle() -> Result<Handle, GptDiskError> {
    let uefi = &UefiImpl;

    let esp_partition_handle = find_esp_partition_handle()?;

    // Get all handles that support the partition info protocol.
    let partition_info_handles = boot::find_handles::<PartitionInfo>()
        .map_err(|err| GptDiskError::PartitionInfoProtocolMissing(err.status()))?;

    for handle in partition_info_handles {
        // Ignore partitions with a name other than "STATE".
        if !is_stateful_partition(handle)? {
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
    let stateful_partition_handle = find_stateful_partition_handle()?;

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
