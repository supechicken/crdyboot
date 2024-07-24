// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::fmt::{self, Display, Formatter};
use core::num::NonZeroU64;
use log::error;
use uefi::prelude::*;
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use vboot::{DiskIo, ReturnCode};

pub enum GptDiskError {
    /// The disk block size is zero.
    InvalidBlockSize,

    /// The number of blocks cannot fit in [`u64`].
    InvalidLastBlock,

    /// No handles support the [`BlockIO`] protocol.
    BlockIoProtocolMissing(Status),

    /// Failed to open the [`BlockIO`] protocol.
    OpenBlockIoProtocolFailed(Status),

    /// Failed to open the [`DevicePath`] protocol.
    OpenDevicePathProtocolFailed(Status),

    /// Failed to open the [`LoadedImage`] protocol.
    OpenLoadedImageProtocolFailed(Status),

    /// The [`LoadedImage`] does not have a device handle set.
    LoadedImageHasNoDevice,

    /// Failed to find the handle for the disk that the current
    /// executable was booted from.
    ParentDiskNotFound,
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
            Self::OpenBlockIoProtocolFailed(status) => {
                write!(f, "failed to open the BlockIO protocol: {status}")
            }
            Self::OpenDevicePathProtocolFailed(status) => {
                write!(f, "failed to open the DevicePath protocol: {status}")
            }
            Self::OpenLoadedImageProtocolFailed(status) => {
                write!(f, "failed to open the LoadedImage protocol: {status}")
            }
            Self::LoadedImageHasNoDevice => {
                write!(f, "the LoadedImage does not have a device handle set")
            }
            Self::ParentDiskNotFound => {
                write!(f, "failed to get parent disk")
            }
        }
    }
}

/// Open `DevicePath` protocol for `handle`.
fn device_paths_for_handle(
    handle: Handle,
    bt: &BootServices,
) -> Result<ScopedProtocol<DevicePath>, GptDiskError> {
    // Safety: this protocol cannot be opened in exclusive mode. This
    // should be fine here as device paths are immutable.
    let device_path = unsafe {
        bt.open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle,
                agent: bt.image_handle(),
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
    potential_parent: Handle,
    partition: Handle,
    bt: &BootServices,
) -> Result<bool, GptDiskError> {
    let potential_parent_device_path = device_paths_for_handle(potential_parent, bt)?;
    let potential_parent_device_path_node_iter = potential_parent_device_path.node_iter();
    let partition_device_path = device_paths_for_handle(partition, bt)?;
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
    block_io_handles: &[Handle],
    partition_handle: Handle,
    bt: &BootServices,
) -> Result<Handle, GptDiskError> {
    for handle in block_io_handles {
        if is_parent_disk(*handle, partition_handle, bt)? {
            return Ok(*handle);
        }
    }

    Err(GptDiskError::ParentDiskNotFound)
}

/// Find the [`Handle`] corresponding to the ESP partition that this
/// executable is running from.
fn find_esp_partition_handle(bt: &BootServices) -> Result<Handle, GptDiskError> {
    // Get the LoadedImage protocol for the image handle. This provides
    // a device handle which should correspond to the partition that the
    // image was loaded from.
    let loaded_image = bt
        .open_protocol_exclusive::<LoadedImage>(bt.image_handle())
        .map_err(|err| GptDiskError::OpenLoadedImageProtocolFailed(err.status()))?;
    loaded_image
        .device()
        .ok_or(GptDiskError::LoadedImageHasNoDevice)
}

fn find_disk_block_io(bt: &BootServices) -> Result<ScopedProtocol<BlockIO>, GptDiskError> {
    let partition_handle = find_esp_partition_handle(bt)?;

    // Get all handles that support BlockIO. This includes both disk devices
    // and logical partition devices.
    let block_io_handles = bt
        .find_handles::<BlockIO>()
        .map_err(|err| GptDiskError::BlockIoProtocolMissing(err.status()))?;

    // Find the parent disk device of the logical partition device.
    let disk_handle = find_parent_disk(&block_io_handles, partition_handle, bt)?;

    // Open the protocol with `GetProtocol` instead of `Exclusive`. On
    // the X1Cg9, opening the protocol in exclusive mode takes over
    // 800ms for some unknown reason.
    //
    // Functionally there's not much difference in safety here, since
    // crdyboot is the only code that should be running other than the
    // firmware. Grub also opens the protocol in non-exclusive mode.
    unsafe {
        bt.open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle: disk_handle,
                agent: bt.image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|err| GptDiskError::OpenBlockIoProtocolFailed(err.status()))
    }
}

pub struct GptDisk<'a> {
    block_io: ScopedProtocol<'a, BlockIO>,
    bytes_per_lba: NonZeroU64,
    lba_count: u64,
}

impl<'a> GptDisk<'a> {
    pub fn new(bt: &'a BootServices) -> Result<GptDisk<'a>, GptDiskError> {
        let block_io = find_disk_block_io(bt)?;

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

impl<'a> DiskIo for GptDisk<'a> {
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
