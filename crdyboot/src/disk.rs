use crate::result::{Error, Result};
use log::error;
use uefi::prelude::*;
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use vboot::DiskIo;
use vboot::ReturnCode;

/// Open `DevicePath` protocol for `handle`.
fn device_paths_for_handle(
    handle: Handle,
    bt: &BootServices,
) -> Result<&DevicePath> {
    let device_path = bt
        .handle_protocol::<DevicePath>(handle)
        .log_warning()
        .map_err(|err| Error::DevicePathProtocolMissing(err.status()))?;
    let device_path = unsafe { &*device_path.get() };
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
) -> Result<bool> {
    let potential_parent_paths_iter =
        device_paths_for_handle(potential_parent, bt)?.iter();
    let mut partition_paths_iter =
        device_paths_for_handle(partition, bt)?.iter();

    for (parent_path, partition_path) in
        potential_parent_paths_iter.zip(&mut partition_paths_iter)
    {
        if parent_path != partition_path {
            return Ok(false);
        }
    }

    // After the zip operation we expect there to be one remaining path for the
    // partition device; validate that this expectation is met.
    let final_partition_path = if let Some(path) = partition_paths_iter.next() {
        path
    } else {
        return Ok(false);
    };

    // That final path should be a Hard Drive Media Device Path.
    if final_partition_path.full_type()
        != (DeviceType::MEDIA, DeviceSubType::MEDIA_HARD_DRIVE)
    {
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
) -> Result<Handle> {
    for handle in block_io_handles {
        if is_parent_disk(*handle, partition_handle, bt)? {
            return Ok(*handle);
        }
    }

    Err(Error::ParentDiskNotFound)
}

pub fn find_disk_block_io(
    crdyboot_image: Handle,
    bt: &BootServices,
) -> Result<&BlockIO> {
    // Get the LoadedImage protocol for the image handle. This provides a
    // device handle which should correspond to the disk that the image was
    // loaded from.
    let loaded_image = bt
        .handle_protocol::<LoadedImage>(crdyboot_image)
        .log_warning()
        .map_err(|err| Error::LoadedImageProtocolMissing(err.status()))?;
    let loaded_image = unsafe { &*loaded_image.get() };
    let partition_handle = loaded_image.device();

    // Get all handles that support BlockIO. This includes both disk devices
    // and logical partition devices.
    let block_io_handles = bt
        .find_handles::<BlockIO>()
        .log_warning()
        .map_err(|err| Error::BlockIoProtocolMissing(err.status()))?;

    // Find the parent disk device of the logical partition device.
    let disk_handle =
        find_parent_disk(&block_io_handles, partition_handle, bt)?;

    let disk_block_io = bt
        .handle_protocol::<BlockIO>(disk_handle)
        .log_warning()
        .map_err(|err| Error::BlockIoProtocolMissing(err.status()))?;
    let disk_block_io = unsafe { &*disk_block_io.get() };
    Ok(disk_block_io)
}

pub struct GptDisk<'a> {
    block_io: &'a BlockIO,
}

impl<'a> GptDisk<'a> {
    pub fn new(
        crdyboot_image: Handle,
        bt: &'a BootServices,
    ) -> Result<GptDisk<'a>> {
        let block_io = find_disk_block_io(crdyboot_image, bt)?;

        Ok(GptDisk { block_io })
    }
}

impl<'a> DiskIo for GptDisk<'a> {
    fn bytes_per_lba(&self) -> u64 {
        self.block_io.media().block_size().into()
    }

    fn lba_count(&self) -> u64 {
        self.block_io.media().last_block() + 1
    }

    fn read(&self, lba_start: u64, buffer: &mut [u8]) -> ReturnCode {
        match self
            .block_io
            .read_blocks(self.block_io.media().media_id(), lba_start, buffer)
            .log_warning()
        {
            Ok(()) => ReturnCode::VB2_SUCCESS,
            Err(err) => {
                error!("disk read failed: lba_start={}, size in bytes: {}, err: {:?}",
                       lba_start, buffer.len(), err);
                // TODO: is there a more specific vb2 error code that would be
                // better to return here?
                ReturnCode::VB2_ERROR_UNKNOWN
            }
        }
    }
}
