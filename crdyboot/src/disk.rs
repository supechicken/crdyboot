use log::error;
use uefi::prelude::*;
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::Result;
use vboot::return_code;
use vboot::DiskIo;

/// Open `DevicePath` protocol for `handle`.
fn device_paths_for_handle(
    handle: Handle,
    bt: &BootServices,
) -> Result<&DevicePath> {
    let device_path = bt.handle_protocol::<DevicePath>(handle).log_warning()?;
    let device_path = unsafe { &*device_path.get() };
    Status::SUCCESS.into_with_val(|| device_path)
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
    let ret = |val: bool| Status::SUCCESS.into_with_val(|| val);

    let potential_parent_paths_iter =
        device_paths_for_handle(potential_parent, bt)
            .log_warning()?
            .iter();
    let mut partition_paths_iter =
        device_paths_for_handle(partition, bt).log_warning()?.iter();

    for (parent_path, partition_path) in
        potential_parent_paths_iter.zip(&mut partition_paths_iter)
    {
        if parent_path != partition_path {
            return ret(false);
        }
    }

    // After the zip operation we expect there to be one remaining path for the
    // partition device; validate that this expectation is met.
    let final_partition_path = if let Some(path) = partition_paths_iter.next() {
        path
    } else {
        return ret(false);
    };

    // That final path should be a Hard Drive Media Device Path.
    if final_partition_path.full_type()
        != (DeviceType::MEDIA, DeviceSubType::MEDIA_HARD_DRIVE)
    {
        return ret(false);
    }

    ret(true)
}

/// Search `block_io_handles` for the device that is a parent of
/// `partition_handle`. See `is_parent_disk` for details.
fn find_parent_disk(
    block_io_handles: &[Handle],
    partition_handle: Handle,
    bt: &BootServices,
) -> Result<Option<Handle>> {
    for handle in block_io_handles {
        if is_parent_disk(*handle, partition_handle, bt).log_warning()? {
            return Status::SUCCESS.into_with_val(|| Some(*handle));
        }
    }

    Status::SUCCESS.into_with_val(|| None)
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
        .log_warning()?;
    let loaded_image = unsafe { &*loaded_image.get() };
    let partition_handle = loaded_image.device();

    // Get all handles that support BlockIO. This includes both disk devices
    // and logical partition devices.
    let block_io_handles = bt.find_handles::<BlockIO>().log_warning()?;

    // Find the parent disk device of the logical partition device.
    let disk_handle = if let Some(parent) =
        find_parent_disk(&block_io_handles, partition_handle, bt)
            .log_warning()?
    {
        parent
    } else {
        error!("parent disk not found");
        return Status::NOT_FOUND.into_with_val(|| unreachable!());
    };

    let disk_block_io =
        bt.handle_protocol::<BlockIO>(disk_handle).log_warning()?;
    let disk_block_io = unsafe { &*disk_block_io.get() };
    Status::SUCCESS.into_with_val(|| disk_block_io)
}

pub struct GptDisk<'a> {
    block_io: &'a BlockIO,
}

impl<'a> GptDisk<'a> {
    pub fn new(
        crdyboot_image: Handle,
        bt: &'a BootServices,
    ) -> Result<GptDisk<'a>> {
        let block_io = find_disk_block_io(crdyboot_image, bt).log_warning()?;

        Status::SUCCESS.into_with_val(|| GptDisk { block_io })
    }
}

impl<'a> DiskIo for GptDisk<'a> {
    fn bytes_per_lba(&self) -> u64 {
        self.block_io.media().block_size().into()
    }

    fn lba_count(&self) -> u64 {
        self.block_io.media().last_block() + 1
    }

    fn read(&self, lba_start: u64, buffer: &mut [u8]) -> return_code {
        match self
            .block_io
            .read_blocks(self.block_io.media().media_id(), lba_start, buffer)
            .log_warning()
        {
            Ok(()) => return_code::VB2_SUCCESS,
            Err(err) => {
                error!("disk read failed: lba_start={}, size in bytes: {}, err: {:?}",
                       lba_start, buffer.len(), err);
                // TODO: is there a more specific vb2 error code that would be
                // better to return here?
                return_code::VB2_ERROR_UNKNOWN
            }
        }
    }
}
