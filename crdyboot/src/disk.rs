use uefi::prelude::*;
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType};
use uefi::Result;

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
pub fn find_parent_disk(
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
