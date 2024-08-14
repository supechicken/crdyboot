// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk;
use crate::firmware::{FirmwareError, UpdateInfo};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};
use ext4_view::{Ext4, Ext4Read, IoError, PathBuf};
use log::info;
use uefi::prelude::*;
use uefi::proto::media::disk::DiskIo;

/// Load a single update capsule from the stateful partition.
fn load_one_capsule_from_disk(fs: &Ext4, update: &UpdateInfo) -> Result<Vec<u8>, FirmwareError> {
    let file_path = update.file_path()?;
    let path = PathBuf::new("/unencrypted/uefi_capsule_updates").join(file_path);

    info!(
        "reading update {} from path: {}",
        update.name(),
        path.display()
    );

    fs.read(&path).map_err(FirmwareError::Ext4ReadFailed)
}

/// Load all update capsules from the stateful partition.
///
/// Any capsule that cannot be read is skipped.
pub fn load_capsules_from_disk(
    boot_services: &BootServices,
    updates: &[UpdateInfo],
) -> Result<Vec<Vec<u8>>, FirmwareError> {
    // Find and open the stateful partition block device.
    let (stateful_disk_io, media_id) = disk::open_stateful_partition(boot_services)
        .map_err(FirmwareError::OpenStatefulPartitionFailed)?;

    // Create a reader and load the stateful filesystem.
    let stateful_reader = Box::new(DiskReader {
        disk_io: &*stateful_disk_io,
        media_id,
    });
    let stateful_fs = Ext4::load(stateful_reader).map_err(FirmwareError::Ext4LoadFailed)?;

    // Load all capsules. Errors are logged but otherwise ignored.
    let mut capsules: Vec<Vec<u8>> = Vec::with_capacity(updates.len());
    for update in updates {
        match load_one_capsule_from_disk(&stateful_fs, update) {
            Ok(capsule) => capsules.push(capsule),
            Err(err) => info!("failed to read capsule: {err}"),
        }
    }

    // Explicit drops to make it clear that `stateful_disk_io` outlives
    // `stateful_fs`. See safety comment `DiskReader::read` for why this
    // is important.
    drop(stateful_fs);
    drop(stateful_disk_io);

    Ok(capsules)
}

struct DiskReader {
    // Use a raw pointer to the protocol rather than `ScopedProtocol`
    // because the latter requires a lifetime parameter, and a lifetime
    // parameter on this struct would make it incompatible with the
    // `Ext4` API,
    //
    // TODO(nicholasbishop): an upcoming release of uefi-rs will provide
    // a lifetime-less `ScopedProtocol` API. Once that's available,
    // switch to that and remove some `unsafe` code.
    disk_io: *const DiskIo,
    media_id: u32,
}

impl Ext4Read for DiskReader {
    fn read(&mut self, start_byte: u64, dst: &mut [u8]) -> Result<(), Box<dyn IoError>> {
        // SAFETY: this is a pointer to the protocol opened in
        // update_firmware. The pointer will remain valid until the
        // `ScopedProtocol` is dropped, which is done explicitly with a
        // call to `drop`.
        let disk_io = unsafe { &*self.disk_io };

        disk_io
            .read_disk(self.media_id, start_byte, dst)
            .map_err(|err| ReadError::boxed(start_byte, dst, err))
    }
}

/// Error type produced by `DiskReader::read`.
#[derive(Debug)]
struct ReadError {
    start_byte: u64,
    len: usize,
    err: uefi::Error,
}

impl ReadError {
    /// Create a boxed `ReadError`. This is returned as a `Box<dyn
    /// IoError>` to match the ext4 API.
    fn boxed(start_byte: u64, dst: &[u8], err: uefi::Error) -> Box<dyn IoError> {
        Box::new(Self {
            start_byte,
            len: dst.len(),
            err,
        })
    }
}

impl Display for ReadError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "disk read of {len} bytes at {start_byte} failed: {err}",
            len = self.len,
            start_byte = self.start_byte,
            err = self.err
        )
    }
}

impl IoError for ReadError {}
