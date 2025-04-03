// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk;
use crate::firmware::{FirmwareError, UpdateInfo};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt::{self, Display, Formatter};
use ext4_view::{Ext4, Ext4Read, PathBuf};
use libcrdy::page_alloc::ScopedPageAllocation;
use libcrdy::uefi::{ScopedDiskIo, Uefi};
use log::info;
use uefi::boot::{AllocateType, MemoryType};

#[cfg_attr(test, mockall::automock)]
pub trait CapsuleLoader {
    /// Load all update capsules from the stateful partition.
    ///
    /// Any capsule that cannot be read is skipped.
    fn load_capsules_from_disk(
        &self,
        uefi: &dyn Uefi,
        updates: &[UpdateInfo],
    ) -> Result<Vec<ScopedPageAllocation>, FirmwareError>;
}

pub struct CapsuleLoaderImpl;

impl CapsuleLoader for CapsuleLoaderImpl {
    fn load_capsules_from_disk(
        &self,
        uefi: &dyn Uefi,
        updates: &[UpdateInfo],
    ) -> Result<Vec<ScopedPageAllocation>, FirmwareError> {
        // Find and open the stateful partition block device.
        let (stateful_disk_io, media_id) = disk::open_stateful_partition(uefi)
            .map_err(FirmwareError::OpenStatefulPartitionFailed)?;

        // Create a reader and load the stateful filesystem.
        let stateful_reader = Box::new(DiskReader {
            disk_io: stateful_disk_io,
            media_id,
        });
        let stateful_fs = Ext4::load(stateful_reader).map_err(FirmwareError::Ext4LoadFailed)?;

        // Load all capsules. Errors are logged but otherwise ignored.
        let mut capsules: Vec<ScopedPageAllocation> = Vec::with_capacity(updates.len());
        for update in updates {
            match load_one_capsule_from_disk(&stateful_fs, update) {
                Ok(capsule) => capsules.push(capsule),
                Err(err) => info!("failed to read capsule: {err}"),
            }
        }

        Ok(capsules)
    }
}

/// Load a single update capsule from the stateful partition.
fn load_one_capsule_from_disk(
    fs: &Ext4,
    update: &UpdateInfo,
) -> Result<ScopedPageAllocation, FirmwareError> {
    let file_path = update.file_path()?;
    let path = PathBuf::new("/unencrypted/uefi_capsule_updates").join(file_path);

    info!(
        "reading update {} from path: {}",
        update.name(),
        path.display()
    );

    // TODO(b/373881398): right now ext4-view-rs only provides this one
    // way to read files, which internally allocates a `Vec`. The UEFI
    // spec requires that capsules be page aligned, which we can't
    // guarantee with a `Vec<u8>`.
    //
    // For now, read into a vec and copy into a new allocation. When
    // ext4-view-rs supports reading into an existing buffer, switch to
    // that API.
    let data = fs.read(&path).map_err(FirmwareError::Ext4ReadFailed)?;

    let mut pages = ScopedPageAllocation::new_unaligned(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        data.len(),
    )
    .map_err(FirmwareError::CapsuleAllocationFailed)?;
    // Slice cannot fail, `alloc.len()` is guaranteed to be at least as
    // large as `data.len()`.
    #[expect(clippy::indexing_slicing)]
    pages[..data.len()].copy_from_slice(&data);

    Ok(pages)
}

struct DiskReader {
    disk_io: ScopedDiskIo,
    media_id: u32,
}

impl Ext4Read for DiskReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        self.disk_io
            .read_disk(self.media_id, start_byte, dst)
            .map_err(|err| ReadError::boxed(start_byte, dst, err))
    }
}

/// Error type produced by `DiskReader::read`.
#[derive(Debug, thiserror::Error)]
struct ReadError {
    start_byte: u64,
    len: usize,
    err: uefi::Error,
}

impl ReadError {
    /// Create a boxed `ReadError`. This is returned as a `Box<dyn ...>`
    /// to match the ext4 API.
    fn boxed(
        start_byte: u64,
        dst: &[u8],
        err: uefi::Error,
    ) -> Box<dyn Error + Send + Sync + 'static> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::tests::{create_mock_uefi, BootDrive};
    use crate::firmware::update_info::tests::{
        create_update_info, create_update_info_with_modified_path,
        create_update_info_with_no_file_path,
    };

    /// Test that `load_capsules_from_disk` successfully loads an update
    /// capsule, and correctly ignores capsules that cannot be loaded.
    #[test]
    fn test_load_capsules_from_disk() {
        log::set_max_level(log::LevelFilter::Info);

        let uefi = create_mock_uefi(BootDrive::Hd1);

        let updates = [
            // This update has no file path and will be silently skipped.
            create_update_info_with_no_file_path(),
            // This update does not exist on disk and will be silently skipped.
            create_update_info_with_modified_path(),
            // This update is valid and will be loaded.
            create_update_info(),
        ];
        let mut expected = b"test capsule data".to_vec();
        expected.resize(4096, 0u8);
        let actual = CapsuleLoaderImpl
            .load_capsules_from_disk(&uefi, &updates)
            .unwrap();
        assert_eq!(actual.len(), 1);
        assert_eq!(&*actual[0], expected);
    }

    /// Test that `DiskReader::read` returns an error when an invalid
    /// range is requested.
    #[test]
    fn test_disk_reader_error() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        let (stateful_disk_io, media_id) = disk::open_stateful_partition(&uefi).unwrap();
        let mut reader = Box::new(DiskReader {
            disk_io: stateful_disk_io,
            media_id,
        });
        // The test disk is much smaller than 1GiB, so reading at this
        // large offset is expected to fail.
        let byte_offset_1gib = 1024 * 1024 * 1024;
        assert!(reader.read(byte_offset_1gib, &mut []).is_err());
    }

    /// Test that `ReadError` formats correctly.
    #[test]
    fn test_read_error() {
        let dst = [0; 7];
        let err = ReadError::boxed(123, &dst, uefi::Status::INVALID_PARAMETER.into());
        assert_eq!(
            format!("{err}"),
            "disk read of 7 bytes at 123 failed: UEFI Error INVALID_PARAMETER: ()"
        )
    }
}
