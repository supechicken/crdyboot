// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::{find_disk_block_io, GptDiskError};
use core::num::NonZeroU64;
use libcrdy::uefi::{ScopedBlockIo, Uefi};
use log::info;
use vboot::{DiskIo, ReturnCode};

pub struct VbootGptDisk {
    block_io: ScopedBlockIo,
    bytes_per_lba: NonZeroU64,
    lba_count: u64,
}

impl VbootGptDisk {
    pub fn new(uefi: &dyn Uefi) -> Result<Self, GptDiskError> {
        let block_io = find_disk_block_io(uefi)?;

        let bytes_per_lba = NonZeroU64::new(block_io.media().block_size().into())
            .ok_or(GptDiskError::InvalidBlockSize)?;
        let lba_count = block_io
            .media()
            .last_block()
            .checked_add(1)
            .ok_or(GptDiskError::InvalidLastBlock)?;

        Ok(Self {
            block_io,
            bytes_per_lba,
            lba_count,
        })
    }
}

impl DiskIo for VbootGptDisk {
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
                info!(
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
                info!(
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
    use crate::disk::tests::{create_mock_uefi, BootDrive, VBOOT_TEST_DISK};
    use libcrdy::util::usize_to_u64;

    /// Test that `VbootGptDisk` accessor methods work.
    #[test]
    fn test_gpt_disk_accessors() {
        let uefi = create_mock_uefi(BootDrive::Hd1);
        let disk = VbootGptDisk::new(&uefi).unwrap();
        assert_eq!(disk.bytes_per_lba().get(), 512);
        assert_eq!(disk.lba_count(), usize_to_u64(VBOOT_TEST_DISK.len() / 512));
    }

    /// Test that `VbootGptDisk` can read via the Block IO protocol.
    #[test]
    fn test_gpt_disk_read() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        let disk = VbootGptDisk::new(&uefi).unwrap();

        // Valid read.
        let mut blocks = vec![0; 512 * 3];
        assert_eq!(disk.read(1, &mut blocks), ReturnCode::VB2_SUCCESS);
        assert_eq!(blocks, VBOOT_TEST_DISK[512..512 * 4]);

        // Out of range starting block.
        assert_eq!(
            disk.read(100_000_000, &mut blocks),
            ReturnCode::VB2_ERROR_UNKNOWN
        );
    }

    /// Test that `VbootGptDisk` can write via the Block IO protocol.
    #[test]
    fn test_gpt_disk_write() {
        let uefi = create_mock_uefi(BootDrive::Hd1);

        let mut disk = VbootGptDisk::new(&uefi).unwrap();
        let block = vec![0; 512];

        // Valid write.
        assert_eq!(disk.write(0, &block), ReturnCode::VB2_SUCCESS);

        // Out of range starting block.
        assert_eq!(
            disk.write(100_000_000, &block),
            ReturnCode::VB2_ERROR_UNKNOWN
        );
    }
}
