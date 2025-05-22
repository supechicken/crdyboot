// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::uefi::ScopedBlockIo;
use gpt_disk_io::gpt_disk_types::{BlockSize, Lba};
use uefi::Status;

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum BlockIoError {
    /// Failed to read blocks.
    #[error("failed to read {0} blocks starting at block {1}: {2}")]
    Read(usize, Lba, Status),

    /// Failed to write blocks.
    #[error("failed to write {0} blocks starting at block {1}: {2}")]
    Write(usize, Lba, Status),

    /// Failed to flush blocks.
    #[error("failed to flush writes: {0}")]
    Flush(Status),
}

impl gpt_disk_io::BlockIo for ScopedBlockIo {
    type Error = BlockIoError;

    fn block_size(&self) -> BlockSize {
        BlockSize::new(self.media().block_size())
            // In the unlikely case that the reported block size is
            // invalid, fall back to the standard 512 byte block size.
            .unwrap_or(BlockSize::BS_512)
    }

    fn num_blocks(&mut self) -> Result<u64, Self::Error> {
        let last_block = self.media().last_block();
        Ok(last_block.saturating_add(1))
    }

    fn read_blocks(&mut self, start_lba: Lba, dst: &mut [u8]) -> Result<(), Self::Error> {
        let media_id = self.media().media_id();
        (**self)
            .read_blocks(media_id, start_lba.0, dst)
            .map_err(|err| BlockIoError::Read(dst.len(), start_lba, err.status()))
    }

    fn write_blocks(&mut self, start_lba: Lba, dst: &[u8]) -> Result<(), Self::Error> {
        let media_id = self.media().media_id();
        (**self)
            .write_blocks(media_id, start_lba.0, dst)
            .map_err(|err| BlockIoError::Write(dst.len(), start_lba, err.status()))
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        (**self)
            .flush_blocks()
            .map_err(|err| BlockIoError::Flush(err.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;
    use core::{mem, slice};
    use gpt_disk_io::BlockIo;
    use uefi::proto::media::block::BlockIO;
    use uefi_raw::protocol::block::{BlockIoMedia, BlockIoProtocol};

    static MEDIA: BlockIoMedia = BlockIoMedia {
        media_id: 123,
        removable_media: false,
        media_present: true,
        logical_partition: false,
        read_only: false,
        write_caching: false,
        block_size: 512,
        io_align: 0,
        last_block: 999,
        lowest_aligned_lba: 0,
        logical_blocks_per_physical_block: 1,
        optimal_transfer_length_granularity: 1,
    };

    unsafe extern "efiapi" fn read_blocks(
        this: *const BlockIoProtocol,
        media_id: u32,
        lba: u64,
        buffer_size: usize,
        buffer: *mut c_void,
    ) -> uefi_raw::Status {
        assert_eq!((*(*this).media).media_id, media_id);
        assert_eq!(media_id, MEDIA.media_id);

        assert_eq!(lba, 123);
        assert_eq!(buffer_size, 1024);

        let dst: &mut [u8] = unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), buffer_size) };
        dst[0] = 10;
        dst[1023] = 20;

        Status::SUCCESS
    }

    unsafe extern "efiapi" fn write_blocks(
        this: *mut BlockIoProtocol,
        media_id: u32,
        lba: u64,
        buffer_size: usize,
        buffer: *const c_void,
    ) -> uefi_raw::Status {
        assert_eq!((*(*this).media).media_id, media_id);
        assert_eq!(media_id, MEDIA.media_id);

        assert_eq!(lba, 123);
        assert_eq!(buffer_size, 1024);

        let dst: &[u8] = unsafe { slice::from_raw_parts(buffer.cast::<u8>(), buffer_size) };
        assert_eq!(dst[0], 10);
        assert_eq!(dst[1023], 20);

        Status::SUCCESS
    }

    unsafe extern "efiapi" fn reset(_: *mut BlockIoProtocol, _: bool) -> uefi_raw::Status {
        unimplemented!()
    }

    unsafe extern "efiapi" fn flush_blocks(_: *mut BlockIoProtocol) -> uefi_raw::Status {
        Status::SUCCESS
    }

    fn create_block_io() -> ScopedBlockIo {
        let bio = BlockIoProtocol {
            revision: 0,
            media: &MEDIA,
            reset,
            read_blocks,
            write_blocks,
            flush_blocks,
        };
        // Safety: `BlockIO` is a `repr(transparent)` wrapper around
        // `BlockIoProtocol`.
        let bio: BlockIO = unsafe { mem::transmute(bio) };
        ScopedBlockIo::for_test(Box::new(bio))
    }

    #[test]
    fn test_block_io_impl() {
        let mut block_io = create_block_io();

        assert_eq!(block_io.block_size().to_u32(), 512);
        assert_eq!(block_io.num_blocks(), Ok(1000));

        let mut buf = vec![0; 1024];
        block_io.read_blocks(Lba(123), &mut buf).unwrap();
        assert_eq!(buf[0], 10);
        assert_eq!(buf[1023], 20);

        block_io.write_blocks(Lba(123), &buf).unwrap();
        block_io.flush().unwrap();
    }
}
