// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the disk API that the vboot C library uses
//! for reading and writing to disk.
//!
//! See `vboot_reference/firmware/include/vboot_api.h` for the C header.
//!
//! The vboot C library accesses the disk in two ways:
//! 1. Random-access block IO is used for reading and writing to the GPT
//!    header and partition entry arrays. This is done through the
//!    `VbExDiskRead` and `VbExDiskWrite` functions.
//! 2. Streaming block IO is used for reading the kernel partition
//!    data. This is done through the `VbExStreamOpen`,
//!    `VbExStreamRead`, and `VbExStreamClose` functions.
//!
//! It's up to the program that links in the vboot library to provide
//! implementations of those `VbEx*` functions, and that's what this
//! module does.
//!
//! This module also provides the `DiskIo` trait, which makes it easy to
//! provide different implementations of disk IO (e.g. in-memory disks
//! for unit tests).

use crate::vboot_sys::{vb2_disk_info, vb2ex_disk_handle_t};
use crate::ReturnCode;
use core::marker::PhantomData;
use core::{ptr, slice};
use cty::c_void;
use log::error;

/// Interface for random-access disk IO.
pub trait DiskIo {
    /// Size of a random-access LBA sector in bytes.
    ///
    /// The value returned by this function is not allowed to change
    /// from one call to the next, and must be greater than zero.
    fn bytes_per_lba(&self) -> u64;

    /// Number of random-access LBA sectors on the device.
    fn lba_count(&self) -> u64;

    /// Read LBA sectors starting at `lba_start` from the device into `buffer`.
    fn read(&self, lba_start: u64, buffer: &mut [u8]) -> ReturnCode;

    /// Write LBA sectors from `buffer` to the device starting at `lba_start`.
    fn write(&mut self, lba_start: u64, buffer: &[u8]) -> ReturnCode;
}

pub struct DiskInfo<'a> {
    info: vb2_disk_info,
    phantom: PhantomData<&'a ()>,
}

impl<'a> DiskInfo<'a> {
    pub fn as_mut_ptr(&mut self) -> *mut vb2_disk_info {
        &mut self.info
    }
}

/// Wrap `DiskIo` into a new struct so that we can convert it to a thin pointer
/// and cast that to a `vb2ex_disk_handle_t`.
///
/// Also contains an optional `DiskStreamState`. Only one stream is
/// allowed to exist at a time.
pub struct Disk<'a> {
    io: &'a mut dyn DiskIo,
    stream: Option<DiskStreamState>,
}

impl<'a> Disk<'a> {
    pub fn new(io: &'a mut dyn DiskIo) -> Disk<'a> {
        Disk { io, stream: None }
    }

    fn as_handle(&mut self) -> vb2ex_disk_handle_t {
        (self as *mut Disk).cast::<c_void>()
    }

    unsafe fn from_handle(handle: vb2ex_disk_handle_t) -> &'a mut Disk<'a> {
        &mut *handle.cast::<Disk>()
    }

    pub fn info(&mut self) -> DiskInfo {
        DiskInfo {
            info: vb2_disk_info {
                handle: self.as_handle(),
                bytes_per_lba: self.bytes_per_lba(),
                lba_count: self.lba_count(),
                streaming_lba_count: 0,
                flags: 0,
                name: ptr::null(),
            },
            phantom: PhantomData,
        }
    }

    /// Convert `num_bytes` to number of blocks. Fail if the input is
    /// not an even multiple of the block size.
    fn bytes_to_blocks(&self, num_bytes: u64) -> Option<u64> {
        let bytes_per_lba = self.io.bytes_per_lba();

        if num_bytes % bytes_per_lba != 0 {
            error!(
                "stream read size is not a multiple of the block size: {}",
                num_bytes
            );
            return None;
        }

        num_bytes.checked_div(bytes_per_lba)
    }
}

impl<'a> DiskIo for Disk<'a> {
    fn bytes_per_lba(&self) -> u64 {
        self.io.bytes_per_lba()
    }

    fn lba_count(&self) -> u64 {
        self.io.lba_count()
    }

    fn read(&self, lba_start: u64, buffer: &mut [u8]) -> ReturnCode {
        self.io.read(lba_start, buffer)
    }

    fn write(&mut self, lba_start: u64, buffer: &[u8]) -> ReturnCode {
        self.io.write(lba_start, buffer)
    }
}

#[no_mangle]
unsafe extern "C" fn VbExDiskRead(
    handle: vb2ex_disk_handle_t,
    lba_start: u64,
    lba_count: u64,
    buffer: *mut u8,
) -> ReturnCode {
    assert!(!handle.is_null());
    assert!(!buffer.is_null());

    let disk = Disk::from_handle(handle);

    let buffer_len = (disk.bytes_per_lba() * lba_count)
        .try_into()
        .expect("invalid read size");

    let buffer = slice::from_raw_parts_mut(buffer, buffer_len);

    disk.read(lba_start, buffer)
}

#[no_mangle]
unsafe extern "C" fn VbExDiskWrite(
    handle: vb2ex_disk_handle_t,
    lba_start: u64,
    lba_count: u64,
    buffer: *const u8,
) -> ReturnCode {
    assert!(!handle.is_null());
    assert!(!buffer.is_null());

    let disk = Disk::from_handle(handle);

    let buffer_len = (disk.bytes_per_lba() * lba_count)
        .try_into()
        .expect("invalid write size");

    let buffer = slice::from_raw_parts(buffer, buffer_len);

    disk.write(lba_start, buffer)
}

/// Pointer to a stream. We only allow one open stream per disk, so this
/// is actually just a pointer to a disk.
type DiskStreamHandle = vb2ex_disk_handle_t;

/// Stateful stream handle for reading blocks from disk in order.
struct DiskStreamState {
    cur_lba: u64,
    remaining_blocks: u64,
}

#[no_mangle]
unsafe extern "C" fn VbExStreamOpen(
    handle: vb2ex_disk_handle_t,
    lba_start: u64,
    lba_count: u64,
    stream: *mut DiskStreamHandle,
) -> ReturnCode {
    assert!(!handle.is_null());
    assert!(!stream.is_null());

    let disk = Disk::from_handle(handle);

    // Our implementation assumes that vboot won't try to open multiple
    // streams at the same time.
    if disk.stream.is_some() {
        error!("attempted to open more than one stream");
        return ReturnCode::VB2_ERROR_UNKNOWN;
    }

    disk.stream = Some(DiskStreamState {
        cur_lba: lba_start,
        remaining_blocks: lba_count,
    });

    // Write out the stream handle, which is the same as the disk
    // handle. We only allow one open stream per disk, so having the
    // disk pointer is sufficient to get the stream.
    //
    // Making these pointers one and the same makes it easier to avoid
    // running afoul of Miri checks, because we don't need a pointer to
    // the disk inside of the stream state. That would be a problem
    // because the stream data is inside the disk data, so you can't
    // mutably borrow both at the same time.
    *stream = handle;

    ReturnCode::VB2_SUCCESS
}

#[no_mangle]
unsafe extern "C" fn VbExStreamRead(
    stream_handle: DiskStreamHandle,
    num_bytes: u32,
    buffer: *mut u8,
) -> ReturnCode {
    assert!(!stream_handle.is_null());
    assert!(!buffer.is_null());

    let num_blocks;
    let cur_lba;

    // Scope access to the disk so that when we call `VbExDiskRead` we
    // don't have any references in use that Miri would warn about.
    {
        let disk = Disk::from_handle(stream_handle);

        // Get the number of blocks to read.
        if let Some(blocks) = disk.bytes_to_blocks(u64::from(num_bytes)) {
            num_blocks = blocks;
        } else {
            return ReturnCode::VB2_ERROR_UNKNOWN;
        };

        let stream = disk.stream.as_mut().expect("no open stream");

        // Check that we aren't reading past the allowed number of blocks.
        if num_blocks > stream.remaining_blocks {
            error!(
                "stream read requested too many blocks: {} > {}",
                num_blocks,
                (*stream).remaining_blocks
            );
            return ReturnCode::VB2_ERROR_UNKNOWN;
        }

        cur_lba = stream.cur_lba;
    }

    // Use the block reader to actually read from the disk.
    let rc = VbExDiskRead(stream_handle, cur_lba, num_blocks, buffer);
    if rc != ReturnCode::VB2_SUCCESS {
        error!("VbExDiskRead failed: {}", crate::return_code_to_str(rc));
        return rc;
    }

    let disk = Disk::from_handle(stream_handle);
    let stream = disk.stream.as_mut().expect("no open stream");

    stream.cur_lba += num_blocks;
    stream.remaining_blocks -= num_blocks;

    ReturnCode::VB2_SUCCESS
}

#[no_mangle]
unsafe extern "C" fn VbExStreamClose(stream: DiskStreamHandle) {
    assert!(!stream.is_null());

    let disk = Disk::from_handle(stream);

    assert!(disk.stream.is_some());
    disk.stream = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemDisk {
        data: Vec<u8>,
    }

    impl DiskIo for MemDisk {
        fn bytes_per_lba(&self) -> u64 {
            4
        }

        fn lba_count(&self) -> u64 {
            self.data.len() as u64 / self.bytes_per_lba()
        }

        fn read(&self, lba_start: u64, buffer: &mut [u8]) -> ReturnCode {
            let start = (lba_start * self.bytes_per_lba()) as usize;
            let end = start + buffer.len();
            buffer.copy_from_slice(&self.data[start..end]);
            ReturnCode::VB2_SUCCESS
        }

        fn write(&mut self, _lba_start: u64, _buffer: &[u8]) -> ReturnCode {
            // The stream API does not support writing.
            panic!("write called");
        }
    }

    #[test]
    fn test_stream_api() {
        let mut disk_io = MemDisk { data: Vec::new() };
        // Block 0.
        disk_io.data.extend([1, 2, 3, 4]);
        // Block 1.
        disk_io.data.extend([5, 6, 7, 8]);
        // Block 2.
        disk_io.data.extend([9, 10, 11, 12]);
        // Block 3.
        disk_io.data.extend([13, 14, 15, 16]);
        // Block 4.
        disk_io.data.extend([17, 18, 19, 20]);

        let mut disk = Disk::new(&mut disk_io);

        let disk_handle = disk.as_handle();

        // Open the stream.
        let mut disk_stream = ptr::null_mut();
        assert_eq!(
            unsafe { VbExStreamOpen(disk_handle, 1, 3, &mut disk_stream) },
            ReturnCode::VB2_SUCCESS
        );

        // Check that opening a second stream fails.
        let mut disk_stream_2 = ptr::null_mut();
        assert_ne!(
            unsafe { VbExStreamOpen(disk_handle, 1, 3, &mut disk_stream_2) },
            ReturnCode::VB2_SUCCESS
        );

        /// Use VbExStreamRead to fill `buf`.
        fn stream_read(
            disk_stream: DiskStreamHandle,
            buf: &mut [u8],
        ) -> ReturnCode {
            unsafe {
                VbExStreamRead(
                    disk_stream,
                    u32::try_from(buf.len()).unwrap(),
                    buf.as_mut_ptr(),
                )
            }
        }

        // Check that reading fails if not a multiple of the block size.
        let mut buf = [0; 5];
        assert_ne!(stream_read(disk_stream, &mut buf), ReturnCode::VB2_SUCCESS);

        // Successful read.
        let mut buf = [0; 4];
        assert_eq!(stream_read(disk_stream, &mut buf), ReturnCode::VB2_SUCCESS);
        assert_eq!(buf, [5, 6, 7, 8]);

        // Successful read of two blocks.
        let mut buf = [0; 8];
        assert_eq!(stream_read(disk_stream, &mut buf), ReturnCode::VB2_SUCCESS);
        assert_eq!(buf, [9, 10, 11, 12, 13, 14, 15, 16]);

        // Check that reading past the number of allowed blocks fails.
        let mut buf = [0; 4];
        assert_ne!(stream_read(disk_stream, &mut buf), ReturnCode::VB2_SUCCESS);

        // Close the stream.
        unsafe { VbExStreamClose(disk_stream) };
    }
}
