// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::vboot_sys::{VbDiskInfo, VbExDiskHandle_t};
use crate::ReturnCode;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::{ptr, slice};

/// Interface for random-access disk IO.
pub trait DiskIo {
    /// Size of a random-access LBA sector in bytes.
    fn bytes_per_lba(&self) -> u64;

    /// Number of random-access LBA sectors on the device.
    fn lba_count(&self) -> u64;

    /// Read LBA sectors starting at `lba_start` from the device into `buffer`.
    fn read(&self, lba_start: u64, buffer: &mut [u8]) -> ReturnCode;

    /// Write LBA sectors from `buffer` to the device starting at `lba_start`.
    fn write(&mut self, lba_start: u64, buffer: &[u8]) -> ReturnCode;
}

pub struct DiskInfo<'a> {
    info: VbDiskInfo,
    phantom: PhantomData<&'a ()>,
}

impl<'a> DiskInfo<'a> {
    pub fn as_mut_ptr(&mut self) -> *mut VbDiskInfo {
        &mut self.info
    }
}

/// Wrap `DiskIo` into a new struct so that we can convert it to a thin pointer
/// and cast that to a `VbExDiskHandle_t`.
pub struct Disk<'a> {
    io: &'a mut dyn DiskIo,
}

impl<'a> Disk<'a> {
    pub fn new(io: &'a mut dyn DiskIo) -> Disk<'a> {
        Disk { io }
    }

    fn as_handle(&mut self) -> VbExDiskHandle_t {
        (self as *mut Disk).cast::<c_void>()
    }

    unsafe fn from_handle(handle: VbExDiskHandle_t) -> &'a mut Disk<'a> {
        &mut *handle.cast::<Disk>()
    }

    pub fn info(&mut self) -> DiskInfo {
        DiskInfo {
            info: VbDiskInfo {
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
    handle: VbExDiskHandle_t,
    lba_start: u64,
    lba_count: u64,
    buffer: *mut u8,
) -> ReturnCode {
    let disk = Disk::from_handle(handle);

    let buffer_len = (disk.bytes_per_lba() * lba_count)
        .try_into()
        .expect("invalid read size");

    let buffer = slice::from_raw_parts_mut(buffer, buffer_len);

    disk.read(lba_start, buffer)
}

#[no_mangle]
unsafe extern "C" fn VbExDiskWrite(
    handle: VbExDiskHandle_t,
    lba_start: u64,
    lba_count: u64,
    buffer: *const u8,
) -> ReturnCode {
    let disk = Disk::from_handle(handle);

    let buffer_len = (disk.bytes_per_lba() * lba_count)
        .try_into()
        .expect("invalid write size");

    let buffer = slice::from_raw_parts(buffer, buffer_len);

    disk.write(lba_start, buffer)
}
