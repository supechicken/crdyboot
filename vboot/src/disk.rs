use crate::vboot_sys::{VbDiskInfo, VbExDiskHandle_t};
use crate::ReturnCode;
use core::convert::TryInto;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::{ptr, slice};
use log::error;

/// Interface for random-access disk IO.
pub trait DiskIo {
    /// Size of a random-access LBA sector in bytes.
    fn bytes_per_lba(&self) -> u64;

    /// Number of random-access LBA sectors on the device.
    fn lba_count(&self) -> u64;

    /// Read LBA sectors starting at `lba_start` from the device into `buffer`.
    fn read(&self, lba_start: u64, buffer: &mut [u8]) -> ReturnCode;
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
    io: &'a dyn DiskIo,
}

impl<'a> Disk<'a> {
    pub fn new(io: &'a dyn DiskIo) -> Disk<'a> {
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
extern "C" fn VbExDiskWrite(
    _handle: VbExDiskHandle_t,
    _lba_start: u64,
    _lba_count: u64,
    _buffer: *const u8,
) -> ReturnCode {
    error!("VbExDiskWrite not implemented");
    ReturnCode::VB2_ERROR_EX_UNIMPLEMENTED
}
