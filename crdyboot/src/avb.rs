// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk;
use avb::avb_ops::{create_ops, AvbDiskOps, AvbDiskOpsRef};
use avb::avb_sys::{
    avb_slot_verify, avb_slot_verify_result_to_string, AvbHashtreeErrorMode, AvbIOResult,
    AvbPartitionData, AvbSlotVerifyData, AvbSlotVerifyFlags, AvbSlotVerifyResult, AvbVBMetaData,
};
use bootimg::BootImage;
use core::ffi::CStr;
use core::{ptr, slice, str};
use libcrdy::page_alloc::{PageAllocationError, ScopedPageAllocation};
use libcrdy::uefi::UefiImpl;
use log::{debug, log_enabled};
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::CString16;

/// Allocated buffers from AVB to execute the kernel.
pub struct LoadedBuffersAvb {
    pub kernel_buffer: ScopedPageAllocation,
    pub initramfs_buffer: ScopedPageAllocation,
    pub cmdline: CString16,
}

#[derive(Debug, thiserror::Error)]
pub enum AvbError {
    /// The avb slot verify call failed.
    #[error("image verification failed: {}", verify_result_to_str(*.0))]
    AvbVerifyFailure(AvbSlotVerifyResult),

    /// Missing a required avb partition.
    #[error("missing the required partition: {0}")]
    MissingAvbPartition(&'static str),

    /// Failed to allocate a buffer.
    #[error("failed to allocate memory")]
    Allocation(#[source] PageAllocationError),

    /// Failed to parse bootimage partition header.
    #[error("unable to parse bootimage partition header: {0}")]
    BootImageHeaderParseError(bootimg::ImageError),

    /// Parsed a bootimg partition header of the wrong version.
    #[error("the partition header is not V4")]
    UnsupportedPartitionHeaderVersion,

    /// Invalid kernel size.
    #[error("invalid kernel size: {0}")]
    InvalidKernelSize(u32),

    /// Invalid ramdisk size.
    #[error("invalid ramdisk size: {0}")]
    InvalidRamdiskSize(u32),

    /// Index is out of bounds for the avb image header.
    #[error("index is out of bounds of the avb image header: {0}")]
    IndexOutOfBounds(&'static str),
}

fn verify_result_to_str(r: AvbSlotVerifyResult) -> &'static str {
    // SAFETY: `avb_slot_verify_result_to_string` always returns a valid
    // pointer to a string literal, so a static lifetime is correct.
    let s = unsafe { CStr::from_ptr(avb_slot_verify_result_to_string(r)) };
    // Unwrap is OK, the string is always UTF-8.
    s.to_str().unwrap()
}

// BootImage boot header page size.
const BOOT_HEADER_PAGE_SIZE: usize = 4096;

pub struct AvbDiskOpsImpl;

// Allow pass by value as it makes the usage easier.
#[expect(clippy::needless_pass_by_value)]
fn map_uefi_status(us: uefi::Error) -> AvbIOResult {
    match us.status() {
        uefi::Status::INVALID_PARAMETER => AvbIOResult::AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION,
        // TODO: Are there better mappings?
        _ => AvbIOResult::AVB_IO_RESULT_ERROR_IO,
    }
}

impl AvbDiskOps for AvbDiskOpsImpl {
    fn read_from_partition(
        &mut self,
        name: &str,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), AvbIOResult> {
        let uefi = &UefiImpl;
        let name = CString16::try_from(name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)?;
        let (disk_io, media_id) = disk::open_partition_by_name(uefi, &name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)?;
        disk_io
            .read_disk(media_id, start_byte, dst)
            .map_err(map_uefi_status)
    }

    fn write_to_partition(
        &mut self,
        name: &str,
        offset: u64,
        buffer: &[u8],
    ) -> Result<(), AvbIOResult> {
        let uefi = &UefiImpl;
        let name = CString16::try_from(name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)?;
        let (mut disk_io, media_id) = disk::open_partition_by_name(uefi, &name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)?;
        disk_io
            .write_disk(media_id, offset, buffer)
            .map_err(map_uefi_status)
    }

    fn get_size_of_partition(&mut self, name: &str) -> Result<u64, AvbIOResult> {
        let uefi = &UefiImpl;
        let name = CString16::try_from(name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)?;
        // TODO: map to better error?
        disk::get_partition_size_in_bytes(uefi, &name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)
    }

    fn get_unique_guid_for_partition(
        &mut self,
        name: &str,
        dest: &mut [u8; 36],
    ) -> Result<(), AvbIOResult> {
        let uefi = &UefiImpl;
        let name = CString16::try_from(name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)?;
        // TODO: map to more specific error?
        let guid = disk::get_partition_unique_guid(uefi, &name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)?;
        dest.copy_from_slice(&guid.to_ascii_hex_lower());
        Ok(())
    }
}

/// Slices to the data sections in a `BootImage` header.
/// Only the sections that relevant for this bootloader
/// are included.
struct BootImageParts<'a> {
    kernel: &'a [u8],
    #[expect(dead_code)]
    initramfs: &'a [u8],
}

impl<'a> BootImageParts<'a> {
    /// Determine the section slices for a partition with a
    /// `BootImage` header.
    fn from_avb_boot_partition(
        partition: &AvbPartitionData,
    ) -> Result<BootImageParts<'a>, AvbError> {
        let data = unsafe { slice::from_raw_parts(partition.data, partition.data_size) };
        let header = BootImage::parse(data).map_err(AvbError::BootImageHeaderParseError)?;
        let BootImage::V4(header) = header else {
            return Err(AvbError::UnsupportedPartitionHeaderVersion);
        };

        // From [bootimg.h boot header v4]
        // When the boot image header has a version of 4, the structure of the boot
        // image is as follows:
        //
        // +---------------------+
        // | boot header         | 4096 bytes
        // +---------------------+
        // | kernel              | m pages
        // +---------------------+
        // | ramdisk             | n pages
        // +---------------------+
        // | boot signature      | g pages
        // +---------------------+
        //
        // m = (kernel_size + 4096 - 1) / 4096
        // n = (ramdisk_size + 4096 - 1) / 4096
        // g = (signature_size + 4096 - 1) / 4096
        //
        // Here the page size is fixed at 4096 bytes.
        // [bootimg.h boot header v4]: https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h#324

        let base = header._base;

        let kernel_size = usize::try_from(base.kernel_size)
            .map_err(|_| AvbError::InvalidKernelSize(base.kernel_size))?;

        // The kernel slice starts after the boot header at one page(4096).
        let kernel_offset = BOOT_HEADER_PAGE_SIZE;

        let ramdisk_size = usize::try_from(base.ramdisk_size)
            .map_err(|_| AvbError::InvalidRamdiskSize(base.ramdisk_size))?;

        // Offset to the start of the ramdisk which will fall on
        // a page size boundary.
        let ramdisk_offset = kernel_size
            .checked_next_multiple_of(BOOT_HEADER_PAGE_SIZE)
            .and_then(|x| x.checked_add(kernel_offset))
            .ok_or(AvbError::IndexOutOfBounds("ramdisk"))?;

        // Get a slice pointing to the kernel's data.
        let kernel = kernel_offset
            .checked_add(kernel_size)
            .and_then(|x| data.get(kernel_offset..x))
            .ok_or(AvbError::IndexOutOfBounds("kernel"))?;

        // Get a slice pointing to the ramdisk data.
        let initramfs = ramdisk_offset
            .checked_add(ramdisk_size)
            .and_then(|x| data.get(ramdisk_offset..x))
            .ok_or(AvbError::IndexOutOfBounds("ramdisk"))?;

        Ok(BootImageParts { kernel, initramfs })
    }
}

fn load_kernel(boot_part: &AvbPartitionData) -> Result<ScopedPageAllocation, AvbError> {
    // From the "boot" partition only the kernel is used.
    let kernel_src = BootImageParts::from_avb_boot_partition(boot_part)?.kernel;

    // Kernel must be non-zero.
    if kernel_src.is_empty() {
        return Err(AvbError::InvalidKernelSize(0));
    }
    // Allocate a buffer that can boot the kernel.
    let mut kernel_buffer = ScopedPageAllocation::new_unaligned(
        AllocateType::AnyPages,
        MemoryType::LOADER_CODE,
        kernel_src.len(),
    )
    .map_err(AvbError::Allocation)?;
    // Any padding will stay 0 from the page allocation.
    // unwrap safe: The allocated buffer is larger than the kernel_size.
    kernel_buffer
        .get_mut(..kernel_src.len())
        .unwrap()
        .copy_from_slice(kernel_src);
    // TODO: pass back the actual kernel length? The callers
    // might find this useful (to measure for example).
    Ok(kernel_buffer)
}

fn debug_print_avb_vbmeta_data(verify_data: *const AvbSlotVerifyData) {
    let vbmeta = unsafe {
        slice::from_raw_parts(
            (*verify_data).vbmeta_images.cast::<AvbVBMetaData>(),
            (*verify_data).num_vbmeta_images,
        )
    };
    for part in vbmeta {
        let name = unsafe { CStr::from_ptr(part.partition_name) }.to_string_lossy();
        debug!("Loaded vbmeta image {name}: {part:?}");
    }
}

/// Use AVB to verify the partitions and return buffers
/// including the loaded data from the partitions
/// necessary to boot the kernel.
pub fn do_avb_verify() -> Result<LoadedBuffersAvb, AvbError> {
    let mut holder = AvbDiskOpsImpl;
    let mut disk_ops_ref = AvbDiskOpsRef(&mut holder);

    let mut avbops = create_ops(&mut disk_ops_ref);

    let boot_partition_name = c"boot";
    let init_partition_name = c"init_boot";
    let vendor_boot_partition_name = c"vendor_boot";

    // Null-pointer terminated list of partitions for
    // the call to `avb_slot_verify`.
    let requested_partitions = [
        boot_partition_name.as_ptr(),
        init_partition_name.as_ptr(),
        vendor_boot_partition_name.as_ptr(),
        ptr::null(),
    ];

    // Forcing only slot a for now.
    // TODO: support boot priority flag checking.
    let slot = c"_a";

    let mut verify_data: *mut AvbSlotVerifyData = ptr::null_mut();
    let res = unsafe {
        avb_slot_verify(
            &mut avbops,
            requested_partitions.as_ptr(),
            slot.as_ptr(),
            AvbSlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
            AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_LOGGING,
            &mut verify_data,
        )
    };
    if res != AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_OK {
        return Err(AvbError::AvbVerifyFailure(res));
    }

    if log_enabled!(log::Level::Debug) {
        debug_print_avb_vbmeta_data(verify_data);
    }

    let verify_cmdline = unsafe { CStr::from_ptr((*verify_data).cmdline) };
    debug!("verify cmdline: {}", verify_cmdline.to_string_lossy());

    let mut boot = None;
    let mut init_boot = None;
    let mut vendor_boot = None;

    // Convert the loaded_partitions list to a slice of AvbPartitionData
    let parts: &[AvbPartitionData] = unsafe {
        slice::from_raw_parts(
            (*verify_data).loaded_partitions,
            (*verify_data).num_loaded_partitions,
        )
    };
    debug!("Loaded partition count {}", parts.len());

    // Locate the three useful partitions:
    // * boot (kernel)
    // * init_boot (initramfs)
    // * vendor_boot (initramfs)
    //
    // There will be three resulting buffers to pass to the kernel loader:
    //  * kernel
    //  * initramfs : created from the two initramfs buffers and
    //    bootconfig options
    //  * cmdline (kernel command line with necessary modifications applied)
    for part in parts {
        let name = unsafe { CStr::from_ptr(part.partition_name) };
        debug!("Loaded partition {}: {part:?}", name.to_string_lossy());
        if name == boot_partition_name {
            boot = Some(part);
        } else if name == init_partition_name {
            init_boot = Some(part);
        } else if name == vendor_boot_partition_name {
            vendor_boot = Some(part);
        }
    }

    let Some(boot) = boot else {
        return Err(AvbError::MissingAvbPartition("boot"));
    };
    let Some(_vendor_boot) = vendor_boot else {
        return Err(AvbError::MissingAvbPartition("vendor_boot"));
    };
    let Some(_init_boot) = init_boot else {
        return Err(AvbError::MissingAvbPartition("init_boot"));
    };

    // Load the kernel buffer from the boot partition header.
    let _kernel_buffer = load_kernel(boot)?;

    todo!("allocate, load and return buffers");
}
