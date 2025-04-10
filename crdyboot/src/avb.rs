// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::alloc::string::ToString;
use crate::disk::{self, Gpt, GptDiskError};
use avb::avb_ops::{create_ops, AvbDiskOps, AvbDiskOpsRef};
use avb::avb_sys::{
    avb_slot_verify, avb_slot_verify_data_free, avb_slot_verify_result_to_string,
    AvbHashtreeErrorMode, AvbIOResult, AvbPartitionData, AvbSlotVerifyData, AvbSlotVerifyFlags,
    AvbSlotVerifyResult, AvbVBMetaData,
};
use bootimg::{
    vendor_ramdisk_table_entry_v4, BootImage, VendorImageHeader, VENDOR_RAMDISK_TYPE_PLATFORM,
};
use core::ffi::{CStr, FromBytesUntilNulError};
use core::ops::Deref;
use core::{ptr, slice, str};
use libcrdy::page_alloc::{PageAllocationError, ScopedPageAllocation};
use libcrdy::uefi::{Uefi, UefiImpl};
use libcrdy::util::u32_to_usize;
use log::{debug, info, log_enabled, warn};
use uefi::boot::{AllocateType, MemoryType};
use uefi::{cstr16, CStr16, CString16, Char16};
use vboot::CgptAttributes;

/// Allocated buffers from AVB to execute the kernel.
pub struct LoadedBuffersAvb {
    pub kernel_buffer: KernelData,
    pub initramfs_buffer: ScopedPageAllocation,
    pub cmdline: CString16,
}

#[derive(Debug, thiserror::Error, PartialEq)]
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

    /// Failed to parse vendor partition header.
    #[error("unable to parse vendor partition header: {0}")]
    VendorImageHeaderParseError(bootimg::ImageError),

    /// Parsed a bootimg partition header of the wrong version.
    #[error("the partition header is not V4")]
    UnsupportedPartitionHeaderVersion,

    /// Unsupported number of ramdisks in the vendor
    /// partition.
    #[error("only one ramdisk is supported for the vendor partition, found: {0}")]
    UnsupportedVendorRamdiskCount(u32),

    /// Invalid kernel size.
    #[error("invalid kernel size: {0}")]
    InvalidKernelSize(u32),

    /// Invalid ramdisk size.
    #[error("invalid ramdisk size: {0}")]
    InvalidRamdiskSize(u32),

    /// Index is out of bounds for the avb image header.
    #[error("index is out of bounds of the avb image header: {0}")]
    IndexOutOfBounds(&'static str),

    /// Ramdisk table entry size is not correct.
    #[error("ramdisk table entry size is {specified} and must be {required_size}")]
    RamdiskTableEntrySize {
        /// Size specified in the header.
        specified: usize,

        /// Required size.
        required_size: usize,
    },

    /// Vendor command line is not terminated.
    #[error("vendor command line is not terminated")]
    VendorCommandlineUnterminated(#[from] FromBytesUntilNulError),

    /// Vendor command line is malformed.
    #[error("vendor command line is malformed")]
    VendorCommandlineMalformed,

    /// Verified command line is malformed.
    #[error("verified command line is malformed")]
    VerifiedCommandlineMalformed,

    /// Combined initramfs is too large.
    #[error("initramfs is too large")]
    InitramfsTooLarge,

    /// Failed finding the partition by name.
    #[error("failed finding the partition {name} : {error}")]
    FailedFindPartition {
        // Partition name
        name: &'static CStr16,
        error: GptDiskError,
    },

    /// No partitions are bootable.
    #[error("no partitions are bootable")]
    NoBootablePartition,

    /// Failed looking up the boot partition uuid.
    #[error("failed reading the boot partition UUID: {0}")]
    FailedBootPartUuid(GptDiskError),
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

/// Slices to the data sections in a `VendorImageHeader`.
/// Only the sections that relevant for this bootloader
/// are included.
struct VendorData<'a> {
    initramfs: &'a [u8],
    cmdline: CString16,
    // TODO: handle bootconfig!
    bootconfig: &'a [u8],
}

impl<'a> VendorData<'a> {
    /// Determine the section slices for a partition with a
    /// `VendorImageHeader`.
    #[expect(clippy::too_many_lines)]
    fn from_avb_vendor_partition(
        vendor_part: &AvbPartitionData,
    ) -> Result<VendorData<'a>, AvbError> {
        // vendor boot image layout comment from [bootimg.h vendor v4]:
        // The structure of the vendor boot image version 4, which is required to be
        // present when a version 4 boot image is used, is as follows:
        //
        // +------------------------+
        // | vendor boot header     | o pages
        // +------------------------+
        // | vendor ramdisk section | p pages
        // +------------------------+
        // | dtb                    | q pages
        // +------------------------+
        // | vendor ramdisk table   | r pages
        // +------------------------+
        // | bootconfig             | s pages
        // +------------------------+
        //
        // o = (2128 + page_size - 1) / page_size
        // p = (vendor_ramdisk_size + page_size - 1) / page_size
        // q = (dtb_size + page_size - 1) / page_size
        // r = (vendor_ramdisk_table_size + page_size - 1) / page_size
        // s = (vendor_bootconfig_size + page_size - 1) / page_size
        //
        // Note that in version 4 of the vendor boot image, multiple vendor ramdisks can
        // be included in the vendor boot image. The bootloader can select a subset of
        // ramdisks to load at runtime. To help the bootloader select the ramdisks, each
        // ramdisk is tagged with a type tag and a set of hardware identifiers
        // describing the board, soc or platform that this ramdisk is intended for.
        //
        // The vendor ramdisk section is consist of multiple ramdisk images concatenated
        // one after another, and vendor_ramdisk_size is the size of the section, which
        // is the total size of all the ramdisks included in the vendor boot image.
        //
        // The vendor ramdisk table holds the size, offset, type, name and hardware
        // identifiers of each ramdisk. The type field denotes the type of its content.
        // The vendor ramdisk names are unique. The hardware identifiers are specified
        // in the board_id field in each table entry. The board_id field is consist of a
        // vector of unsigned integer words, and the encoding scheme is defined by the
        // hardware vendor.
        //
        // For the different type of ramdisks, there are:
        //    - VENDOR_RAMDISK_TYPE_NONE indicates the value is unspecified.
        //    - VENDOR_RAMDISK_TYPE_PLATFORM ramdisks contain platform specific bits, so
        //      the bootloader should always load these into memory.
        //    - VENDOR_RAMDISK_TYPE_RECOVERY ramdisks contain recovery resources, so
        //      the bootloader should load these when booting into recovery.
        //    - VENDOR_RAMDISK_TYPE_DLKM ramdisks contain dynamic loadable kernel
        //      modules.
        //
        // Version 4 of the vendor boot image also adds a bootconfig section to the end
        // of the image. This section contains Boot Configuration parameters known at
        // build time. The bootloader is responsible for placing this section directly
        // after the generic ramdisk, followed by the bootconfig trailer, before
        // entering the kernel.
        //
        // [bootimg.h vendor v4]: https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h#344

        // The vendor_boot partition contains a VendorImageHeader V4.
        let vendor_data = unsafe { slice::from_raw_parts(vendor_part.data, vendor_part.data_size) };
        let vendor_header =
            VendorImageHeader::parse(vendor_data).map_err(AvbError::VendorImageHeaderParseError)?;
        let VendorImageHeader::V4(vendor_header) = vendor_header else {
            return Err(AvbError::UnsupportedPartitionHeaderVersion);
        };
        let vendor_base = vendor_header._base;

        // This bootloader requires a non-zero vendor ramdisk size.
        if vendor_base.vendor_ramdisk_size == 0 {
            return Err(AvbError::InvalidRamdiskSize(0))?;
        }

        // Page size for the vendor boot partition is specified in
        // the header.
        let page_size = u32_to_usize(vendor_base.page_size);

        // Find the section lengths and offsets of each section.
        // Each section is a multiple of the `page_size`.
        // The header is at the front of the buffer.
        let vendor_boot_header_section_bytes = u32_to_usize(vendor_base.header_size)
            .checked_next_multiple_of(page_size)
            .ok_or(AvbError::IndexOutOfBounds("vendor header"))?;

        // Length of the 'vendor ramdisk section'.
        let ramdisk_section_bytes = u32_to_usize(vendor_base.vendor_ramdisk_size)
            .checked_next_multiple_of(page_size)
            .ok_or(AvbError::IndexOutOfBounds("vendor ramdisk"))?;
        // Length of the dtb section.
        let dtb_section_bytes = u32_to_usize(vendor_base.dtb_size)
            .checked_next_multiple_of(page_size)
            .ok_or(AvbError::IndexOutOfBounds("vendor dtb"))?;
        // Length of the vendor ramdisk table section in bytes.
        let ramdisk_table_section_bytes = u32_to_usize(vendor_header.vendor_ramdisk_table_size)
            .checked_next_multiple_of(page_size)
            .ok_or(AvbError::IndexOutOfBounds("vendor ramdisk table"))?;

        // Expect a zero dtb on an x86 image, warn otherwise.
        if dtb_section_bytes != 0 {
            warn!("vendor dtb section is non-zero and ignored.");
        }

        // Calculate the offset to the ramdisk_table section.
        let ramdisk_table_offset = {
            || {
                vendor_boot_header_section_bytes
                    .checked_add(ramdisk_section_bytes)?
                    .checked_add(dtb_section_bytes)
            }
        }()
        .ok_or(AvbError::IndexOutOfBounds("ramdisk_table"))?;

        let bootconfig_size = u32_to_usize(vendor_header.bootconfig_size);
        // Calculate the offset to the bootconfig section following
        // the ramdisk_table section.
        let bootconfig_offset_bytes = ramdisk_table_offset
            .checked_add(ramdisk_table_section_bytes)
            .ok_or(AvbError::IndexOutOfBounds("bootconfig"))?;

        // Parse the vendor_ramdisk_table of vendor_ramdisk_table_entry_v4
        // entries describing the ramdisks in the ramdisk section.

        // Bounds check the table's declared sizes.
        let ramdisk_table_size = u32_to_usize(vendor_header.vendor_ramdisk_table_size);
        let ramdisk_table_entry_count = u32_to_usize(vendor_header.vendor_ramdisk_table_entry_num);
        let ramdisk_table_entry_size = u32_to_usize(vendor_header.vendor_ramdisk_table_entry_size);

        if size_of::<vendor_ramdisk_table_entry_v4>() != ramdisk_table_entry_size {
            return Err(AvbError::RamdiskTableEntrySize {
                specified: ramdisk_table_entry_size,
                required_size: size_of::<vendor_ramdisk_table_entry_v4>(),
            });
        };

        if ramdisk_table_size
            < ramdisk_table_entry_count
                .checked_mul(ramdisk_table_entry_size)
                .ok_or(AvbError::IndexOutOfBounds("ramdisk_table"))?
        {
            return Err(AvbError::IndexOutOfBounds("ramdisk_table"));
        }

        let ramdisk_table = ramdisk_table_offset
            .checked_add(ramdisk_table_size)
            .and_then(|x| vendor_data.get(ramdisk_table_offset..x))
            .ok_or(AvbError::IndexOutOfBounds("ramdisk_table"))?;

        // Get a slice to the table of vendor_ramdisk_table_entry_v4 entries
        // in the ramdisk table section.
        let ramdisk_entries = unsafe {
            slice::from_raw_parts(
                ramdisk_table
                    .as_ptr()
                    .cast::<vendor_ramdisk_table_entry_v4>(),
                ramdisk_table_entry_count,
            )
        };

        let mut platform_ramdisk_count: u32 = 0;
        let mut ramdisk_offset = 0;
        let mut ramdisk_size = 0;
        for ramdisk_entry in ramdisk_entries {
            let name = CStr::from_bytes_until_nul(&ramdisk_entry.ramdisk_name)
                .unwrap()
                .to_string_lossy();
            debug!("Ramdisk entry: {name} {ramdisk_entry:?}");
            // For now just include the platform ramdisk.
            if ramdisk_entry.ramdisk_type == VENDOR_RAMDISK_TYPE_PLATFORM {
                platform_ramdisk_count = platform_ramdisk_count.checked_add(1).unwrap();
                if ramdisk_size == 0 {
                    // The individual ramdisk offsets are from the start of the
                    // whole ramdisk section which follows the header.
                    ramdisk_offset = vendor_boot_header_section_bytes
                        .checked_add(u32_to_usize(ramdisk_entry.ramdisk_offset))
                        .ok_or(AvbError::IndexOutOfBounds("ramdisk"))?;
                    ramdisk_size = u32_to_usize(ramdisk_entry.ramdisk_size);
                }
            }
        }

        // For now only support a single platform ramdisk.
        if platform_ramdisk_count != 1 {
            return Err(AvbError::UnsupportedVendorRamdiskCount(
                platform_ramdisk_count,
            ))?;
        }

        // Ensure the ramdisk size is non-zero.
        if ramdisk_size == 0 {
            return Err(AvbError::InvalidRamdiskSize(0));
        };

        // For now ignore the recovery and any additional ramdisk entries
        // and only select the single platform entry.

        // Get a slice pointing to the ramdisk offset of
        // for the length of the ramdisk.
        let initramfs = ramdisk_offset
            .checked_add(ramdisk_size)
            .and_then(|x| vendor_data.get(ramdisk_offset..x))
            .ok_or(AvbError::IndexOutOfBounds("ramdisk"))?;

        // Slice into the bootconfig data.
        let bootconfig = bootconfig_offset_bytes
            .checked_add(bootconfig_size)
            .and_then(|x| vendor_data.get(bootconfig_offset_bytes..x))
            .ok_or(AvbError::IndexOutOfBounds("bootconfig"))?;

        let cmdline = CStr::from_bytes_until_nul(&vendor_base.cmdline)
            .map_err(AvbError::VendorCommandlineUnterminated)?;

        // Convert the CStr to &str then to CString16.
        // Return an error if any of those fail.
        let cmdline = cmdline
            .to_str()
            .ok()
            .and_then(|x| CString16::try_from(x).ok())
            .ok_or(AvbError::VendorCommandlineMalformed)?;

        // TODO: return bootconfig information in a useful way.
        // It might need to be modified or packed in a certain way.
        // Find additional context in
        // https://android-review.git.corp.google.com/c/platform/external/u-boot/+/1579246/7 for
        Ok(VendorData {
            initramfs,
            cmdline,
            bootconfig,
        })
    }
}

pub struct KernelData {
    /// Underlying buffer allocated for the referenced data.
    allocation: ScopedPageAllocation,
    /// Space in the buffer that is being used.
    /// The length of the data without the padding.
    used_bytes: usize,
}

impl KernelData {
    /// Create a new `KernelData`
    ///
    /// Panics if `used_bytes` > `allocation.len()`
    pub fn new(allocation: ScopedPageAllocation, used_bytes: usize) -> Self {
        assert!(used_bytes <= allocation.len());
        KernelData {
            allocation,
            used_bytes,
        }
    }
}

impl Deref for KernelData {
    type Target = [u8];

    /// Slice to the area of the buffer that is used.
    fn deref(&self) -> &[u8] {
        // Unwrap is ok, used bytes is never larger than
        // the allocation length.
        self.allocation.get(..self.used_bytes).unwrap()
    }
}

fn load_kernel(boot_part: &AvbPartitionData) -> Result<KernelData, AvbError> {
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

    Ok(KernelData::new(kernel_buffer, kernel_src.len()))
}

/// Assemble the initramfs by concatenating the vendor and
/// generic (init) ramdisks.
/// Allocates a buffer to contain the assembled initramfs.
///
/// See the description in [bootimg.h] and [partitions architecture]
/// for a description of the layout.
///
/// [partitions architecture]: https://source.android.com/docs/core/architecture/partitions/generic-boot#architecture
/// [bootimg.h]: https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h#404
fn assemble_initramfs(
    vendor_data: &VendorData,
    init_data: &BootImageParts,
) -> Result<ScopedPageAllocation, AvbError> {
    let vendor_initramfs = vendor_data.initramfs;
    let generic_initramfs = init_data.initramfs;

    // Generic ramdisk must have a size.
    if generic_initramfs.is_empty() {
        return Err(AvbError::InvalidRamdiskSize(0));
    }

    // Size of the combined initramfs data.
    let initramfs_size = generic_initramfs
        .len()
        .checked_add(vendor_initramfs.len())
        .ok_or(AvbError::InitramfsTooLarge)?;

    let mut initramfs_buffer = ScopedPageAllocation::new_unaligned(
        AllocateType::AnyPages,
        MemoryType::LOADER_CODE,
        initramfs_size,
    )
    .map_err(AvbError::Allocation)?;

    let vendor_initramfs = vendor_data.initramfs;
    let generic_initramfs = init_data.initramfs;

    // Copy the vendor_initramfs to the front of the buffer.
    initramfs_buffer
        .get_mut(..vendor_initramfs.len())
        .expect("buffer should be large enough")
        .copy_from_slice(vendor_initramfs);

    // Append the generic_initramfs after the vendor_initramfs.
    initramfs_buffer
        .get_mut(vendor_initramfs.len()..initramfs_size)
        .expect("buffer should be large enough")
        .copy_from_slice(generic_initramfs);

    // TODO: This must also handle the bootconfig config options which
    // are supposed to be placed after the initramfs with a
    // bootconfig trailer.
    // See https://android-review.git.corp.google.com/c/platform/external/u-boot/+/1579246
    Ok(initramfs_buffer)
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

    let slot = get_priority_slot(&UefiImpl)?;

    let mut verify_data: *mut AvbSlotVerifyData = ptr::null_mut();
    let res = unsafe {
        avb_slot_verify(
            &mut avbops,
            requested_partitions.as_ptr(),
            slot.slot_suffix_cstr().as_ptr(),
            AvbSlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
            AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART,
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
    let Some(vendor_boot) = vendor_boot else {
        return Err(AvbError::MissingAvbPartition("vendor_boot"));
    };
    let Some(init_boot) = init_boot else {
        return Err(AvbError::MissingAvbPartition("init_boot"));
    };

    // Load the kernel buffer from the boot partition header.
    let kernel_buffer = load_kernel(boot)?;

    // Parse the "generic" `initramfs` from the "init_boot" partition.
    // The initramfs is the only part of this partition that is used.
    let init_data = BootImageParts::from_avb_boot_partition(init_boot)?;

    // Slice up the vendor boot partition data.
    let vendor_data = VendorData::from_avb_vendor_partition(vendor_boot)?;
    debug!("vendor bootconfig_size: {}", vendor_data.bootconfig.len());
    debug!("vendor cmdline: {}", vendor_data.cmdline);

    let initramfs_buffer = assemble_initramfs(&vendor_data, &init_data)?;

    // Convert the verified command line to UCS-2.
    let mut cmdline = verify_cmdline
        .to_str()
        .ok()
        .and_then(|x| CString16::try_from(x).ok())
        .ok_or(AvbError::VerifiedCommandlineMalformed)?;

    // Append the vendor command line after the avb verify
    // command line.
    // Safe unwrap: the ' ' will convert to Char16.
    cmdline.push(Char16::try_from(' ').unwrap());
    cmdline.push_str(vendor_data.cmdline.as_ref());
    info!("combined command line: {cmdline}");

    // TODO: Have this handle dynamic boot slots.
    // TODO: have this be part of bootconfig once this handles bootconfig.
    cmdline.push_str(cstr16!(" androidboot.slot_suffix="));
    cmdline.push_str(slot.slot_suffix_cstr16());

    // Add the UUID of the boot partition needed for the second stage to
    // load the file system.
    // TODO: Put as bootconfig once it is supported.
    let boot_part_uuid = get_android_boot_part_uuid(&UefiImpl, slot)?;
    cmdline.push_str(cstr16!(" androidboot.boot_part_uuid="));
    cmdline.push_str(&boot_part_uuid);

    cmdline.push_str(cstr16!(" androidboot.verifiedbootstate=orange"));

    // At this point the cmdline, kernel and initramfs buffers
    // are allocated locally to this function.
    // The slot_verify_data can now be freed.
    // TODO: move this to some owned scoped struct that can
    // free this itself as well when out of scope.
    unsafe { avb_slot_verify_data_free(verify_data) };

    Ok(LoadedBuffersAvb {
        kernel_buffer,
        initramfs_buffer,
        cmdline,
    })
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum BootSlot {
    A,
    B,
}

impl BootSlot {
    fn all() -> &'static [Self] {
        &[Self::A, Self::B]
    }

    /// Get the `CStr16` representation of the boot partititon name
    /// for the given slot.
    fn boot_part_name(self) -> &'static CStr16 {
        match self {
            BootSlot::A => cstr16!("boot_a"),
            BootSlot::B => cstr16!("boot_b"),
        }
    }

    /// Get the `CStr` representation of the slot suffix.
    fn slot_suffix_cstr(self) -> &'static CStr {
        match self {
            BootSlot::A => c"_a",
            BootSlot::B => c"_b",
        }
    }

    /// Get the `CStr16` representation of the slot suffix.
    fn slot_suffix_cstr16(self) -> &'static CStr16 {
        match self {
            BootSlot::A => cstr16!("_a"),
            BootSlot::B => cstr16!("_b"),
        }
    }
}

/// Determines which boot slot to use based on partition priority.
/// Return Err if we don't find a bootable partition.
fn get_priority_slot(uefi: &dyn Uefi) -> Result<BootSlot, AvbError> {
    // Priority must be > 0 or the partition is not bootable per standard.
    let mut max_priority: u8 = 0;
    let mut result_slot = BootSlot::A;
    for slot in BootSlot::all() {
        let name = slot.boot_part_name();
        let gpt = Gpt::load_boot_disk(uefi)
            .map_err(|error| AvbError::FailedFindPartition { name, error })?;
        let (_, gpt_partition_entry) = gpt
            .find_partition_by_name(name)
            .map_err(|error| AvbError::FailedFindPartition { name, error })?;

        let attributes = gpt_partition_entry.attributes;
        let priority = CgptAttributes::from_u64(attributes.0.to_u64()).priority;
        debug!("partition: {} priority: {}", name, priority);
        // TODO: check and update tries
        // b:393358402
        if priority > max_priority {
            max_priority = priority;
            result_slot = *slot;
        }
    }

    if max_priority != 0 {
        Ok(result_slot)
    } else {
        Err(AvbError::NoBootablePartition)
    }
}

/// Look up the UUID of the boot partition and return as a `CString16`.
/// Return Err if there was an issue looking it up.
fn get_android_boot_part_uuid(uefi: &dyn Uefi, slot: BootSlot) -> Result<CString16, AvbError> {
    let name = slot.boot_part_name();
    let guid = disk::get_partition_unique_guid(uefi, name).map_err(AvbError::FailedBootPartUuid)?;
    let boot_part_string = guid.to_string();
    Ok(CString16::try_from(boot_part_string.as_str()).unwrap())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::disk::tests::{create_mock_uefi, BootDrive};

    #[test]
    fn test_get_priority_slot_basic() {
        // In default setup boot_a has priority 14, success 1
        // boot_b has priority 15, success 0, tries 3
        let uefi = create_mock_uefi(BootDrive::Hd2);
        assert_eq!(get_priority_slot(&uefi), Ok(BootSlot::B));
    }
}
