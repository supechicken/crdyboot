// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::avb::AvbError;
use bootimg::{
    vendor_ramdisk_table_entry_v4, BootImage, VendorImageHeader, VENDOR_RAMDISK_TYPE_PLATFORM,
};
use core::ffi::CStr;
use core::mem::size_of;
use core::ops::Range;
use core::slice;
use libcrdy::util::u32_to_usize;
use log::{debug, warn};
use uefi::CString16;

// BootImage boot header page size.
const BOOT_HEADER_PAGE_SIZE: usize = 4096;

/// Slices to the data sections in a `BootImage` header.
/// Only the sections that relevant for this bootloader
/// are included.
pub struct BootImageParts<'a> {
    pub kernel: &'a [u8],
    pub initramfs: &'a [u8],
}

impl<'a> BootImageParts<'a> {
    /// Determine the section slices for a partition with a
    /// `BootImage` header.
    pub fn from_boot_partition(data: &'a [u8]) -> Result<BootImageParts<'a>, AvbError> {
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
pub struct VendorData<'a> {
    pub initramfs: &'a [u8],
    pub cmdline: CString16,
    pub bootconfig: &'a [u8],
}

impl<'a> VendorData<'a> {
    /// Determine the section slices for a partition with a
    /// `VendorImageHeader`.
    pub fn from_vendor_partition(vendor_data: &'a [u8]) -> Result<VendorData<'a>, AvbError> {
        // Parse the ranges into vendor_data for the various sections and
        // ramdisks.
        let ranges = VendorRanges::from_vendor_partition_data(vendor_data)?;

        // This bootloader requires a non-zero vendor ramdisk size.
        // If there needs to be zero length vendor ramdisk support
        // it could be added.
        if ranges.ramdisk.is_empty() {
            return Err(AvbError::InvalidRamdiskSize(0))?;
        }

        // Expect a zero dtb on an x86 image, warn otherwise.
        if !ranges.dtb.is_empty() {
            warn!("vendor dtb section is non-zero and ignored.");
        }

        // For now ignore the recovery and any additional ramdisk entries
        // and only select the single platform entry.

        // Get a slice for the platform ramdisk into the vendor
        // data:
        let initramfs = vendor_data
            .get(ranges.platform_ramdisk)
            .ok_or(AvbError::IndexOutOfBounds("ramdisk"))?;

        // Slice into the bootconfig data.
        let bootconfig = vendor_data
            .get(ranges.bootconfig)
            .ok_or(AvbError::IndexOutOfBounds("bootconfig"))?;

        Ok(VendorData {
            initramfs,
            cmdline: ranges.cmdline,
            bootconfig,
        })
    }
}

#[derive(Default, PartialEq)]
struct VendorRanges {
    header: Range<usize>,
    cmdline: CString16,
    ramdisk: Range<usize>,
    dtb: Range<usize>,
    ramdisk_table: Range<usize>,
    bootconfig: Range<usize>,
    platform_ramdisk: Range<usize>,
}

impl VendorRanges {
    fn from_vendor_partition_data(vendor_data: &[u8]) -> Result<Self, AvbError> {
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
        let vendor_header =
            VendorImageHeader::parse(vendor_data).map_err(AvbError::VendorImageHeaderParseError)?;
        let VendorImageHeader::V4(vendor_header) = vendor_header else {
            return Err(AvbError::UnsupportedPartitionHeaderVersion);
        };
        let vendor_base = vendor_header._base;

        let mut ranges = VendorRanges::default();

        // Page size for the vendor boot partition is specified in
        // the header.
        let mut range_builder = RangeBuilder::new(u32_to_usize(vendor_base.page_size));

        // Vendor boot header is the first section.
        ranges.header = range_builder
            .next_range(vendor_base.header_size)
            .ok_or(AvbError::IndexOutOfBounds("vendor header"))?;

        // Ramdisk section follows the vendor boot header.
        ranges.ramdisk = range_builder
            .next_range(vendor_base.vendor_ramdisk_size)
            .ok_or(AvbError::IndexOutOfBounds("vendor ramdisk"))?;

        // Dtb follows the ramdisk section.
        ranges.dtb = range_builder
            .next_range(vendor_base.dtb_size)
            .ok_or(AvbError::IndexOutOfBounds("vendor dtb"))?;

        // Ramdisk table follows the dtb.
        ranges.ramdisk_table = range_builder
            .next_range(vendor_header.vendor_ramdisk_table_size)
            .ok_or(AvbError::IndexOutOfBounds("vendor ramdisk table"))?;

        // Bootconfig follows the ramdisk table.
        ranges.bootconfig = range_builder
            .next_range(vendor_header.bootconfig_size)
            .ok_or(AvbError::IndexOutOfBounds("bootconfig"))?;

        // Parse the ramdisk table to locate the offsets into
        // the ramdisk section.

        // Bounds check the table's declared sizes.
        let ramdisk_table_entry_count = u32_to_usize(vendor_header.vendor_ramdisk_table_entry_num);
        let ramdisk_table_entry_size = u32_to_usize(vendor_header.vendor_ramdisk_table_entry_size);

        // Check that the parsed size matches the expected size.
        if size_of::<vendor_ramdisk_table_entry_v4>() != ramdisk_table_entry_size {
            return Err(AvbError::RamdiskTableEntrySize {
                specified: ramdisk_table_entry_size,
                required_size: size_of::<vendor_ramdisk_table_entry_v4>(),
            });
        }

        // Confirm the declared ramdisk table size fits in the ramdisk table
        // section.
        if ranges.ramdisk_table.len()
            < ramdisk_table_entry_count
                .checked_mul(ramdisk_table_entry_size)
                .ok_or(AvbError::IndexOutOfBounds("ramdisk_table"))?
        {
            return Err(AvbError::IndexOutOfBounds("ramdisk_table"));
        }

        // Get a slice into vendor_data to the ramdisk table itself.
        let ramdisk_table = vendor_data
            .get(ranges.ramdisk_table.clone())
            .ok_or(AvbError::IndexOutOfBounds("ramdisk_table"))?;

        // Get a slice to the table of vendor_ramdisk_table_entry_v4 entries
        // in the ramdisk table section.
        // Safety: The bounds are checked above that the count of entries fits in
        // the ramdisk_table section.
        let ramdisk_entries = unsafe {
            slice::from_raw_parts(
                ramdisk_table
                    .as_ptr()
                    .cast::<vendor_ramdisk_table_entry_v4>(),
                ramdisk_table_entry_count,
            )
        };

        // Iterate over the ramdisk entries finding the ones that
        // are interesting.
        // This bootloader only looks for a single platform section.
        let mut platform_ramdisk_count: u32 = 0;

        for ramdisk_entry in ramdisk_entries {
            let name = CStr::from_bytes_until_nul(&ramdisk_entry.ramdisk_name)
                .unwrap()
                .to_string_lossy();
            debug!("Ramdisk entry: {name} {ramdisk_entry:?}");
            // For now just include the platform ramdisk.
            if ramdisk_entry.ramdisk_type == VENDOR_RAMDISK_TYPE_PLATFORM {
                platform_ramdisk_count = platform_ramdisk_count.checked_add(1).unwrap();
                // Only handle a single platform_ramdisk for now.
                if platform_ramdisk_count == 1 {
                    // Ramdisk table's offset is an offset into the ramdisk section
                    // of the overall data.
                    let ramdisk_start = ranges
                        .ramdisk
                        .start
                        .checked_add(u32_to_usize(ramdisk_entry.ramdisk_offset))
                        .ok_or(AvbError::IndexOutOfBounds("ramdisk"))?;
                    let ramdisk_end = ramdisk_start
                        .checked_add(u32_to_usize(ramdisk_entry.ramdisk_size))
                        .ok_or(AvbError::IndexOutOfBounds("ramdisk"))?;

                    // TODO: check here that this ramdisk range fits in
                    // ranges.ramdisk? A range.contains() check could
                    // be done.
                    ranges.platform_ramdisk = Range {
                        start: ramdisk_start,
                        end: ramdisk_end,
                    };
                }
            }
        }

        // For now only support a single platform ramdisk.
        if platform_ramdisk_count != 1 {
            return Err(AvbError::UnsupportedVendorRamdiskCount(
                platform_ramdisk_count,
            ))?;
        }

        // The cmdline range could be determined by determining
        // the offset into the vendor_base.cmdline [u8; 2048] member.
        // Instead of setting the scope here just parse the cmdline
        // into a cstr and return it.
        let cmdline = CStr::from_bytes_until_nul(&vendor_base.cmdline)
            .map_err(AvbError::VendorCommandlineUnterminated)?;

        // Convert the CStr to &str then to CString16.
        // Return an error if any of those fail.
        ranges.cmdline = cmdline
            .to_str()
            .ok()
            .and_then(|x| CString16::try_from(x).ok())
            .ok_or(AvbError::VendorCommandlineMalformed)?;

        Ok(ranges)
    }
}

struct RangeBuilder {
    page_size: usize,
    /// End of any previous sections
    end: usize,
}

impl RangeBuilder {
    fn new(page_size: usize) -> Self {
        Self { page_size, end: 0 }
    }

    fn next_range(&mut self, size: u32) -> Option<Range<usize>> {
        let size = u32_to_usize(size);

        // Create the range starting at the end of the previous section
        // of the length of the data for this section.
        let range = Range {
            start: self.end,
            end: self.end.checked_add(size)?,
        };

        // Find the end of the section for this newly added
        // range. They align on a page_size boundary.
        self.end = range.end.checked_next_multiple_of(self.page_size)?;

        Some(range)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use uefi::cstr16;

    pub(crate) static TEST_BOOT_IMAGE: &[u8] = include_bytes!("../test_data/bootimg/test_boot.img");
    pub(crate) static TEST_INIT_BOOT_IMAGE: &[u8] =
        include_bytes!("../test_data/bootimg/test_init.img");
    pub(crate) static TEST_VENDOR_BOOT_IMAGE: &[u8] =
        include_bytes!("../test_data/bootimg/test_vendor.img");

    /// Test parsing a boot image with only a kernel.
    #[test]
    fn test_boot_image() {
        let res = BootImageParts::from_boot_partition(TEST_BOOT_IMAGE).unwrap();
        assert_eq!(b"KERNEL", res.kernel);
    }

    /// Test parsing the vendor boot image with a ramdisk.
    #[test]
    fn test_init_boot_image() {
        let res = BootImageParts::from_boot_partition(TEST_INIT_BOOT_IMAGE).unwrap();
        assert_eq!(b"INIT_RAMDISK", res.initramfs);
    }

    /// Test parsing the vendor image with multiple ramdisks.
    #[test]
    fn test_vendor_boot_image() {
        let res = VendorData::from_vendor_partition(TEST_VENDOR_BOOT_IMAGE).unwrap();
        assert_eq!(b"VENDOR_RAMDISK", res.initramfs);
        assert_eq!(cstr16!("vendor cmdline"), res.cmdline);
        assert_eq!(b"bootconfig value", res.bootconfig);
    }

    #[test]
    fn test_range_builder() {
        let mut rb = RangeBuilder::new(1024);

        // Section with a size of 25.
        assert_eq!(rb.next_range(25).unwrap(), Range { start: 0, end: 25 });

        // Confirm the end includes the page_size.
        assert_eq!(rb.end, 1024);

        // A section with a size of 0 is OK and does
        // not cause an error.
        assert_eq!(
            rb.next_range(0).unwrap(),
            Range {
                start: 1024,
                end: 1024
            }
        );
        // Confirm the end has not changed due to
        // a 0 size section.
        assert_eq!(rb.end, 1024);

        // Added range larger than a single page size.
        assert_eq!(
            rb.next_range(1026).unwrap(),
            Range {
                start: 1024,
                end: 2050
            }
        );
        assert_eq!(rb.end, 1024 * 3);
    }
}
