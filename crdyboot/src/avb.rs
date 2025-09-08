// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::alloc::string::{String, ToString};
use crate::boot_image::{BootImageParts, VendorData};
use crate::disk::{self, Gpt, GptDiskError, PartitionNum};
use avb::avb_ops::{create_ops, AvbDiskOps, AvbDiskOpsRef};
use avb::avb_sys::{
    avb_slot_verify, avb_slot_verify_data_free, avb_slot_verify_result_to_string,
    AvbHashtreeErrorMode, AvbIOResult, AvbPartitionData, AvbSlotVerifyData, AvbSlotVerifyFlags,
    AvbSlotVerifyResult, AvbVBMetaData,
};
use core::ffi::{CStr, FromBytesUntilNulError};
use core::ops::Deref;
use core::str::Utf8Error;
use core::{ptr, slice, str};
use libcrdy::page_alloc::{PageAllocationError, ScopedPageAllocation};
use libcrdy::uefi::{Uefi, UefiImpl};
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

    /// Failed loading the boot disk.
    #[error("failed loading the boot disk: {0}")]
    FailedLoadBootDisk(GptDiskError),

    /// Failed updating the gpt partition entry attributes.
    #[error("failed updating the gpt partition entry attributes: {0}")]
    FailedUpdateAttributes(GptDiskError),

    /// Bootconfig buffer is invalid size
    #[error("invalid size for the bootconfig buffer: expected {0}, actual {1}")]
    InvalidBufferSize(usize, usize),

    /// Failed to write boot config size into `u32`
    #[error("boot config is too large for u32")]
    BootConfigTooLarge,

    /// Boot config is not valid
    #[error("boot config is not valid: {0}")]
    BootConfigInvalid(Utf8Error),

    /// Buffer does not have enough space
    #[error("allocated buffer is too small")]
    BufferTooSmall,
}

fn verify_result_to_str(r: AvbSlotVerifyResult) -> &'static str {
    // SAFETY: `avb_slot_verify_result_to_string` always returns a valid
    // pointer to a string literal, so a static lifetime is correct.
    let s = unsafe { CStr::from_ptr(avb_slot_verify_result_to_string(r)) };
    // Unwrap is OK, the string is always UTF-8.
    s.to_str().unwrap()
}

const BOOT_PARTITION_NAME: &CStr = c"boot";
const INIT_PARTITION_NAME: &CStr = c"init_boot";
const VENDOR_BOOT_PARTITION_NAME: &CStr = c"vendor_boot";

// See https://docs.kernel.org/admin-guide/bootconfig.html#attaching-a-boot-config-to-initrd for
// definition of the trailer. See also
// https://android.googlesource.com/platform/bootable/libbootloader/+/main/gbl/libbootparams/src/bootconfig.rs
// for GBL implementation.
const BOOTCONFIG_MAGIC: &str = "#BOOTCONFIG\n";
const BOOTCONFIG_TRAILER_SIZE: usize = 4 + 4 + BOOTCONFIG_MAGIC.len();

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
        let mut pio = disk::open_partition_by_name(uefi, &name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)?;
        pio.read(start_byte, dst).map_err(map_uefi_status)
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
        let mut pio = disk::open_partition_by_name(uefi, &name)
            .map_err(|_| AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION)?;
        pio.write(offset, buffer).map_err(map_uefi_status)
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

struct BootConfig {
    /// Bootconfig data
    config: String,
}

impl BootConfig {
    /// Creates a new `BootConfig` from bootconfig data.
    pub fn new(data: &[u8]) -> Result<Self, AvbError> {
        let config = str::from_utf8(data)
            .map_err(AvbError::BootConfigInvalid)?
            .to_string();
        Ok(Self { config })
    }

    /// The size of the bootconfig with trailer.
    pub fn write_size(&self) -> Result<usize, AvbError> {
        self.config
            .len()
            .checked_add(BOOTCONFIG_TRAILER_SIZE)
            .ok_or(AvbError::BootConfigTooLarge)
    }

    /// Adds the dynamically determined androidboot values to the boot config.
    pub fn add_android_boot_values(
        &mut self,
        slot: BootSlot,
        uefi: &dyn Uefi,
    ) -> Result<(), AvbError> {
        self.config.push_str("androidboot.slot_suffix=");
        self.config.push_str(slot.slot_suffix_str());
        self.config.push('\n');

        // Add the UUID of the boot partition needed for the second stage to
        // load the file system.
        let boot_part_uuid = get_android_boot_part_uuid(uefi, slot)?;
        self.config.push_str("androidboot.boot_part_uuid=");
        self.config.push_str(&boot_part_uuid);
        self.config.push('\n');

        self.config
            .push_str("androidboot.verifiedbootstate=orange\n");
        Ok(())
    }

    /// Writes the bootconfig and trailer to `buffer` which should be `write_size()`.
    pub fn write(&self, buffer: &mut [u8]) -> Result<(), AvbError> {
        if buffer.len() != self.write_size()? {
            return Err(AvbError::InvalidBufferSize(
                self.write_size()?,
                buffer.len(),
            ));
        }

        let (config_buf, trailer_buf) = buffer.split_at_mut(self.config.len());
        config_buf.copy_from_slice(self.config.as_bytes());
        self.write_trailer(trailer_buf)
    }

    /// Writes the `trailer` for the given `bootconfig` based on the definition from
    /// <https://docs.kernel.org/admin-guide/bootconfig.html#attaching-a-boot-config-to-initrd>
    /// Panics if `trailer.len()` != `BOOTCONFIG_TRAILER_SIZE`
    fn write_trailer(&self, trailer: &mut [u8]) -> Result<(), AvbError> {
        assert!(trailer.len() == BOOTCONFIG_TRAILER_SIZE);
        let size: u32 = self
            .config
            .len()
            .try_into()
            .map_err(|_| AvbError::BootConfigTooLarge)?;
        let checksum: u32 = self
            .config
            .as_bytes()
            .iter()
            .fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)));
        let (size_buf, rest) = trailer.split_at_mut(4);
        let (checksum_buf, magic_buf) = rest.split_at_mut(4);
        size_buf.copy_from_slice(&size.to_le_bytes());
        checksum_buf.copy_from_slice(&checksum.to_le_bytes());
        magic_buf.copy_from_slice(BOOTCONFIG_MAGIC.as_bytes());
        Ok(())
    }
}

/// Assemble the initramfs and bootconfig values into
/// the passed `initramfs_buffer`.
/// This uses the `bootconfig` parameter and ignores
/// the `bootconfig` member of `vendor_data`.
fn assemble_initramfs_buffer(
    initramfs_buffer: &mut [u8],
    vendor_data: &VendorData,
    init_data: &BootImageParts,
    bootconfig: &BootConfig,
) -> Result<(), AvbError> {
    struct Appender<'a> {
        end: usize,
        buffer: &'a mut [u8],
    }

    impl Appender<'_> {
        fn append_initramfs(&mut self, buffer: &[u8]) -> Result<(), AvbError> {
            let start = self.end;
            self.end = start
                .checked_add(buffer.len())
                .ok_or(AvbError::InitramfsTooLarge)?;
            self.buffer
                .get_mut(start..self.end)
                .ok_or(AvbError::BufferTooSmall)?
                .copy_from_slice(buffer);
            Ok(())
        }
    }
    let vendor_initramfs = vendor_data.initramfs;
    let generic_initramfs = init_data.initramfs;

    let mut app = Appender {
        end: 0,
        buffer: initramfs_buffer,
    };

    // Copy the vendor_initramfs to the front of the buffer.
    app.append_initramfs(vendor_initramfs)?;
    // Append the generic_initramfs after the vendor_initramfs.
    app.append_initramfs(generic_initramfs)?;

    // Append the bootconfig at the end of the complete buffer.
    // It must be at the end.
    let bootconfig_size = bootconfig.write_size()?;

    let bootconfig_start = initramfs_buffer
        .len()
        .checked_sub(bootconfig_size)
        .ok_or(AvbError::BufferTooSmall)?;

    let bootconfig_slice = initramfs_buffer
        .get_mut(bootconfig_start..)
        .ok_or(AvbError::BufferTooSmall)?;
    bootconfig.write(bootconfig_slice)
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
    slot: BootSlot,
    uefi: &dyn Uefi,
) -> Result<ScopedPageAllocation, AvbError> {
    let vendor_initramfs = vendor_data.initramfs;
    let generic_initramfs = init_data.initramfs;
    let mut bootconfig = BootConfig::new(vendor_data.bootconfig)?;
    bootconfig.add_android_boot_values(slot, uefi)?;

    // Generic ramdisk must have a size.
    if generic_initramfs.is_empty() {
        return Err(AvbError::InvalidRamdiskSize(0));
    }

    let bootconfig_size = bootconfig.write_size()?;

    // Size of the combined initramfs data.
    let initramfs_size = generic_initramfs
        .len()
        .checked_add(vendor_initramfs.len())
        .ok_or(AvbError::InitramfsTooLarge)?
        .checked_add(bootconfig_size)
        .ok_or(AvbError::InitramfsTooLarge)?;

    let mut initramfs_buffer = ScopedPageAllocation::new_unaligned(
        AllocateType::AnyPages,
        MemoryType::LOADER_CODE,
        initramfs_size,
    )
    .map_err(AvbError::Allocation)?;

    assemble_initramfs_buffer(&mut initramfs_buffer, vendor_data, init_data, &bootconfig)?;

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

    // Null-pointer terminated list of partitions for
    // the call to `avb_slot_verify`.
    let requested_partitions = [
        BOOT_PARTITION_NAME.as_ptr(),
        INIT_PARTITION_NAME.as_ptr(),
        VENDOR_BOOT_PARTITION_NAME.as_ptr(),
        ptr::null(),
    ];

    let mut gpt = Gpt::load_boot_disk(&UefiImpl).map_err(AvbError::FailedLoadBootDisk)?;
    let (slot, mut attributes, partition_num) = get_priority_slot(&UefiImpl, &mut gpt)?;

    let mut verify_data: *mut AvbSlotVerifyData = ptr::null_mut();
    let res = unsafe {
        avb_slot_verify(
            &raw mut avbops,
            requested_partitions.as_ptr(),
            slot.slot_suffix_cstr().as_ptr(),
            AvbSlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
            AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART,
            &raw mut verify_data,
        )
    };
    if res != AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_OK {
        attributes.make_unbootable();
        gpt.update_partition_entry_attributes(&UefiImpl, attributes, partition_num)
            .map_err(AvbError::FailedUpdateAttributes)?;
        return Err(AvbError::AvbVerifyFailure(res));
    }

    if attributes.tries() != 0 {
        if attributes.successful() {
            // Tries should be 0 when successful, give a warning but let
            // userspace handle this.
            warn!(
                "Boot partition {} has both tries and successful attributes",
                slot.vbmeta_part_name()
            );
        } else {
            // Safety: tries is guaranteed to be >= 1.
            attributes.set_tries(attributes.tries().checked_sub(1).unwrap());
            gpt.update_partition_entry_attributes(&UefiImpl, attributes, partition_num)
                .map_err(AvbError::FailedUpdateAttributes)?;
        }
    }

    if log_enabled!(log::Level::Debug) {
        debug_print_avb_vbmeta_data(verify_data);
    }

    let verify_cmdline = unsafe { CStr::from_ptr((*verify_data).cmdline) };
    debug!("verify cmdline: {}", verify_cmdline.to_string_lossy());

    let (boot, init_boot, vendor_boot) = get_boot_parts(verify_data)?;

    // Load the kernel buffer from the boot partition header.
    let kernel_buffer = load_kernel(boot)?;

    // Parse the "generic" `initramfs` from the "init_boot" partition.
    // The initramfs is the only part of this partition that is used.
    let init_data = BootImageParts::from_avb_boot_partition(init_boot)?;

    // Slice up the vendor boot partition data.
    let vendor_data = VendorData::from_avb_vendor_partition(vendor_boot)?;
    debug!("vendor bootconfig_size: {}", vendor_data.bootconfig.len());
    debug!(
        "vendor bootconfig: {:?}",
        str::from_utf8(vendor_data.bootconfig)
    );
    debug!("vendor cmdline: {}", vendor_data.cmdline);

    let initramfs_buffer = assemble_initramfs(&vendor_data, &init_data, slot, &UefiImpl)?;

    let cmdline = generate_cmdline(verify_cmdline, &vendor_data)?;

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

    /// Get the `CStr16` representation of the vbmeta partititon name
    /// for the given slot.
    fn vbmeta_part_name(self) -> &'static CStr16 {
        match self {
            BootSlot::A => cstr16!("vbmeta_a"),
            BootSlot::B => cstr16!("vbmeta_b"),
        }
    }

    /// Get the `str` representation of the slot suffix.
    fn slot_suffix_str(self) -> &'static str {
        match self {
            BootSlot::A => "_a",
            BootSlot::B => "_b",
        }
    }

    /// Get the `CStr` representation of the slot suffix.
    fn slot_suffix_cstr(self) -> &'static CStr {
        match self {
            BootSlot::A => c"_a",
            BootSlot::B => c"_b",
        }
    }
}

/// Determines which boot slot to use based on partition priority.
/// Returns the slot, the Cgpt attributes for the slot, and the
/// partition number of the slot. Also marks partitions which have
/// exceeded their `tries` as unbootable.
/// Return Err if we don't find a bootable partition.
fn get_priority_slot(
    uefi: &dyn Uefi,
    gpt: &mut Gpt,
) -> Result<(BootSlot, CgptAttributes, PartitionNum), AvbError> {
    // Priority must be > 0 or the partition is not bootable per standard.
    let mut max_priority: u8 = 0;
    let mut result_slot = BootSlot::A;
    let mut result_attributes = CgptAttributes::from_u64(0);
    let mut result_partition_num = 0;
    for slot in BootSlot::all() {
        let name = slot.vbmeta_part_name();
        let (partition_num, gpt_partition_entry) = gpt
            .find_partition_by_name(name)
            .map_err(|error| AvbError::FailedFindPartition { name, error })?;

        let mut attributes = CgptAttributes::from_u64(gpt_partition_entry.attributes.0.to_u64());
        debug!("partition: {} attributes: {:?}", name, attributes);
        if !attributes.successful() && attributes.tries() == 0 && attributes.priority() != 0 {
            // This partition can't be booted, set all attributes to 0 to signify this.
            attributes.make_unbootable();
            gpt.update_partition_entry_attributes(uefi, attributes, *partition_num)
                .map_err(AvbError::FailedUpdateAttributes)?;
        } else if attributes.priority() > max_priority {
            max_priority = attributes.priority();
            result_slot = *slot;
            result_attributes = attributes;
            result_partition_num = *partition_num;
        }
    }

    if max_priority != 0 {
        Ok((result_slot, result_attributes, result_partition_num))
    } else {
        Err(AvbError::NoBootablePartition)
    }
}

/// Look up the UUID of the boot partition and return as a `String`.
/// Return Err if there was an issue looking it up.
fn get_android_boot_part_uuid(uefi: &dyn Uefi, slot: BootSlot) -> Result<String, AvbError> {
    let name = slot.vbmeta_part_name();
    let guid = disk::get_partition_unique_guid(uefi, name).map_err(AvbError::FailedBootPartUuid)?;
    Ok(guid.to_string())
}

/// Given the `verify_cmdline` output, return the three useful partitions
/// `boot`, `init_boot`, and `vendor_boot` in that order.
fn get_boot_parts<'a>(
    verify_data: *mut AvbSlotVerifyData,
) -> Result<
    (
        &'a AvbPartitionData,
        &'a AvbPartitionData,
        &'a AvbPartitionData,
    ),
    AvbError,
> {
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
        if name == BOOT_PARTITION_NAME {
            boot = Some(part);
        } else if name == INIT_PARTITION_NAME {
            init_boot = Some(part);
        } else if name == VENDOR_BOOT_PARTITION_NAME {
            vendor_boot = Some(part);
        }
    }

    let Some(boot) = boot else {
        return Err(AvbError::MissingAvbPartition("boot"));
    };
    let Some(init_boot) = init_boot else {
        return Err(AvbError::MissingAvbPartition("init_boot"));
    };
    let Some(vendor_boot) = vendor_boot else {
        return Err(AvbError::MissingAvbPartition("vendor_boot"));
    };

    Ok((boot, init_boot, vendor_boot))
}

/// Generates the `cmdline` for the kernel as a `CString16`
fn generate_cmdline(
    verify_cmdline: &CStr,
    vendor_data: &VendorData,
) -> Result<CString16, AvbError> {
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
    Ok(cmdline)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::disk::tests::{create_mock_uefi, BootDrive};

    #[test]
    fn test_get_priority_slot_basic() {
        // In default setup vbmeta_a has priority 14, success 1
        // vbmeta_b has priority 15, success 0, tries 3
        let uefi = create_mock_uefi(BootDrive::Hd2);
        let mut gpt = Gpt::load_boot_disk(&uefi).unwrap();
        let (boot_slot, attributes, partition_number) = get_priority_slot(&uefi, &mut gpt).unwrap();
        assert_eq!(boot_slot, BootSlot::B);
        assert_eq!(attributes, CgptAttributes::from_u64(0x3F000000000000));
        assert_eq!(partition_number, 16);
    }

    #[test]
    fn test_write_bootconfig() {
        const EMPTY_CONFIG_TRAILER: &[u8; BOOTCONFIG_TRAILER_SIZE] =
            b"\x00\x00\x00\x00\x00\x00\x00\x00#BOOTCONFIG\n";
        const TEST_CONFIG_TRAILER: &[u8; BOOTCONFIG_TRAILER_SIZE] =
            b"\x7A\x00\x00\x00\xC1\x2F\x00\x00#BOOTCONFIG\n";
        const TEST_CONFIG_TRAILER_2: &[u8; BOOTCONFIG_TRAILER_SIZE] =
            b"\xFA\x00\x00\x00\x54\x5D\x00\x00#BOOTCONFIG\n";
        const TEST_CONFIG_STRING: &str = "androidboot.hardware.platform=android-desktop
androidboot.hardware=android-desktop
androidboot.load_modules_parallel=true
";
        const TEST_CONFIG_STRING_2: &str = "androidboot.hardware.platform=android-desktop
androidboot.hardware=android-desktop
androidboot.load_modules_parallel=true
androidboot.slot_suffix=_b
androidboot.boot_part_uuid=8ae7710a-e709-44aa-8c8e-b454f48319fb
androidboot.verifiedbootstate=orange
";

        // Writing an empty config will only be a trailer.
        let empty_config = [0u8; 0];
        let empty_bootconfig = BootConfig::new(&empty_config).unwrap();
        let mut buffer = [0u8; BOOTCONFIG_TRAILER_SIZE];
        assert_eq!(
            empty_bootconfig.write_size().unwrap(),
            BOOTCONFIG_TRAILER_SIZE
        );
        empty_bootconfig.write(&mut buffer).unwrap();
        assert_eq!(&buffer[..], EMPTY_CONFIG_TRAILER);

        let mut test_bootconfig = BootConfig::new(TEST_CONFIG_STRING.as_bytes()).unwrap();

        // Test that writing to a buffer that's too small throws an error
        let expected_size = TEST_CONFIG_STRING.len() + BOOTCONFIG_TRAILER_SIZE;
        let result = test_bootconfig.write(&mut buffer);
        assert_eq!(
            result,
            Err(AvbError::InvalidBufferSize(
                expected_size,
                BOOTCONFIG_TRAILER_SIZE
            ))
        );

        let mut buffer = [0u8; TEST_CONFIG_STRING.len() + BOOTCONFIG_TRAILER_SIZE];
        test_bootconfig.write(&mut buffer).unwrap();
        assert_eq!(
            &buffer[..TEST_CONFIG_STRING.len()],
            TEST_CONFIG_STRING.as_bytes()
        );
        assert_eq!(&buffer[TEST_CONFIG_STRING.len()..], TEST_CONFIG_TRAILER);

        let uefi = create_mock_uefi(BootDrive::Hd2);
        test_bootconfig
            .add_android_boot_values(BootSlot::B, &uefi)
            .unwrap();
        let mut buffer = [0u8; TEST_CONFIG_STRING_2.len() + BOOTCONFIG_TRAILER_SIZE];
        test_bootconfig.write(&mut buffer).unwrap();
        assert_eq!(
            &buffer[..TEST_CONFIG_STRING_2.len()],
            TEST_CONFIG_STRING_2.as_bytes()
        );
        assert_eq!(&buffer[TEST_CONFIG_STRING_2.len()..], TEST_CONFIG_TRAILER_2);
    }

    #[test]
    fn test_assemble_initramfs_buffer() {
        let mut buffer = [0u8; 128];
        // Use an expected buffer larger than needed to check
        // for unmodified sections.
        let mut expected = [0u8; 128];

        let expected_ramdisk = b"vendor generic";

        let vd = VendorData {
            initramfs: b"vendor ",
            cmdline: CString16::from(cstr16!("cmdline")),
            bootconfig: b"",
        };

        let bi = BootImageParts {
            kernel: b"kernel",
            initramfs: b"generic",
        };

        let bootconfig = BootConfig::new(b"xyz").unwrap();

        // Put the expected ramdisk data at the front of the buffer.
        expected[..expected_ramdisk.len()].copy_from_slice(expected_ramdisk);

        // Write the bootconfig at the end of the buffer, it must be at the end.
        let bootconfig_start = expected.len() - bootconfig.write_size().unwrap();
        bootconfig
            .write(expected.get_mut(bootconfig_start..).unwrap())
            .unwrap();

        assemble_initramfs_buffer(&mut buffer, &vd, &bi, &bootconfig).unwrap();

        assert_eq!(&buffer[..expected.len()], expected);
    }
}
