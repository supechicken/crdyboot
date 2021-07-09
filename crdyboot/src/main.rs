#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

mod linux;
mod truncate;

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{
    convert::{TryFrom, TryInto},
    fmt,
};
use log::{debug, error, info};
use uefi::data_types::chars::NUL_16;
use uefi::gpt::GptHeader;
use uefi::prelude::*;
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::partition::{GptPartitionEntry, GptPartitionType};
use uefi::{Char16, Guid, Result};
use vboot::{verify_kernel, CgptAttributes, PublicKey};

const KERNEL_TYPE_GUID: Guid = Guid::from_values(
    0xfe3a2a5d,
    0x4f32,
    0x41a7,
    0xb725,
    [0xac, 0xcc, 0x32, 0x85, 0xa3, 0x09],
);

// TODO: open protocol vs handle protocol

struct KernelPartition {
    disk_handle: Handle,
    entry: GptPartitionEntry,
}

impl KernelPartition {
    fn num_bytes(&self, bio: &BlockIO) -> Option<usize> {
        let num_blocks: usize = self.entry.num_blocks()?.try_into().ok()?;
        let block_size: usize = bio.media().block_size().try_into().ok()?;
        num_blocks.checked_mul(block_size)
    }

    fn priority(&self) -> u8 {
        CgptAttributes::from_u64(self.entry.attributes).priority
    }
}

impl fmt::Display for KernelPartition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let entry = &self.entry;
        write!(
            f,
            "KernelPartition {{ guid: {}, name: {}, lba: {:x?}, priority={} }}",
            { entry.unique_partition_guid },
            uefi_str_to_string(&{ entry.partition_name }),
            entry.starting_lba..=entry.ending_lba,
            self.priority()
        )
    }
}

/// Open `DevicePath` protocol for `handle`.
fn device_paths_for_handle(
    handle: Handle,
    bt: &BootServices,
) -> Result<&DevicePath> {
    let device_path = bt.handle_protocol::<DevicePath>(handle).log_warning()?;
    let device_path = unsafe { &*device_path.get() };
    Status::SUCCESS.into_with_val(|| device_path)
}

/// True if `potential_parent` is the handle representing the disk that
/// contains the `partition` device.
///
/// This is determined by looking at the Device Paths associated with each
/// handle. The parent device should have exactly the same set of paths, except
/// that the partition paths end with a Hard Drive Media Device Path.
fn is_parent_disk(
    potential_parent: Handle,
    partition: Handle,
    bt: &BootServices,
) -> Result<bool> {
    let ret = |val: bool| Status::SUCCESS.into_with_val(|| val);

    let potential_parent_paths_iter =
        device_paths_for_handle(potential_parent, bt)
            .log_warning()?
            .iter();
    let mut partition_paths_iter =
        device_paths_for_handle(partition, bt).log_warning()?.iter();

    for (parent_path, partition_path) in
        potential_parent_paths_iter.zip(&mut partition_paths_iter)
    {
        if parent_path != partition_path {
            return ret(false);
        }
    }

    // After the zip operation we expect there to be one remaining path for the
    // partition device; validate that this expectation is met.
    let final_partition_path = if let Some(path) = partition_paths_iter.next() {
        path
    } else {
        return ret(false);
    };

    // That final path should be a Hard Drive Media Device Path.
    if final_partition_path.full_type()
        != (DeviceType::MEDIA, DeviceSubType::MEDIA_HARD_DRIVE)
    {
        return ret(false);
    }

    ret(true)
}

/// Search `block_io_handles` for the device that is a parent of
/// `partition_handle`. See `is_parent_disk` for details.
fn find_parent_disk(
    block_io_handles: &[Handle],
    partition_handle: Handle,
    bt: &BootServices,
) -> Result<Option<Handle>> {
    for handle in block_io_handles {
        if is_parent_disk(*handle, partition_handle, bt).log_warning()? {
            return Status::SUCCESS.into_with_val(|| Some(*handle));
        }
    }

    Status::SUCCESS.into_with_val(|| None)
}

/// Find all non-stub ChromeOS kernel partitions that are on the same disk as
/// the crdyboot image.
///
/// This uses `BlockIO` to directly read the GPT rather than the
/// `PartitionInfo` protocol because not all UEFI implementations support the
/// latter protocol.
fn get_kernel_partitions(
    crdyboot_image: Handle,
    bt: &BootServices,
) -> Result<Vec<KernelPartition>> {
    // Get the LoadedImage protocol for the image handle. This provides a
    // device handle which should correspond to the disk that the image was
    // loaded from.
    let loaded_image = bt
        .handle_protocol::<LoadedImage>(crdyboot_image)
        .log_warning()?;
    let loaded_image = unsafe { &*loaded_image.get() };
    let partition_handle = loaded_image.device();

    // Get all handles that support BlockIO. This includes both disk devices
    // and logical partition devices.
    let block_io_handles = bt.find_handles::<BlockIO>().unwrap_success();

    // Find the parent disk device of the logical partition device.
    let disk_handle = if let Some(parent) =
        find_parent_disk(&block_io_handles, partition_handle, bt)
            .log_warning()?
    {
        parent
    } else {
        error!("parent disk not found");
        return Status::NOT_FOUND.into_with_val(Vec::new);
    };

    let disk_block_io =
        bt.handle_protocol::<BlockIO>(disk_handle).log_warning()?;
    let disk_block_io = unsafe { &*disk_block_io.get() };

    let entries = match GptHeader::read_valid_header_and_entries(disk_block_io)
    {
        Ok((_header, entries)) => entries,
        Err(err) => {
            error!("no valid GPT found: {:?}", err);
            return Status::NOT_FOUND.into_with_val(Vec::new);
        }
    };

    let mut v = Vec::with_capacity(2);

    for entry in entries {
        let partition_type = entry.partition_type_guid;

        if entry.starting_lba == entry.ending_lba {
            debug!("skipping stub partition");
        } else if partition_type != GptPartitionType(KERNEL_TYPE_GUID) {
            debug!("skipping non-kernel partition");
        } else {
            v.push(KernelPartition { disk_handle, entry });
        }
    }

    Status::SUCCESS.into_with_val(|| v)
}

fn read_kernel_partition(
    bt: &BootServices,
    partition: &KernelPartition,
) -> Result<Vec<u8>> {
    let bio = bt
        .handle_protocol::<BlockIO>(partition.disk_handle)
        .log_warning()?;
    let bio = unsafe { &*bio.get() };

    debug!("got bio: {:?}", bio.media());

    // TODO: maybe uninit
    let mut kernel_buffer = vec![0; partition.num_bytes(bio).unwrap()];
    debug!("allocated kernel buffer");

    info!("reading kernel from disk");
    bio.read_blocks(
        bio.media().media_id(),
        partition.entry.starting_lba,
        &mut kernel_buffer,
    )
    .log_warning()?;
    info!("done reading blocks");

    Status::SUCCESS.into_with_val(|| kernel_buffer)
}

// TODO: check if uefi-rs already has a way to do this.
fn ascii_str_to_uefi_str(input: &str) -> Option<Vec<Char16>> {
    if !input.is_ascii() {
        return None;
    }

    // Expect two bytes for each byte of the input, plus a null byte.
    let mut output = Vec::with_capacity(input.len() + 1);

    output.extend(
        input
            .encode_utf16()
            // OK to unwrap because all ASCII characters are
            // valid UCS-2.
            .map(|c| Char16::try_from(c).unwrap()),
    );
    output.push(NUL_16);

    Some(output)
}

// TODO: check if uefi-rs already has a way to do this.
fn uefi_str_to_string(input: &[Char16]) -> String {
    // Get the end of the string, either the first nul character or
    // the end of the slice.
    let end = input
        .iter()
        .position(|c| *c == NUL_16)
        .unwrap_or(input.len());

    let input = &input[..end];
    let input: Vec<u16> = input.iter().map(|c| (*c).into()).collect();

    String::from_utf16(&input).unwrap()
}

fn run_kernel(
    crdyboot_image: Handle,
    st: SystemTable<Boot>,
    partition: &KernelPartition,
    kernel_key: &PublicKey,
) -> Result<()> {
    let st_clone: SystemTable<Boot> = unsafe { st.unsafe_clone() };

    let bt = st.boot_services();

    // Read the whole kernel partition into memory.
    let kernel_buffer = read_kernel_partition(bt, partition).log_warning()?;

    // Parse and verify the whole partition.
    let kernel = verify_kernel(&kernel_buffer, kernel_key).unwrap();
    info!("kernel verified");

    // Get the kernel command line and replace %U with the kernel
    // partition GUID. (References to the rootfs partition are
    // expressed as offsets from the kernel partition, so only the
    // kernel partition's GUID is ever needed.)
    let load_options_str = kernel
        .command_line
        .replace("%U", &{ partition.entry.unique_partition_guid }.to_string());
    info!("command line: {}", load_options_str);

    // Convert the string to UCS-2.
    let load_options_ucs2 = ascii_str_to_uefi_str(&load_options_str).unwrap();

    // Use the EFI stub to run the kernel.
    linux::execute_linux_efi_stub(
        kernel.data,
        crdyboot_image,
        st_clone,
        &load_options_ucs2,
    )
    .log_warning()?;

    // TODO: unload the image on failure?

    Status::SUCCESS.into()
}

fn run(crdyboot_image: Handle, st: SystemTable<Boot>) -> Result<()> {
    let st_clone = unsafe { st.unsafe_clone() };
    let bt = st_clone.boot_services();

    // TODO
    let test_key_vbpubk =
        include_bytes!("../../vboot/test_data/kernel_key.vbpubk");
    let kernel_key = PublicKey::from_le_bytes(test_key_vbpubk).unwrap();

    let mut partitions =
        get_kernel_partitions(crdyboot_image, bt).log_warning()?;
    info!("found {} kernel partitions", partitions.len());

    // Sort partitions by priority from high to low.
    partitions.sort_unstable_by_key(|p| p.priority());
    partitions.reverse();

    for partition in partitions {
        info!("kernel partition: {}", partition);

        let st = unsafe { st.unsafe_clone() };

        if let Err(err) =
            run_kernel(crdyboot_image, st, &partition, &kernel_key)
                .log_warning()
        {
            error!("failed to run kernel: {:?}", err);
        }
    }

    // Failed to run any kernel.
    Status::LOAD_ERROR.into()
}

#[entry]
fn efi_main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st)
        .expect_success("failed to initialize utilities");

    run(image, st).expect_success("run failed");

    panic!("failed to run any kernel");
}

#[no_mangle]
#[link_section = ".sbat"]
static SBAT: [u8; 163] = *include_bytes!("sbat.csv");
