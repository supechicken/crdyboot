#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

mod truncate;

use alloc::{string::ToString, vec, vec::Vec};
use core::convert::{TryFrom, TryInto};
use log::{error, info};
use uefi::data_types::chars::NUL_16;
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::partition::{
    GptPartitionEntry, GptPartitionType, PartitionInfo,
};
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
    handle: Handle,
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

// TODO: use blockio instead just to have less reliance on UEFI
// implementations working correctly?
//
// TODO: what happens if there are multiple disks? How do we pick
// the one we booted from? Presumably there's some way to use the
// image handle for this.
fn get_kernel_partitions(
    _crdyboot_image: Handle,
    bt: &BootServices,
) -> Result<Vec<KernelPartition>> {
    let handles = bt
        .find_handles::<PartitionInfo>()
        .expect_success("Failed to get handles for `PartitionInfo` protocol");

    let mut v = Vec::with_capacity(12);

    for handle in handles {
        let pi = bt
            .handle_protocol::<PartitionInfo>(handle)
            .expect_success("Failed to get partition info");
        let pi = unsafe { &*pi.get() };

        if let Some(gpt) = pi.gpt_partition_entry() {
            let partition_type = gpt.partition_type_guid;

            if gpt.starting_lba == gpt.ending_lba {
                info!("skipping stub partition");
            } else if partition_type != GptPartitionType(KERNEL_TYPE_GUID) {
                info!("skipping non-kernel partition");
            } else {
                v.push(KernelPartition {
                    handle,
                    entry: *gpt,
                });
            }
        }
    }

    Status::SUCCESS.into_with_val(|| v)
}

fn read_kernel_partition(
    bt: &BootServices,
    partition: &KernelPartition,
) -> Result<Vec<u8>> {
    let bio = bt
        .handle_protocol::<BlockIO>(partition.handle)
        .log_warning()?;
    let bio = unsafe { &*bio.get() };

    info!("got bio: {:?}", bio.media());

    // TODO: maybe uninit
    let mut kernel_buffer = vec![0; partition.num_bytes(bio).unwrap()];
    info!("allocated kernel buffer");

    info!("reading kernel from disk");
    bio.read_blocks(
        bio.media().media_id(),
        // This bio is the partition, not the whole
        // device, so this is 0 instead of starting_lba.
        0,
        &mut kernel_buffer,
    )
    .log_warning()?;
    info!("done reading blocks");

    Status::SUCCESS.into_with_val(|| kernel_buffer)
}

// TODO: check if uefi-rs already has a way to do this.
fn str_to_uefi_str(input: &str) -> Option<Vec<Char16>> {
    // The kernel command line should always be ASCII.
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

fn run_kernel(
    crdyboot_image: Handle,
    bt: &BootServices,
    partition: &KernelPartition,
    kernel_key: &PublicKey,
) -> Result<()> {
    // Read the whole kernel partition into memory.
    let kernel_buffer = read_kernel_partition(bt, &partition).log_warning()?;

    // Parse and verify the whole partition.
    let kernel = verify_kernel(&kernel_buffer, &kernel_key).unwrap();
    info!("kernel verified");

    // Load the kernel as a UEFI image.
    let kernel_image = bt
        .load_image_from_buffer(crdyboot_image, kernel.data)
        .log_warning()?;
    info!("image loaded");

    // Get the kernel command line and replace %U with the kernel
    // partition GUID. (References to the rootfs partition are
    // expressed as offsets from the kernel partition, so only the
    // kernel partition's GUID is ever needed.)
    let load_options_str = kernel
        .command_line
        .replace("%U", &{ partition.entry.unique_partition_guid }.to_string());
    info!("command line: {}", load_options_str);

    // Convert the string to UCS-2, then set it in the image
    // options.
    let load_options = str_to_uefi_str(&load_options_str).unwrap();
    let loaded_image = bt
        .handle_protocol::<LoadedImage>(kernel_image)
        .log_warning()?;
    let loaded_image = unsafe { &mut *loaded_image.get() };
    unsafe {
        loaded_image.set_load_options(
            load_options.as_ptr(),
            (2 * load_options.len()) as u32,
        );
    }

    info!("starting kernel...");
    bt.start_image(kernel_image).log_warning()?;

    // TODO: unload the image on failure?

    Status::SUCCESS.into()
}

fn run(crdyboot_image: Handle, bt: &BootServices) -> Result<()> {
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
        info!("kernel partition: {:x?}", partition.entry);

        if let Err(err) =
            run_kernel(crdyboot_image, bt, &partition, &kernel_key)
                .log_warning()
        {
            error!("failed to run kernel: {:?}", err);
        }
    }

    // Failed to run any kernel.
    Status::LOAD_ERROR.into()
}

#[entry]
fn efi_main(image: Handle, st: SystemTable<Boot>) -> Status {
    uefi_services::init(&st).expect_success("failed to initialize utilities");

    let bt = st.boot_services();

    run(image, bt).expect_success("run failed");

    panic!("failed to run any kernel");
}
