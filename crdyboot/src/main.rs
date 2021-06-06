#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

mod truncate;

use alloc::{vec, vec::Vec};
use core::convert::TryFrom;
use log::info;
use uefi::data_types::chars::NUL_16;
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::partition::{GptPartitionType, PartitionInfo};
use uefi::{Char16, Guid, Result};
use vboot::rimpl::{verify_kernel, PublicKey};

const KERNEL_TYPE_GUID: Guid = Guid::from_values(
    0xfe3a2a5d,
    0x4f32,
    0x41a7,
    0xb725,
    [0xac, 0xcc, 0x32, 0x85, 0xa3, 0x09],
);

// TODO: open protocol vs handle protocol

fn run(crdyboot_image: Handle, bt: &BootServices) -> Result<()> {
    let handles = bt
        .find_handles::<PartitionInfo>()
        .expect_success("Failed to get handles for `PartitionInfo` protocol");

    // TODO
    let test_key_vbpubk =
        include_bytes!("../../vboot/test_data/kernel_key.vbpubk");
    let kernel_key = PublicKey::from_le_bytes(test_key_vbpubk).unwrap();

    let a = 1u128;
    let b = 12742837032881555980u128;
    info!("BISH: modtest: {}", a % b);

    // TODO: use blockio instead just to have less reliance on UEFI
    // implementations working correctly?
    //
    // TODO: what happens if there are multiple disks? How do we pick
    // the one we booted from? Presumably there's some way to use the
    // image handle for this.
    for handle in handles {
        let pi = bt
            .handle_protocol::<PartitionInfo>(handle)
            .expect_success("Failed to get partition info");
        let pi = unsafe { &*pi.get() };

        if let Some(gpt) = pi.gpt_partition_entry() {
            if { gpt.partition_type_guid } == GptPartitionType(KERNEL_TYPE_GUID)
            {
                // TODO: for now arbitrarily pick the first one found.
                info!("kernel partition: {:x?}", gpt);

                // Read the whole kernel into memory.

                let bio =
                    bt.handle_protocol::<BlockIO>(handle).log_warning()?;
                let bio = unsafe { &*bio.get() };

                info!("got bio: {:?}", bio.media());

                let num_blocks = gpt.ending_lba - gpt.starting_lba + 1;
                let num_bytes = num_blocks * bio.media().block_size() as u64;
                info!("num_bytes: {}", num_bytes);

                // TODO: maybe uninit
                let mut kernel_buffer = vec![0; num_bytes as usize];
                info!("allocated kernel buffer");

                bio.read_blocks(
                    bio.media().media_id(),
                    // This bio is the partition, not the whole
                    // device, so this is 0 instead of starting_lba.
                    0,
                    &mut kernel_buffer,
                )
                .log_warning()?;

                info!("done reading blocks");

                // Verifying!

                let kernel_actual =
                    verify_kernel(&kernel_buffer, &kernel_key).unwrap();

                info!("verified!");

                let kernel_image = bt
                    .load_image_from_buffer(crdyboot_image, kernel_actual)
                    .expect_success("lifb failed");

                info!("loaded!");

                // TODO: root
                let load_options_str = "init=/sbin/init boot=local rootwait ro noresume noswap loglevel=7 noinitrd i915.modeset=1 cros_efi cros_debug       root=/dev/sda18";
                let mut load_options: Vec<Char16> = load_options_str
                    .encode_utf16()
                    .map(|c| Char16::try_from(c).unwrap())
                    .collect();
                load_options.push(NUL_16);

                let loaded_image = bt
                    .handle_protocol::<LoadedImage>(kernel_image)
                    .log_warning()?;
                let loaded_image = unsafe { &mut *loaded_image.get() };
                loaded_image.set_load_options(
                    load_options.as_ptr(),
                    (2 * load_options.len()) as u32,
                );

                info!("starting kernel...");

                bt.start_image(kernel_image).log_warning()?;
            }
        }
    }

    Status::SUCCESS.into()
}

#[entry]
fn efi_main(image: Handle, st: SystemTable<Boot>) -> Status {
    uefi_services::init(&st).expect_success("failed to initialize utilities");

    let bt = st.boot_services();

    run(image, bt).expect_success("run failed");

    todo!();
}
