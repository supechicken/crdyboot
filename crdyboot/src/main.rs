#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::convert::TryFrom;
use log::info;
use uefi::data_types::chars::NUL_16;
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{
    File, FileAttribute, FileInfo, FileMode, FileType,
};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::media::partition::{
    GptPartitionEntry, GptPartitionType, PartitionInfo,
};
use uefi::{Char16, Guid, Result};

const KERNEL_TYPE_GUID: Guid = Guid::from_values(
    0xfe3a2a5d,
    0x4f32,
    0x41a7,
    0xb725,
    [0xac, 0xcc, 0x32, 0x85, 0xa3, 0x09],
);

fn get_kernel_partitions(
    _image: Handle,
    bt: &BootServices,
) -> Result<Vec<GptPartitionEntry>> {
    info!("partition info");

    let handles = bt
        .find_handles::<PartitionInfo>()
        .expect_success("Failed to get handles for `PartitionInfo` protocol");

    // We expect to find three: KERN-A, KERN-B, and KERN-C.
    let mut v = Vec::with_capacity(3);

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
                v.push(gpt.clone());
            }
        }
    }

    Status::SUCCESS.into_with_val(|| v)
}

fn run(image: Handle, bt: &BootServices) -> Result<()> {
    let kernel_partitions = get_kernel_partitions(image, bt).log_warning()?;
    info!("kernel partitions: {:?}", kernel_partitions);

    let sfs = bt.locate_protocol::<SimpleFileSystem>()?;
    let sfs = sfs.expect("Cannot open `SimpleFileSystem` protocol");
    let sfs = unsafe { &mut *sfs.get() };

    let mut directory = sfs.open_volume().log_warning()?;
    let mut f = directory
        .open(
            "\\syslinux\\vmlinuz.A",
            FileMode::Read,
            FileAttribute::empty(),
        )
        .log_warning()?;

    let mut buffer = [0u8; 255];
    let info = f.get_info::<FileInfo>(&mut buffer).unwrap_success();

    info!("file size: {}", info.file_size());

    let mut v = vec![0; info.file_size() as usize];

    let ft = f.into_type().unwrap_success();
    if let FileType::Regular(mut f) = ft {
        f.read(&mut v).unwrap_success();
    } else {
        panic!("bad file type");
    }

    info!("file loaded");

    let image = bt
        .load_image_from_buffer(image, &v)
        .expect_success("lifb failed");

    info!("image loaded");

    // TODO: root
    let load_options_str = "init=/sbin/init boot=local rootwait ro noresume noswap loglevel=7 noinitrd i915.modeset=1 cros_efi cros_debug       root=/dev/sda18";
    let mut load_options: Vec<Char16> = load_options_str
        .encode_utf16()
        .map(|c| Char16::try_from(c).unwrap())
        .collect();
    load_options.push(NUL_16);

    let loaded_image =
        bt.handle_protocol::<LoadedImage>(image).log_warning()?;
    let loaded_image = unsafe { &mut *loaded_image.get() };
    loaded_image.set_load_options(
        load_options.as_ptr(),
        (2 * load_options.len()) as u32,
    );

    bt.start_image(image).log_warning()?;

    Status::SUCCESS.into()
}

#[entry]
fn efi_main(image: Handle, st: SystemTable<Boot>) -> Status {
    uefi_services::init(&st).expect_success("failed to initialize utilities");

    let bt = st.boot_services();

    run(image, bt).expect_success("run failed");

    todo!();
}
