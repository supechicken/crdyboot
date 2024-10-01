// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use alloc::vec::Vec;
use log::info;
use uefi::boot::{self, LoadImageSource};
use uefi::cstr16;
use uefi::proto::device_path::build::{self, DevicePathBuilder};
use uefi::proto::device_path::text::{AllowShortcuts, DisplayOnly};
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType, LoadedImageDevicePath};
use uefi::proto::BootPolicy;

/// Get the device path of crdyshim. This is the same as the
/// currently-loaded image's device path, but with the file path part
/// changed.
fn get_crdyshim_device_path(storage: &mut Vec<u8>) -> &DevicePath {
    let loaded_image_device_path =
        boot::open_protocol_exclusive::<LoadedImageDevicePath>(boot::image_handle())
            .expect("failed to open LoadedImageDevicePath protocol");

    let mut builder = DevicePathBuilder::with_vec(storage);
    for node in loaded_image_device_path.node_iter() {
        if node.full_type() == (DeviceType::MEDIA, DeviceSubType::MEDIA_FILE_PATH) {
            break;
        }
        builder = builder.push(&node).unwrap();
    }
    builder = builder
        .push(&build::media::FilePath {
            path_name: cstr16!(r"efi\boot\crdyshimx64.efi"),
        })
        .unwrap();
    builder.finalize().unwrap()
}

pub fn launch_crdyshim() {
    let mut storage = Vec::new();
    let crdyshim_path = get_crdyshim_device_path(&mut storage);

    info!(
        "loading {}",
        crdyshim_path
            .to_string(DisplayOnly(true), AllowShortcuts(true))
            .unwrap(),
    );
    let crdyshim_image_handle = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: crdyshim_path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )
    .expect("failed to load crdyshim");

    info!("launching crdyshim");
    boot::start_image(crdyshim_image_handle).expect("failed to launch crdyshim");
}
