// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use log::{error, LevelFilter};
use uefi::prelude::cstr16;
use uefi::proto::device_path::DevicePath;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{BootServices, ScopedProtocol};
use uefi::{CStr16, Result, Status};

/// Open the `SimpleFileSystem` protocol for the file system containing
/// the currently-running executable.
fn get_image_file_system(boot_services: &BootServices) -> Result<ScopedProtocol<SimpleFileSystem>> {
    let loaded_image =
        boot_services.open_protocol_exclusive::<LoadedImage>(boot_services.image_handle())?;
    let device_path = boot_services.open_protocol_exclusive::<DevicePath>(loaded_image.device())?;
    let device_handle = boot_services.locate_device_path::<SimpleFileSystem>(&mut &*device_path)?;
    boot_services.open_protocol_exclusive(device_handle)
}

/// Check if `efi\boot\crdyboot_verbose` exists on the boot
/// filesystem. If any error occurs when checking for this file, `false`
/// is returned.
fn does_verbose_file_exist(boot_services: &BootServices) -> bool {
    let mut sfs = match get_image_file_system(boot_services) {
        Ok(sfs) => sfs,
        Err(err) => {
            error!("failed to open SimpleFileSystem: {err:?}");
            return false;
        }
    };

    let mut root = match sfs.open_volume() {
        Ok(root) => root,
        Err(err) => {
            error!("failed to open volume: {err:?}");
            return false;
        }
    };

    let path: &CStr16 = cstr16!(r"efi\boot\crdyboot_verbose");
    match root.open(path, FileMode::Read, FileAttribute::empty()) {
        Ok(_) => true,
        Err(err) => {
            if err.status() != Status::NOT_FOUND {
                error!("unexpected error when opening {path}: {err:?}");
            }
            false
        }
    }
}

/// Set the log level. By default it's set to `Warn` so that only
/// warnings and errors are shown. In a normal boot, this will result in
/// no output. If a file named `crdyboot_verbose` exists in the same
/// directory as the bootloader executable, the log level will be set to
/// `Debug`.
pub fn set_log_level(boot_services: &BootServices) {
    // Default to only warnings and errors. Set this before calling
    // `does_verbose_file_exist` to guard against any early verbose
    // logs.
    log::set_max_level(LevelFilter::Warn);

    if does_verbose_file_exist(boot_services) {
        log::set_max_level(LevelFilter::Debug);
    }
}
