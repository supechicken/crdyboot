// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use log::{info, LevelFilter};
use uefi::prelude::cstr16;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::{boot, CStr16, Status};

/// Check if `efi\boot\crdyboot_verbose` exists on the boot
/// filesystem. If any error occurs when checking for this file, `false`
/// is returned.
#[must_use]
pub fn does_verbose_file_exist() -> bool {
    let mut sfs = match boot::get_image_file_system(boot::image_handle()) {
        Ok(sfs) => sfs,
        Err(err) => {
            info!("failed to open SimpleFileSystem: {err:?}");
            return false;
        }
    };

    let mut root = match sfs.open_volume() {
        Ok(root) => root,
        Err(err) => {
            info!("failed to open volume: {err:?}");
            return false;
        }
    };

    let path: &CStr16 = cstr16!(r"efi\boot\crdyboot_verbose");
    match root.open(path, FileMode::Read, FileAttribute::empty()) {
        Ok(_) => true,
        Err(err) => {
            if err.status() != Status::NOT_FOUND {
                info!("unexpected error when opening {path}: {err:?}");
            }
            false
        }
    }
}

/// Initialize logging.
///
/// By default the log level is set to `Warn` so that only warnings and
/// errors are shown. In a normal boot, this will result in no
/// output. If a file named `crdyboot_verbose` exists in the same
/// directory as the bootloader executable, the log level will be set to
/// `Debug`.
///
/// # Panics
///
/// Panics if called more than once.
pub fn initialize_logging() {
    // Note: despite the generic name of 'helpers', this call is just
    // initializing the logger.
    uefi::helpers::init().expect("must not be called more than once");

    let level = if does_verbose_file_exist() {
        LevelFilter::Debug
    } else {
        LevelFilter::Warn
    };
    log::set_max_level(level);
}
