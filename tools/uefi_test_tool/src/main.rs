// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]

extern crate alloc;

mod launch;
mod operation;
mod tpm_v1;

use core::mem;
use core::sync::atomic::{AtomicU32, Ordering};
use libcrdy::logging::initialize_logging_with_level;
use log::{info, LevelFilter};
use operation::Operation;
use uefi::boot;
use uefi::{cstr16, entry, fs, Status};

static OPERATION: AtomicU32 = AtomicU32::new(Operation::Unset as u32);

impl Operation {
    /// Read the operation from a file on the ESP.
    ///
    /// Panics if the file can't be read, or if the contents are
    /// invalid.
    ///
    /// The operation is stored in the global `OPERATION`.
    fn init() {
        let sfs = boot::get_image_file_system(boot::image_handle())
            .expect("failed to open SimpleFileSystem");
        let mut fs = fs::FileSystem::new(sfs);

        let content = fs
            .read_to_string(cstr16!(r"\efi\boot\crdy_test_control"))
            .expect("failed to read control file");
        let content = content.trim();

        let op: Operation = match content.parse() {
            Ok(op) => op,
            Err(_) => panic!("invalid control file: {content}"),
        };

        info!("operation: {op}");

        OPERATION.store(op as u32, Ordering::Release);
    }

    /// Load the operation from the global `OPERATION`.
    fn get() -> Self {
        let op: u32 = OPERATION.load(Ordering::Acquire);
        // SAFETY: `Operation` is a `u32`, so the underlying
        // representation matches. The value of `OPERATION` is only
        // written by `Operation::init`, which always writes a valid
        // variant of `Operation`.
        unsafe { mem::transmute(op) }
    }
}

#[entry]
fn efi_main() -> Status {
    initialize_logging_with_level(LevelFilter::Debug);

    Operation::init();
    match Operation::get() {
        Operation::Unset => unreachable!(),
        Operation::Tpm1Deactivated | Operation::Tpm1ExtendFail => tpm_v1::create_tpm1(),
    }

    launch::launch_crdyshim();

    Status::SUCCESS
}
