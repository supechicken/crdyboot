#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::ptr_as_ptr)]

extern crate alloc;

mod disk;
mod handover;
mod linux;
mod result;

use log::{info, LevelFilter};
use result::{Error, Result};
use uefi::prelude::*;
use vboot::LoadedKernel;

fn run_kernel(
    crdyboot_image: Handle,
    st: SystemTable<Boot>,
    kernel: &LoadedKernel,
) -> Result<()> {
    let load_options_utf8 =
        kernel.command_line().ok_or(Error::GetCommandLineFailed)?;
    info!("command line: {}", load_options_utf8);

    // Run the kernel.
    linux::execute_linux_kernel(
        kernel.data(),
        crdyboot_image,
        st,
        &load_options_utf8,
    )?;

    Ok(())
}

fn set_log_level() {
    #[cfg(feature = "verbose")]
    let level = LevelFilter::Debug;
    #[cfg(not(feature = "verbose"))]
    let level = LevelFilter::Warn;

    log::set_max_level(level);
}

/// Get the public key used to verify the kernel. By default the key is read
/// from `keys/kernel_key.vbpubk`. If the `use_test_key` feature is enabled
/// then the key is read from a test file in the repo instead.
fn get_kernel_verification_key() -> &'static [u8] {
    let key;

    #[cfg(feature = "use_test_key")]
    {
        log::warn!("using test key for kernel verification");
        key = include_bytes!("../../vboot/test_data/kernel_key.vbpubk");
    }

    #[cfg(not(feature = "use_test_key"))]
    {
        key = include_bytes!("../../keys/kernel_key.vbpubk");
    }

    key
}

fn run(crdyboot_image: Handle, mut st: SystemTable<Boot>) -> Result<()> {
    uefi_services::init(&mut st)
        .log_warning()
        .map_err(|err| Error::UefiServicesInitFailed(err.status()))?;

    set_log_level();

    let kernel_verification_key = get_kernel_verification_key();
    let mut gpt_disk = disk::GptDisk::new(crdyboot_image, st.boot_services())?;
    let kernel = vboot::load_kernel(kernel_verification_key, &mut gpt_disk)
        .map_err(Error::LoadKernelFailed)?;

    run_kernel(crdyboot_image, st, &kernel)?;

    Err(Error::KernelDidNotTakeControl)
}

#[entry]
fn efi_main(image: Handle, st: SystemTable<Boot>) -> Status {
    match run(image, st) {
        Ok(()) => unreachable!("kernel did not take control"),
        Err(err) => {
            panic!("boot failed: {}", err);
        }
    }
}

// See https://github.com/rhboot/shim/blob/main/SBAT.md for details of what
// this section is used for.
#[no_mangle]
#[link_section = ".sbat"]
static SBAT: [u8; 165] = *include_bytes!(concat!(env!("OUT_DIR"), "/sbat.csv"));
