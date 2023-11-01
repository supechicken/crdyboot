// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]
// TODO(nicholasbishop): temporarily allow dead_code to make it easier
// to split up changes into separate CLs.
#![allow(dead_code)]

extern crate alloc;

mod fs;
mod relocation;
mod sbat_revocation;

use core::fmt::{self, Display, Formatter};
use fs::FsError;
use libcrdy::embed_section;
use libcrdy::launch::LaunchError;
use libcrdy::nx::NxError;
use libcrdy::page_alloc::PageAllocationError;
use libcrdy::tpm::TpmError;
use log::info;
use relocation::RelocationError;
use sbat_revocation::RevocationError;
use uefi::cstr16;
use uefi::prelude::*;
use uefi::table::runtime::VariableVendor;
use uefi::table::{Boot, SystemTable};

#[cfg(not(target_os = "uefi"))]
use libcrdy::uefi_services;

pub enum CrdyshimError {
    /// Failed to get the revocation data.
    RevocationDataError(RevocationError),

    /// The current executable is revoked.
    SelfRevoked(RevocationError),

    /// The next stage is revoked.
    NextStageRevoked(RevocationError),

    /// Failed to allocate memory.
    Allocation(PageAllocationError),

    /// Failed to open the boot file system.
    BootFileSystemError(FsError),

    /// Failed to read the next stage executable file.
    ExecutableReadFailed(FsError),

    /// Failed to read the signature file.
    SignatureReadFailed(FsError),

    /// The embedded public key is not valid.
    InvalidPublicKey,

    /// The contents of the next stage signature file are not valid.
    InvalidSignature,

    /// The next stage did not pass signature validation.
    SignatureVerificationFailed,

    /// Failed to relocate a PE executable.
    Relocation(RelocationError),

    /// Failed to parse a PE executable.
    InvalidPe(object::Error),

    /// Failed to measure the next stage into the TPM.
    Tpm(TpmError),

    /// Failed to update memory attributes.
    MemoryProtection(NxError),

    /// Failed to launch the next stage.
    Launch(LaunchError),
}

impl Display for CrdyshimError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RevocationDataError(err) => write!(f, "revocation data error: {err}"),
            Self::SelfRevoked(err) => write!(f, "current image is revoked: {err}"),
            Self::NextStageRevoked(err) => write!(f, "next stage is revoked: {err}"),
            Self::Allocation(err) => write!(f, "failed to allocate memory: {err}"),
            Self::BootFileSystemError(err) => {
                write!(f, "failed to open the boot file system: {err}")
            }
            Self::ExecutableReadFailed(err) => {
                write!(f, "failed to read the next stage executable: {err}")
            }
            Self::SignatureReadFailed(err) => {
                write!(f, "failed to read the next stage signature: {err}")
            }
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSignature => write!(f, "invalid signature file"),
            Self::SignatureVerificationFailed => write!(f, "signature verification failed"),
            Self::Relocation(err) => {
                write!(f, "failed to relocate the next stage executable: {err}")
            }
            Self::InvalidPe(err) => write!(f, "invalid PE: {err}"),
            Self::Tpm(error) => write!(f, "TPM error: {error}"),
            Self::MemoryProtection(error) => {
                write!(f, "failed to set up memory protection: {error}")
            }
            Self::Launch(error) => write!(f, "failed to launch next stage: {error}"),
        }
    }
}

#[allow(clippy::doc_markdown)]
/// Check whether secure boot is enabled or not.
///
/// The firmware communicates secure boot status with a global
/// "SecureBoot" UEFI variable containing a `u8` value. If the value is
/// 0, secure boot is disabled. If the value is 1, secure boot is
/// enabled.
///
/// If the variable cannot be read, or if the value is anything other
/// than 0 or 1, log an error and treat it as secure boot being
/// disabled.
fn is_secure_boot_enabled(runtime_services: &RuntimeServices) -> bool {
    let mut buf: [u8; 1] = [0];
    match runtime_services.get_variable(
        cstr16!("SecureBoot"),
        &VariableVendor::GLOBAL_VARIABLE,
        &mut buf,
    ) {
        Ok(([0], _)) => false,
        Ok(([1], _)) => true,
        Ok((val, _)) => {
            // Only the values 0 and 1 are valid per the spec. If the
            // variable contains some other number, treat it as secure
            // boot being disabled.
            info!("unexpected SecureBoot value: {val:x?}");
            false
        }
        Err(err) => {
            // If the variable cannot be read, treat it as secure boot
            // being disabled.
            info!("failed to read SecureBoot variable: {}", err.status());
            false
        }
    }
}

#[entry]
fn efi_main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("failed to initialize uefi_services");

    todo!()
}

// Add `.sbat` section to the binary.
//
// See https://github.com/rhboot/shim/blob/main/SBAT.md for details of what
// this section is used for.
embed_section!(SBAT, ".sbat", "../sbat.csv");
