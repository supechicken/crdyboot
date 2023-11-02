// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]
// TODO(nicholasbishop): temporarily allow some lints to make it easier
// to split up changes into separate CLs.
#![allow(dead_code)]
#![allow(clippy::needless_pass_by_value)]

extern crate alloc;

mod fs;
mod relocation;
mod sbat_revocation;

use core::fmt::{self, Display, Formatter};
use fs::FsError;
use libcrdy::arch::Arch;
use libcrdy::launch::LaunchError;
use libcrdy::nx::NxError;
use libcrdy::page_alloc::PageAllocationError;
use libcrdy::tpm::TpmError;
use libcrdy::{embed_section, set_log_level};
use log::{error, info};
use relocation::RelocationError;
use sbat_revocation::RevocationError;
use uefi::prelude::*;
use uefi::proto::media::file::Directory;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::tcg::PcrIndex;
use uefi::table::boot::ScopedProtocol;
use uefi::table::runtime::VariableVendor;
use uefi::table::{Boot, SystemTable};
use uefi::{cstr16, CStr16, CString16};

#[cfg(not(target_os = "uefi"))]
use libcrdy::uefi_services;

/// TPM PCR to measure into.
///
/// This is the same PCR shim uses.
///
/// See also the Linux TPM PCR Registry:
/// <https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/>
const PCR_INDEX: PcrIndex = PcrIndex(4);

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

/// Provides methods to read the next-stage bootloader's executable and
/// signature.
struct NextStageFileLoader<'a> {
    // This field is used to keep the file system protocol open.
    _file_system: ScopedProtocol<'a, SimpleFileSystem>,
    boot_dir: Directory,
    executable_name: CString16,
}

impl<'a> NextStageFileLoader<'a> {
    /// Create a new `NextStageFileLoader` for the given name and arch.
    fn new(
        boot_services: &'a BootServices,
        name: &CStr16,
        arch: Arch,
    ) -> Result<Self, CrdyshimError> {
        let mut executable_name = CString16::from(name);
        executable_name.push_str(match arch {
            Arch::Ia32 => cstr16!("ia32.efi"),
            Arch::X86_64 => cstr16!("x64.efi"),
        });

        let mut file_system =
            fs::open_boot_file_system(boot_services).map_err(CrdyshimError::BootFileSystemError)?;
        let boot_dir = fs::open_efi_boot_directory(&mut file_system)
            .map_err(CrdyshimError::BootFileSystemError)?;
        Ok(Self {
            _file_system: file_system,
            boot_dir,
            executable_name,
        })
    }

    /// Read the raw executable data into `buffer`.
    fn read_executable<'buf>(
        &mut self,
        buffer: &'buf mut [u8],
    ) -> Result<&'buf mut [u8], CrdyshimError> {
        fs::read_file(&mut self.boot_dir, &self.executable_name, buffer)
            .map_err(CrdyshimError::ExecutableReadFailed)
    }

    /// Read and return the raw signature data. Valid signature data has
    /// a fixed size of 64 bytes; an error will be returned if the file
    /// has the wrong length.
    fn read_signature(&mut self) -> Result<[u8; ed25519_compact::Signature::BYTES], CrdyshimError> {
        let mut signature_name = self.executable_name.clone();
        signature_name.push_str(cstr16!(".sig"));

        let mut signature = [0; ed25519_compact::Signature::BYTES];
        let read_size = fs::read_file(&mut self.boot_dir, &signature_name, &mut signature)
            .map_err(CrdyshimError::SignatureReadFailed)?
            .len();
        if read_size == signature.len() {
            Ok(signature)
        } else {
            error!("invalid signature file size: {}", read_size);
            Err(CrdyshimError::InvalidSignature)
        }
    }
}
/// The main application.
///
/// The following operations are performed:
/// 1. Get revocations, updating if necessary.
/// 2. Perform the self-revocation check.
/// 3. Load, verify, and execute the next stage.
///
/// This is separated out from `efi_main` so that it can return a
/// `Result` and propagate errors with `?`.
fn run(system_table: SystemTable<Boot>) -> Result<(), CrdyshimError> {
    let embedded_revocations = include_bytes!("../revocations.csv");
    let revocations = sbat_revocation::update_and_get_revocations(
        system_table.runtime_services(),
        embedded_revocations,
    )
    .map_err(CrdyshimError::RevocationDataError)?;

    // IMPORTANT: this self revocation check must happen as early in the
    // program as possible. If a security flaw is found that
    // necessitates a revocation of crdyshim, that revocation can only
    // occur via SBAT if the flaw is _after_ this point, so we want as
    // little code as possible prior to this point.
    sbat_revocation::validate_image(&SBAT, &revocations).map_err(CrdyshimError::SelfRevoked)?;

    // TODO(nicholasbishop): load, verify, and execute the next stage here.
    todo!()
}

#[entry]
fn efi_main(image: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).expect("failed to initialize uefi_services");
    set_log_level(system_table.boot_services());

    match run(system_table) {
        Ok(()) => unreachable!("next stage did not take control"),
        Err(err) => {
            panic!("boot failed: {err}");
        }
    }
}

// Add `.sbat` section to the binary.
//
// See https://github.com/rhboot/shim/blob/main/SBAT.md for details of what
// this section is used for.
embed_section!(SBAT, ".sbat", "../sbat.csv");
