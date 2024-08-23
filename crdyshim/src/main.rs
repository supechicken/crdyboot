// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]

extern crate alloc;

mod fs;
mod sbat_revocation;

use core::fmt::{self, Display, Formatter};
use fs::FsError;
use libcrdy::arch::{Arch, PeFileForCurrentArch};
use libcrdy::embed_section;
use libcrdy::entry_point::get_primary_entry_point;
use libcrdy::launch::{LaunchError, NextStage};
use libcrdy::nx::{self, NxError};
use libcrdy::page_alloc::{PageAllocationError, ScopedPageAllocation};
use libcrdy::relocation::{relocate_pe_into, RelocationError};
use libcrdy::set_log_level;
use libcrdy::tpm::extend_pcr_and_log;
use log::{error, info};
use sbat::RevocationSbat;
use sbat_revocation::RevocationError;
use uefi::prelude::*;
use uefi::proto::media::file::Directory;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::tcg::PcrIndex;
use uefi::table::boot::{AllocateType, BootServices, MemoryType, ScopedProtocol};
use uefi::table::runtime::VariableVendor;
use uefi::table::{Boot, SystemTable};
use uefi::{cstr16, CStr16, CString16};

/// TPM PCR to measure into.
///
/// This is the same PCR shim uses.
///
/// See also the Linux TPM PCR Registry:
/// <https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/>
const PCR_INDEX: PcrIndex = PcrIndex(4);

/// Amount of memory to allocate for both the raw executable and the
/// relocated version (each).
///
/// This value does not need to be particularly precise, other than
/// being a multiple of the UEFI page size.
///
/// Choose 2 MiB, which is a small enough amount of memory that we
/// don't need to worry about it, but still much larger than what our
/// next stage actually needs.
const NEXT_STAGE_ALLOCATION_SIZE_IN_BYTES: usize = 2 * 1024 * 1024;

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

    /// The signature file name was not successfully created.
    InvalidSignatureName,

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
            Self::InvalidSignatureName => {
                write!(f, "failed to create the signature file name")
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
        let signature_name = fs::replace_final_extension(&self.executable_name, cstr16!("sig"))
            .ok_or(CrdyshimError::InvalidSignatureName)?;

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

/// Get the Ed25519 public key used to verify the next stage.
///
/// This function is also where the raw public key data is
/// embedded. Which key data is embedded depends on the `use_dev_pubkey`
/// feature. If enabled, the key generated by xtask will be
/// embedded. Otherwise, the official reven public key will be embedded.
fn get_public_key() -> Result<ed25519_compact::PublicKey, CrdyshimError> {
    // If the `use_dev_pubkey` feature is enabled, use the dev key from
    // vboot_reference/tests/devkeys/uefi/crdyshim.pub.pem.
    #[cfg(feature = "use_dev_pubkey")]
    let public_key_raw = &[
        0xe0, 0x0c, 0xd0, 0x7d, 0xb6, 0xf6, 0xe4, 0x8f, 0x2e, 0xf8, 0x9b, 0x58, 0xb2, 0xc1, 0xa1,
        0x65, 0xb4, 0x0f, 0x37, 0x36, 0xba, 0x0f, 0xed, 0x78, 0x55, 0x0d, 0x33, 0x7d, 0xf2, 0x34,
        0x2d, 0x33,
    ];

    // If the `use_dev_pubkey` feature is disabled (the default), use
    // the official reven public key.
    #[cfg(not(feature = "use_dev_pubkey"))]
    let public_key_raw = &[
        0x21, 0x9e, 0x48, 0x62, 0xcb, 0xd, 0x1a, 0x49, 0x2f, 0x3c, 0x14, 0x7f, 0xd1, 0x86, 0xf8,
        0x2a, 0xec, 0x63, 0x7b, 0xab, 0xd4, 0xa3, 0x54, 0xb4, 0xa9, 0xb9, 0x25, 0xfa, 0xac, 0x90,
        0x43, 0x9b,
    ];

    // Parse the raw key data as an Ed25519 public key.
    ed25519_compact::PublicKey::from_slice(public_key_raw)
        .map_err(|_| CrdyshimError::InvalidPublicKey)
}

fn load_and_validate_next_stage<'a>(
    next_stage_name: &CStr16,
    system_table: &SystemTable<Boot>,
) -> Result<ScopedPageAllocation<'a>, CrdyshimError> {
    let is_secure_boot_enabled = is_secure_boot_enabled(system_table.runtime_services());
    info!("secure boot enabled? {}", is_secure_boot_enabled);

    // Allocate space for the raw next stage executable.
    let mut raw_exe_alloc = ScopedPageAllocation::new(
        // Safety: this system table clone will remain valid until
        // ExitBootServices is called. That won't happen until after the
        // next stage is executed, at which point this buffer will have
        // already been freed.
        unsafe { system_table.unsafe_clone() },
        AllocateType::AnyPages,
        // Use `LOADER_DATA` because this buffer will not be used
        // for code execution. The executable will be relocated in a
        // separate buffer.
        MemoryType::LOADER_DATA,
        NEXT_STAGE_ALLOCATION_SIZE_IN_BYTES,
    )
    .map_err(CrdyshimError::Allocation)?;

    // Read the next stage executable and signature.
    let mut loader = NextStageFileLoader::new(
        system_table.boot_services(),
        next_stage_name,
        Arch::get_current_exe_arch(),
    )?;
    let raw_exe = loader.read_executable(&mut raw_exe_alloc)?;
    let raw_signature = match loader.read_signature() {
        Ok(raw_signature) => raw_signature,
        Err(err) => {
            if is_secure_boot_enabled {
                // If secure boot is enabled, a missing signature file is a
                // fatal error.
                return Err(err);
            }

            // If secure boot is not enabled, signature verification is
            // allowed to fail, so allow the signature file to be
            // missing entirely. Initialize an arbitrary signature value
            // here.
            info!("secure boot is not enabled, allow missing signature file");
            [0xff; ed25519_compact::Signature::BYTES]
        }
    };

    let public_key = get_public_key()?;
    info!("embedded public key: {:02x?}", public_key.as_slice());

    // Verify the executable's signature.
    let signature = ed25519_compact::Signature::from_slice(raw_signature.as_slice())
        .map_err(|_| CrdyshimError::InvalidSignature)?;
    info!("next-stage signature: {:02x?}", signature.as_slice());
    let verified = public_key.verify(&raw_exe, &signature).is_ok();

    info!("signature verified? {}", verified);

    if !verified {
        if is_secure_boot_enabled {
            return Err(CrdyshimError::SignatureVerificationFailed);
        }

        info!("secure boot is not enabled, allowing failed verification");
    }

    // Measure the raw executable into the TPM.
    //
    // This measurement must be done on the raw data rather than the
    // relocated version. Relocations depend on where the image is
    // loaded in memory, so the measurement would essentially be random.
    //
    // We measure at this point because we still have access to
    // `raw_exe`. The full `raw_exe_alloc` has extra padding at the end
    // filled with zeroes, which would make the measurement less useful.
    extend_pcr_and_log(system_table.boot_services(), PCR_INDEX, raw_exe);

    Ok(raw_exe_alloc)
}

fn execute_relocated_next_stage(
    relocated_exe: &[u8],
    system_table: SystemTable<Boot>,
) -> Result<(), CrdyshimError> {
    let pe = PeFileForCurrentArch::parse(relocated_exe).map_err(CrdyshimError::InvalidPe)?;

    let entry_point_offset = get_primary_entry_point(&pe);

    nx::update_mem_attrs(&pe, system_table.boot_services())
        .map_err(CrdyshimError::MemoryProtection)?;

    let next_stage = NextStage {
        image_data: relocated_exe,
        load_options: &[],
        entry_point_offset,
    };
    unsafe { next_stage.launch(system_table) }.map_err(CrdyshimError::Launch)
}

/// Load, validate, and execute the next stage.
///
/// This loads the next stage executable from a hardcoded path. The
/// executable's signature is also loaded from a hardcoded path, and
/// used to verify that the executable data has been properly signed by
/// the expected key.
///
/// The validated raw executable is then relocated into a new buffer to
/// move sections to the correct offset and apply relocations from the
/// .reloc section.
///
/// The relocated executable is then launched, and control transfers to
/// that executable.
fn load_and_execute_next_stage(
    system_table: SystemTable<Boot>,
    revocations: &RevocationSbat,
) -> Result<(), CrdyshimError> {
    // Base file name of the next stage. The actual file name will have
    // an arch suffix and extension, e.g. "crdybootx64.efi".
    let next_stage_name = cstr16!("crdyboot");

    // Allocate space for the relocated next stage executable. This is
    // the allocation the next stage will actually run from, so it is
    // allocated as type `LOADER_CODE`.
    let mut relocated_exe_alloc = ScopedPageAllocation::new(
        // Safety: this system table clone will remain valid until
        // ExitBootServices is called. That won't happen until after
        // the kernel is executed, at which point the bootloader
        // code is no longer in use.
        unsafe { system_table.unsafe_clone() },
        AllocateType::AnyPages,
        MemoryType::LOADER_CODE,
        NEXT_STAGE_ALLOCATION_SIZE_IN_BYTES,
    )
    .map_err(CrdyshimError::Allocation)?;

    {
        let raw_exe_alloc = load_and_validate_next_stage(next_stage_name, &system_table)?;
        let pe = PeFileForCurrentArch::parse(&raw_exe_alloc).map_err(CrdyshimError::InvalidPe)?;
        sbat_revocation::validate_pe(&pe, revocations).map_err(CrdyshimError::NextStageRevoked)?;
        relocate_pe_into(&pe, &mut relocated_exe_alloc).map_err(CrdyshimError::Relocation)?;
    }

    execute_relocated_next_stage(&relocated_exe_alloc, system_table)
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

    load_and_execute_next_stage(system_table, &revocations)
}

#[entry]
fn efi_main(image: Handle, system_table: SystemTable<Boot>) -> Status {
    uefi::helpers::init().expect("failed to initialize uefi::helpers");
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
