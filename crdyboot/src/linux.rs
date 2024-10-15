// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::{GptDisk, GptDiskError};
use crate::revocation::RevocationError;
use crate::vbpubk::{get_vbpubk_from_image, VbpubkError};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::fmt::{self, Display, Formatter};
use libcrdy::arch::Arch;
use libcrdy::entry_point::{get_ia32_compat_entry_point, get_primary_entry_point};
use libcrdy::fs::{get_file_size, read_regular_file, FsError};
use libcrdy::launch::{LaunchError, NextStage};
use libcrdy::nx::{self, NxError};
use libcrdy::page_alloc::{PageAllocationError, ScopedPageAllocation};
use libcrdy::relocation::{relocate_pe_into, RelocationError};
use libcrdy::tpm::extend_pcr_and_log;
use libcrdy::uefi::UefiImpl;
use libcrdy::util::mib_to_bytes;
use log::info;
use object::read::pe::PeFile64;
use sha2::{Digest, Sha256};
use uefi::boot::{self, SearchType};
use uefi::data_types::Identify;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::tcg::PcrIndex;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::{cstr16, CStr16, CString16, Status};
use vboot::{LoadKernelError, LoadKernelInputs, LoadedKernel};

/// TPM PCR to measure into.
///
/// PCRs 0-7 are for the firmware. Other than that, the choice is
/// somewhat arbitrary. On a typical Linux setup PCR 8 is used by GRUB,
/// which crdyboot is an alternative to, so the uses are not
/// conflicting.
///
/// See also the Linux TPM PCR Registry:
/// <https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/>
const PCR_INDEX: PcrIndex = PcrIndex(8);

// Max size (32 MiB) for the flexor kernel image, for safety reasons.
const FLEXOR_KERNEL_MAX_SIZE: usize = 33_554_432;

// List of valid `flexor_vmlinuz` SHA256 hashes.
const VALID_FLEXOR_SHA256_HASHES: &[&str] = &[];

pub enum CrdybootError {
    /// Failed to allocate memory.
    Allocation(PageAllocationError),

    /// Self-revocation check failed.
    Revocation(RevocationError),

    /// The kernel partition is missing the command line data.
    GetCommandLineFailed,

    /// The command line contains characters that cannot be encoded as
    /// UCS-2.
    CommandLineUcs2ConversionFailed,

    /// Failed to get the current executable's vbpubk section.
    Vbpubk(VbpubkError),

    /// Failed to open the disk for reads and writes.
    GptDisk(GptDiskError),

    /// Vboot failed to find a valid kernel partition.
    LoadKernelFailed(LoadKernelError),

    /// Failed to relocate a PE executable.
    Relocation(RelocationError),

    /// Failed to parse the kernel as a PE executable.
    InvalidPe(object::Error),

    /// The kernel does not have an entry point for booting from 32-bit
    /// firmware.
    MissingIa32CompatEntryPoint,

    /// Failed to update memory attributes.
    MemoryProtection(NxError),

    /// Failed to launch the kernel.
    Launch(LaunchError),

    /// Failed to get file handles for a protocol.
    GetFileSystemHandlesFailed(Status),

    /// Failed to open the `SimpleFileSystem` protocol.
    OpenSimpleFileSystemProtocolFailed(Status),

    /// Failed to open a Volume.
    OpenVolumeFailed(Status),

    /// Failed to convert to a regular file.
    RegularFileConversionFailed,

    /// Failed to get the size of a file.
    GetFileSizeFailed(FsError),

    /// Flexor kernel image size is too big.
    FlexorKernelSizeTooBig(usize),

    /// Failed to read file.
    ReadFileFailed(FsError),

    /// Failed to load the flexor kernel.
    LoadFlexorKernelFailed,

    /// Flexor kernel hash is not present in the list of valid hashes.
    FlexorKernelNotInAllowList,
}

impl Display for CrdybootError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation(err) => write!(f, "failed to allocate memory: {err}"),
            Self::Revocation(err) => write!(f, "self-revocation check failed: {err}"),
            Self::GetCommandLineFailed => write!(f, "failed to get kernel command line"),
            Self::CommandLineUcs2ConversionFailed => {
                write!(f, "failed to convert kernel command line to UCS-2")
            }
            Self::Vbpubk(err) => write!(f, "failed to get packed public key: {err}"),
            Self::GptDisk(err) => write!(f, "failed to open GPT disk: {err}"),
            Self::LoadKernelFailed(err) => write!(f, "failed to load kernel: {err}"),
            Self::InvalidPe(err) => write!(f, "invalid PE: {err}"),
            Self::Relocation(err) => {
                write!(f, "failed to relocate the kernel: {err}")
            }
            Self::MissingIa32CompatEntryPoint => {
                write!(f, "missing ia32 compatibility entry point")
            }
            Self::MemoryProtection(err) => write!(f, "failed to set up memory protection: {err}"),
            Self::Launch(err) => write!(f, "failed to launch next stage: {err}"),
            Self::GetFileSystemHandlesFailed(status) => {
                write!(f, "failed to get handles for the protocol: {status}")
            }
            Self::OpenSimpleFileSystemProtocolFailed(status) => {
                write!(f, "failed to open protocol: {status}")
            }
            Self::OpenVolumeFailed(status) => write!(f, "failed to open volume: {status}"),
            Self::RegularFileConversionFailed => write!(f, "failed to convert to a regular file"),
            Self::GetFileSizeFailed(err) => write!(f, "failed to get the file size: {err}"),
            Self::FlexorKernelSizeTooBig(file_size) => {
                write!(f, "flexor kernel image size is too big: {file_size}")
            }
            Self::ReadFileFailed(err) => write!(f, "Failed to read file: {err}"),
            Self::LoadFlexorKernelFailed => write!(f, "Failed to load the flexor kernel"),
            Self::FlexorKernelNotInAllowList => write!(
                f,
                "flexor kernel hash is not present in the list of valid hashes"
            ),
        }
    }
}

/// Get the kernel command line as a UCS-2 string.
fn get_kernel_command_line(kernel: &LoadedKernel) -> Result<CString16, CrdybootError> {
    let cmdline = kernel
        .command_line()
        .ok_or(CrdybootError::GetCommandLineFailed)?;
    info!("command line: {cmdline}");

    // Convert the command-line to UCS-2.
    CString16::try_from(cmdline.as_str())
        .map_err(|_| CrdybootError::CommandLineUcs2ConversionFailed)
}

/// Hand off control to the Linux EFI stub.
///
/// As mentioned in [1], the preferred method for loading the kernel
/// on UEFI is to build in the EFI stub and run it as a normal PE/COFF
/// executable. This is indeed much simpler than trying to use the EFI
/// handover protocol, which is not fully documented. The kernel's PE
/// header does not require any relocations to be performed, so the
/// only thing we need to get from the header is the entry point.
///
/// Note that we can't use LoadImage+StartImage for this, because with
/// secure boot enabled it would try to verify the signature of the
/// kernel which would fail unless we signed the kernel in the way
/// UEFI expects. Since we have already verified the kernel via the
/// vboot structures (as well as the command line parameters), this
/// would be an unnecessary verification.
///
/// [1]: kernel.org/doc/html/latest/x86/boot.html#efi-handover-protocol-deprecated
fn execute_linux_kernel(kernel_data: &[u8], cmdline: &CStr16) -> Result<(), CrdybootError> {
    let pe = PeFile64::parse(kernel_data).map_err(CrdybootError::InvalidPe)?;

    nx::update_mem_attrs(&pe).map_err(CrdybootError::MemoryProtection)?;

    let entry_point_offset = match Arch::get_current_exe_arch() {
        Arch::X86_64 => get_primary_entry_point(&pe),
        Arch::Ia32 => {
            get_ia32_compat_entry_point(&pe).ok_or(CrdybootError::MissingIa32CompatEntryPoint)?
        }
    };

    let next_stage = NextStage {
        image_data: kernel_data,
        load_options: cmdline.as_bytes(),
        entry_point_offset,
    };
    unsafe { next_stage.launch() }.map_err(CrdybootError::Launch)
}

/// Use vboot to load the kernel from the appropriate kernel partition,
/// then execute it. If successful, this function will never return.
pub fn load_and_execute_kernel() -> Result<(), CrdybootError> {
    let mut workbuf = ScopedPageAllocation::new(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        LoadKernelInputs::RECOMMENDED_WORKBUF_SIZE,
    )
    .map_err(CrdybootError::Allocation)?;

    // Allocate a fairly large buffer. This buffer must be big enough to
    // hold the kernel data loaded by vboot. Allocating 64MiB should be
    // more than enough for the forseeable future.
    let mut kernel_buffer = ScopedPageAllocation::new(
        AllocateType::AnyPages,
        // Use `LOADER_DATA` because this buffer will not be used
        // for code execution. The executable will be relocated in a
        // separate buffer.
        MemoryType::LOADER_DATA,
        mib_to_bytes(64),
    )
    .map_err(CrdybootError::Allocation)?;

    let kernel_verification_key = get_vbpubk_from_image().map_err(CrdybootError::Vbpubk)?;
    info!(
        "kernel_verification_key len={}",
        kernel_verification_key.len()
    );

    let kernel = vboot::load_kernel(
        LoadKernelInputs {
            workbuf: &mut workbuf,
            kernel_buffer: &mut kernel_buffer,
            packed_pubkey: kernel_verification_key,
        },
        &mut GptDisk::new(&UefiImpl).map_err(CrdybootError::GptDisk)?,
    )
    .map_err(CrdybootError::LoadKernelFailed)?;

    // Go ahead and free the workbuf, not needed anymore.
    drop(workbuf);

    // Measure the kernel into the TPM.
    extend_pcr_and_log(PCR_INDEX, kernel.data());

    let cmdline = get_kernel_command_line(&kernel)?;

    // Relocate the kernel into an allocated buffer.
    // This buffer will never be freed, unless loading or executing the
    // kernel fails.
    //
    // As of R130 the required size is about 17.9MiB. Developer
    // kernels with different config options may be slightly larger,
    // so add some extra space, bringing the total to 24 MiB.
    let kernel_reloc_buffer = relocate_kernel(kernel.data(), mib_to_bytes(24))?;

    // Drop the original kernel buffer, not needed anymore.
    drop(kernel_buffer);

    if cfg!(feature = "flexor") {
        // Temporarily calling load_flexor_kernel here,
        // it will be properly implemented in b/361836044.
        let _ = load_flexor_kernel();
    }

    execute_linux_kernel(&kernel_reloc_buffer, &cmdline)
}

fn relocate_kernel(data: &[u8], reloc_size: usize) -> Result<ScopedPageAllocation, CrdybootError> {
    // Allocate a buffer to relocate the kernel into.
    let mut kernel_reloc_buffer =
        ScopedPageAllocation::new(AllocateType::AnyPages, MemoryType::LOADER_CODE, reloc_size)
            .map_err(CrdybootError::Allocation)?;

    // Relocate the kernel into the new buffer. Even though the kernel
    // doesn't have a `.reloc` section, it still needs to be relocated
    // to ensure that sections are properly aligned and unused data is
    // zeroed. In particular, the `.data` section has a larger virtual
    // size than the file size, and that data must be zeroed per the PE
    // spec. The kernel uses that space for the BSS section during
    // decompression, and depending on the kernel version, it may or may
    // not clear the BSS itself. This has been observed to cause boot
    // failures on 32-bit UEFI.
    //
    // See this discussion thread:
    // https://lore.kernel.org/linux-efi/CAAzv750HTnposziTOPDjnUQM0K2JVrE3-1HCxiPkp+QtWi=jEw@mail.gmail.com/T/#u
    let pe = PeFile64::parse(data).map_err(CrdybootError::InvalidPe)?;
    relocate_pe_into(&pe, &mut kernel_reloc_buffer).map_err(CrdybootError::Relocation)?;
    Ok(kernel_reloc_buffer)
}

/// Load the flexor kernel.
///
/// Iterate over all the file system handles that support the simple file system
/// protocol, look for a `flexor_vmlinuz` file, validate and return its raw data.
/// An error is returned if:
///  * File system could not be opened or accessed.
///  * `flexor_vmlinuz` file is not found.
///  * Any error occurs when reading the file data.
///  * A valid flexor kernel image is not found.
fn load_flexor_kernel() -> Result<Vec<u8>, CrdybootError> {
    const FILE_NAME: &CStr16 = cstr16!("flexor_vmlinuz");
    let handles_buffer =
        boot::locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID))
            .map_err(|err| CrdybootError::GetFileSystemHandlesFailed(err.status()))?;

    // Iterate over all the file system handles.
    for handle in &*handles_buffer {
        // Open SimpleFileSystemProtocol for each handle.
        let mut scoped_proto = boot::open_protocol_exclusive::<SimpleFileSystem>(*handle)
            .map_err(|err| CrdybootError::OpenSimpleFileSystemProtocolFailed(err.status()))?;

        let mut root = scoped_proto
            .open_volume()
            .map_err(|err| CrdybootError::OpenVolumeFailed(err.status()))?;

        // Read from the filesystem to check if it contains flexor_vmlinuz.
        let Ok(file_handle) = root.open(FILE_NAME, FileMode::Read, FileAttribute::empty()) else {
            // Continue and look in the next handle if the file is not found.
            continue;
        };

        let mut file = file_handle
            .into_regular_file()
            .ok_or(CrdybootError::RegularFileConversionFailed)?;
        let file_size = get_file_size(&mut file).map_err(CrdybootError::GetFileSizeFailed)?;
        // Check to make sure the flexor kernel image size is not too big.
        if file_size > FLEXOR_KERNEL_MAX_SIZE {
            return Err(CrdybootError::FlexorKernelSizeTooBig(file_size));
        }
        let mut buffer: Vec<u8> = vec![0; file_size];

        // Read file contents into a buffer.
        read_regular_file(&mut file, file_size, &mut buffer)
            .map_err(CrdybootError::ReadFileFailed)?;

        // Continue looking for other valid flexor images.
        if validate_flexor_kernel(&buffer, VALID_FLEXOR_SHA256_HASHES).is_err() {
            info!("flexor kernel validation failed.");
            continue;
        }

        return Ok(buffer);
    }
    Err(CrdybootError::LoadFlexorKernelFailed)
}

/// Validate flexor kernel image against a list of valid hashes.
///
/// An error is returned if:
///  * Hash of the flexor image is not present in the list of valid hashes.
fn validate_flexor_kernel(buffer: &[u8], valid_hashes: &[&str]) -> Result<(), CrdybootError> {
    // Get SHA256 hash of the input buffer.
    let hash = format!("{:x}", Sha256::digest(buffer));

    if valid_hashes.contains(&hash.as_str()) {
        Ok(())
    } else {
        Err(CrdybootError::FlexorKernelNotInAllowList)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA: &[u8] = &[1, 2, 3];
    const FLEXOR_SHA256_TEST_HASHES: &[&str] = &[
        // SHA256 hash for `TEST_DATA`
        "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
    ];

    /// Test that validate_flexor_kernel fails with an invalid kernel image.
    #[test]
    fn test_validate_flexor_kernel_error() {
        assert!(matches!(
            validate_flexor_kernel(&[0, 0], FLEXOR_SHA256_TEST_HASHES),
            Err(CrdybootError::FlexorKernelNotInAllowList)
        ));
    }

    /// Test that validate_flexor_kernel succeeds with an valid kernel image.
    #[test]
    fn test_validate_flexor_kernel_success() {
        assert!(validate_flexor_kernel(TEST_DATA, FLEXOR_SHA256_TEST_HASHES).is_ok());
    }
}
