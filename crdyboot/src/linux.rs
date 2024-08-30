// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::{GptDisk, GptDiskError};
use crate::revocation::RevocationError;
use crate::vbpubk::{get_vbpubk_from_image, VbpubkError};
use core::fmt::{self, Display, Formatter};
use libcrdy::arch::Arch;
use libcrdy::entry_point::{get_ia32_compat_entry_point, get_primary_entry_point};
use libcrdy::launch::{LaunchError, NextStage};
use libcrdy::nx::{self, NxError};
use libcrdy::page_alloc::{PageAllocationError, ScopedPageAllocation};
use libcrdy::relocation::{relocate_pe_into, RelocationError};
use libcrdy::tpm::extend_pcr_and_log;
use log::info;
use object::read::pe::PeFile64;
use uefi::proto::tcg::PcrIndex;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::table::{Boot, SystemTable};
use uefi::{CStr16, CString16};
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
fn execute_linux_kernel(
    kernel_data: &[u8],
    cmdline: &CStr16,
    system_table: &SystemTable<Boot>,
) -> Result<(), CrdybootError> {
    let pe = PeFile64::parse(kernel_data).map_err(CrdybootError::InvalidPe)?;

    nx::update_mem_attrs(&pe, system_table.boot_services())
        .map_err(CrdybootError::MemoryProtection)?;

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
pub fn load_and_execute_kernel(system_table: &SystemTable<Boot>) -> Result<(), CrdybootError> {
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
        MemoryType::LOADER_CODE,
        // 64 MiB.
        64 * 1024 * 1024,
    )
    .map_err(CrdybootError::Allocation)?;

    let boot_services = system_table.boot_services();

    let kernel_verification_key =
        get_vbpubk_from_image(boot_services).map_err(CrdybootError::Vbpubk)?;
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
        &mut GptDisk::new().map_err(CrdybootError::GptDisk)?,
    )
    .map_err(CrdybootError::LoadKernelFailed)?;

    // Go ahead and free the workbuf, not needed anymore.
    drop(workbuf);

    // Measure the kernel into the TPM.
    extend_pcr_and_log(system_table.boot_services(), PCR_INDEX, kernel.data());

    let cmdline = get_kernel_command_line(&kernel)?;

    // Allocate a buffer to relocate the kernel into. As of R127 the
    // minimum size is about 17MiB, so allocate 20MiB to provide some
    // headroom.
    //
    // This buffer will never be freed, unless loading or executing the
    // kernel fails.
    let mut kernel_reloc_buffer = ScopedPageAllocation::new(
        AllocateType::AnyPages,
        MemoryType::LOADER_CODE,
        // 20 MiB.
        20 * 1024 * 1024,
    )
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
    {
        let pe = PeFile64::parse(kernel.data()).map_err(CrdybootError::InvalidPe)?;
        relocate_pe_into(&pe, &mut kernel_reloc_buffer).map_err(CrdybootError::Relocation)?;
    }

    // Drop the original kernel buffer, not needed anymore.
    drop(kernel_buffer);

    execute_linux_kernel(&kernel_reloc_buffer, &cmdline, system_table)
}
