// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::disk::{GptDisk, GptDiskError};
use crate::entry_point::{get_ia32_compat_entry_point, get_primary_entry_point};
use crate::launch::{LaunchError, NextStage};
use crate::nx::{self, NxError};
use crate::page_alloc::{PageAllocationError, ScopedPageAllocation};
use crate::revocation::RevocationError;
use crate::tpm::{extend_pcr_and_log, TpmError};
use crate::vbpubk::{get_vbpubk_from_image, VbpubkError};
use core::fmt::{self, Display, Formatter};
use log::info;
use object::read::pe::PeFile64;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::table::{Boot, SystemTable};
use uefi::CString16;
use vboot::{LoadKernelError, LoadKernelInputs, LoadedKernel};

pub enum Error {
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

    /// Failed to parse the kernel as a PE executable.
    InvalidPe(object::Error),

    /// The kernel does not have an entry point for booting from 32-bit
    /// firmware.
    MissingIa32CompatEntryPoint,

    /// Failed to update memory attributes.
    MemoryProtection(NxError),

    /// Failed to launch the kernel.
    Launch(LaunchError),

    /// Failed to measure the kernel into the TPM.
    Tpm(TpmError),
}

impl Display for Error {
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
            Self::MissingIa32CompatEntryPoint => {
                write!(f, "missing ia32 compatibility entry point")
            }
            Self::MemoryProtection(err) => write!(f, "failed to set up memory protection: {err}"),
            Self::Launch(err) => write!(f, "failed to launch next stage: {err}"),
            Self::Tpm(err) => write!(f, "TPM error: {err}"),
        }
    }
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
    kernel: &LoadedKernel,
    system_table: SystemTable<Boot>,
) -> Result<(), Error> {
    let cmdline = kernel.command_line().ok_or(Error::GetCommandLineFailed)?;
    info!("command line: {cmdline}");

    // Convert the command-line to UCS-2.
    let cmdline = CString16::try_from(cmdline.as_str())
        .map_err(|_| Error::CommandLineUcs2ConversionFailed)?;

    let pe = PeFile64::parse(kernel.data()).map_err(Error::InvalidPe)?;

    nx::update_mem_attrs(&pe, system_table.boot_services()).map_err(Error::MemoryProtection)?;

    let entry_point_offset = match Arch::get_current_exe_arch() {
        Arch::X86_64 => get_primary_entry_point(&pe),
        Arch::Ia32 => get_ia32_compat_entry_point(&pe).ok_or(Error::MissingIa32CompatEntryPoint)?,
    };

    let next_stage = NextStage {
        image_data: kernel.data(),
        load_options: cmdline.as_bytes(),
        entry_point_offset,
    };
    unsafe { next_stage.launch(system_table) }.map_err(Error::Launch)
}

/// Use vboot to load the kernel from the appropriate kernel partition,
/// then execute it. If successful, this function will never return.
pub fn load_and_execute_kernel(system_table: SystemTable<Boot>) -> Result<(), Error> {
    let mut workbuf = ScopedPageAllocation::new(
        // Safety: this system table clone will remain valid until
        // ExitBootServices is called. That won't happen until after the
        // kernel is executed, at which point crdyboot code is no longer
        // running.
        unsafe { system_table.unsafe_clone() },
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        LoadKernelInputs::RECOMMENDED_WORKBUF_SIZE,
    )
    .map_err(Error::Allocation)?;

    // Allocate a fairly large buffer. This buffer must be big enough to
    // hold the kernel data loaded by vboot. Allocating 64MiB should be
    // more than enough for the forseeable future.
    //
    // This buffer will never be freed, unless loading or executing the
    // kernel fails.
    let mut kernel_buffer = ScopedPageAllocation::new(
        // Safety: this system table clone will remain valid until
        // ExitBootServices is called. That won't happen until after the
        // kernel is executed, at which point crdyboot code is no longer
        // running.
        unsafe { system_table.unsafe_clone() },
        AllocateType::AnyPages,
        MemoryType::LOADER_CODE,
        // 64 MiB.
        64 * 1024 * 1024,
    )
    .map_err(Error::Allocation)?;

    let boot_services = system_table.boot_services();

    let kernel_verification_key = get_vbpubk_from_image(boot_services).map_err(Error::Vbpubk)?;
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
        &mut GptDisk::new(boot_services).map_err(Error::GptDisk)?,
    )
    .map_err(Error::LoadKernelFailed)?;

    // Go ahead and free the workbuf, not needed anymore.
    drop(workbuf);

    // Measure the kernel into the TPM.
    extend_pcr_and_log(system_table.boot_services(), kernel.data()).map_err(Error::Tpm)?;

    execute_linux_kernel(&kernel, system_table)
}
