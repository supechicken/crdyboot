// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "android")]
use crate::avb::{do_avb_verify, AvbError};
use crate::disk::{GptDisk, GptDiskError};
#[cfg(feature = "android")]
use crate::initramfs::set_up_loadfile_protocol;
use crate::revocation::RevocationError;
use crate::vbpubk::{get_vbpubk_from_image, VbpubkError};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use libcrdy::arch::Arch;
use libcrdy::entry_point::{get_ia32_compat_entry_point, get_primary_entry_point};
use libcrdy::fs::{FileLoader, FileLoaderImpl};
use libcrdy::launch::{LaunchError, NextStage};
use libcrdy::logging::does_verbose_file_exist;
use libcrdy::nx::{self, NxError};
use libcrdy::page_alloc::{PageAllocationError, ScopedPageAllocation};
use libcrdy::relocation::{relocate_pe_into, RelocationError};
use libcrdy::tpm::extend_pcr_and_log;
use libcrdy::uefi::{Uefi, UefiImpl};
use libcrdy::util::mib_to_bytes;
use log::info;
use object::read::pe::PeFile64;
use sha2::{Digest, Sha256};
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::tcg::PcrIndex;
use uefi::{cstr16, CStr16, CString16, Handle, Status};
use vboot::LoadKernelInputs;

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

/// Maximum size in bytes for the flexor kernel image. If the file is
/// larger than this limit it will not be loaded.
const FLEXOR_KERNEL_MAX_SIZE: usize = mib_to_bytes(32);

/// List of valid `flexor_vmlinuz` SHA256 hashes.
const VALID_FLEXOR_SHA256_HASHES: &[&str] = &[
    // M126: gs://chromeos-releases/dev-channel/reven/15940.0.0/\
    // flexor_15940.0.0_reven_dev-channel.bin
    "2e7f43d5cd03a3dd9c23d9adca64095b8b5e7dc088d2f9b222f07a0291e9d4aa",
    // M134: gs://chromeos-releases/dev-channel/reven/16180.0.0/
    // flexor_16180.0.0_reven_dev-channel.bin
    "5950b2c31f2853e4687a286ea8b4579fa09737caa9d71d098e931bed812e926c",
];

/// Size (in bytes) of the buffer into which vboot loads the kernel
/// data. 64MiB is the current size of the kernel partitions on reven.
const VBOOT_KERNEL_ALLOC_SIZE: usize = mib_to_bytes(64);

#[derive(Debug, thiserror::Error)]
pub enum CrdybootError {
    /// Failed to allocate memory.
    #[error("failed to allocate memory")]
    Allocation(#[source] PageAllocationError),

    /// Self-revocation check failed.
    #[error("self-revocation check failed")]
    Revocation(#[source] RevocationError),

    /// The kernel partition is missing the command line data.
    #[error("failed to get kernel command line")]
    GetCommandLineFailed,

    /// The command line contains characters that cannot be encoded as
    /// UCS-2.
    #[error("failed to convert kernel command line to UCS-2")]
    CommandLineUcs2ConversionFailed,

    /// Failed to get the current executable's vbpubk section.
    #[error("failed to get packed public key")]
    Vbpubk(#[source] VbpubkError),

    /// Failed to open the disk for reads and writes.
    #[error("failed to open GPT disk")]
    GptDisk(#[source] GptDiskError),

    /// Failed to relocate a PE executable.
    #[error("failed to relocate the kernel")]
    Relocation(#[source] RelocationError),

    /// Failed to parse the kernel as a PE executable.
    #[error("invalid PE: {0}")]
    InvalidPe(object::Error),

    /// The kernel does not have an entry point for booting from 32-bit
    /// firmware.
    #[error("missing ia32 compatibility entry point")]
    MissingIa32CompatEntryPoint,

    /// Failed to update memory attributes.
    #[error("failed to set up memory protection")]
    MemoryProtection(#[source] NxError),

    /// Failed to launch the kernel.
    #[error("failed to launch next stage")]
    Launch(#[source] LaunchError),

    /// Failed to get file handles for a protocol.
    #[error("failed to get handles for the protocol: {0}")]
    GetFileSystemHandlesFailed(Status),

    /// Failed to open the `SimpleFileSystem` protocol.
    #[error("failed to open protocol: {0}")]
    OpenSimpleFileSystemProtocolFailed(Status),

    /// Failed to load the flexor kernel.
    #[error("failed to load the flexor kernel")]
    LoadFlexorKernelFailed,

    /// Flexor kernel hash is not present in the list of valid hashes.
    #[error("flexor kernel hash is not present in the list of valid hashes")]
    FlexorKernelNotInAllowList,

    /// Failed loading the android image.
    #[cfg(feature = "android")]
    #[error("failed to load the android image")]
    AndroidLoadFailure(#[source] AvbError),
}

/// Represents the high-level flow of loading, verifying, and launching
/// the kernel.
///
/// This is implemented as a trait to allow for mocking.
#[cfg_attr(test, mockall::automock)]
// Named lifetimes are required by automock.
#[allow(clippy::needless_lifetimes)]
trait RunKernel {
    fn allocate_pages(
        &self,
        memory_type: MemoryType,
        num_bytes: usize,
    ) -> Result<ScopedPageAllocation, PageAllocationError>;

    fn get_vbpubk_from_image(&self) -> Result<&'static [u8], VbpubkError>;

    fn extend_pcr_and_log(&self, data: &[u8]);

    fn update_mem_attrs<'a>(&self, pe: &PeFile64<'a>) -> Result<(), NxError>;

    unsafe fn launch_next_stage<'a>(&self, next_stage: NextStage<'a>) -> Result<(), LaunchError>;

    fn verbose_logging(&self) -> bool;

    fn get_valid_flexor_sha256_hashes(&self) -> &'static [&'static str];

    fn open_file_loader(&self, handle: Handle) -> Result<Box<dyn FileLoader>, CrdybootError>;
}

/// The real implementation of the `RunKernel` trait used at runtime.
struct RunKernelImpl;

impl RunKernel for RunKernelImpl {
    fn allocate_pages(
        &self,
        memory_type: MemoryType,
        num_bytes: usize,
    ) -> Result<ScopedPageAllocation, PageAllocationError> {
        ScopedPageAllocation::new(AllocateType::AnyPages, memory_type, num_bytes)
    }

    fn get_vbpubk_from_image(&self) -> Result<&'static [u8], VbpubkError> {
        get_vbpubk_from_image()
    }

    fn extend_pcr_and_log(&self, data: &[u8]) {
        extend_pcr_and_log(PCR_INDEX, data);
    }

    fn update_mem_attrs(&self, pe: &PeFile64) -> Result<(), NxError> {
        nx::update_mem_attrs(pe)
    }

    unsafe fn launch_next_stage(&self, next_stage: NextStage) -> Result<(), LaunchError> {
        unsafe { next_stage.launch() }
    }

    fn verbose_logging(&self) -> bool {
        does_verbose_file_exist()
    }

    fn get_valid_flexor_sha256_hashes(&self) -> &'static [&'static str] {
        VALID_FLEXOR_SHA256_HASHES
    }

    fn open_file_loader(&self, handle: Handle) -> Result<Box<dyn FileLoader>, CrdybootError> {
        let sfs = boot::open_protocol_exclusive::<SimpleFileSystem>(handle)
            .map_err(|err| CrdybootError::OpenSimpleFileSystemProtocolFailed(err.status()))?;

        Ok(Box::new(FileLoaderImpl::new(sfs)))
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
    rk: &dyn RunKernel,
    kernel_data: &[u8],
    cmdline: &CStr16,
) -> Result<(), CrdybootError> {
    let pe = PeFile64::parse(kernel_data).map_err(CrdybootError::InvalidPe)?;

    rk.update_mem_attrs(&pe)
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
    unsafe { rk.launch_next_stage(next_stage) }.map_err(CrdybootError::Launch)
}

#[cfg(feature = "android")]
fn avb_load_kernel(rk: &dyn RunKernel) -> Result<(), CrdybootError> {
    let buffers = do_avb_verify().map_err(CrdybootError::AndroidLoadFailure)?;

    // Measure the kernel into the TPM.
    // Measure only the used space avoiding the extra 0 padding.
    extend_pcr_and_log(PCR_INDEX, &buffers.kernel_buffer);

    // TODO: it is known what the size of the kernel is from avb_load, it
    // can be used instead.
    let relocate_size = mib_to_bytes(24);
    let kernel_reloc_buffer = relocate_kernel(&buffers.kernel_buffer, relocate_size)?;

    // Initialize the linux uefi initramfs loader protocol
    // when an initramfs is present.
    // This must stay in scope until after the kernel is loaded.
    let _lf2 = set_up_loadfile_protocol(buffers.initramfs_buffer);

    execute_linux_kernel(rk, &kernel_reloc_buffer, &buffers.cmdline)
}

fn get_flexor_cmdline(verbose: bool) -> String {
    let base = "earlycon=efifb keep_bootcon earlyprintk=vga,keep \
     console=tty1 init=/sbin/init \
     cros_efi drm.trace=0x106 root=/dev/dm-0 rootwait ro \
     dm_verity.error_behavior=3 dm_verity.max_bios=-1 \
     dm_verity.dev_wait=1 noinitrd panic=60 vt.global_cursor_default=0 \
     kern_guid=%U add_efi_memmap noresume i915.modeset=1 vga=0x31e \
     kvm-intel.vmentry_l1d_flush=always";

    let loglevel = if verbose { 7 } else { 1 };

    // When verbose logging is enabled, turn off ratelimiting for kmsg:
    // https://docs.kernel.org/admin-guide/sysctl/kernel.html#printk-devkmsg
    let devkmsg = if verbose { "on" } else { "ratelimit" };

    format!("{base} loglevel={loglevel} printk.devkmsg={devkmsg}")
}

/// Use vboot to load the kernel from the appropriate kernel partition,
/// then execute it. If successful, this function will never return.
fn vboot_load_kernel(rk: &dyn RunKernel, uefi: &dyn Uefi) -> Result<(), CrdybootError> {
    let mut workbuf = rk
        .allocate_pages(
            MemoryType::LOADER_DATA,
            LoadKernelInputs::RECOMMENDED_WORKBUF_SIZE,
        )
        .map_err(CrdybootError::Allocation)?;

    // Allocate a fairly large buffer. This buffer must be big enough to
    // hold the kernel data loaded by vboot.
    let mut kernel_buffer = rk
        .allocate_pages(
            // Use `LOADER_DATA` because this buffer will not be used
            // for code execution. The executable will be relocated in a
            // separate buffer.
            MemoryType::LOADER_DATA,
            VBOOT_KERNEL_ALLOC_SIZE,
        )
        .map_err(CrdybootError::Allocation)?;

    let kernel_verification_key = rk.get_vbpubk_from_image().map_err(CrdybootError::Vbpubk)?;
    info!(
        "kernel_verification_key len={}",
        kernel_verification_key.len()
    );

    let vboot_kernel;
    let flexor_kernel;
    let kernel_data: &[u8];
    let kernel_cmdline: String;

    match vboot::load_kernel(
        LoadKernelInputs {
            workbuf: &mut workbuf,
            kernel_buffer: &mut kernel_buffer,
            packed_pubkey: kernel_verification_key,
        },
        &mut GptDisk::new(uefi).map_err(CrdybootError::GptDisk)?,
    ) {
        Ok(loaded_kernel) => {
            vboot_kernel = loaded_kernel;
            kernel_data = vboot_kernel.data();
            kernel_cmdline = vboot_kernel
                .command_line()
                .ok_or(CrdybootError::GetCommandLineFailed)?;
        }
        Err(err) => {
            // Loading via vboot failed. Log the error and move on to
            // attempting to loading a flexor kernel instead.
            info!("vboot failed: {err}");

            flexor_kernel = load_flexor_kernel_with_retry(rk, uefi)?;
            kernel_data = &flexor_kernel;
            kernel_cmdline = get_flexor_cmdline(rk.verbose_logging());
        }
    }

    // Convert kernel command line to UCS-2.
    let kernel_cmdline = CString16::try_from(kernel_cmdline.as_str())
        .map_err(|_| CrdybootError::CommandLineUcs2ConversionFailed)?;
    info!("command line: {kernel_cmdline}");

    // Go ahead and free the workbuf, not needed anymore.
    drop(workbuf);

    // Measure the kernel into the TPM.
    rk.extend_pcr_and_log(kernel_data);

    // Relocate the kernel into an allocated buffer.
    // This buffer will never be freed, unless loading or executing the
    // kernel fails.
    //
    // As of R130 the required size is about 17.9MiB. Developer
    // kernels with different config options may be slightly larger,
    // so add some extra space. The flexor kernel is about 27.1 MiB, so to
    // accommodate either of these, buffer of 32MiB should be sufficient.
    let kernel_reloc_buffer = relocate_kernel(kernel_data, mib_to_bytes(32))?;

    // Drop the original kernel buffer, not needed anymore.
    drop(kernel_buffer);

    execute_linux_kernel(rk, &kernel_reloc_buffer, &kernel_cmdline)
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

fn load_and_execute_kernel_impl(rk: &dyn RunKernel, uefi: &dyn Uefi) -> Result<(), CrdybootError> {
    #[cfg(feature = "android")]
    avb_load_kernel(rk)?;
    vboot_load_kernel(rk, uefi)
}

/// Load the kernel from the appropriate kernel partition then execute it.
/// If successful, this function will never return.
pub fn load_and_execute_kernel() -> Result<(), CrdybootError> {
    load_and_execute_kernel_impl(&RunKernelImpl, &UefiImpl)
}

/// Load the flexor kernel with a retry on failure.
///
/// See `connect_nvme_handles` for details of the bug this works around.
fn load_flexor_kernel_with_retry(
    rk: &dyn RunKernel,
    uefi: &dyn Uefi,
) -> Result<Vec<u8>, CrdybootError> {
    match load_flexor_kernel(rk, uefi) {
        Ok(flexor_kernel) => Ok(flexor_kernel),
        Err(err) => {
            info!("failed to load flexor kernel: {err}");

            // Connect nvme controllers and try again.
            connect_nvme_handles(uefi);
            load_flexor_kernel(rk, uefi)
        }
    }
}

/// Attempt to recursively connect a driver to NVME handles.
///
/// In b/388506108, it was found that on the HP Probook 445 fails to
/// boot flexor because the `SimpleFileSystem` protocol is not loaded
/// for the Flexor data partition.
///
/// Recursively connecting controllers for handles supporting the NVME
/// express passthrough protocol fixes the issue.
fn connect_nvme_handles(uefi: &dyn Uefi) {
    info!("connecting nvme handles...");
    let nvme_handles = match uefi.find_nvme_express_pass_through_handles() {
        Ok(handles) => handles,
        Err(err) => {
            info!("failed to get nvme handles: {err}");
            return;
        }
    };

    for handle in nvme_handles {
        // This will fail if no new controllers are connected, so ignore
        // the result.
        let _ = uefi.connect_controller_recursive(handle);
    }
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
fn load_flexor_kernel(rk: &dyn RunKernel, uefi: &dyn Uefi) -> Result<Vec<u8>, CrdybootError> {
    const FILE_NAME: &CStr16 = cstr16!(r"flexor_vmlinuz");
    let handles_buffer = uefi
        .find_simple_file_system_handles()
        .map_err(|err| CrdybootError::GetFileSystemHandlesFailed(err.status()))?;
    info!("found {} SimpleFileSystem handles", handles_buffer.len());

    let valid_hashes = rk.get_valid_flexor_sha256_hashes();

    // Iterate over all the file system handles.
    for handle in handles_buffer {
        let mut file_loader = rk.open_file_loader(handle)?;

        let Ok(buffer) = file_loader.read_file_to_vec(FILE_NAME, FLEXOR_KERNEL_MAX_SIZE) else {
            // Continue looking for other valid flexor images.
            continue;
        };

        if validate_flexor_kernel(&buffer, valid_hashes).is_err() {
            // Continue looking for other valid flexor images.
            info!("flexor kernel validation failed.");
            continue;
        }

        info!("successfully loaded a {} byte flexor kernel", buffer.len());
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
    use crate::disk::tests::{create_mock_uefi, BootDrive};
    use crate::vbpubk::tests::create_test_pe;
    use core::ptr;
    use libcrdy::fs::MockFileLoader;
    use libcrdy::uefi::MockUefi;

    const TEST_DATA: &[u8] = &[1, 2, 3];
    const FLEXOR_SHA256_TEST_HASHES: &[&str] = &[
        // SHA256 hash for `TEST_DATA`
        "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
    ];

    const TEST_KEY_VBPUBK: &[u8] =
        include_bytes!("../../third_party/vboot_reference/tests/devkeys/kernel_subkey.vbpubk");

    const INVALID_VBPUBK: &[u8] = &[1, 2, 3];

    /// SHA-256 of `create_test_pe(1)`.
    const SHA_256_OF_TEST_PE: &str =
        "83935b989fca584b6123b6d45586a31b92968bcc5a5a46e2b940c9d731d8915b";

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

    /// Test that get_flexor_cmdline adds the appropriate log level.
    #[test]
    fn test_get_flexor_cmdline() {
        let verbose = false;
        assert!(get_flexor_cmdline(verbose).ends_with(" loglevel=1 printk.devkmsg=ratelimit"));
        let verbose = true;
        assert!(get_flexor_cmdline(verbose).ends_with(" loglevel=7 printk.devkmsg=on"));
    }

    /// Return true if `data` looks like a valid kernel buffer, false otherwise.
    fn looks_like_a_kernel(data: &[u8]) -> bool {
        // Length is a multiple of a kibibyte.
        (data.len() % 1024) == 0 &&
            // Starts with the MZ magic bytes.
            data[..2] == *b"MZ"
    }

    fn get_sfs_handle() -> Handle {
        static IMAGE_HANDLE: u8 = 234u8;
        unsafe { Handle::from_ptr(ptr::from_ref(&IMAGE_HANDLE).cast_mut().cast()) }.unwrap()
    }

    fn get_nvme_handle() -> Handle {
        static IMAGE_HANDLE: u8 = 235u8;
        unsafe { Handle::from_ptr(ptr::from_ref(&IMAGE_HANDLE).cast_mut().cast()) }.unwrap()
    }

    fn expect_allocate_pages(rk: &mut MockRunKernel) {
        for expected_size in [
            LoadKernelInputs::RECOMMENDED_WORKBUF_SIZE,
            VBOOT_KERNEL_ALLOC_SIZE,
        ] {
            rk.expect_allocate_pages()
                .times(1)
                .withf(move |ty, size| (*ty, *size) == (MemoryType::LOADER_DATA, expected_size))
                .returning(|ty, size| {
                    Ok(ScopedPageAllocation::new(AllocateType::AnyPages, ty, size).unwrap())
                });
        }
    }

    fn expect_get_vbpubk_from_image(rk: &mut MockRunKernel, vbpubk: &'static [u8]) {
        rk.expect_get_vbpubk_from_image()
            .times(1)
            .return_const(Ok(vbpubk));
    }

    fn expect_extend_pcr_and_log(rk: &mut MockRunKernel) {
        rk.expect_extend_pcr_and_log()
            .times(1)
            .withf(looks_like_a_kernel)
            .return_const(());
    }

    fn expect_update_mem_attrs(rk: &mut MockRunKernel) {
        rk.expect_update_mem_attrs()
            .times(1)
            .return_once(|_| Ok(()));
    }

    fn expect_launch_next_stage(rk: &mut MockRunKernel) {
        rk.expect_launch_next_stage()
            .times(1)
            .withf(|next_stage| {
                let cmdline = unsafe { CStr16::from_ptr(next_stage.load_options.as_ptr().cast()) };
                looks_like_a_kernel(next_stage.image_data) &&
                    // Check for a string that should always be in the
                    // command line.
                    cmdline.to_string().contains("cros_efi") &&
                    // The entry point should be somewhere fairly far
                    // into the buffer.
                    next_stage.entry_point_offset > 1024
            })
            .return_once(|_| Ok(()));
    }

    fn expect_verbose_logging(rk: &mut MockRunKernel) {
        rk.expect_verbose_logging().times(1).return_const(false);
    }

    fn expect_get_valid_flexor_sha256_hashes(
        rk: &mut MockRunKernel,
        hashes: &'static [&'static str],
    ) {
        rk.expect_get_valid_flexor_sha256_hashes()
            .times(1)
            .return_const(hashes);
    }

    fn expect_open_file_loader(rk: &mut MockRunKernel) {
        rk.expect_open_file_loader()
            .times(1)
            .withf(|handle| *handle == get_sfs_handle())
            .returning(|_| {
                let mut loader = MockFileLoader::new();
                loader
                    .expect_read_file_to_vec()
                    .times(1)
                    .withf(|path, max_size| {
                        path == cstr16!(r"flexor_vmlinuz") && *max_size == FLEXOR_KERNEL_MAX_SIZE
                    })
                    .returning(|_, _| Ok(create_test_pe(1)));
                Ok(Box::new(loader))
            });
    }

    fn expect_find_simple_file_system_handles(uefi: &mut MockUefi) {
        uefi.expect_find_simple_file_system_handles()
            .times(1)
            .returning(|| Ok(vec![get_sfs_handle()]));
    }

    fn expect_find_nvme_express_pass_through_handles(uefi: &mut MockUefi) {
        uefi.expect_find_nvme_express_pass_through_handles()
            .times(1)
            .returning(|| Ok(vec![get_nvme_handle()]));
    }

    fn expect_connect_nvme_controller(uefi: &mut MockUefi) {
        uefi.expect_connect_controller_recursive()
            .times(1)
            .withf(|h| *h == get_nvme_handle())
            .returning(|_| Ok(()));
    }

    /// Test that `load_and_execute_kernel_impl` succeeds with a valid
    /// kernel partition loaded by vboot.
    #[test]
    #[cfg_attr(any(miri, feature = "android"), ignore)]
    fn test_vboot_success() {
        let mut rk = MockRunKernel::new();

        expect_allocate_pages(&mut rk);
        expect_get_vbpubk_from_image(&mut rk, TEST_KEY_VBPUBK);
        expect_extend_pcr_and_log(&mut rk);
        expect_update_mem_attrs(&mut rk);
        expect_launch_next_stage(&mut rk);

        let uefi = create_mock_uefi(BootDrive::Hd1);

        load_and_execute_kernel_impl(&rk, &uefi).unwrap();
    }

    /// Test that `load_and_execute_kernel_impl` successfully loads a
    /// flexor kernel after failing to load via vboot.
    #[test]
    #[cfg_attr(any(miri, feature = "android"), ignore)]
    fn test_flexor_success() {
        let mut rk = MockRunKernel::new();

        expect_allocate_pages(&mut rk);
        expect_get_vbpubk_from_image(&mut rk, INVALID_VBPUBK);
        expect_extend_pcr_and_log(&mut rk);
        expect_update_mem_attrs(&mut rk);
        expect_launch_next_stage(&mut rk);
        expect_verbose_logging(&mut rk);
        expect_get_valid_flexor_sha256_hashes(&mut rk, &[SHA_256_OF_TEST_PE]);
        expect_open_file_loader(&mut rk);

        let mut uefi = create_mock_uefi(BootDrive::Hd1);
        expect_find_simple_file_system_handles(&mut uefi);

        load_and_execute_kernel_impl(&rk, &uefi).unwrap();
    }

    /// Test that `load_and_execute_kernel_impl` correctly fails if
    /// there are no valid vboot kernels and no valid flexor kernels.
    #[test]
    #[cfg_attr(any(miri, feature = "android"), ignore)]
    fn test_no_valid_kernels() {
        let mut rk = MockRunKernel::new();
        let mut uefi = create_mock_uefi(BootDrive::Hd1);

        expect_allocate_pages(&mut rk);
        expect_get_vbpubk_from_image(&mut rk, INVALID_VBPUBK);
        expect_find_nvme_express_pass_through_handles(&mut uefi);
        expect_connect_nvme_controller(&mut uefi);

        // Called twice due to `load_flexor_kernel_with_retry`.
        for _ in 0..2 {
            expect_get_valid_flexor_sha256_hashes(&mut rk, &[]);
            expect_open_file_loader(&mut rk);
            expect_find_simple_file_system_handles(&mut uefi);
        }

        assert!(matches!(
            load_and_execute_kernel_impl(&rk, &uefi),
            Err(CrdybootError::LoadFlexorKernelFailed)
        ));
    }
}
