// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod load_capsules;
mod update_info;

use crate::disk::GptDiskError;
use alloc::vec::Vec;
use core::mem;
use ext4_view::{Ext4Error, PathError};
use libcrdy::page_alloc::{PageAllocationError, ScopedPageAllocation};
use libcrdy::uefi::{Uefi, UefiImpl};
use libcrdy::util::u32_to_usize;
use load_capsules::{CapsuleLoader, CapsuleLoaderImpl};
use log::info;
use uefi::boot::PAGE_SIZE;
use uefi::runtime::{CapsuleBlockDescriptor, CapsuleHeader, ResetType};
use uefi::Status;
use update_info::{get_update_table, set_update_statuses, UpdateInfo};

#[derive(Debug, thiserror::Error)]
enum FirmwareError {
    #[error("failed to read variable: {0}")]
    GetVariableFailed(Status),

    #[error("failed to write variable: {0}")]
    SetVariableFailed(Status),

    #[error("invalid variable key: {0}")]
    InvalidVariableKey(Status),

    #[error("invalid update variable: not enough data")]
    UpdateInfoTooShort,

    #[error("invalid update variable: malformed device path")]
    UpdateInfoMalformedDevicePath,

    #[error("file path is not present in update info device path")]
    FilePathMissing,

    #[error("file path encoding is invalid")]
    FilePathEncodingInvalid,

    #[error("file path is not valid for ext4: {0}")]
    FilePathInvalid(PathError),

    #[error("failed to allocate pages for a capsule")]
    CapsuleAllocationFailed(#[source] PageAllocationError),

    #[error("failed to open the stateful partition")]
    OpenStatefulPartitionFailed(#[source] GptDiskError),

    #[error("failed to load the stateful filesystem: {0}")]
    Ext4LoadFailed(Ext4Error),

    #[error("failed to read an update capsule: {0}")]
    Ext4ReadFailed(Ext4Error),

    #[error("capsule is too small: {actual} < {required}")]
    CapsuleTooSmall { required: usize, actual: usize },

    #[error("firmware capsule update failed: {0}")]
    UpdateCapsuleFailed(Status),
}

/// Ask the firmware what type of system reset is needed for capsule updates.
///
/// If an error occurs, default to [`ResetType::WARM`].
fn get_reset_type(uefi: &dyn Uefi, capsules: &[&CapsuleHeader]) -> ResetType {
    match uefi.query_capsule_capabilities(capsules) {
        Ok(capabilities) => {
            info!("query capsule capabilities: {capabilities:?}");
            capabilities.reset_type
        }
        Err(err) => {
            info!("query capsule capabilities failed: {err}");
            ResetType::WARM
        }
    }
}

/// Get a `CapsuleHeader` reference from raw bytes.
fn get_one_capsule_ref(capsule: &ScopedPageAllocation) -> Result<&CapsuleHeader, FirmwareError> {
    let capsule_ptr: *const CapsuleHeader = capsule.as_ptr().cast();

    // Make sure the capsule data is large enough to contain the
    // header. Since `ScopedPageAllocation` holds at least one page,
    // this assert cannot fail.
    assert!(capsule.len() >= mem::size_of::<CapsuleHeader>());

    // Check the alignment to make sure it matches CapsuleHeader. Since
    // page allocations are `PAGE_SIZE` aligned, these asserts cannot fail.
    assert!(capsule_ptr.is_aligned());
    assert_eq!(capsule_ptr.align_offset(PAGE_SIZE), 0);

    // SAFETY: the pointed-to data is aligned and large enough to be
    // a `CapsuleHeader`.
    let capsule_ref: &CapsuleHeader = unsafe { &*capsule_ptr };

    // The header contains a header size (which may be larger than
    // `CapsuleHeader`), validate that enough data is present.
    let required_size = u32_to_usize(capsule_ref.header_size);
    if capsule.len() < required_size {
        return Err(FirmwareError::CapsuleTooSmall {
            required: required_size,
            actual: capsule.len(),
        });
    }

    // The header contains the expected size of the full capsule; make
    // sure that enough data is present.
    let required_size = u32_to_usize(capsule_ref.capsule_image_size);
    if capsule.len() < required_size {
        return Err(FirmwareError::CapsuleTooSmall {
            required: required_size,
            actual: capsule.len(),
        });
    }

    Ok(capsule_ref)
}

/// Get a `Vec` of `CapsuleHeader` references from the list of raw
/// capsule bytes.
///
/// Any capsules that are not valid are skipped.
fn get_capsule_refs(capsules: &[ScopedPageAllocation]) -> Vec<&CapsuleHeader> {
    let mut capsule_refs: Vec<&CapsuleHeader> = Vec::with_capacity(capsules.len());
    for capsule in capsules {
        match get_one_capsule_ref(capsule) {
            Ok(capsule_ref) => capsule_refs.push(capsule_ref),
            Err(err) => info!("failed to get capsule ref: {err}"),
        }
    }

    capsule_refs
}

/// Get a `Vec` of `CapsuleBlockDescriptor` from the list of capsule
/// headers.
///
/// This is used as the "scatter gather list" argument to
/// `update_capsule`. The vec is terminated with an all-zero sentinel
/// value, as required by the spec.
fn get_capsule_block_descriptors(capsules: &[&CapsuleHeader]) -> Vec<CapsuleBlockDescriptor> {
    // One entry for each capsule, plus a sentinel value at the end.
    //
    // OK to unwrap: the number of capsules is capped to a relatively
    // low value (see `MAX_UPDATE_CAPSULES` in update_info.rs).
    let len = capsules.len().checked_add(1).unwrap();

    let mut descriptors: Vec<CapsuleBlockDescriptor> = Vec::with_capacity(len);

    for capsule in capsules {
        let capsule_ptr: *const CapsuleHeader = *capsule;
        descriptors.push(CapsuleBlockDescriptor {
            length: u64::from(capsule.capsule_image_size),
            address: capsule_ptr as u64,
        });
    }

    // Add sentinel value of all zeroes to terminate the list.
    descriptors.push(CapsuleBlockDescriptor {
        length: 0,
        address: 0,
    });

    descriptors
}

/// Try to install firmware update capsules, if any are present.
///
/// If successful, the system will reset and this function will never
/// return.
///
/// Some errors are logged but otherwise ignored, with the intent of
/// processing as many valid capsules as possible. Fatal errors are
/// propagated to the caller.
fn update_firmware_impl(
    uefi: &dyn Uefi,
    capsule_loader: &dyn CapsuleLoader,
) -> Result<(), FirmwareError> {
    // Check if any updates are available by searching for and validating
    // any update state variables.
    let updates = get_update_table(uefi, uefi.variable_keys());
    info!("found {} capsule update variables", updates.len());

    let capsules = capsule_loader.load_capsules_from_disk(uefi, &updates)?;
    info!("loaded {} capsules from disk", capsules.len());

    let capsule_refs = get_capsule_refs(&capsules);
    info!("got {} valid capsule headers", capsule_refs.len());

    // The capsule list is now finalized. If there are no capsules at
    // this point then there's nothing left to do.
    if capsule_refs.is_empty() {
        return Ok(());
    }

    let descriptors = get_capsule_block_descriptors(&capsule_refs);

    set_update_statuses(uefi, &updates)?;

    let reset_type = get_reset_type(uefi, &capsule_refs);

    info!("calling update_capsule");
    uefi.update_capsule(&capsule_refs, &descriptors)
        .map_err(|err| FirmwareError::UpdateCapsuleFailed(err.status()))?;

    info!("resetting the system: {reset_type:?}");
    uefi.reset(reset_type);

    Ok(())
}

/// Try to install firmware update capsules, if any are present.
///
/// If successful, the system will reset and this function will never
/// return.
///
/// Errors are logged but otherwise ignored.
pub fn update_firmware() {
    if !cfg!(feature = "firmware_update") {
        info!("firmware updates disabled");
        return;
    }

    if let Err(err) = update_firmware_impl(&UefiImpl, &CapsuleLoaderImpl) {
        info!("firmware update failed: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use libcrdy::uefi::{MockUefi, VariableKey, VariableKeys};
    use load_capsules::MockCapsuleLoader;
    use uefi::boot::{AllocateType, MemoryType};
    use uefi::runtime::{CapsuleFlags, CapsuleInfo};
    use uefi::{guid, Guid, Status};
    use update_info::tests::{create_mock_uefi_with_get_var, VAR_NAME};
    use update_info::FWUPDATE_VENDOR;

    const TEST_GUID: Guid = guid!("4f5c8eed-4346-4de8-82b2-48b884a84dee");
    const TEST_FLAGS: CapsuleFlags = CapsuleFlags::PERSIST_ACROSS_RESET;

    /// Test that `get_reset_type` returns the same thing as
    /// `query_capsule_capabilities` on success.
    #[test]
    fn test_get_reset_type_success() {
        let mut uefi = MockUefi::new();

        uefi.expect_query_capsule_capabilities()
            .return_const(Ok(CapsuleInfo {
                maximum_capsule_size: 1234,
                reset_type: ResetType::COLD,
            }));

        assert_eq!(get_reset_type(&uefi, &[]), ResetType::COLD);
    }

    /// Test that `get_reset_type` returns `WARM` if
    /// `query_capsule_capabilities` fails.
    #[test]
    fn test_get_reset_type_error() {
        let mut uefi = MockUefi::new();

        uefi.expect_query_capsule_capabilities()
            .return_const(Err(Status::DEVICE_ERROR.into()));

        assert_eq!(get_reset_type(&uefi, &[]), ResetType::WARM);
    }

    /// Create a test capsule. The returned allocation contains one page
    /// of memory. The `header` is copied to the beginning of the that
    /// memory.
    fn create_capsule(header: &CapsuleHeader) -> ScopedPageAllocation {
        // Allocate one page.
        let mut capsule =
            ScopedPageAllocation::new(AllocateType::AnyPages, MemoryType::LOADER_CODE, PAGE_SIZE)
                .unwrap();

        // Copy the header to the capsule.
        unsafe { capsule.as_mut_ptr().cast::<CapsuleHeader>().write(*header) };

        capsule
    }

    /// Test that `get_one_capsule_ref` succeeds with valid data.
    #[test]
    fn test_get_one_capsule_ref_success() {
        let header = CapsuleHeader {
            capsule_guid: TEST_GUID,
            flags: TEST_FLAGS,
            header_size: 28,
            capsule_image_size: 64,
        };
        let capsule = create_capsule(&header);

        assert_eq!(*get_one_capsule_ref(&capsule).unwrap(), header);
    }

    /// Test that `get_one_capsule_ref` fails if the input data is
    /// smaller than the header size specified in the header.
    #[test]
    fn test_get_one_capsule_ref_too_small_for_header() {
        let capsule = create_capsule(&CapsuleHeader {
            capsule_guid: TEST_GUID,
            flags: TEST_FLAGS,
            header_size: 5000,
            capsule_image_size: 6000,
        });

        assert!(matches!(
            get_one_capsule_ref(&capsule).unwrap_err(),
            FirmwareError::CapsuleTooSmall {
                required: 5000,
                actual: 4096,
            }
        ));
    }

    /// Test that `get_one_capsule_ref` fails if the input data is
    /// smaller than the full capsule size specified in the header.
    #[test]
    fn test_get_one_capsule_ref_too_small_for_capsule() {
        let capsule = create_capsule(&CapsuleHeader {
            capsule_guid: TEST_GUID,
            flags: TEST_FLAGS,
            header_size: 28,
            capsule_image_size: 9999,
        });

        assert!(matches!(
            get_one_capsule_ref(&capsule).unwrap_err(),
            FirmwareError::CapsuleTooSmall {
                required: 9999,
                actual: 4096,
            }
        ));
    }

    /// Test that `get_capsule_refs` ignores invalid capsules and
    /// successfully gets valid capsule headers.
    #[test]
    fn test_get_capsule_refs() {
        let valid_header = CapsuleHeader {
            capsule_guid: TEST_GUID,
            flags: TEST_FLAGS,
            header_size: 28,
            capsule_image_size: 1000,
        };
        let invalid_header = CapsuleHeader {
            // Too large to fit in a page.
            capsule_image_size: 9999,
            ..valid_header
        };

        let capsules = &[
            create_capsule(&invalid_header),
            create_capsule(&valid_header),
        ];

        assert_eq!(get_capsule_refs(capsules), [&valid_header]);
    }

    /// Test that `get_capsule_block_descriptors` returns a valid
    /// sentinel-terminated list of descriptors.
    #[test]
    fn test_get_capsule_block_descriptors() {
        let capsules = [
            &CapsuleHeader {
                capsule_guid: TEST_GUID,
                flags: TEST_FLAGS,
                header_size: 28,
                capsule_image_size: 64,
            },
            &CapsuleHeader {
                capsule_guid: TEST_GUID,
                flags: TEST_FLAGS,
                header_size: 28,
                capsule_image_size: 128,
            },
        ];

        assert_eq!(
            get_capsule_block_descriptors(&capsules),
            [
                CapsuleBlockDescriptor {
                    length: 64,
                    address: ptr::from_ref(capsules[0]) as u64,
                },
                CapsuleBlockDescriptor {
                    length: 128,
                    address: ptr::from_ref(capsules[1]) as u64,
                },
                CapsuleBlockDescriptor {
                    length: 0,
                    address: 0
                }
            ]
        )
    }

    /// Test that `update_firmware_impl` succeeds with a valid update
    /// variable and valid capsule.
    #[test]
    fn test_update_firmware_impl_success() {
        let mut uefi = create_mock_uefi_with_get_var();
        uefi.expect_variable_keys().returning(|| {
            VariableKeys::ForTest(vec![Ok(VariableKey::new(VAR_NAME, FWUPDATE_VENDOR))])
        });
        let mut loader = MockCapsuleLoader::new();
        loader.expect_load_capsules_from_disk().returning(|_, _| {
            Ok(vec![create_capsule(&CapsuleHeader {
                capsule_guid: TEST_GUID,
                flags: TEST_FLAGS,
                header_size: 28,
                capsule_image_size: 128,
            })])
        });
        uefi.expect_set_variable().returning(|name, vendor, _, _| {
            assert_eq!(name, VAR_NAME);
            assert_eq!(*vendor, FWUPDATE_VENDOR);
            Ok(())
        });
        uefi.expect_query_capsule_capabilities()
            .returning(|capsules| {
                assert_eq!(capsules.len(), 1);
                Ok(CapsuleInfo {
                    maximum_capsule_size: 123,
                    reset_type: ResetType::COLD,
                })
            });
        uefi.expect_update_capsule().returning(|capsules, desc| {
            assert_eq!(capsules.len(), 1);
            assert_eq!(desc.len(), 2);
            Ok(())
        });
        uefi.expect_reset().returning(|reset_type| {
            assert_eq!(reset_type, ResetType::COLD);
        });
        assert!(update_firmware_impl(&uefi, &loader).is_ok());
    }

    /// Test that `update_firmware_impl` returns early if no valid
    /// capsules are loaded.
    #[test]
    fn test_update_firmware_impl_no_valid_capsule() {
        let mut uefi = create_mock_uefi_with_get_var();
        uefi.expect_variable_keys().returning(|| {
            VariableKeys::ForTest(vec![Ok(VariableKey::new(VAR_NAME, FWUPDATE_VENDOR))])
        });
        let mut loader = MockCapsuleLoader::new();
        loader
            .expect_load_capsules_from_disk()
            .returning(|_, _| Ok(vec![]));
        assert!(update_firmware_impl(&uefi, &loader).is_ok());
    }
}
