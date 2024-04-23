// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::operation::Operation;
use core::sync::atomic::{AtomicU32, Ordering};
use uefi::data_types::PhysicalAddress;
use uefi::proto::tcg::v1;
use uefi::table::boot::BootServices;
use uefi::{Identify, Status};

/// Install a TPM v1 protocol. This isn't a real TPM, just enough to
/// test some error cases (e.g. the behavior of crdyshim if the TPM is
/// deactivated).
pub fn create_tpm1(boot_services: &BootServices) {
    static TPM_V1: TpmV1 = TpmV1 {
        status_check,
        hash_log_extend_event,

        // These aren't called, so don't bother implementing.
        hash_all: not_implemented,
        log_event: not_implemented,
        pass_through_to_tpm: not_implemented,
    };

    let interface: *const _ = &TPM_V1;

    // SAFETY: The layout of `TPM_V1` matches the spec, and the GUID is
    // correct.
    unsafe { boot_services.install_protocol_interface(None, &v1::Tcg::GUID, interface.cast()) }
        .unwrap();
}

/// Get TPM status. Depending on the operation, the TPM may be deactivated.
extern "efiapi" fn status_check(
    _this: *mut TpmV1,
    protocol_capability: *mut TpmV1Capability,
    _feature_flags: *mut u32,
    _event_log_location: *mut PhysicalAddress,
    _event_log_last_entry: *mut PhysicalAddress,
) -> Status {
    let caps = TpmV1Capability {
        tpm_present_flag: 1,
        tpm_deactivated_flag: if Operation::get() == Operation::Tpm1Deactivated {
            1
        } else {
            0
        },
        ..TpmV1Capability::default()
    };
    unsafe {
        *protocol_capability = caps;
    }
    Status::SUCCESS
}

/// Stub implementation for extending a PCR. Just returns a status code
/// that depends on the operation.
unsafe extern "efiapi" fn hash_log_extend_event(
    _this: *mut TpmV1,
    _hash_data: PhysicalAddress,
    _hash_data_len: u64,
    _algorithm_id: u32,
    _event: *mut v1::FfiPcrEvent,
    _event_number: *mut u32,
    _event_log_last_entry: *mut PhysicalAddress,
) -> Status {
    static CALL_COUNT: AtomicU32 = AtomicU32::new(0);

    // Get the current call count, and increment the static.
    let call_count = CALL_COUNT.fetch_add(1, Ordering::Acquire);

    // The initial calls to this function happen implicitly in the
    // firmware when loading crdyshim. Always return success for those,
    // otherwise the load will fail.
    //
    // There's no guarantee that the behavior of OVMF won't change in
    // the future, but if it does, the test will fail rather than
    // silently passing. If `call_count` is too low, crdyshim won't be
    // loaded. If too high, the test won't see the expected
    // `DEVICE_ERROR` log.
    if call_count <= 2 {
        return Status::SUCCESS;
    }

    if Operation::get() == Operation::Tpm1ExtendFail {
        Status::DEVICE_ERROR
    } else {
        Status::SUCCESS
    }
}

extern "efiapi" fn not_implemented() -> Status {
    unimplemented!()
}

#[derive(Default)]
#[repr(C)]
pub struct TpmV1Capability {
    size: u8,
    structure_version: [u8; 4],
    protocol_spec_version: [u8; 4],
    hash_algorithm_bitmap: u8,
    tpm_present_flag: u8,
    tpm_deactivated_flag: u8,
}

#[repr(C)]
pub struct TpmV1 {
    status_check: unsafe extern "efiapi" fn(
        this: *mut Self,
        protocol_capability: *mut TpmV1Capability,
        feature_flags: *mut u32,
        event_log_location: *mut PhysicalAddress,
        event_log_last_entry: *mut PhysicalAddress,
    ) -> Status,
    hash_all: unsafe extern "efiapi" fn() -> Status,
    log_event: unsafe extern "efiapi" fn() -> Status,
    pass_through_to_tpm: unsafe extern "efiapi" fn() -> Status,
    hash_log_extend_event: unsafe extern "efiapi" fn(
        this: *mut Self,
        hash_data: PhysicalAddress,
        hash_data_len: u64,
        algorithm_id: u32,
        event: *mut v1::FfiPcrEvent,
        event_number: *mut u32,
        event_log_last_entry: *mut PhysicalAddress,
    ) -> Status,
}
