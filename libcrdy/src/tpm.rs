// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module provides an interface for measuring the kernel data into
//! a PCR.
//!
//! This allows later stages of the boot process to know what happened
//! earlier. Each measurement has two effects:
//!
//! 1. A new event is appended to the TPM event log. This event includes
//!    the PCR index, the event type, a digest of the data being
//!    measured (the kernel data in this case), and informational event
//!    data (the [`EVENT_DATA`] string in this case).
//! 2. The PCR is extended with the digest of the data being
//!    measured. The extend operation takes the existing hash value in
//!    the PCR, appends the bytes of the new digest, and takes the hash
//!    of the whole thing. That new hash is the new value of the
//!    PCR. Since extending the PCR is the only allowed write operation,
//!    there's no way to arbitrarily set the PCR value.
//!
//! Once the OS boots, it can examine the event log to check things
//! about the firmware, bootloader, and system state. The event log
//! itself can be validated by manually calculating the chain of hashes
//! and checking against the current PCR value.
//!
//! # Choice of PCR
//!
//! PCRs 0-7 are for the firmware. Other than that, the choice is
//! somewhat arbitrary. On a typical Linux setup PCR 8 is used by GRUB,
//! which crdyboot is an alternative to, so the uses are not
//! conflicting.
//!
//! See also the Linux TPM PCR Registry:
//! <https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/>

use core::fmt::{self, Display, Formatter};
use core::mem::MaybeUninit;
use log::info;
use uefi::proto::tcg::{v1, v2, EventType, PcrIndex};
use uefi::table::boot::BootServices;
use uefi::{Handle, Status};

/// Measure into PCR 8. See module docstring for more information on how
/// this PCR was chosen.
const PCR_INDEX: PcrIndex = PcrIndex(8);

const EVENT_TYPE: EventType = EventType::IPL;
const EVENT_DATA: &[u8] = b"ChromeOS kernel partition data";

enum TpmVersion {
    V1,
    V2,
}

pub struct TpmError {
    version: TpmVersion,
    kind: TpmErrorKind,
    status: Status,
}

impl TpmError {
    #[allow(clippy::needless_pass_by_value)]
    fn v1(kind: TpmErrorKind, err: uefi::Error) -> Self {
        Self {
            version: TpmVersion::V1,
            kind,
            status: err.status(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn v2(kind: TpmErrorKind, err: uefi::Error) -> Self {
        Self {
            version: TpmVersion::V2,
            kind,
            status: err.status(),
        }
    }
}

enum TpmErrorKind {
    /// An unexpected error occurred when getting a `Tcg` handle.
    ///
    /// This error is not used if the handle is simply not present.
    InvalidHandle,

    /// Failed to open the `Tcg` protocol.
    OpenProtocolFailed,

    // Failed to create a `PcrEvent`.
    InvalidPcrEvent,

    /// Failed to log to the TPM.
    HashLogExtendEventFailed,
}

impl Display for TpmError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let status = self.status;
        let version = match self.version {
            TpmVersion::V1 => 1,
            TpmVersion::V2 => 2,
        };

        match self.kind {
            TpmErrorKind::InvalidHandle => {
                write!(f, "unexpected error getting TPMv{version} handle: {status}")
            }
            TpmErrorKind::OpenProtocolFailed => {
                write!(f, "failed to open the TPMv{version} protocol: {status}")
            }
            TpmErrorKind::InvalidPcrEvent => {
                write!(f, "failed to create TPMv{version} PcrEvent: {status}")
            }
            TpmErrorKind::HashLogExtendEventFailed => {
                write!(f, "TPMv{version} hash_log_extend_event failed: {status}")
            }
        }
    }
}

enum TpmHandle {
    V1(Handle),
    V2(Handle),
    None,
}

impl TpmHandle {
    /// Search for a TPM handle. First look for a V2 TPM, then for a V1
    /// TPM.
    ///
    /// Any errors other than `NOT_FOUND` are propagated to the caller.
    fn find(boot_services: &BootServices) -> Result<Self, TpmError> {
        // Try to get a V2 handle first.
        match boot_services.get_handle_for_protocol::<v2::Tcg>() {
            Ok(handle) => Ok(Self::V2(handle)),
            Err(err) => {
                if err.status() == Status::NOT_FOUND {
                    // There's no V2 handle; try to get a V1 handle.
                    match boot_services.get_handle_for_protocol::<v1::Tcg>() {
                        Ok(handle) => Ok(Self::V1(handle)),
                        Err(err) => {
                            if err.status() == Status::NOT_FOUND {
                                Ok(Self::None)
                            } else {
                                Err(TpmError::v1(TpmErrorKind::InvalidHandle, err))
                            }
                        }
                    }
                } else {
                    Err(TpmError::v2(TpmErrorKind::InvalidHandle, err))
                }
            }
        }
    }
}

fn extend_pcr_and_log_v1(
    boot_services: &BootServices,
    data_to_hash: &[u8],
    handle: Handle,
) -> Result<(), TpmError> {
    let mut tcg = boot_services
        .open_protocol_exclusive::<v1::Tcg>(handle)
        .map_err(|err| TpmError::v1(TpmErrorKind::OpenProtocolFailed, err))?;

    // Make a buffer big enough to hold the event.
    let mut event_buf = [MaybeUninit::uninit(); 64];

    let event = v1::PcrEvent::new_in_buffer(
        &mut event_buf,
        PCR_INDEX,
        EVENT_TYPE,
        // The digest will be filled in by passing `data_to_hash` into
        // `hash_log_extend_event`.
        [0; 20],
        EVENT_DATA,
    )
    .map_err(|err| TpmError::v1(TpmErrorKind::InvalidPcrEvent, err))?;

    tcg.hash_log_extend_event(event, Some(data_to_hash))
        .map_err(|err| TpmError::v1(TpmErrorKind::HashLogExtendEventFailed, err))?;

    Ok(())
}

fn extend_pcr_and_log_v2(
    boot_services: &BootServices,
    data_to_hash: &[u8],
    handle: Handle,
) -> Result<(), TpmError> {
    let mut tcg = boot_services
        .open_protocol_exclusive::<v2::Tcg>(handle)
        .map_err(|err| TpmError::v2(TpmErrorKind::OpenProtocolFailed, err))?;

    // Make a buffer big enough to hold the event.
    let mut event_buf = [MaybeUninit::uninit(); 64];

    let event =
        v2::PcrEventInputs::new_in_buffer(&mut event_buf, PCR_INDEX, EVENT_TYPE, EVENT_DATA)
            .map_err(|err| TpmError::v2(TpmErrorKind::InvalidPcrEvent, err))?;

    tcg.hash_log_extend_event(v2::HashLogExtendEventFlags::empty(), data_to_hash, event)
        .map_err(|err| TpmError::v2(TpmErrorKind::HashLogExtendEventFailed, err))?;

    Ok(())
}

/// Extend PCR 8 with a measurement of `data_to_hash` and add to the event log.
pub fn extend_pcr_and_log(
    boot_services: &BootServices,
    data_to_hash: &[u8],
) -> Result<(), TpmError> {
    match TpmHandle::find(boot_services)? {
        TpmHandle::V1(handle) => {
            info!("measuring to v1 TPM");
            extend_pcr_and_log_v1(boot_services, data_to_hash, handle)?;
        }
        TpmHandle::V2(handle) => {
            info!("measuring to v2 TPM");
            extend_pcr_and_log_v2(boot_services, data_to_hash, handle)?;
        }
        TpmHandle::None => {
            info!("no TPM device found");
        }
    }

    Ok(())
}
