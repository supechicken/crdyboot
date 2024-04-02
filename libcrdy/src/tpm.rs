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
use uefi::table::boot::{BootServices, ScopedProtocol};
use uefi::Status;

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

/// Storage for an open TPM protocol, either v1 or v2.
enum TpmProtocol<'a> {
    V1(ScopedProtocol<'a, v1::Tcg>),
    V2(ScopedProtocol<'a, v2::Tcg>),
}

impl<'a> TpmProtocol<'a> {
    /// Open a TPM protocol, trying v2 first, then falling back to v1.
    ///
    /// If no handle exists for either protocol, returns `Ok(None)`.
    fn open(boot_services: &'a BootServices) -> Result<Option<Self>, TpmError> {
        // Try v2 first.
        match open_protocol_v2(boot_services) {
            Ok(Some(v2)) => {
                // Successfully opened v2 protocol.
                return Ok(Some(Self::V2(v2)));
            }
            Ok(None) => {
                // No v2 handle exists.
            }
            Err(err) => {
                // Log at info level since it's not critical.
                info!("failed to open TPM v2 protocol: {err}");
            }
        }

        // Fall back to v1.
        let v1 = open_protocol_v1(boot_services)?;
        Ok(v1.map(Self::V1))
    }
}

/// Open the TPM v1 protocol if possible.
///
/// If no handle exists, returns `Ok(None)`.
fn open_protocol_v1(
    boot_services: &BootServices,
) -> Result<Option<ScopedProtocol<v1::Tcg>>, TpmError> {
    let handle = match boot_services.get_handle_for_protocol::<v1::Tcg>() {
        Ok(handle) => handle,
        Err(err) => {
            if err.status() == Status::NOT_FOUND {
                return Ok(None);
            }
            return Err(TpmError::v1(TpmErrorKind::InvalidHandle, err));
        }
    };

    let proto = boot_services
        .open_protocol_exclusive::<v1::Tcg>(handle)
        .map_err(|err| TpmError::v1(TpmErrorKind::OpenProtocolFailed, err))?;

    // TODO(nicholasbishop): check validity.

    Ok(Some(proto))
}

/// Open the TPM v2 protocol if possible.
///
/// If no handle exists, returns `Ok(None)`.
fn open_protocol_v2(
    boot_services: &BootServices,
) -> Result<Option<ScopedProtocol<v2::Tcg>>, TpmError> {
    let handle = match boot_services.get_handle_for_protocol::<v2::Tcg>() {
        Ok(handle) => handle,
        Err(err) => {
            if err.status() == Status::NOT_FOUND {
                return Ok(None);
            }
            return Err(TpmError::v2(TpmErrorKind::InvalidHandle, err));
        }
    };

    let proto = boot_services
        .open_protocol_exclusive::<v2::Tcg>(handle)
        .map_err(|err| TpmError::v2(TpmErrorKind::OpenProtocolFailed, err))?;

    // TODO(nicholasbishop): check validity.

    Ok(Some(proto))
}

fn extend_pcr_and_log_v1(
    mut tcg: ScopedProtocol<v1::Tcg>,
    pcr_index: PcrIndex,
    data_to_hash: &[u8],
) -> Result<(), TpmError> {
    // Make a buffer big enough to hold the event.
    let mut event_buf = [MaybeUninit::uninit(); 64];

    let event = v1::PcrEvent::new_in_buffer(
        &mut event_buf,
        pcr_index,
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
    mut tcg: ScopedProtocol<v2::Tcg>,
    pcr_index: PcrIndex,
    data_to_hash: &[u8],
) -> Result<(), TpmError> {
    // Make a buffer big enough to hold the event.
    let mut event_buf = [MaybeUninit::uninit(); 64];

    let event =
        v2::PcrEventInputs::new_in_buffer(&mut event_buf, pcr_index, EVENT_TYPE, EVENT_DATA)
            .map_err(|err| TpmError::v2(TpmErrorKind::InvalidPcrEvent, err))?;

    tcg.hash_log_extend_event(v2::HashLogExtendEventFlags::empty(), data_to_hash, event)
        .map_err(|err| TpmError::v2(TpmErrorKind::HashLogExtendEventFailed, err))?;

    Ok(())
}

/// Extend PCR 8 with a measurement of `data_to_hash` and add to the event log.
pub fn extend_pcr_and_log(
    boot_services: &BootServices,
    pcr_index: PcrIndex,
    data_to_hash: &[u8],
) -> Result<(), TpmError> {
    match TpmProtocol::open(boot_services) {
        Ok(Some(TpmProtocol::V1(protocol))) => {
            info!("measuring to v1 TPM");
            extend_pcr_and_log_v1(protocol, pcr_index, data_to_hash)?;
        }
        Ok(Some(TpmProtocol::V2(protocol))) => {
            info!("measuring to v2 TPM");
            extend_pcr_and_log_v2(protocol, pcr_index, data_to_hash)?;
        }
        Ok(None) => {
            info!("no TPM device found");
        }
        Err(err) => {
            info!("a TPM handle exists but is not valid: {}", err);
        }
    }

    Ok(())
}
