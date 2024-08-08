// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(clippy::indexing_slicing)]

use crate::disk;
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};
use core::ops::Range;
use core::{mem, ptr, slice};
use log::{error, info, warn};
use uefi::prelude::*;
use uefi::proto::device_path::DevicePath;
use uefi::table::runtime::{Time, VariableAttributes, VariableKey, VariableVendor};
use uefi::{guid, CStr16, CString16, Status};

const FWUPDATE_ATTEMPT_UPDATE: u32 = 0x0000_0001;
const FWUPDATE_ATTEMPTED: u32 = 0x0000_0002;

const FWUPDATE_VENDOR: VariableVendor =
    VariableVendor(guid!("0abba7dc-e516-4167-bbf5-4d9d1c739416"));

const FWUPDATE_VERBOSE: &CStr16 = cstr16!("FWUPDATE_VERBOSE");
const FWUPDATE_DEBUG_LOG: &CStr16 = cstr16!("FWUPDATE_DEBUG_LOG");

const MAX_UPDATE_CAPSULES: usize = 128;

#[derive(Debug, Eq, PartialEq)]
pub enum FirmwareError {
    GetVariableKeysFailed(Status),
    GetVariableFailed(Status),
    SetVariableFailed(Status),
    UpdateInfoTooShort,
    UpdateInfoMalformedDevicePath,
}

impl Display for FirmwareError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::GetVariableKeysFailed(status) => {
                write!(f, "failed to get variable keys: {status}")
            }
            Self::GetVariableFailed(status) => write!(f, "failed to read variable: {status}"),
            Self::SetVariableFailed(status) => write!(f, "failed to write variable: {status}"),
            Self::UpdateInfoTooShort => write!(f, "invalid update variable: not enough data"),
            Self::UpdateInfoMalformedDevicePath => {
                write!(f, "invalid update variable: malformed device path")
            }
        }
    }
}

/// Info for a single capsule update, provided by fwupd's [uefi-capsule]
/// plugin via a UEFI variable.
///
/// [uefi-capsule]: https://github.com/fwupd/fwupd/tree/main/plugins/uefi-capsule
#[derive(Debug, Eq, PartialEq)]
struct UpdateInfo {
    /// Name of the update's UEFI variable.
    name: CString16,

    /// Attributes of the update's UEFI variable.
    attrs: VariableAttributes,

    /// Raw data from the variable.
    data: Box<[u8]>,
}

impl UpdateInfo {
    /// Byte range of the `time_attempted` field.
    const TIME_ATTEMPTED_RANGE: Range<usize> = 32..48;

    /// Byte range of the `status` field.
    const STATUS_RANGE: Range<usize> = 48..52;

    /// Size of the fixed fields (plus padding) when in serialized
    /// form. The rest of the data is a variable-length device path.
    const HEADER_SIZE_IN_BYTES: usize = 52;

    /// Create an `UpdateInfo` from a variable's name, attributes, and
    /// data. Some minimal validation is performed.
    fn new(
        name: CString16,
        attrs: VariableAttributes,
        data: Box<[u8]>,
    ) -> Result<Self, FirmwareError> {
        // Return an error if there's not enough data.
        if data.len() < UpdateInfo::HEADER_SIZE_IN_BYTES {
            return Err(FirmwareError::UpdateInfoTooShort);
        }

        // Return an error if the device path is not valid.
        <&DevicePath>::try_from(&data[Self::HEADER_SIZE_IN_BYTES..])
            .map_err(|_| FirmwareError::UpdateInfoMalformedDevicePath)?;

        Ok(Self { name, attrs, data })
    }

    /// Set the `time_attempted` field to the current time.
    ///
    /// If the current time cannot be retrieved, log an error and leave
    /// the `time_attempted` field unchanged.
    fn update_time_attempted(&mut self, rt: &RuntimeServices) {
        // Get the current time.
        let time: Time = match rt.get_time() {
            Ok(time) => time,
            Err(err) => {
                warn!("failed to get current time: {err}");
                return;
            }
        };

        self.data[Self::TIME_ATTEMPTED_RANGE].copy_from_slice(time_to_bytes(&time));
    }

    fn status(&self) -> u32 {
        u32::from_le_bytes(self.data[Self::STATUS_RANGE].try_into().unwrap())
    }

    fn set_status(&mut self, status: u32) {
        self.data[Self::STATUS_RANGE].copy_from_slice(&status.to_le_bytes());
    }

    fn device_path(&self) -> &DevicePath {
        let path = <&DevicePath>::try_from(&self.data[Self::HEADER_SIZE_IN_BYTES..]);
        // OK to unwrap: the validity of the device path was checked in
        // `UpdateInfo::new`.
        path.unwrap()
    }
}

// TODO(nicholasbishop): add a variation of this function to uefi-rs.
fn time_to_bytes(time: &Time) -> &[u8] {
    let time_ptr: *const Time = ptr::from_ref(time);
    let byte_ptr: *const u8 = time_ptr.cast();
    let num_bytes = mem::size_of::<Time>();

    // SAFETY: `time` contains 16 bytes of valid data. It is correctly
    // aligned since u8 has an alignment of 1.
    unsafe { slice::from_raw_parts(byte_ptr, num_bytes) }
}

/// Get a list of all available updates by iterating through all UEFI
/// variables, searching for those with the [`FWUPDATE_VENDOR`]
/// GUID. Any such variables will be parsed into an [`UpdateInfo`], from
/// which an update can be applied.
///
/// If no updates are found, an empty vector is returned.
///
/// Any UEFI error causes early termination and the error to be returned.
fn get_update_table(
    st: &SystemTable<Boot>,
    variables: Vec<VariableKey>,
) -> Result<Vec<UpdateInfo>, FirmwareError> {
    let mut updates: Vec<UpdateInfo> = Vec::new();
    for var in variables {
        // Must be a fwupd state variable.
        if var.vendor != FWUPDATE_VENDOR {
            continue;
        }

        let name: CString16 = match var.name() {
            Ok(n) => n.to_owned(),
            Err(err) => {
                error!("could not get variable name: {err}");
                continue;
            }
        };

        // Skip fwupd-efi debugging settings.
        if name == FWUPDATE_VERBOSE || name == FWUPDATE_DEBUG_LOG {
            continue;
        }

        if updates.len() > MAX_UPDATE_CAPSULES {
            warn!("too many updates, ignoring {name}");
        }

        info!("found update {name}");

        let (data, attrs) = st
            .runtime_services()
            .get_variable_boxed(&name, &FWUPDATE_VENDOR)
            .map_err(|err| FirmwareError::GetVariableFailed(err.status()))?;

        let mut info = match UpdateInfo::new(name.clone(), attrs, data) {
            Ok(info) => info,
            Err(err) => {
                // Delete the malformed variable. If this fails, log the
                // error but otherwise ignore it.
                if let Err(err) = st
                    .runtime_services()
                    .delete_variable(&name, &FWUPDATE_VENDOR)
                {
                    warn!(
                        "failed to delete variable {name}-{vendor}: {err}",
                        vendor = FWUPDATE_VENDOR.0
                    );
                }

                warn!("could not populate update info for {name}");
                return Err(err);
            }
        };

        if (info.status() & FWUPDATE_ATTEMPT_UPDATE) != 0 {
            info.update_time_attempted(st.runtime_services());
            info.set_status(FWUPDATE_ATTEMPTED);
            updates.push(info);
        }
    }
    Ok(updates)
}

/// Mark all updates as [`FWUPDATE_ATTEMPTED`] and note the time of the attempt.
fn set_update_statuses(
    st: &SystemTable<Boot>,
    updates: &[UpdateInfo],
) -> Result<(), FirmwareError> {
    for update in updates {
        st.runtime_services()
            .set_variable(&update.name, &FWUPDATE_VENDOR, update.attrs, &update.data)
            .map_err(|err| {
                warn!(
                    "could not update variable status for {0}: {err}",
                    update.name
                );
                FirmwareError::SetVariableFailed(err.status())
            })?;
    }
    Ok(())
}

pub fn update_firmware(st: &SystemTable<Boot>) -> Result<(), FirmwareError> {
    let variables = st
        .runtime_services()
        .variable_keys()
        .map_err(|err| FirmwareError::GetVariableKeysFailed(err.status()))?;
    // Check if any updates are available by searching for and validating
    // any update state variables.
    let updates = get_update_table(st, variables)?;

    if updates.is_empty() {
        info!("no firmware updates available");
        return Ok(());
    }

    let _ = disk::open_stateful_partition(st.boot_services());

    // TODO(b/338423918): Create update capsules from each
    // [`UpdateInfo`]. In particular, implement the translation from
    // [`UpdateInfo::path`]` to its actual location on the stateful
    // partition. For now, just print the update info.
    for update in &updates {
        info!("update {} path: {:?}", update.name, update.device_path());
    }

    set_update_statuses(st, &updates)

    // TODO(b/338423918): Apply the update capsules and reboot.
}

#[cfg(test)]
mod tests {
    use super::*;
    use uefi::proto::device_path::build::{self, DevicePathBuilder};
    use uefi::proto::device_path::media::{PartitionFormat, PartitionSignature};

    #[test]
    fn test_update_info() {
        // This test file is a direct copy of an efivarfs file created
        // by `fwupd install`.
        let data = include_bytes!(
            "../test_data/\
            fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523-0-0abba7dc-e516-4167-bbf5-4d9d1c739416"
        );
        let name = cstr16!("fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523-0").to_owned();
        // Efivarfs stores the UEFI variable attributes in the first
        // four bytes.
        let attrs = VariableAttributes::from_bits_retain(u32::from_le_bytes(
            data[0..4].try_into().unwrap(),
        ));
        let data = &data[4..];

        let mut info = UpdateInfo::new(name, attrs, data.to_vec().into_boxed_slice()).unwrap();

        // Create the expected device path.
        let mut storage = Vec::new();
        let expected_path = DevicePathBuilder::with_vec(&mut storage)
            .push(&build::media::HardDrive {
                partition_number: 12,
                partition_start: 0,
                partition_size: 0,
                partition_signature: PartitionSignature::Guid(guid!(
                    "99cc6f39-2fd1-4d85-b15a-543e7b023a1f"
                )),
                partition_format: PartitionFormat::GPT,
            })
            .unwrap()
            .push(&build::media::FilePath {
                path_name: cstr16!(
                    r"\EFI\chromeos\fw\fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523.cap"
                ),
            })
            .unwrap()
            .finalize()
            .unwrap();

        assert_eq!(info.device_path(), expected_path);
        assert_eq!(info.status(), FWUPDATE_ATTEMPT_UPDATE);

        // Check setting the status.
        info.set_status(123);
        assert_eq!(info.status(), 123);
    }
}
