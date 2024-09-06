// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::firmware::FirmwareError;
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;
use core::{mem, ptr, slice};
use ext4_view::PathBuf;
use log::{error, info, warn};
use uefi::proto::device_path::{DevicePath, DevicePathNodeEnum};
use uefi::runtime::{self, Time, VariableAttributes, VariableKey, VariableVendor};
use uefi::{cstr16, guid, CStr16, CString16};

const FWUPDATE_ATTEMPT_UPDATE: u32 = 0x0000_0001;
const FWUPDATE_ATTEMPTED: u32 = 0x0000_0002;

const FWUPDATE_VENDOR: VariableVendor =
    VariableVendor(guid!("0abba7dc-e516-4167-bbf5-4d9d1c739416"));

const FWUPDATE_VERBOSE: &CStr16 = cstr16!("FWUPDATE_VERBOSE");
const FWUPDATE_DEBUG_LOG: &CStr16 = cstr16!("FWUPDATE_DEBUG_LOG");

const MAX_UPDATE_CAPSULES: usize = 128;

/// Info for a single capsule update, provided by fwupd's [uefi-capsule]
/// plugin via a UEFI variable.
///
/// [uefi-capsule]: https://github.com/fwupd/fwupd/tree/main/plugins/uefi-capsule
#[derive(Debug, Eq, PartialEq)]
pub struct UpdateInfo {
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

    /// Set the `time_attempted` field to `time`.
    fn set_time_attempted(&mut self, time: Time) {
        self.data[Self::TIME_ATTEMPTED_RANGE].copy_from_slice(time_to_bytes(&time));
    }

    /// Get the UEFI variable name.
    pub fn name(&self) -> &CStr16 {
        &self.name
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

    /// Get the file path of the update capsule.
    ///
    /// The path is extracted from the final node of the device
    /// path. The path is converted from a Windows-style path to a
    /// Unix-style path, and made relative instead of absolute.
    pub fn file_path(&self) -> Result<PathBuf, FirmwareError> {
        let device_path = self.device_path();

        // Get the last node, which should be a file path node.
        let Some(DevicePathNodeEnum::MediaFilePath(path)) = device_path
            .node_iter()
            .last()
            .and_then(|node| node.as_enum().ok())
        else {
            return Err(FirmwareError::FilePathMissing);
        };

        // The file path node contains an unaligned UCS-2 string.
        // Convert it to a `CString16`.
        let path = path
            .path_name()
            .to_cstring16()
            .map_err(|_| FirmwareError::FilePathEncodingInvalid)?;

        // Convert from UCS-2 to UTF-8.
        let path = String::from(&path);

        // Convert path separator style from Windows to Unix.
        let path = path.replace('\\', "/");

        // Make the path relative instead of absolute.
        let path = path.trim_start_matches('/');

        PathBuf::try_from(path).map_err(FirmwareError::FilePathInvalid)
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

/// Get the current time via runtime services. If an error occurs, log
/// the error and return `None`.
fn current_time() -> Option<Time> {
    match runtime::get_time() {
        Ok(time) => Some(time),
        Err(err) => {
            warn!("failed to get current time: {err}");
            None
        }
    }
}

/// Get a list of all available updates by iterating through all UEFI
/// variables, searching for those with the [`FWUPDATE_VENDOR`]
/// GUID. Any such variables will be parsed into an [`UpdateInfo`], from
/// which an update can be applied.
///
/// If no updates are found, an empty vector is returned.
///
/// Any UEFI error causes early termination and the error to be returned.
pub fn get_update_table(variables: Vec<VariableKey>) -> Result<Vec<UpdateInfo>, FirmwareError> {
    let now = current_time();

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

        let (data, attrs) = runtime::get_variable_boxed(&name, &FWUPDATE_VENDOR)
            .map_err(|err| FirmwareError::GetVariableFailed(err.status()))?;

        let mut info = match UpdateInfo::new(name.clone(), attrs, data) {
            Ok(info) => info,
            Err(err) => {
                // Delete the malformed variable. If this fails, log the
                // error but otherwise ignore it.
                if let Err(err) = runtime::delete_variable(&name, &FWUPDATE_VENDOR) {
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
            if let Some(now) = now {
                info.set_time_attempted(now);
            }
            info.set_status(FWUPDATE_ATTEMPTED);
            updates.push(info);
        }
    }
    Ok(updates)
}

/// Mark all updates as [`FWUPDATE_ATTEMPTED`] and note the time of the attempt.
pub fn set_update_statuses(updates: &[UpdateInfo]) -> Result<(), FirmwareError> {
    for update in updates {
        runtime::set_variable(&update.name, &FWUPDATE_VENDOR, update.attrs, &update.data).map_err(
            |err| {
                warn!(
                    "could not update variable status for {0}: {err}",
                    update.name
                );
                FirmwareError::SetVariableFailed(err.status())
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uefi::proto::device_path::build::{self, DevicePathBuilder};
    use uefi::proto::device_path::media::{PartitionFormat, PartitionSignature};
    use uefi::runtime::{Daylight, TimeParams};

    static VAR_NAME: &CStr16 = cstr16!("fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523-0");

    fn create_update_info() -> UpdateInfo {
        // This test file is a direct copy of an efivarfs file created
        // by `fwupd install`.
        let data = include_bytes!(
            "../../test_data/\
            fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523-0-0abba7dc-e516-4167-bbf5-4d9d1c739416"
        );
        // Efivarfs stores the UEFI variable attributes in the first
        // four bytes.
        let attrs = VariableAttributes::from_bits_retain(u32::from_le_bytes(
            data[0..4].try_into().unwrap(),
        ));
        let data = &data[4..];

        UpdateInfo::new(VAR_NAME.to_owned(), attrs, data.to_vec().into_boxed_slice()).unwrap()
    }

    #[test]
    fn test_update_info_construction() {
        // Successful construction.
        create_update_info();

        // Error: not enough data.
        assert!(matches!(
            UpdateInfo::new(
                VAR_NAME.to_owned(),
                VariableAttributes::empty(),
                vec![].into_boxed_slice()
            )
            .unwrap_err(),
            FirmwareError::UpdateInfoTooShort
        ));
    }

    #[test]
    fn test_update_info_device_path() {
        let info = create_update_info();

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
    }

    #[test]
    fn test_update_info_file_path() {
        let info = create_update_info();

        assert_eq!(
            info.file_path().unwrap(),
            "EFI/chromeos/fw/fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523.cap"
        );
    }

    #[test]
    fn test_update_info_status() {
        let mut info = create_update_info();

        assert_eq!(info.status(), FWUPDATE_ATTEMPT_UPDATE);

        info.set_status(123);
        assert_eq!(info.status(), 123);
    }

    #[test]
    fn test_update_info_name() {
        let info = create_update_info();
        assert_eq!(info.name(), VAR_NAME);
    }

    #[test]
    fn test_time_to_bytes() {
        let time = Time::new(TimeParams {
            year: 2024,
            month: 9,
            day: 6,
            hour: 11,
            minute: 13,
            second: 45,
            nanosecond: 123,
            time_zone: Some(3),
            daylight: Daylight::IN_DAYLIGHT,
        })
        .unwrap();

        // Test round-trip conversion.
        let bytes: &[u8] = time_to_bytes(&time);
        assert_eq!(Time::try_from(bytes).unwrap(), time);
    }
}
