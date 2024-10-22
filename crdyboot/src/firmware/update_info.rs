// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::firmware::FirmwareError;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;
use core::{mem, ptr, slice};
use ext4_view::PathBuf;
use libcrdy::uefi::{Uefi, VariableKey, VariableKeys};
use log::{info, warn};
use uefi::proto::device_path::{DevicePath, DevicePathNodeEnum};
use uefi::runtime::{Time, VariableAttributes, VariableVendor};
use uefi::{cstr16, guid, CStr16, CString16};

const FWUPDATE_ATTEMPT_UPDATE: u32 = 0x0000_0001;
const FWUPDATE_ATTEMPTED: u32 = 0x0000_0002;

pub(super) const FWUPDATE_VENDOR: VariableVendor =
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
        let device_path_data = data
            .get(Self::HEADER_SIZE_IN_BYTES..)
            .ok_or(FirmwareError::UpdateInfoTooShort)?;

        // Return an error if the device path is not valid.
        <&DevicePath>::try_from(device_path_data)
            .map_err(|_| FirmwareError::UpdateInfoMalformedDevicePath)?;

        Ok(Self { name, attrs, data })
    }

    /// Set the `time_attempted` field to `time`.
    fn set_time_attempted(&mut self, time: Time) {
        // Length checked in `UpdateInfo::new`.
        #[expect(clippy::indexing_slicing)]
        self.data[Self::TIME_ATTEMPTED_RANGE].copy_from_slice(time_to_bytes(&time));
    }

    /// Get the UEFI variable name.
    pub fn name(&self) -> &CStr16 {
        &self.name
    }

    fn status(&self) -> u32 {
        // Length checked in `UpdateInfo::new`.
        #[expect(clippy::indexing_slicing)]
        u32::from_le_bytes(self.data[Self::STATUS_RANGE].try_into().unwrap())
    }

    fn set_status(&mut self, status: u32) {
        // Length checked in `UpdateInfo::new`.
        #[expect(clippy::indexing_slicing)]
        self.data[Self::STATUS_RANGE].copy_from_slice(&status.to_le_bytes());
    }

    fn device_path(&self) -> &DevicePath {
        // Length checked in `UpdateInfo::new`.
        #[expect(clippy::indexing_slicing)]
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
fn current_time(uefi: &dyn Uefi) -> Option<Time> {
    match uefi.get_time() {
        Ok(time) => Some(time),
        Err(err) => {
            warn!("failed to get current time: {err}");
            None
        }
    }
}

/// Delete a UEFI variable.
///
/// If deletion fails, log the error but otherwise ignore it.
fn delete_variable_no_error(uefi: &dyn Uefi, name: &CStr16, vendor: &VariableVendor) {
    if let Err(err) = uefi.delete_variable(name, vendor) {
        warn!(
            "failed to delete variable {name}-{vendor}: {err}",
            vendor = vendor.0
        );
    }
}

/// Try to read a variable and convert it to an `UpdateInfo`.
///
/// Returns `Ok(Some(_))` if successful, `Ok(None)` for non-update
/// variables, and `Err` if something goes wrong.
///
/// If a variable looks like it should contain update info, but parsing
/// the data fails, the variable will be deleted.
fn get_update_from_var(
    uefi: &dyn Uefi,
    key: uefi::Result<VariableKey>,
) -> Result<Option<UpdateInfo>, FirmwareError> {
    let key = key.map_err(|err| FirmwareError::InvalidVariableKey(err.status()))?;

    // Must be a fwupd state variable.
    if key.vendor != FWUPDATE_VENDOR {
        return Ok(None);
    }

    // Skip fwupd-efi debugging settings.
    if key.name == FWUPDATE_VERBOSE || key.name == FWUPDATE_DEBUG_LOG {
        return Ok(None);
    }

    info!("found update {}", key.name);

    let (data, attrs) = uefi
        .get_variable_boxed(&key.name, &FWUPDATE_VENDOR)
        .map_err(|err| FirmwareError::GetVariableFailed(err.status()))?;

    match UpdateInfo::new(key.name.clone(), attrs, data) {
        Ok(info) => Ok(Some(info)),
        Err(err) => {
            // Delete the malformed variable.
            delete_variable_no_error(uefi, &key.name, &FWUPDATE_VENDOR);

            warn!("could not populate update info for {}", key.name);
            Err(err)
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
/// Errors are logged but otherwise ignored.
pub fn get_update_table(uefi: &dyn Uefi, variables: VariableKeys) -> Vec<UpdateInfo> {
    let now = current_time(uefi);

    let mut updates: Vec<UpdateInfo> = Vec::new();
    for var in variables {
        let mut info = match get_update_from_var(uefi, var.clone()) {
            Ok(Some(info)) => info,
            Ok(None) => {
                // Ignore non-update variable.
                continue;
            }
            Err(err) => {
                // Log the error but otherwise ignore.
                warn!("variable {var:?} is not a valid update variable: {err}");
                continue;
            }
        };

        if (info.status() & FWUPDATE_ATTEMPT_UPDATE) != 0 {
            // Cap the number of updates.
            if updates.len() == MAX_UPDATE_CAPSULES {
                warn!("too many updates, ignoring {}", info.name);
                break;
            }

            if let Some(now) = now {
                info.set_time_attempted(now);
            }
            info.set_status(FWUPDATE_ATTEMPTED);
            updates.push(info);
        }
    }
    updates
}

/// Mark all updates as [`FWUPDATE_ATTEMPTED`] and note the time of the attempt.
pub fn set_update_statuses(uefi: &dyn Uefi, updates: &[UpdateInfo]) -> Result<(), FirmwareError> {
    for update in updates {
        uefi.set_variable(&update.name, &FWUPDATE_VENDOR, update.attrs, &update.data)
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use core::array;
    use libcrdy::uefi::MockUefi;
    use uefi::proto::device_path::build::{self, DevicePathBuilder};
    use uefi::proto::device_path::media::{PartitionFormat, PartitionSignature};
    use uefi::proto::device_path::{DeviceSubType, DeviceType};
    use uefi::runtime::{Daylight, TimeParams};
    use uefi::Status;

    pub(crate) const VAR_NAME: &CStr16 = cstr16!("fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523-0");
    const BAD_VAR_NAME: &CStr16 = cstr16!("fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523-1");
    const NO_ATTEMPT_VAR_NAME: &CStr16 = cstr16!("fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523-2");

    /// This test file is a direct copy of an efivarfs file created by
    /// `fwupd install`. The first four bytes are the variable
    /// attributes, the rest is the variable data which encodes update
    /// info.
    const VAR_DATA: &[u8] = include_bytes!(
        "../../test_data/\
            fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523-0-0abba7dc-e516-4167-bbf5-4d9d1c739416"
    );

    /// Create a valid `UpdateInfo` for testing.
    pub(crate) fn create_update_info() -> UpdateInfo {
        // Efivarfs stores the UEFI variable attributes in the first
        // four bytes.
        let attrs = VariableAttributes::from_bits_retain(u32::from_le_bytes(
            VAR_DATA[0..4].try_into().unwrap(),
        ));
        let data = &VAR_DATA[4..];

        UpdateInfo::new(VAR_NAME.to_owned(), attrs, data.to_vec().into_boxed_slice()).unwrap()
    }

    /// Same as `create_update_info`, but the device path is modified so
    /// that the file extension is `.cax` instead of `.cap`. This is
    /// used to test handling of a capsule that does not exist on disk.
    pub(crate) fn create_update_info_with_modified_path() -> UpdateInfo {
        let mut info = create_update_info();
        info.data[info.data.len() - 8] = b'x';
        assert_eq!(
            info.file_path().unwrap(),
            "EFI/chromeos/fw/fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523.cax"
        );
        info
    }

    /// Same as `create_update_info`, but the device path is modified so
    /// that it does not contain a file path.
    pub(crate) fn create_update_info_with_no_file_path() -> UpdateInfo {
        let mut info = create_update_info();

        // Search for the bytes that encode the type and subtype of a
        // media file path node. Alter the node's subtype so that it is
        // no longer a file path.
        for i in 0..info.data.len() {
            if info.data[i] == DeviceType::MEDIA.0
                && info.data[i + 1] == DeviceSubType::MEDIA_FILE_PATH.0
            {
                info.data[i + 1] = DeviceSubType::MEDIA_VENDOR.0;
            }
        }

        info
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

    /// Test that `UpdateInfo::file_path` fails if the device path does
    /// not end with a media file path.
    #[test]
    fn test_update_info_invalid_file_path() {
        let info = create_update_info_with_no_file_path();

        assert!(matches!(
            info.file_path().unwrap_err(),
            FirmwareError::FilePathMissing
        ));
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

    fn create_time() -> Time {
        Time::new(TimeParams {
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
        .unwrap()
    }

    #[test]
    fn test_update_info_time() {
        let mut info = create_update_info();
        let time = create_time();

        info.set_time_attempted(time);
        assert_eq!(
            Time::try_from(&info.data[UpdateInfo::TIME_ATTEMPTED_RANGE]).unwrap(),
            time
        );
    }

    #[test]
    fn test_time_to_bytes() {
        let time = create_time();

        // Test round-trip conversion.
        let bytes: &[u8] = time_to_bytes(&time);
        assert_eq!(Time::try_from(bytes).unwrap(), time);
    }

    fn create_mock_uefi_with_time() -> MockUefi {
        let mut uefi = MockUefi::new();
        uefi.expect_get_time().return_const(Ok(create_time()));
        uefi
    }

    pub(crate) fn create_mock_uefi_with_get_var() -> MockUefi {
        let mut uefi = create_mock_uefi_with_time();

        uefi.expect_get_variable_boxed().returning(|name, vendor| {
            assert_eq!(*vendor, FWUPDATE_VENDOR);

            let data = if name == VAR_NAME {
                // Valid update info.
                VAR_DATA[4..].to_vec()
            } else if name == NO_ATTEMPT_VAR_NAME {
                let mut data = VAR_DATA[4..].to_vec();
                // Clear the `status` field so that `ATTEMPT_UPDATE` is
                // not set.
                data[UpdateInfo::STATUS_RANGE].copy_from_slice(&[0; 4]);
                data
            } else if name == BAD_VAR_NAME {
                // Invalid update info.
                vec![1, 2, 3]
            } else {
                panic!("unexpected name: {name}");
            };

            let attrs = VariableAttributes::NON_VOLATILE
                | VariableAttributes::BOOTSERVICE_ACCESS
                | VariableAttributes::RUNTIME_ACCESS;
            Ok((data.into_boxed_slice(), attrs))
        });
        uefi
    }

    /// Test that `current_time` returns `None` if an error occurs.
    #[test]
    fn test_current_time_error() {
        let mut uefi = MockUefi::new();
        uefi.expect_get_time()
            .return_const(Err(Status::DEVICE_ERROR.into()));
        assert_eq!(current_time(&uefi), None);
    }

    /// Test successful call to `current_time`.
    #[test]
    fn test_current_time_success() {
        let uefi = create_mock_uefi_with_time();
        assert_eq!(current_time(&uefi), Some(create_time()));
    }

    /// Test that `delete_variable_no_error` does not panic if an error
    /// occurs.
    #[test]
    fn test_delete_variable_no_error() {
        let mut uefi = MockUefi::new();
        uefi.expect_delete_variable().returning(|name, vendor| {
            assert_eq!(name, VAR_NAME);
            assert_eq!(*vendor, FWUPDATE_VENDOR);
            Err(Status::DEVICE_ERROR.into())
        });
        delete_variable_no_error(&uefi, VAR_NAME, &FWUPDATE_VENDOR);
    }

    /// Test that `get_update_from_var` skips variables with a vendor
    /// other than `FWUPDATE_VENDOR`.
    #[test]
    fn test_get_update_from_var_other_vendor() {
        let uefi = create_mock_uefi_with_time();

        let var = Ok(VariableKey::new(
            VAR_NAME,
            VariableVendor(guid!("dfedddc7-c8d3-4250-9e10-0d11d192421b")),
        ));
        assert!(get_update_from_var(&uefi, var).unwrap().is_none());
    }

    /// Test that `get_update_table` ignores `FWUPDATE_VERBOSE` and
    /// `FWUPDATE_DEBUG_LOG`.
    #[test]
    fn test_get_update_from_var_ignore_vars() {
        let uefi = create_mock_uefi_with_time();

        let vars = [
            (Ok(VariableKey::new(FWUPDATE_VERBOSE, FWUPDATE_VENDOR))),
            (Ok(VariableKey::new(FWUPDATE_DEBUG_LOG, FWUPDATE_VENDOR))),
        ];
        for var in vars {
            assert!(get_update_from_var(&uefi, var).unwrap().is_none());
        }
    }

    /// Test that `get_update_from_var` skips variables with an invalid key.
    #[test]
    fn test_get_update_from_var_invalid_key() {
        let uefi = create_mock_uefi_with_time();

        let var = Err(Status::UNSUPPORTED.into());
        assert!(matches!(
            get_update_from_var(&uefi, var),
            Err(FirmwareError::InvalidVariableKey(Status::UNSUPPORTED))
        ));
    }

    /// Test that `get_update_from_var` deletes a variable with invalid
    /// data and returns an error.
    #[test]
    fn test_get_update_from_var_invalid_data() {
        let mut uefi = create_mock_uefi_with_get_var();
        uefi.expect_delete_variable().returning(|name, vendor| {
            assert_eq!(name, BAD_VAR_NAME);
            assert_eq!(*vendor, FWUPDATE_VENDOR);
            Ok(())
        });

        let var = Ok(VariableKey::new(BAD_VAR_NAME, FWUPDATE_VENDOR));
        assert!(matches!(
            get_update_from_var(&uefi, var),
            Err(FirmwareError::UpdateInfoTooShort)
        ));
    }

    /// Test that `get_update_table` returns no updates if there are no
    /// variables.
    #[test]
    fn test_get_update_table_empty() {
        let uefi = create_mock_uefi_with_time();

        let vars = VariableKeys::ForTest(vec![]);
        assert_eq!(get_update_table(&uefi, vars.into_iter()), []);
    }

    /// Test successful call to `get_update_table`.
    #[test]
    fn test_get_update_table() {
        let uefi = create_mock_uefi_with_get_var();

        let mut info = create_update_info();
        info.set_time_attempted(create_time());
        info.set_status(FWUPDATE_ATTEMPTED);

        let vars = VariableKeys::ForTest(vec![Ok(VariableKey::new(VAR_NAME, FWUPDATE_VENDOR))]);
        assert_eq!(get_update_table(&uefi, vars), [info]);
    }

    /// Test that `get_update_table` skips non-update variables,
    /// variables that have some error, and variables that do not have
    /// an ATTEMPT_UPDATE status, while still including successful
    /// variables.
    #[test]
    fn test_get_update_table_skip() {
        let mut uefi = create_mock_uefi_with_get_var();
        uefi.expect_delete_variable().returning(|name, vendor| {
            assert_eq!(name, BAD_VAR_NAME);
            assert_eq!(*vendor, FWUPDATE_VENDOR);
            Ok(())
        });

        let mut info = create_update_info();
        info.set_time_attempted(create_time());
        info.set_status(FWUPDATE_ATTEMPTED);

        let vars = VariableKeys::ForTest(vec![
            Ok(VariableKey::new(BAD_VAR_NAME, FWUPDATE_VENDOR)),
            Ok(VariableKey::new(FWUPDATE_DEBUG_LOG, FWUPDATE_VENDOR)),
            Ok(VariableKey::new(NO_ATTEMPT_VAR_NAME, FWUPDATE_VENDOR)),
            Ok(VariableKey::new(VAR_NAME, FWUPDATE_VENDOR)),
        ]);
        assert_eq!(get_update_table(&uefi, vars.into_iter()), [info]);
    }

    /// Test that `get_update_table` ignores more than
    /// `MAX_UPDATE_CAPSULES` updates.
    #[cfg_attr(miri, ignore)] // This test is quite slow in miri.
    #[test]
    fn test_get_update_table_limit() {
        let uefi = create_mock_uefi_with_get_var();

        let expected: [UpdateInfo; MAX_UPDATE_CAPSULES] = array::from_fn(|_| {
            let mut info = create_update_info();
            info.set_time_attempted(create_time());
            info.set_status(FWUPDATE_ATTEMPTED);
            info
        });

        let vars = VariableKeys::ForTest(vec![
            Ok(VariableKey::new(VAR_NAME, FWUPDATE_VENDOR));
            MAX_UPDATE_CAPSULES + 10
        ]);
        assert_eq!(get_update_table(&uefi, vars), expected);
    }

    /// Test that `set_update_statuses` writes out variables for each
    /// update info.
    #[test]
    fn test_set_update_statuses_success() {
        let expected_attrs = VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS;

        let mut uefi = MockUefi::new();
        for expected_name in [VAR_NAME, cstr16!("update var 2")] {
            uefi.expect_set_variable()
                .withf(move |name, vendor, attrs, _data| {
                    name == expected_name && *vendor == FWUPDATE_VENDOR && *attrs == expected_attrs
                })
                .return_const(Ok(()));
        }

        let info1 = create_update_info();
        let mut info2 = create_update_info();
        info2.name = cstr16!("update var 2").into();
        set_update_statuses(&uefi, &[info1, info2]).unwrap();
    }

    /// Test that `set_update_statuses` stops on the first error and
    /// propagates it.
    #[test]
    fn test_set_update_statuses_error() {
        let mut uefi = MockUefi::new();
        uefi.expect_set_variable()
            .withf(|name, vendor, _attrs, _data| name == VAR_NAME && *vendor == FWUPDATE_VENDOR)
            .return_const(Err(Status::DEVICE_ERROR.into()));

        let info1 = create_update_info();
        let mut info2 = create_update_info();
        info2.name = cstr16!("update var 2").into();
        assert!(matches!(
            set_update_statuses(&uefi, &[info1, info2]),
            Err(FirmwareError::SetVariableFailed(_))
        ));
    }
}
