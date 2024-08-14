// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::firmware::FirmwareError;
use alloc::boxed::Box;
use alloc::string::String;
use core::ops::Range;
use core::{mem, ptr, slice};
use ext4_view::PathBuf;
use log::warn;
use uefi::proto::device_path::{DevicePath, DevicePathNodeEnum};
use uefi::table::runtime::{RuntimeServices, Time, VariableAttributes};
use uefi::CString16;

/// Info for a single capsule update, provided by fwupd's [uefi-capsule]
/// plugin via a UEFI variable.
///
/// [uefi-capsule]: https://github.com/fwupd/fwupd/tree/main/plugins/uefi-capsule
#[derive(Debug, Eq, PartialEq)]
pub struct UpdateInfo {
    /// Name of the update's UEFI variable.
    pub name: CString16,

    /// Attributes of the update's UEFI variable.
    pub attrs: VariableAttributes,

    /// Raw data from the variable.
    pub data: Box<[u8]>,
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
    pub fn new(
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
    pub fn update_time_attempted(&mut self, rt: &RuntimeServices) {
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

    pub fn status(&self) -> u32 {
        u32::from_le_bytes(self.data[Self::STATUS_RANGE].try_into().unwrap())
    }

    pub fn set_status(&mut self, status: u32) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use uefi::proto::device_path::build::{self, DevicePathBuilder};
    use uefi::proto::device_path::media::{PartitionFormat, PartitionSignature};
    use uefi::{cstr16, guid};

    #[test]
    fn test_update_info() {
        // This test file is a direct copy of an efivarfs file created
        // by `fwupd install`.
        let data = include_bytes!(
            "../../test_data/\
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
        assert_eq!(info.status(), super::super::FWUPDATE_ATTEMPT_UPDATE);

        // Check setting the status.
        info.set_status(123);
        assert_eq!(info.status(), 123);

        assert_eq!(
            info.file_path().unwrap(),
            "EFI/chromeos/fw/fwupd-61b65ccc-0116-4b62-80ed-ec5f089ae523.cap"
        );
    }
}
