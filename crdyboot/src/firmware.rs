// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(clippy::indexing_slicing)]

mod load_capsules;
mod update_info;

use crate::disk::GptDiskError;
use core::fmt::{self, Display, Formatter};
use ext4_view::{Ext4Error, PathError};
use load_capsules::load_capsules_from_disk;
use log::info;
use uefi::prelude::*;
use uefi::Status;
use update_info::{get_update_table, set_update_statuses, UpdateInfo};

#[derive(Debug)]
pub enum FirmwareError {
    GetVariableKeysFailed(Status),
    GetVariableFailed(Status),
    SetVariableFailed(Status),
    UpdateInfoTooShort,
    UpdateInfoMalformedDevicePath,
    FilePathMissing,
    FilePathEncodingInvalid,
    FilePathInvalid(PathError),
    OpenStatefulPartitionFailed(GptDiskError),
    Ext4LoadFailed(Ext4Error),
    Ext4ReadFailed(Ext4Error),
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
            Self::FilePathMissing => {
                write!(f, "file path is not present in update info device path")
            }
            Self::FilePathEncodingInvalid => write!(f, "file path encoding is invalid"),
            Self::FilePathInvalid(err) => write!(f, "file path is not valid for ext4: {err}"),
            Self::OpenStatefulPartitionFailed(err) => {
                write!(f, "failed to open the stateful partition: {err}")
            }
            Self::Ext4LoadFailed(err) => write!(f, "failed to load the stateful filesystem: {err}"),
            Self::Ext4ReadFailed(err) => write!(f, "failed to read an update capsule: {err}"),
        }
    }
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

    let _capsules = load_capsules_from_disk(st.boot_services(), &updates)?;

    // TODO(b/338423918): Create update capsules from each
    // [`UpdateInfo`]. In particular, implement the translation from
    // [`UpdateInfo::path`]` to its actual location on the stateful
    // partition. For now, just print the update info.
    for update in &updates {
        info!("update {} path: {:?}", update.name(), update.file_path());
    }

    set_update_statuses(st, &updates)

    // TODO(b/338423918): Apply the update capsules and reboot.
}
