// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(clippy::indexing_slicing)]

mod load_capsules;
mod update_info;

use crate::disk::GptDiskError;
use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};
use ext4_view::{Ext4Error, PathError};
use load_capsules::load_capsules_from_disk;
use log::{error, info, warn};
use uefi::prelude::*;
use uefi::table::runtime::{VariableKey, VariableVendor};
use uefi::{guid, CStr16, CString16, Status};
use update_info::UpdateInfo;

const FWUPDATE_ATTEMPT_UPDATE: u32 = 0x0000_0001;
const FWUPDATE_ATTEMPTED: u32 = 0x0000_0002;

const FWUPDATE_VENDOR: VariableVendor =
    VariableVendor(guid!("0abba7dc-e516-4167-bbf5-4d9d1c739416"));

const FWUPDATE_VERBOSE: &CStr16 = cstr16!("FWUPDATE_VERBOSE");
const FWUPDATE_DEBUG_LOG: &CStr16 = cstr16!("FWUPDATE_DEBUG_LOG");

const MAX_UPDATE_CAPSULES: usize = 128;

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

    let _capsules = load_capsules_from_disk(st.boot_services(), &updates)?;

    // TODO(b/338423918): Create update capsules from each
    // [`UpdateInfo`]. In particular, implement the translation from
    // [`UpdateInfo::path`]` to its actual location on the stateful
    // partition. For now, just print the update info.
    for update in &updates {
        info!("update {} path: {:?}", update.name, update.file_path());
    }

    set_update_statuses(st, &updates)

    // TODO(b/338423918): Apply the update capsules and reboot.
}
