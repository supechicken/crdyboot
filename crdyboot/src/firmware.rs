// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(clippy::indexing_slicing)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use core::mem::size_of;
use log::{error, info, warn};
use uefi::prelude::*;
use uefi::proto::device_path::DevicePath;
use uefi::table::runtime::{CapsuleFlags, Time, VariableAttributes, VariableKey, VariableVendor};
use uefi::{guid, CStr16, CString16, Guid};

const FWUPDATE_ATTEMPT_UPDATE: u32 = 0x0000_0001;
const FWUPDATE_ATTEMPTED: u32 = 0x0000_0002;

const FWUPDATE_VENDOR: VariableVendor =
    VariableVendor(guid!("0abba7dc-e516-4167-bbf5-4d9d1c739416"));

const FWUPDATE_VERBOSE: &CStr16 = cstr16!("FWUPDATE_VERBOSE");
const FWUPDATE_DEBUG_LOG: &CStr16 = cstr16!("FWUPDATE_DEBUG_LOG");

const MAX_UPDATE_CAPSULES: usize = 128;

/// This struct closely matches the format of the data written to UEFI
/// vars by the fwupd UEFI plugin [1], with an exception noted below. It
/// is used to create an update capsule.
///
/// [`UpdateInfo::path`] is stored by reference rather than value, however
/// this is accounted for by both [`UpdateInfo::to_bytes`] and
/// [`TryFrom<&[u8]>`] for [`UpdateInfo`].
///
/// [1]: https://github.com/fwupd/fwupd/tree/main/plugins/uefi-capsule
struct UpdateInfo<'a> {
    // Version of UpdateInfo struct.
    version: u32,

    // Info needed to apply an update.
    efi_guid: Guid,
    capsule_flags: CapsuleFlags,
    hw_inst: u64,

    // Metadata used by fwupd to determine whether and when an update was attempted.
    time_attempted: Time,
    status: u32,

    // Path to firmware update blob.
    path: &'a DevicePath,
}

impl UpdateInfo<'_> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(52);
        bytes.extend(self.version.to_le_bytes());
        bytes.extend(self.efi_guid.to_bytes());
        bytes.extend(self.capsule_flags.bits().to_le_bytes());
        bytes.extend(self.hw_inst.to_le_bytes());
        bytes.extend(self.time_attempted.year().to_le_bytes());

        bytes.push(self.time_attempted.month());
        bytes.push(self.time_attempted.day());
        bytes.push(self.time_attempted.hour());
        bytes.push(self.time_attempted.minute());
        bytes.push(self.time_attempted.second());
        bytes.push(0);
        bytes.extend(self.time_attempted.nanosecond().to_le_bytes());
        let time_zone = self.time_attempted.time_zone().unwrap_or(0x07ff);
        bytes.extend(time_zone.to_le_bytes());
        bytes.push(self.time_attempted.daylight().bits());
        bytes.push(0);

        bytes.extend(self.status.to_le_bytes());
        bytes.extend(self.path.as_bytes());

        bytes
    }
}

impl<'a> TryFrom<&[u8]> for UpdateInfo<'a> {
    type Error = uefi::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if size_of::<UpdateInfo>() <= bytes.len() {
            let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            let efi_guid = Guid::from_bytes(bytes[4..20].try_into().unwrap());
            let raw_flag_bits = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
            let capsule_flags = CapsuleFlags::from_bits_retain(raw_flag_bits);
            let hw_inst = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
            let time = &bytes[32..48];
            // fwupd sometimes has invalid EFI_TIME structs in its vars.
            // We update the time anyways, so just continue.
            let time_attempted = Time::try_from(time).unwrap_or(Time::invalid());
            let status = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
            let path = <&DevicePath>::try_from(&bytes[52..])
                .map_err(|_| uefi::Error::from(Status::INVALID_PARAMETER))?;

            let update = UpdateInfo {
                version,
                efi_guid,
                capsule_flags,
                hw_inst,
                time_attempted,
                status,
                path,
            };
            Ok(update)
        } else {
            Err(uefi::Error::from(Status::INVALID_PARAMETER))
        }
    }
}

/// A complete firmware update.
struct UpdateTable<'a> {
    // Name of the update's associated UEFI variable.
    name: CString16,
    // The attributes of the update's associated UEFI variable.
    attrs: VariableAttributes,
    // The info needed to create an update capsule.
    info: UpdateInfo<'a>,
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
) -> uefi::Result<Vec<UpdateTable>> {
    let mut updates: Vec<UpdateTable> = Vec::new();
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
            .get_variable_boxed(&name, &FWUPDATE_VENDOR)?;

        let mut info = match UpdateInfo::try_from(&*data) {
            Ok(i) => i,
            Err(err) => {
                st.runtime_services()
                    .delete_variable(&name, &FWUPDATE_VENDOR)?;
                warn!("could not populate update info for {name}");
                return Err(err);
            }
        };

        if (info.status & FWUPDATE_ATTEMPT_UPDATE) != 0 {
            info.time_attempted = st.runtime_services().get_time()?;
            info.status = FWUPDATE_ATTEMPTED;
            updates.push(UpdateTable { name, attrs, info });
        }
    }
    Ok(updates)
}

/// Mark all updates as [`FWUPDATE_ATTEMPTED`] and note the time of the attempt.
fn set_update_statuses(st: &SystemTable<Boot>, updates: &Vec<UpdateTable>) -> uefi::Result {
    for update in updates {
        if let Err(err) = st.runtime_services().set_variable(
            &update.name,
            &FWUPDATE_VENDOR,
            update.attrs,
            &update.info.to_bytes(),
        ) {
            warn!(
                "could not update variable status for {0}: {err}",
                update.name
            );
            return Err(err);
        };
    }
    Ok(())
}

pub fn update_firmware(st: &SystemTable<Boot>) -> uefi::Result {
    let variables = st.runtime_services().variable_keys()?;
    // Check if any updates are available by searching for and validating
    // any update state variables.
    let updates = get_update_table(st, variables)?;

    if updates.is_empty() {
        info!("no firmware updates available");
        return Ok(());
    }

    // TODO(b/338423918): Create update capsules from each
    // [`UpdateInfo`]. In particular, implement the translation from
    // [`UpdateInfo::path`]` to its actual location on the stateful
    // partition.

    set_update_statuses(st, &updates)

    // TODO(b/338423918): Apply the update capsules and reboot.
}
