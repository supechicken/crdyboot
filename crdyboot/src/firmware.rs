// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(clippy::indexing_slicing)]

mod load_capsules;
mod update_info;

use crate::disk::GptDiskError;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};
use core::mem;
use ext4_view::{Ext4Error, PathError};
use libcrdy::util::u32_to_usize;
use load_capsules::load_capsules_from_disk;
use log::info;
use uefi::prelude::*;
use uefi::table::runtime::CapsuleHeader;
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
    CapsuleNotAligned,
    CapsuleTooSmall { required: usize, actual: usize },
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
            Self::CapsuleNotAligned => write!(f, "capsule is not aligned"),
            Self::CapsuleTooSmall { required, actual } => {
                write!(f, "capsule is too small: {actual} < {required}")
            }
        }
    }
}

/// Get a `CapsuleHeader` reference from raw bytes.
fn get_one_capsule_ref(capsule: &[u8]) -> Result<&CapsuleHeader, FirmwareError> {
    // Make sure the capsule data is large enough to contain the header.
    if capsule.len() < mem::size_of::<CapsuleHeader>() {
        return Err(FirmwareError::CapsuleTooSmall {
            required: mem::size_of::<CapsuleHeader>(),
            actual: capsule.len(),
        });
    }

    // Check the alignment to make sure it matches CapsuleHeader. Since
    // all UEFI allocations are 8-byte aligned, this should never fail.
    let capsule_ptr: *const CapsuleHeader = capsule.as_ptr().cast();
    // TODO(nicholasbishop): starting in Rust 1.79 can use `is_aligned` here.
    if capsule_ptr.align_offset(mem::align_of::<CapsuleHeader>()) != 0 {
        return Err(FirmwareError::CapsuleNotAligned);
    }

    // SAFETY: the pointed-to data is aligned and large enough to be
    // a `CapsuleHeader`.
    let capsule_ref: &CapsuleHeader = unsafe { &*capsule_ptr };

    // The header contains the expected size of the full capsule; make
    // sure that enough data is present.
    let required_size = u32_to_usize(capsule_ref.capsule_image_size);
    if required_size < capsule.len() {
        return Err(FirmwareError::CapsuleTooSmall {
            required: required_size,
            actual: capsule.len(),
        });
    }

    Ok(capsule_ref)
}

/// Get a `Vec` of `CapsuleHeader` references from the list of raw
/// capsule bytes.
///
/// Any capsules that are not valid are skipped.
fn get_capsule_refs(capsules: &[Vec<u8>]) -> Vec<&CapsuleHeader> {
    let mut capsule_refs: Vec<&CapsuleHeader> = Vec::with_capacity(capsules.len());
    for capsule in capsules {
        match get_one_capsule_ref(capsule) {
            Ok(capsule_ref) => capsule_refs.push(capsule_ref),
            Err(err) => info!("failed to get capsule ref: {err}"),
        }
    }

    capsule_refs
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

    let capsules = load_capsules_from_disk(st.boot_services(), &updates)?;
    let _capsule_refs = get_capsule_refs(&capsules);

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
