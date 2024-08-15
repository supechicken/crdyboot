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
use log::{error, info};
use uefi::prelude::*;
use uefi::table::runtime::{CapsuleBlockDescriptor, CapsuleHeader, ResetType};
use uefi::Status;
use update_info::{get_update_table, set_update_statuses, UpdateInfo};

#[derive(Debug)]
enum FirmwareError {
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
    UpdateCapsuleFailed(Status),
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
            Self::UpdateCapsuleFailed(status) => {
                write!(f, "firmware capsule update failed: {status}")
            }
        }
    }
}

/// Ask the firmware what type of system reset is needed for capsule updates.
///
/// If an error occurs, default to [`ResetType::WARM`].
fn get_reset_type(runtime_services: &RuntimeServices, capsules: &[&CapsuleHeader]) -> ResetType {
    match runtime_services.query_capsule_capabilities(capsules) {
        Ok(capabilities) => {
            info!("query capsule capabilities: {capabilities:?}");
            capabilities.reset_type
        }
        Err(err) => {
            info!("query capsule capabilities failed: {err}");
            ResetType::WARM
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

/// Get a `Vec` of `CapsuleBlockDescriptor` from the list of capsule
/// headers.
///
/// This is used as the "scatter gather list" argument to
/// `update_capsule`. The vec is terminated with an all-zero sentinel
/// value, as required by the spec.
fn get_capsule_block_descriptors(capsules: &[&CapsuleHeader]) -> Vec<CapsuleBlockDescriptor> {
    // One entry for each capsule, plus a sentinel value at the end.
    //
    // OK to unwrap: the number of capsules is capped to a relatively
    // low value (see `MAX_UPDATE_CAPSULES` in update_info.rs).
    let len = capsules.len().checked_add(1).unwrap();

    let mut descriptors: Vec<CapsuleBlockDescriptor> = Vec::with_capacity(len);

    for capsule in capsules {
        let capsule_ptr: *const CapsuleHeader = *capsule;
        descriptors.push(CapsuleBlockDescriptor {
            length: u64::from(capsule.capsule_image_size),
            address: capsule_ptr as u64,
        });
    }

    // Add sentinel value of all zeroes to terminate the list.
    descriptors.push(CapsuleBlockDescriptor {
        length: 0,
        address: 0,
    });

    descriptors
}

/// Try to install firmware update capsules, if any are present.
///
/// If successful, the system will reset and this function will never
/// return.
///
/// Some errors are logged but otherwise ignored, with the intent of
/// processing as many valid capsules as possible. Fatal errors are
/// propagated to the caller.
fn update_firmware_impl(st: &SystemTable<Boot>) -> Result<(), FirmwareError> {
    let variables = st
        .runtime_services()
        .variable_keys()
        .map_err(|err| FirmwareError::GetVariableKeysFailed(err.status()))?;
    // Check if any updates are available by searching for and validating
    // any update state variables.
    let updates = get_update_table(st, variables)?;
    info!("found {} capsule update variables", updates.len());

    let capsules = load_capsules_from_disk(st.boot_services(), &updates)?;
    info!("loaded {} capsules from disk", capsules.len());

    let capsule_refs = get_capsule_refs(&capsules);
    info!("got {} valid capsule headers", capsule_refs.len());

    let descriptors = get_capsule_block_descriptors(&capsule_refs);

    set_update_statuses(st, &updates)?;

    // If there are no capsules at this point then there's nothing left to do.
    if capsule_refs.is_empty() {
        return Ok(());
    }

    let reset_type = get_reset_type(st.runtime_services(), &capsule_refs);

    info!("calling update_capsule");
    st.runtime_services()
        .update_capsule(&capsule_refs, &descriptors)
        .map_err(|err| FirmwareError::UpdateCapsuleFailed(err.status()))?;

    info!("resetting the system: {reset_type:?}");
    st.runtime_services()
        .reset(reset_type, Status::SUCCESS, None);
}

/// Try to install firmware update capsules, if any are present.
///
/// If successful, the system will reset and this function will never
/// return.
///
/// Errors are logged but otherwise ignored.
pub fn update_firmware(st: &SystemTable<Boot>) {
    if let Err(err) = update_firmware_impl(st) {
        error!("firmware update failed: {err}");
    }
}
