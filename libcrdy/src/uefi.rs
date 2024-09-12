// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use alloc::boxed::Box;
use core::ops::Deref;
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::proto::device_path::DevicePath;
use uefi::proto::media::partition::{self, GptPartitionEntry, MbrPartitionRecord};
use uefi::runtime::{self, Time, VariableAttributes, VariableVendor};
use uefi::{CStr16, Handle, Status};

/// Interface for accessing UEFI boot services and UEFI runtime services.
///
/// The implementation used at runtime is normally `UefiImpl`; unit
/// tests can use `MockUefi` instead.
#[cfg_attr(feature = "test_util", mockall::automock)]
pub trait Uefi {
    fn get_time(&self) -> uefi::Result<Time>;

    fn get_variable_boxed(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
    ) -> uefi::Result<(Box<[u8]>, VariableAttributes)>;

    fn delete_variable(&self, name: &CStr16, vendor: &VariableVendor) -> uefi::Result;

    fn device_path_for_handle(&self, handle: Handle) -> uefi::Result<ScopedDevicePath>;

    fn partition_info_for_handle(&self, handle: Handle) -> uefi::Result<PartitionInfo>;
}

pub struct UefiImpl;

impl Uefi for UefiImpl {
    fn get_time(&self) -> uefi::Result<Time> {
        runtime::get_time()
    }

    fn get_variable_boxed(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
    ) -> uefi::Result<(Box<[u8]>, VariableAttributes)> {
        runtime::get_variable_boxed(name, vendor)
    }

    fn delete_variable(&self, name: &CStr16, vendor: &VariableVendor) -> uefi::Result {
        runtime::delete_variable(name, vendor)
    }

    fn device_path_for_handle(&self, handle: Handle) -> uefi::Result<ScopedDevicePath> {
        // Safety: this protocol cannot be opened in exclusive
        // mode. This is OK here as device paths are immutable.
        unsafe {
            boot::open_protocol(
                OpenProtocolParams {
                    handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .map(ScopedDevicePath::Protocol)
    }

    fn partition_info_for_handle(&self, handle: Handle) -> uefi::Result<PartitionInfo> {
        // Use non-exclusive mode because opening disk handles in
        // exclusive mode can be slow.
        //
        // Safety: the protocol is closed within this function, and
        // there is no risk of it being mutated by other code during
        // this function call.
        let info = unsafe {
            boot::open_protocol::<partition::PartitionInfo>(
                OpenProtocolParams {
                    handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }?;

        if let Some(gpt) = info.gpt_partition_entry() {
            Ok(PartitionInfo::Gpt(*gpt))
        } else if let Some(mbr) = info.mbr_partition_record() {
            Ok(PartitionInfo::Mbr(*mbr))
        } else {
            // This should never happen in practice.
            Err(Status::UNSUPPORTED.into())
        }
    }
}

/// Wrapper around `ScopedProtocol<DevicePath>` that allows for mocking.
#[derive(Debug)]
pub enum ScopedDevicePath {
    Protocol(ScopedProtocol<DevicePath>),
    #[cfg(feature = "test_util")]
    Boxed(Box<DevicePath>),
}

impl Deref for ScopedDevicePath {
    type Target = DevicePath;

    fn deref(&self) -> &DevicePath {
        match self {
            Self::Protocol(p) => p,
            #[cfg(feature = "test_util")]
            Self::Boxed(b) => b,
        }
    }
}

#[derive(Clone)]
pub enum PartitionInfo {
    Mbr(MbrPartitionRecord),
    Gpt(GptPartitionEntry),
}
