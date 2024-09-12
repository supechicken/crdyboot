// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use alloc::boxed::Box;
use core::ops::Deref;
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::proto::device_path::DevicePath;
use uefi::runtime::{self, Time, VariableAttributes, VariableVendor};
use uefi::{CStr16, Handle};

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
