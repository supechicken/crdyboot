// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use alloc::boxed::Box;
use uefi::runtime::{self, Time, VariableAttributes, VariableVendor};
use uefi::CStr16;

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
}
