// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use log::{info, LevelFilter};
use uefi::runtime::{self, VariableAttributes, VariableVendor};
use uefi::{cstr16, guid, CStr16};

// These constants match shim.
const SBAT_VAR_NAME: &CStr16 = cstr16!("SbatLevel");
const SBAT_VAR_VENDOR: VariableVendor =
    VariableVendor(guid!("605dab50-e046-4300-abb6-3dd810dd8b23"));
const SBAT_RT_VAR_NAME: &CStr16 = cstr16!("SbatLevelRT");
const SBAT_RT_VAR_ATTRS: VariableAttributes =
    VariableAttributes::BOOTSERVICE_ACCESS.union(VariableAttributes::RUNTIME_ACCESS);

/// If verbose logging is enabled, copy the `SbatLevel` UEFI variable to
/// a runtime-accessible UEFI variable called `SbatLevelRT`.
///
/// This is helpful for seeing what SBAT revocations are currently
/// installed while the OS is running, since the `SbatLevel` variable
/// cannot be accessed from the OS.
pub fn maybe_copy_sbat_revocations() {
    // Do nothing if verbose logging isn't enabled. This ensures that in
    // a normal end-user boot this function does nothing and takes
    // essentially no time.
    if log::max_level() != LevelFilter::Debug {
        return;
    }

    // Read SbatLevel.
    let sbat_level = match runtime::get_variable_boxed(SBAT_VAR_NAME, &SBAT_VAR_VENDOR) {
        Ok((sbat_level, _attrs)) => sbat_level,
        Err(err) => {
            info!("failed to read {SBAT_VAR_NAME}: {err}");
            return;
        }
    };

    // Write SbatLevel to SbatLevelRT.
    match runtime::set_variable(
        SBAT_RT_VAR_NAME,
        &SBAT_VAR_VENDOR,
        SBAT_RT_VAR_ATTRS,
        &sbat_level,
    ) {
        Ok(()) => info!("copied {} to {}", SBAT_VAR_NAME, SBAT_RT_VAR_NAME),
        Err(err) => info!("failed to write {SBAT_RT_VAR_NAME}: {err}"),
    }
}
