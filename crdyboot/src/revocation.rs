// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Self-revocation check for crdyboot.
//!
//! This feature is very similar to [SBAT]. The idea is that old
//! versions of crdyboot can be prevented from booting, as long as a
//! newer version of crdyboot has run at least once. This is a form of
//! rollback protection. The revocation variable could also be set
//! through other means outside of crdyboot, although this would be
//! specific to the deployment.
//!
//! Revocation is checked by comparing an embedded level against a level
//! stored in a UEFI variable. A level is just a `u32` number; higher
//! means newer. If the embedded level is lower than the level stored in
//! the UEFI variable, crdyboot considers itself revoked and will not
//! continue boot. If the UEFI variable is not set, or is not set
//! correctly, or is less than the embedded level in the executable, the
//! embedded level is written out to the variable.
//!
//! The revocation check occurs as soon as possible after launching
//! crdyboot, so that security bugs in the more complex parts of
//! crdyboot (i.e. loading, validating, and launching the kernel) can be
//! dealt with by updating to a new version of crdyboot with a higher
//! minimum embedded level.
//!
//! The UEFI variable is only accessible during boot services; when exit
//! boot services is called (early in the Linux kernel's startup
//! process) the variable can no longer be read or written to. This
//! forms a security boundary; once the OS is running a rogue program
//! cannot alter the variable.
//!
//! As mentioned earlier this check is very similar to [SBAT]. Crdyboot
//! also embeds SBAT data so that it can be revoked by shim or by
//! firmware that knows about SBAT (if such a thing is ever
//! implemented); the self-revocation check is complementary and
//! especially useful if crdyboot is used as the first-stage bootloader.
//!
//! # Updating the revocation level
//!
//! In the event that a security vulnerability is found, the
//! executable's embedded revocation level should be updated by
//! incrementing the value of `CRDYBOOT_EXECUTABLE_LEVEL`. The SBAT
//! level should be updated at the same time (a test enforces that these
//! values match).
//!
//! [SBAT]: https://github.com/rhboot/shim/blob/main/SBAT.md

use core::cmp::Ordering;
use core::{fmt, mem};
use libcrdy::uefi::{Uefi, UefiImpl, CRDYBOOT_VAR_VENDOR};
use log::{error, info};
use uefi::prelude::*;
use uefi::runtime::{VariableAttributes, VariableVendor};
use uefi::CStr16;

/// Revocation level.
type Level = u32;

/// Name of the UEFI variable.
const REVOCATION_VAR_NAME: &CStr16 = cstr16!("crdyboot_min_lvl");

/// Attributes of the UEFI variable.
///
/// * `NON_VOLATILE`: the variable must persist between reboots to be
///   useful.
///
/// * `BOOTSERVICE_ACCESS`: the variable can be accessed while boot
///   services are active.
///
/// `RUNTIME_ACCESS` is *not* set, so the variable cannot be accessed
/// after exiting boot services. This acts as a security boundary: once
/// the OS boots nothing can modify the variable.
///
/// Note that use of `union` here is equivalent to using the `|`
/// operator, but works in a const context.
const REVOCATION_VAR_ATTRS: VariableAttributes =
    VariableAttributes::NON_VOLATILE.union(VariableAttributes::BOOTSERVICE_ACCESS);

/// Level of the currently-running executable.
///
/// This should match the SBAT level in `/crdyboot/sbat.csv`; this is
/// enforced by `test_executable_level_matches_sbat`.
///
/// This level should be increased any time a fix is released for a
/// security vulnerability to prevent rollback to older versions.
const CRDYBOOT_EXECUTABLE_LEVEL: Level = 1;

/// Error indicating that the currently-running executable has been
/// revoked.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub struct RevocationError {
    /// Revocation level of the executable.
    pub executable_level: Level,

    /// Revocation level in the UEFI variable.
    pub stored_minimum_level: Level,
}

impl fmt::Display for RevocationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "executable level is less than the stored minimum level: {} < {}",
            self.executable_level, self.stored_minimum_level,
        )
    }
}

struct Revocation<'a> {
    var_access: &'a dyn Uefi,

    var_vendor: &'a VariableVendor,
    var_name: &'a CStr16,
    var_attrs: VariableAttributes,

    /// Level of the currently-running executable.
    executable_level: Level,
}

impl<'a> Revocation<'a> {
    fn new(var_access: &'a dyn Uefi) -> Self {
        Self {
            var_access,

            var_vendor: &CRDYBOOT_VAR_VENDOR,
            var_name: REVOCATION_VAR_NAME,
            var_attrs: REVOCATION_VAR_ATTRS,

            executable_level: CRDYBOOT_EXECUTABLE_LEVEL,
        }
    }

    /// Run the revocation check.
    ///
    /// This reads the UEFI variable and checks it against the
    /// executable's level.
    /// * If the executable's level is less than the stored minimum level, a
    ///   `RevocationError` is returned.
    /// * If the executable's level is greater than the stored minimum level,
    ///   the variable is updated.
    /// * If the UEFI variable is not present, has the wrong attributes,
    ///   or contains invalid data, the variable is created/updated with
    ///   the executable's level. Any errors in creating or updating the
    ///   variable are logged but otherwise ignored, as this indicates
    ///   something is wrong with the firmware or NVRAM space that we
    ///   can't do anything about, and we don't want to block booting
    ///   for that.
    fn check_revocation(&self) -> core::result::Result<(), RevocationError> {
        info!(
            "checking revocation: executable_level={}",
            self.executable_level
        );

        let mut buf = [0; 4];
        match self.get_variable(&mut buf) {
            Ok((data, attrs)) => {
                if attrs == self.var_attrs {
                    if data.len() == mem::size_of::<Level>() {
                        // OK to unwrap, we just checked the length.
                        let data: [u8; 4] = data.try_into().unwrap();
                        let stored_minimum_level = Level::from_le_bytes(data);
                        info!("stored minimum level: {stored_minimum_level}");

                        match self.executable_level.cmp(&stored_minimum_level) {
                            Ordering::Less => Err(RevocationError {
                                executable_level: self.executable_level,
                                stored_minimum_level,
                            }),
                            Ordering::Greater => {
                                info!("no revocation, updating stored minimum level");
                                self.write_variable();
                                Ok(())
                            }
                            Ordering::Equal => {
                                info!("no revocation and not updating stored minimum level");
                                Ok(())
                            }
                        }
                    } else {
                        // The size of the data in the variable is
                        // wrong, so just write it out fresh.
                        info!(
                            "revocation variable has unexpected data length: {:02x?}",
                            data
                        );
                        self.write_variable();
                        Ok(())
                    }
                } else {
                    // The attributes aren't the expected set. Changing
                    // the attributes requires first deleting the
                    // variable, so do that and then write the variable
                    // out again.
                    info!("revocation variable has unexpected attrs: {:?}", attrs);
                    self.delete_variable();
                    self.write_variable();
                    Ok(())
                }
            }
            Err(err) => {
                info!("unable to get revocation variable: {:?}", err.status());
                self.write_variable();
                Ok(())
            }
        }
    }

    /// Read the revocation variable.
    fn get_variable<'b>(
        &self,
        buf: &'b mut [u8; 4],
    ) -> uefi::Result<(&'b [u8], VariableAttributes)> {
        let (size, attrs) = self
            .var_access
            .get_variable(self.var_name, self.var_vendor, buf)
            .discard_errdata()?;
        // OK to unwrap: `size` never exceeds the input buffer length.
        let data = buf.get(..size).unwrap();
        Ok((data, attrs))
    }

    /// Update the revocation variable. Errors are logged but otherwise
    /// ignored (see `check_revocation` for more details).
    fn write_variable(&self) {
        info!(
            "writing revocation variable with value {}",
            self.executable_level
        );
        if let Err(err) = self.var_access.set_variable(
            self.var_name,
            self.var_vendor,
            self.var_attrs,
            &self.executable_level.to_le_bytes(),
        ) {
            error!("failed to write revocation variable: {:?}", err.status());
        }
    }

    /// Delete the revocation variable. Errors are logged but otherwise
    /// ignored (see `check_revocation` for more details).
    fn delete_variable(&self) {
        // Passing in an empty data array deletes the variable.
        info!("deleting revocation variable");
        if let Err(err) =
            self.var_access
                .set_variable(self.var_name, self.var_vendor, self.var_attrs, &[])
        {
            error!("failed to delete revocation variable: {:?}", err.status());
        }
    }
}

/// Check if the currently-running executable has been revoked.
pub fn self_revocation_check() -> Result<(), RevocationError> {
    Revocation::new(&UefiImpl).check_revocation()
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrdy::uefi::MockUefi;

    fn expect_get_variable<const N: usize>(
        uefi: &mut MockUefi,
        data: [u8; N],
        attrs: VariableAttributes,
    ) {
        uefi.expect_get_variable()
            .times(1)
            .withf(|name, vendor, buf| {
                name == REVOCATION_VAR_NAME && *vendor == CRDYBOOT_VAR_VENDOR && buf.len() == 4
            })
            .return_once(move |_, _, buf| {
                buf[..data.len()].copy_from_slice(&data);
                Ok((data.len(), attrs))
            });
    }

    fn expect_get_variable_err(uefi: &mut MockUefi, err: uefi::Error<Option<usize>>) {
        uefi.expect_get_variable()
            .times(1)
            .withf(|name, vendor, buf| {
                name == REVOCATION_VAR_NAME && *vendor == CRDYBOOT_VAR_VENDOR && buf.len() == 4
            })
            .return_once(move |_, _, _| Err(err));
    }

    fn expect_set_variable(uefi: &mut MockUefi, level: Level) {
        uefi.expect_set_variable()
            .times(1)
            .withf(move |name, vendor, attrs, data| {
                name == REVOCATION_VAR_NAME
                    && *vendor == CRDYBOOT_VAR_VENDOR
                    && *attrs == REVOCATION_VAR_ATTRS
                    && data == level.to_le_bytes()
            })
            .return_const(Ok(()));
    }

    fn expect_set_variable_empty(uefi: &mut MockUefi) {
        uefi.expect_set_variable()
            .times(1)
            .withf(move |name, vendor, attrs, data| {
                name == REVOCATION_VAR_NAME
                    && *vendor == CRDYBOOT_VAR_VENDOR
                    && *attrs == REVOCATION_VAR_ATTRS
                    && data.is_empty()
            })
            .return_const(Ok(()));
    }

    /// Test no revocation.
    #[test]
    fn test_no_revocation() {
        let stored_level = 1u32;
        let executable_level = 1u32;

        let mut uefi = MockUefi::new();
        expect_get_variable(&mut uefi, stored_level.to_le_bytes(), REVOCATION_VAR_ATTRS);

        let mut r = Revocation::new(&uefi);
        r.executable_level = executable_level;

        r.check_revocation().unwrap();
    }

    /// Test no revocation, but stored minimum needs update.
    #[test]
    fn test_no_revocation_increase_minimum() {
        let stored_level = 1u32;
        let executable_level = 2u32;

        let mut uefi = MockUefi::new();
        expect_get_variable(&mut uefi, stored_level.to_le_bytes(), REVOCATION_VAR_ATTRS);
        expect_set_variable(&mut uefi, executable_level);

        let mut r = Revocation::new(&uefi);
        r.executable_level = executable_level;

        r.check_revocation().unwrap();
    }

    /// Test revocation.
    #[test]
    fn test_revocation() {
        let stored_level = 2u32;
        let executable_level = 1u32;

        let mut uefi = MockUefi::new();
        expect_get_variable(&mut uefi, stored_level.to_le_bytes(), REVOCATION_VAR_ATTRS);

        let mut r = Revocation::new(&uefi);
        r.executable_level = executable_level;

        // Executable level is 1 but the stored minimum level is 2,
        // so we are revoked.
        assert_eq!(
            r.check_revocation(),
            Err(RevocationError {
                executable_level: 1,
                stored_minimum_level: 2,
            })
        );
    }

    /// Test variable read error.
    #[test]
    fn test_read_error() {
        let executable_level = 2u32;

        let mut uefi = MockUefi::new();
        expect_get_variable_err(&mut uefi, uefi::Error::new(Status::NOT_FOUND, None));
        expect_set_variable(&mut uefi, executable_level);

        let mut r = Revocation::new(&uefi);
        r.executable_level = executable_level;

        r.check_revocation().unwrap();
    }

    /// Test handling of unexpected variable attributes.
    #[test]
    fn test_unexpected_variable_attrs() {
        let stored_level = 1u32;
        let executable_level = 2u32;

        let mut uefi = MockUefi::new();
        expect_get_variable(
            &mut uefi,
            stored_level.to_le_bytes(),
            VariableAttributes::empty(),
        );
        expect_set_variable_empty(&mut uefi);
        expect_set_variable(&mut uefi, executable_level);

        let mut r = Revocation::new(&uefi);
        r.executable_level = executable_level;

        r.check_revocation().unwrap();
    }

    /// Test handling of unexpected variable data.
    #[test]
    fn test_unexpected_variable_data() {
        let executable_level = 2u32;

        let mut uefi = MockUefi::new();
        expect_get_variable(
            &mut uefi,
            // Invalid data; not a u32:
            [1, 2, 3],
            REVOCATION_VAR_ATTRS,
        );
        expect_set_variable(&mut uefi, executable_level);

        let mut r = Revocation::new(&uefi);
        r.executable_level = executable_level;

        r.check_revocation().unwrap();
    }

    /// Test that `CRDYBOOT_EXECUTABLE_LEVEL` matches the crdyboot SBAT
    /// level.
    #[test]
    fn test_executable_level_matches_sbat() {
        let sbat_csv = include_str!("../../crdyboot/sbat.csv");
        let crdyboot_sbat: Vec<_> = sbat_csv.lines().nth(1).unwrap().split(",").collect();
        assert_eq!(crdyboot_sbat[0], "crdyboot");
        assert_eq!(crdyboot_sbat[1], CRDYBOOT_EXECUTABLE_LEVEL.to_string());
    }
}
