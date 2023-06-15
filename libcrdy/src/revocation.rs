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

use crate::{Error, Result};
use core::cmp::Ordering;
use core::fmt;
use core::mem;
use log::{error, info};
use uefi::prelude::*;
use uefi::table::runtime::{RuntimeServices, VariableAttributes, VariableVendor};
use uefi::{guid, CStr16};

/// Revocation level.
pub type Level = u32;

/// Name of the UEFI variable.
const REVOCATION_VAR_NAME: &CStr16 = cstr16!("crdyboot_min_lvl");

/// GUID namespace for the UEFI variable. This is an arbitrarily-chosen
/// GUID that henceforth shall be crdyboot's vendor GUID.
const REVOCATION_VAR_VENDOR: VariableVendor =
    VariableVendor(guid!("2a6f93c9-29ea-46bf-b618-271b63baacf3"));

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

/// Trait for reading and writing UEFI variables. The two methods are
/// identical to the interface provided by `RuntimeServices`. This trait
/// is used to allow mocking in unit tests.
pub trait UefiVarAccess {
    /// Get the value and attributes of a UEFI variable.
    fn get_variable<'a>(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        buf: &'a mut [u8],
    ) -> uefi::Result<(&'a [u8], VariableAttributes)>;

    /// Set a UEFI variable, or delete it if `data` is empty.
    fn set_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> uefi::Result;
}

impl UefiVarAccess for RuntimeServices {
    fn get_variable<'a>(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        buf: &'a mut [u8],
    ) -> uefi::Result<(&'a [u8], VariableAttributes)> {
        self.get_variable(name, vendor, buf)
    }

    fn set_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> uefi::Result {
        self.set_variable(name, vendor, attributes, data)
    }
}

/// Error indicating that the currently-running executable has been
/// revoked.
#[derive(Debug, Eq, PartialEq)]
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
    var_access: &'a dyn UefiVarAccess,

    var_vendor: &'a VariableVendor,
    var_name: &'a CStr16,
    var_attrs: VariableAttributes,

    /// Level of the currently-running executable.
    executable_level: Level,
}

impl<'a> Revocation<'a> {
    fn new(var_access: &'a dyn UefiVarAccess) -> Self {
        Self {
            var_access,

            var_vendor: &REVOCATION_VAR_VENDOR,
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
        self.var_access
            .get_variable(self.var_name, self.var_vendor, buf)
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
pub fn self_revocation_check(runtime_services: &RuntimeServices) -> Result<()> {
    Revocation::new(runtime_services)
        .check_revocation()
        .map_err(Error::Revocation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MockVarAccess<'a> {
        test: &'a RevocationTest,
        set_variable_calls: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl<'a> UefiVarAccess for MockVarAccess<'a> {
        fn get_variable<'b>(
            &self,
            name: &CStr16,
            vendor: &VariableVendor,
            buf: &'b mut [u8],
        ) -> uefi::Result<(&'b [u8], VariableAttributes)> {
            assert_eq!(name, REVOCATION_VAR_NAME);
            assert_eq!(vendor, &REVOCATION_VAR_VENDOR);
            let data = &mut buf[0..self.test.get_variable_data.len()];
            data.copy_from_slice(&self.test.get_variable_data);
            self.test
                .get_variable_status
                .to_result_with_val(|| (&*data, self.test.get_variable_attrs))
        }

        fn set_variable(
            &self,
            name: &CStr16,
            vendor: &VariableVendor,
            attributes: VariableAttributes,
            data: &[u8],
        ) -> uefi::Result {
            assert_eq!(name, REVOCATION_VAR_NAME);
            assert_eq!(vendor, &REVOCATION_VAR_VENDOR);
            assert_eq!(
                attributes,
                VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS
            );
            self.set_variable_calls.borrow_mut().push(data.to_vec());
            Ok(())
        }
    }

    /// Inputs and expected outputs for a single revocation test.
    struct RevocationTest {
        executable_level: Level,

        get_variable_data: Vec<u8>,
        get_variable_attrs: VariableAttributes,
        get_variable_status: Status,

        expected_revocation_result: core::result::Result<(), RevocationError>,
        expected_set_variable_calls: Vec<Vec<u8>>,
    }

    impl RevocationTest {
        #[track_caller]
        fn run(&self) {
            // Initialize the test inputs.
            let var_access = MockVarAccess {
                test: self,
                set_variable_calls: Rc::default(),
            };
            let mut r = Revocation::new(&var_access);
            r.executable_level = self.executable_level;

            // Check the actual results against expectations.
            assert_eq!(r.check_revocation(), self.expected_revocation_result);
            assert_eq!(
                *var_access.set_variable_calls.borrow(),
                self.expected_set_variable_calls
            );
        }
    }

    /// Test no revocation.
    #[test]
    fn test_no_revocation() {
        RevocationTest {
            executable_level: 1,

            get_variable_data: 1u32.to_le_bytes().to_vec(),
            get_variable_attrs: REVOCATION_VAR_ATTRS,
            get_variable_status: Status::SUCCESS,

            // Executable level is 1 and the stored minimum level is 1,
            // so we are not revoked.
            expected_revocation_result: Ok(()),
            // The minimum level is 1 which is already stored in the
            // variable, so no change is made.
            expected_set_variable_calls: vec![],
        }
        .run()
    }

    /// Test no revocation, but stored minimum needs update.
    #[test]
    fn test_no_revocation_increase_minimum() {
        RevocationTest {
            executable_level: 2,

            get_variable_data: 1u32.to_le_bytes().to_vec(),
            get_variable_attrs: REVOCATION_VAR_ATTRS,
            get_variable_status: Status::SUCCESS,

            // Executable level is 2 and the stored minimum level is 1,
            // so we are not revoked.
            expected_revocation_result: Ok(()),
            // The stored minimum level is 1 so it needs an update.
            expected_set_variable_calls: vec![2u32.to_le_bytes().to_vec()],
        }
        .run()
    }

    /// Test revocation.
    #[test]
    fn test_revocation() {
        RevocationTest {
            executable_level: 1,

            get_variable_data: 2u32.to_le_bytes().to_vec(),
            get_variable_attrs: REVOCATION_VAR_ATTRS,
            get_variable_status: Status::SUCCESS,

            // Executable level is 1 but the stored minimum level is 2,
            // so we are revoked.
            expected_revocation_result: Err(RevocationError {
                executable_level: 1,
                stored_minimum_level: 2,
            }),
            // Minimum level is 1 but the stored minimum level is 2, so no
            // change to the stored value is made.
            expected_set_variable_calls: vec![],
        }
        .run()
    }

    /// Test variable read error.
    #[test]
    fn test_read_error() {
        RevocationTest {
            executable_level: 1,

            get_variable_data: 1u32.to_le_bytes().to_vec(),
            get_variable_attrs: REVOCATION_VAR_ATTRS,
            get_variable_status: Status::NOT_FOUND,

            expected_revocation_result: Ok(()),
            expected_set_variable_calls: vec![1u32.to_le_bytes().to_vec()],
        }
        .run()
    }

    /// Test handling of unexpected variable attributes.
    #[test]
    fn test_unexpected_variable_attrs() {
        RevocationTest {
            executable_level: 1,

            get_variable_data: 1u32.to_le_bytes().to_vec(),
            get_variable_attrs: VariableAttributes::empty(),
            get_variable_status: Status::SUCCESS,

            expected_revocation_result: Ok(()),
            expected_set_variable_calls: vec![
                // Call to delete, then properly set the variable.
                vec![],
                1u32.to_le_bytes().to_vec(),
            ],
        }
        .run()
    }

    /// Test handling of unexpected variable data.
    #[test]
    fn test_unexpected_variable_data() {
        RevocationTest {
            executable_level: 1,

            // Wrong length of data.
            get_variable_data: vec![1, 2, 3],
            get_variable_attrs: REVOCATION_VAR_ATTRS,
            get_variable_status: Status::SUCCESS,

            expected_revocation_result: Ok(()),
            expected_set_variable_calls: vec![1u32.to_le_bytes().to_vec()],
        }
        .run()
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
