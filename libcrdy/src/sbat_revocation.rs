// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module provides functions for retrieving and updating SBAT
//! (Secure Boot Advanced Targeting) revocations, as well as checking PE
//! images to see if they have been revoked.
//!
//! This code is intended to provide exactly the same revocation
//! behavior as shim. It uses the same UEFI variable to store
//! revocations, it puts the same data in that UEFI variable, and it
//! checks if PE images are revoked in the same way.
//!
//! The reason for exactly duplicating shim's behavior is that SBAT
//! should really be in the UEFI firmware; putting it in the bootloader
//! is a workaround for the fact that updating all UEFI firmware is not
//! currently realistic. So any first-stage bootloader signed by
//! Microsoft should apply and respect the shared set of SBAT
//! revocations. If, for example, a device boots a recent version of
//! crdyshim, and then tries to boot an old version of shim that has
//! been revoked, these revocations should prevent the old shim from
//! booting (assuming that the early self revocation check is
//! functioning as expected in that version of shim).
//!
//! Additional documentation:
//! * <https://github.com/rhboot/shim/blob/HEAD/SBAT.md>
//! * <https://github.com/rhboot/shim/blob/HEAD/SbatLevel_Variable.txt>
//! * <../../docs/sbat.md>

use crate::arch::PeFileForCurrentArch;
use crate::uefi::{Uefi, UefiImpl};
use alloc::boxed::Box;
use core::fmt::{self, Display, Formatter};
use log::info;
use object::{Object, ObjectSection};
use sbat::{ImageSbat, RevocationSbat, RevocationSbatOwned, ValidationResult};
use uefi::runtime::{VariableAttributes, VariableVendor};
use uefi::{cstr16, guid, CStr16};

const REVOCATION_VAR_ATTRS: VariableAttributes =
    VariableAttributes::NON_VOLATILE.union(VariableAttributes::BOOTSERVICE_ACCESS);

/// Name of the UEFI variable.
const REVOCATION_VAR_NAME: &CStr16 = cstr16!("SbatLevel");

/// Shim GUID.
const REVOCATION_VAR_VENDOR: VariableVendor =
    VariableVendor(guid!("605dab50-e046-4300-abb6-3dd810dd8b23"));

#[derive(Debug, PartialEq, Eq)]
pub enum RevocationError {
    /// The revocations embedded in the executable are not valid.
    InvalidEmbeddedRevocations(sbat::ParseError),

    /// The revocations embedded in the executable do not have a
    /// datestamp.
    UndatedEmbeddedRevocations,

    /// The image SBAT is not valid.
    InvalidImageSbat(sbat::ParseError),

    /// The image's SBAT did not pass the revocation check.
    Revoked,

    /// The image does not have a `.sbat` section.
    MissingSbatSection,
}

impl Display for RevocationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEmbeddedRevocations(err) => {
                write!(f, "invalid embedded revocations: {err}")
            }
            Self::UndatedEmbeddedRevocations => {
                write!(f, "embedded revocations are missing the datestamp")
            }
            Self::InvalidImageSbat(err) => {
                write!(f, "invalid image sbat: {err}")
            }
            Self::Revoked => {
                write!(f, "image has been revoked")
            }
            Self::MissingSbatSection => {
                write!(f, "image has no `.sbat` section")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RevocationVariableError {
    DoesNotExist,
    BadAttributes,
    Unparseable,
    MissingDate,
}

struct Revocation<'a> {
    var_access: &'a dyn Uefi,

    /// Vendor GUID and name of the UEFI variable.
    var_vendor: &'a VariableVendor,
    var_name: &'a CStr16,

    /// The raw data from `../revocations.csv`.
    embedded_revocations: &'a [u8],
}

impl<'a> Revocation<'a> {
    /// Read the UEFI variable and parse as revocation data.
    ///
    /// # Errors
    ///
    /// * `DoesNotExist` if the variable cannot be read.
    /// * `BadAttributes` if the variable has the wrong attributes set.
    /// * `Unparseable` if the variable's contents are not valid SBAT
    ///   revocation data.
    /// * `MissingDate` if the SBAT revocation data does not include a
    ///   datestamp. The datestamp is used to check if the UEFI variable
    ///   is older than the embedded revocations in the executable.
    fn read_revocations_from_uefi_variable(
        &self,
    ) -> Result<RevocationSbatOwned, RevocationVariableError> {
        match self.get_variable() {
            Ok((data, attrs)) => {
                if attrs == REVOCATION_VAR_ATTRS {
                    match RevocationSbatOwned::parse(&data) {
                        Ok(revocations) => {
                            if revocations.date().is_some() {
                                Ok(revocations)
                            } else {
                                Err(RevocationVariableError::MissingDate)
                            }
                        }
                        Err(_err) => Err(RevocationVariableError::Unparseable),
                    }
                } else {
                    Err(RevocationVariableError::BadAttributes)
                }
            }
            Err(_err) => Err(RevocationVariableError::DoesNotExist),
        }
    }

    /// Read the UEFI variable and update it if necessary.
    ///
    /// The variable is read with `read_revocations_from_uefi_variable`.
    /// If any errors occur, or if the revocation data is older than the
    /// revocation data embedded in the executable, the variable is updated.
    ///
    /// Returns the revocations that will be used to check if crdyshim
    /// or any following stages have been revoked.
    fn update_and_get_revocations(&self) -> Result<RevocationSbatOwned, RevocationError> {
        let embedded_revocations = RevocationSbatOwned::parse(self.embedded_revocations)
            .map_err(RevocationError::InvalidEmbeddedRevocations)?;
        let embedded_revocations_date = embedded_revocations
            .date()
            .ok_or(RevocationError::UndatedEmbeddedRevocations)?;
        info!("embedded revocations date: {}", embedded_revocations_date);

        match self.read_revocations_from_uefi_variable() {
            Ok(stored_revocations) => {
                // OK to unwrap: `read_revocations_from_uefi_variable`
                // verifies that the datestamp is present.
                let stored_revocations_date = stored_revocations.date().unwrap();
                info!("stored revocations date: {}", stored_revocations_date);

                if embedded_revocations_date > stored_revocations_date {
                    self.write_variable();
                    Ok(embedded_revocations)
                } else {
                    Ok(stored_revocations)
                }
            }
            Err(RevocationVariableError::BadAttributes) => {
                info!("invalid revocation variable attributes");
                self.delete_variable();
                self.write_variable();
                Ok(embedded_revocations)
            }
            Err(err) => {
                info!("invalid revocation variable: {:?}", err);
                self.write_variable();
                Ok(embedded_revocations)
            }
        }
    }

    /// Read the UEFI variable.
    fn get_variable(&self) -> uefi::Result<(Box<[u8]>, VariableAttributes)> {
        self.var_access
            .get_variable_boxed(self.var_name, self.var_vendor)
    }

    /// Write the UEFI variable.
    ///
    /// Note that if the variable already exists but with different
    /// attributes, `delete_variable` must be called first.
    fn write_variable(&self) {
        if let Err(err) = self.var_access.set_variable(
            self.var_name,
            self.var_vendor,
            REVOCATION_VAR_ATTRS,
            self.embedded_revocations,
        ) {
            info!("failed to write revocation variable: {:?}", err.status());
        }
    }

    /// Delete the UEFI variable.
    fn delete_variable(&self) {
        // Passing in an empty data array deletes the variable.
        if let Err(err) =
            self.var_access
                .set_variable(self.var_name, self.var_vendor, REVOCATION_VAR_ATTRS, &[])
        {
            info!("failed to delete revocation variable: {:?}", err.status());
        }
    }
}

/// Get the current SBAT revocations, updating the UEFI variable if necessary.
///
/// `embedded_revocations` contains the raw data from `../revocations.csv`.
///
/// See [`Revocation::update_and_get_revocations`] for details.
pub fn update_and_get_revocations(
    embedded_revocations: &[u8],
) -> Result<RevocationSbatOwned, RevocationError> {
    let var_access = UefiImpl;
    let revocation = Revocation {
        var_access: &var_access,
        var_vendor: &REVOCATION_VAR_VENDOR,
        var_name: REVOCATION_VAR_NAME,
        embedded_revocations,
    };
    revocation.update_and_get_revocations()
}

/// Validate that an image is not revoked.
///
/// `image_sbat` is the raw data from the `.sbat` section of the image.
pub fn validate_image(
    image_sbat: &[u8],
    revocations: &RevocationSbat,
) -> Result<(), RevocationError> {
    let image_sbat = ImageSbat::parse(image_sbat).map_err(RevocationError::InvalidImageSbat)?;
    match revocations.validate_image(image_sbat) {
        ValidationResult::Allowed => Ok(()),
        ValidationResult::Revoked(entry) => {
            info!("revoked entry: {:?}", entry);
            Err(RevocationError::Revoked)
        }
    }
}

/// Validate that an image is not revoked.
///
/// The image SBAT data is read from the `.sbat` section of the `pe` data.
pub fn validate_pe(
    pe: &PeFileForCurrentArch<'_>,
    revocations: &RevocationSbat,
) -> Result<(), RevocationError> {
    let section = pe
        .section_by_name(sbat::SBAT_SECTION_NAME)
        .ok_or(RevocationError::MissingSbatSection)?;
    let image_sbat = section
        .data()
        .map_err(|_| RevocationError::MissingSbatSection)?;
    validate_image(image_sbat, revocations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uefi::MockUefi;
    use mockall::predicate::*;
    use uefi::Status;

    const TEST_VAR_NAME: &CStr16 = cstr16!("SbatTest");
    const TEST_VAR_VENDOR: VariableVendor =
        VariableVendor(guid!("e726a05c-caad-4d0c-bdaf-f42df22cce0f"));

    fn call_read_revocations_from_uefi_variable(
        result: uefi::Result<(Box<[u8]>, VariableAttributes)>,
    ) -> Result<RevocationSbatOwned, RevocationVariableError> {
        let mut var_access = MockUefi::new();

        var_access
            .expect_get_variable_boxed()
            .with(eq(TEST_VAR_NAME), eq(TEST_VAR_VENDOR))
            .times(1)
            .return_const(result);

        let revocations = Revocation {
            var_access: &var_access,
            var_vendor: &TEST_VAR_VENDOR,
            var_name: TEST_VAR_NAME,
            embedded_revocations: b"",
        };

        revocations.read_revocations_from_uefi_variable()
    }

    #[test]
    fn test_read_revocations_from_uefi_variable() {
        // Test the various errors.
        assert_eq!(
            call_read_revocations_from_uefi_variable(Err(Status::NOT_FOUND.into())),
            Err(RevocationVariableError::DoesNotExist)
        );
        assert_eq!(
            call_read_revocations_from_uefi_variable(Ok((
                b"".to_vec().into_boxed_slice(),
                VariableAttributes::BOOTSERVICE_ACCESS
            ))),
            Err(RevocationVariableError::BadAttributes)
        );
        assert_eq!(
            call_read_revocations_from_uefi_variable(Ok((
                b"bad_data".to_vec().into_boxed_slice(),
                REVOCATION_VAR_ATTRS,
            ))),
            Err(RevocationVariableError::Unparseable)
        );
        assert_eq!(
            call_read_revocations_from_uefi_variable(Ok((
                b"sbat,1".to_vec().into_boxed_slice(),
                REVOCATION_VAR_ATTRS,
            ))),
            Err(RevocationVariableError::MissingDate)
        );

        // Successful read.
        assert_eq!(
            call_read_revocations_from_uefi_variable(Ok((
                b"sbat,1,2023012900".to_vec().into_boxed_slice(),
                REVOCATION_VAR_ATTRS,
            ))),
            Ok(RevocationSbatOwned::parse(b"sbat,1,2023012900").unwrap())
        );
    }

    fn call_update_and_get_revocations(
        get_var_result: uefi::Result<(Box<[u8]>, VariableAttributes)>,
        set_var_data: &[&'static [u8]],
    ) -> Result<RevocationSbatOwned, RevocationError> {
        let mut var_access = MockUefi::new();

        var_access
            .expect_get_variable_boxed()
            .with(eq(TEST_VAR_NAME), eq(TEST_VAR_VENDOR))
            .times(1)
            .return_const(get_var_result);

        for data in set_var_data {
            var_access
                .expect_set_variable()
                .with(
                    eq(TEST_VAR_NAME),
                    eq(TEST_VAR_VENDOR),
                    eq(REVOCATION_VAR_ATTRS),
                    eq(*data),
                )
                .times(1)
                .return_const(Ok(()));
        }

        let revocations = Revocation {
            var_access: &var_access,
            var_vendor: &TEST_VAR_VENDOR,
            var_name: TEST_VAR_NAME,
            embedded_revocations: b"sbat,1,2022",
        };

        revocations.update_and_get_revocations()
    }

    #[test]
    fn test_update_and_get_revocations() {
        // Var exists and contains newer revocations than the embedded
        // ones, so the var should not be updated.
        assert_eq!(
            call_update_and_get_revocations(
                Ok((
                    b"sbat,1,2023".to_vec().into_boxed_slice(),
                    REVOCATION_VAR_ATTRS,
                )),
                &[],
            ),
            Ok(RevocationSbatOwned::parse(b"sbat,1,2023").unwrap())
        );

        // Var exists and contains older revocations than the embedded
        // ones, so the var should be updated.
        assert_eq!(
            call_update_and_get_revocations(
                Ok((
                    b"sbat,1,2021".to_vec().into_boxed_slice(),
                    REVOCATION_VAR_ATTRS,
                )),
                &[b"sbat,1,2022"],
            ),
            Ok(RevocationSbatOwned::parse(b"sbat,1,2022").unwrap())
        );

        // Var exists and contains the same revocation version as the
        // embedded ones, so the var should not be updated.
        assert_eq!(
            call_update_and_get_revocations(
                Ok((
                    b"sbat,1,2022".to_vec().into_boxed_slice(),
                    REVOCATION_VAR_ATTRS,
                )),
                &[],
            ),
            Ok(RevocationSbatOwned::parse(b"sbat,1,2022").unwrap())
        );

        // Var exists but has the wrong attrs. It must be deleted and
        // then written fresh.
        assert_eq!(
            call_update_and_get_revocations(
                Ok((
                    b"sbat,1,2023".to_vec().into_boxed_slice(),
                    VariableAttributes::BOOTSERVICE_ACCESS,
                )),
                &[b"", b"sbat,1,2022"],
            ),
            Ok(RevocationSbatOwned::parse(b"sbat,1,2022").unwrap())
        );

        // Var does not exist, so it must be written.
        assert_eq!(
            call_update_and_get_revocations(Err(Status::NOT_FOUND.into()), &[b"sbat,1,2022"],),
            Ok(RevocationSbatOwned::parse(b"sbat,1,2022").unwrap())
        );
    }
}
