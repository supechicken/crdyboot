//! UEFI SBAT (Secure Boot Advanced Targeting)
//!
//! SBAT is used to revoke insecure UEFI exectuables in a way that won't
//! eat up the limited storage space available in the UEFI environment.
//!
//! There are two important sources of data:
//! 1. The SBAT metadata associated with each image describes the
//!    components in that image.
//! 2. The SBAT revocation data stored in a UEFI variable provides a
//!    list of component versions that are no longer allowed to boot.
//!
//! Each entry in the revocation list contains component name and
//! version fields. (The first entry, which is the sbat version, also
//! has a date field, but it is purely cosmetic.) When validating an
//! image, each component in the image is checked against the revocation
//! entries. If the name matches, and if the component's version is less
//! than the version in the corresponding revocation entry, the
//! component is considered revoked and the image will not pass
//! validation.
//!
//! The details and exact validation rules are described further in the
//! SBAT.md and SBAT.example.md files in the shim repo:
//!
//! - <https://github.com/rhboot/shim/blob/e5bf2ba744731646749b605a322c353011f93c8e/SBAT.md>
//! - <https://github.com/rhboot/shim/blob/e5bf2ba744731646749b605a322c353011f93c8e/SBAT.example.md>

#![warn(missing_docs)]
// Turn off std, except when running tests.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod csv;
mod generation;
mod metadata;
mod revocations;

use ascii::AsciiStr;

pub use generation::Generation;
pub use metadata::{Metadata, MetadataReader};
pub use revocations::ValidationResult;
pub use revocations::{Revocations, RevocationsReader};

pub use ValidationResult::{Allowed, Revoked};

/// SBAT component. This is the machine-readable portion of SBAT that is
/// actually used for revocation (other fields are human-readable and
/// not used for comparisons).
#[derive(Debug, Eq, PartialEq)]
pub struct Component<'a> {
    /// Component name.
    pub name: &'a AsciiStr,

    /// Component generation.
    pub generation: Generation,
}

impl<'a> Component<'a> {
    const NUM_FIELDS: usize = 2;

    /// Create a `Component`.
    pub fn new(name: &AsciiStr, generation: Generation) -> Component {
        Component { name, generation }
    }
}

/// SBAT errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// CSV field exceeds the maximum size.
    FieldTooLarge,

    /// CSV field is not ASCII. According to the SBAT spec, all fields
    /// must be ASCII.
    InvalidAscii,

    /// CSV field is not a valid `Generation` number.
    InvalidGeneration,

    /// CSV has more records than allowed.
    TooManyRecords,

    /// Parsed CSV exceeds the maximum allocation size.
    TooMuchData,

    /// CSV record has two few fields.
    TooFewFields,
}

/// SBAT `Result` type alias.
pub type Result<T> = core::result::Result<T, Error>;
