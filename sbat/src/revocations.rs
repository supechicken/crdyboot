//! SBAT revocations.
//!
//! Typically this data is read from a UEFI variable. See the crate
//! documentation for details of how it is used.

use crate::csv::{Csv, Record};
use crate::metadata::{Entry, Metadata};
use crate::{Component, Error, Result};
use alloc::vec::Vec;
use ascii::AsciiStr;

/// The first entry has the component name and generation like the
/// others, but may also have a date field.
const MAX_HEADER_FIELDS: usize = 3;

#[derive(Debug, Eq, PartialEq)]
pub struct Revocations<'a> {
    pub date: Option<&'a AsciiStr>,
    pub components: Vec<Component<'a>>,
}

/// Whether an image is allowed or revoked.
#[derive(Debug, Eq, PartialEq)]
pub enum ValidationResult<'a> {
    /// The image has not been revoked.
    Allowed,

    /// The image has been revoked. The first revoked entry is provided
    /// (there could be additional revoked components).
    Revoked(&'a Entry<'a>),
}

impl<'a> Revocations<'a> {
    fn new(date: Option<&'a AsciiStr>, components: Vec<Component<'a>>) -> Self {
        Self { date, components }
    }

    /// Check if `component` is revoked.
    fn is_component_revoked(&self, component: &Component) -> bool {
        self.components.iter().any(|revoked_component| {
            component.name == revoked_component.name
                && component.generation < revoked_component.generation
        })
    }

    /// Check if any component in `metadata` is revoked.
    ///
    /// Each component in the image metadata is checked against the
    /// revocation entries. If the name matches, and if the component's
    /// version is less than the version in the corresponding revocation
    /// entry, the component is considered revoked and the image will
    /// not pass validation. If a component is not in the revocation
    /// list then it is implicitly allowed.
    pub fn validate_metadata<'b>(
        &self,
        metadata: &'b Metadata,
    ) -> ValidationResult<'b> {
        if let Some(revoked_entry) = metadata
            .entries()
            .iter()
            .find(|entry| self.is_component_revoked(&entry.component))
        {
            ValidationResult::Revoked(revoked_entry)
        } else {
            ValidationResult::Allowed
        }
    }
}

/// Reader for the SBAT revocation CSV.
pub struct RevocationsReader {
    parsed: Csv<MAX_HEADER_FIELDS>,
}

impl RevocationsReader {
    /// Parse SBAT data from raw CSV. This data typically comes from a
    /// UEFI variable.
    pub fn new(csv: &[u8]) -> Result<Self> {
        Csv::parse(csv).map(|parsed| Self { parsed })
    }

    fn record_to_component(
        &self,
        record: &Record<MAX_HEADER_FIELDS>,
    ) -> Result<Component> {
        Ok(Component {
            name: record
                .get_field_as_ascii(0, &self.parsed)?
                .ok_or(Error::TooFewFields)?,
            generation: record
                .get_field_as_generation(1, &self.parsed)?
                .ok_or(Error::TooFewFields)?,
        })
    }

    /// Convert the parsed CSV records to a `Revocations`.
    pub fn revocations(&self) -> Result<Revocations> {
        let records = self.parsed.records();

        let date = if let Some(header) = records.first() {
            header.get_field_as_ascii(2, &self.parsed)?
        } else {
            None
        };

        let components = records
            .iter()
            .map(|record| self.record_to_component(record))
            .collect::<Result<_>>()?;

        Ok(Revocations::new(date, components))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::Vendor;
    use crate::Generation;

    fn ascii(s: &str) -> &AsciiStr {
        AsciiStr::from_ascii(s).unwrap()
    }

    fn make_component(name: &str, gen: u32) -> Component {
        Component::new(ascii(name), Generation::new(gen).unwrap())
    }

    fn make_entry(name: &str, gen: u32) -> Entry {
        Entry::new(make_component(name, gen), Vendor::default())
    }

    fn make_metadata(components: Vec<Component>) -> Metadata {
        Metadata::new(
            components
                .into_iter()
                .map(|comp| Entry::new(comp, Vendor::default()))
                .collect(),
        )
    }

    #[test]
    fn parse_success() {
        let input = b"sbat,1,2021030218\ncompA,1\ncompB,2";
        let reader = RevocationsReader::new(input).unwrap();

        assert_eq!(
            reader.revocations().unwrap(),
            Revocations::new(
                Some(ascii("2021030218")),
                vec![
                    make_component("sbat", 1),
                    make_component("compA", 1),
                    make_component("compB", 2)
                ],
            )
        );
    }

    #[test]
    fn too_few_fields() {
        let input = b"sbat";
        let reader = RevocationsReader::new(input).unwrap();

        assert_eq!(reader.revocations().unwrap_err(), Error::TooFewFields);
    }

    #[test]
    fn no_date_field() {
        let input = b"sbat,1";
        let reader = RevocationsReader::new(input).unwrap();

        assert_eq!(
            reader.revocations().unwrap(),
            Revocations::new(None, vec![make_component("sbat", 1),],)
        );
    }

    #[test]
    fn is_component_revoked() {
        let revocations = Revocations::new(
            None,
            vec![make_component("compA", 2), make_component("compB", 3)],
        );

        // compA: anything less than 2 is invalid.
        assert!(revocations.is_component_revoked(&make_component("compA", 1)));
        assert!(!revocations.is_component_revoked(&make_component("compA", 2)));
        assert!(!revocations.is_component_revoked(&make_component("compA", 3)));

        // compB: anything less than 3 is invalid.
        assert!(revocations.is_component_revoked(&make_component("compB", 2)));
        assert!(!revocations.is_component_revoked(&make_component("compB", 3)));
        assert!(!revocations.is_component_revoked(&make_component("compB", 4)));

        // compC: anything is valid.
        assert!(!revocations.is_component_revoked(&make_component("compC", 1)));
        assert!(!revocations.is_component_revoked(&make_component("compC", 2)));
        assert!(!revocations.is_component_revoked(&make_component("compC", 3)));
    }

    #[test]
    fn validate_metadata() {
        use ValidationResult::{Allowed, Revoked};

        let revocations = Revocations::new(
            None,
            vec![make_component("compA", 2), make_component("compB", 3)],
        );

        // Invalid component.
        assert_eq!(
            revocations.validate_metadata(&make_metadata(vec![
                make_component("compA", 1)
            ])),
            Revoked(&make_entry("compA", 1))
        );

        // compA valid, compB invalid.
        assert_eq!(
            revocations.validate_metadata(&make_metadata(vec![
                make_component("compA", 2),
                make_component("compB", 2),
            ])),
            Revoked(&make_entry("compB", 2))
        );

        // compA invalid, compB valid.
        assert_eq!(
            revocations.validate_metadata(&make_metadata(vec![
                make_component("compA", 1),
                make_component("compB", 3),
            ])),
            Revoked(&make_entry("compA", 1))
        );

        // compA valid, compB valid.
        assert_eq!(
            revocations.validate_metadata(&make_metadata(vec![
                make_component("compA", 2),
                make_component("compB", 3),
            ])),
            Allowed
        );

        // compC valid.
        assert_eq!(
            revocations.validate_metadata(&make_metadata(vec![
                make_component("compC", 1)
            ])),
            Allowed
        );

        // compC valid, compA invalid.
        assert_eq!(
            revocations.validate_metadata(&make_metadata(vec![
                make_component("compC", 1),
                make_component("compA", 1)
            ])),
            Revoked(&make_entry("compA", 1))
        );
    }
}
