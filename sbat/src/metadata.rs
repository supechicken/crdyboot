//! SBAT metadata associated with an executable.
//!
//! Typically this data is read from the `.sbat` section of a UEFI PE
//! executable. See the crate documentation for details of how it is
//! used.

use crate::csv::{Csv, Record};
use crate::{Component, Error, Result};
use alloc::vec::Vec;
use ascii::AsciiStr;

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Vendor<'a> {
    pub name: Option<&'a AsciiStr>,
    pub package_name: Option<&'a AsciiStr>,
    pub version: Option<&'a AsciiStr>,
    pub url: Option<&'a AsciiStr>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Entry<'a> {
    pub component: Component<'a>,
    pub vendor: Vendor<'a>,
}

impl<'a> Entry<'a> {
    const NUM_FIELDS: usize = 6;

    pub fn new(component: Component<'a>, vendor: Vendor<'a>) -> Entry<'a> {
        Entry { component, vendor }
    }
}

/// Image SBAT metadata.
///
/// This contains SBAT entries parsed from the `.sbat` section of a UEFI
/// PE executable.
#[derive(Debug, Eq, PartialEq)]
pub struct Metadata<'a>(Vec<Entry<'a>>);

impl<'a> Metadata<'a> {
    /// Create a `Metadata`.
    pub fn new(entries: Vec<Entry<'a>>) -> Self {
        Self(entries)
    }

    /// Get the SBAT entries.
    pub fn entries(&self) -> &[Entry<'a>] {
        &self.0
    }
}

/// Reader for the image SBAT metadata CSV.
pub struct MetadataReader {
    parsed: Csv<{ Entry::NUM_FIELDS }>,
}

impl MetadataReader {
    /// Parse SBAT metadata from raw CSV. This data typically comes from
    /// the `.sbat` section of a UEFI PE executable.
    pub fn new(csv: &[u8]) -> Result<Self> {
        Csv::parse(csv).map(|parsed| Self { parsed })
    }

    fn record_to_entry(
        &self,
        record: &Record<{ Entry::NUM_FIELDS }>,
    ) -> Result<Entry> {
        // Require at least the component fields to exist. Fields past
        // that are treated as human-readable comments.
        if record.num_fields() < Component::NUM_FIELDS {
            return Err(Error::TooFewFields);
        }

        let ascii_field = |index| -> Result<_> {
            record.get_field_as_ascii(index, &self.parsed)
        };

        let generation_field = |index| -> Result<_> {
            record.get_field_as_generation(index, &self.parsed)
        };

        Ok(Entry::new(
            Component {
                name: ascii_field(0)?.ok_or(Error::TooFewFields)?,
                generation: generation_field(1)?.ok_or(Error::TooFewFields)?,
            },
            Vendor {
                name: ascii_field(2)?,
                package_name: ascii_field(3)?,
                version: ascii_field(4)?,
                url: ascii_field(5)?,
            },
        ))
    }

    /// Convert the parsed CSV records to a `Metadata`.
    pub fn metadata(&self) -> Result<Metadata> {
        let entries = self
            .parsed
            .records()
            .iter()
            .map(|record| self.record_to_entry(record))
            .collect::<Result<_>>()?;
        Ok(Metadata::new(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Generation;

    #[test]
    fn parse_success() {
        // The current value of the SBAT data in the shim repo.
        let shim_sbat = b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,1,UEFI shim,shim,1,https://github.com/rhboot/shim";
        let reader = MetadataReader::new(shim_sbat).unwrap();
        let metadata = reader.metadata().unwrap();

        let ascii = |s| AsciiStr::from_ascii(s).unwrap();

        assert_eq!(
            metadata.0,
            vec![
                Entry::new(
                    Component {
                        name: ascii("sbat"),
                        generation: Generation::new(1).unwrap(),
                    },
                    Vendor {
                        name: Some(ascii("SBAT Version")),
                        package_name: Some(ascii("sbat")),
                        version: Some(ascii("1")),
                        url: Some(ascii(
                            "https://github.com/rhboot/shim/blob/main/SBAT.md"
                        )),
                    },
                ),
                Entry::new(
                    Component {
                        name: ascii("shim"),
                        generation: Generation::new(1).unwrap(),
                    },
                    Vendor {
                        name: Some(ascii("UEFI shim")),
                        package_name: Some(ascii("shim")),
                        version: Some(ascii("1")),
                        url: Some(ascii("https://github.com/rhboot/shim")),
                    }
                )
            ]
        );
    }

    #[test]
    fn invalid_record() {
        let sbat = "a";
        let reader = MetadataReader::new(sbat.as_bytes()).unwrap();
        assert_eq!(reader.metadata().unwrap_err(), Error::TooFewFields);
    }
}
