//! Utility for generating SBAT metadata from build.rs.
//!
//! See https://github.com/rhboot/shim/blob/main/SBAT.md for details of
//! what SBAT is and what it's used for.

pub use sbat;
pub use sbat::{Component, Entry, Vendor};

use sbat::ascii::AsciiStr;
use sbat::Generation;
use std::fs;
use std::path::Path;

fn entry_to_csv(entry: &Entry) -> String {
    format!(
        "{},{},{},{},{},{}",
        entry.component.name,
        entry.component.generation,
        entry.vendor.name.expect("SBAT vendor name not set"),
        entry
            .vendor
            .package_name
            .expect("SBAT package name not set"),
        entry.vendor.version.expect("SBAT vendor version not set"),
        entry.vendor.url.expect("SBAT vendor URL not set"),
    )
}

/// Create an [`AsciiStr`] from a [`str`]. Panics if the input is not
/// ASCII.
pub fn ascii(s: &str) -> &AsciiStr {
    AsciiStr::from_ascii(s).expect("input is not ASCII")
}

/// Create a [`Generation`] from a [`u32`]. Panics if the input is zero.
pub fn generation(gen: u32) -> Generation {
    Generation::new(gen).expect("generation is zero")
}

/// Collection of SBAT entries.
#[derive(Default)]
pub struct Sbat<'a> {
    entries: Vec<Entry<'a>>,
}

impl<'a> Sbat<'a> {
    /// Create a new SBAT that already contains the entry for SBAT itself.
    pub fn new() -> Self {
        Self {
            entries: vec![Entry::new(
                Component::new(ascii("sbat"), generation(1)),
                Vendor {
                    name: Some(ascii("SBAT Version")),
                    package_name: Some(ascii("sbat")),
                    version: Some(ascii("1")),
                    url: Some(ascii(
                        "https://github.com/rhboot/shim/blob/main/SBAT.md",
                    )),
                },
            )],
        }
    }

    /// Add an SBAT entry.
    pub fn add(&mut self, entry: Entry<'a>) {
        self.entries.push(entry);
    }

    /// Write out CSV and length files.
    ///
    /// The output files are:
    /// 1. `<dir>/sbat.csv`
    /// 2. `<dir>/sbat.csv.len`
    pub fn write_files(&self, dir: &Path) {
        let csv = self.to_csv();

        let out_path = dir.join("sbat.csv");
        fs::write(&out_path, &csv).unwrap();

        let out_path = dir.join("sbat.csv.len");
        fs::write(&out_path, csv.len().to_string()).unwrap();
    }

    fn to_csv(&self) -> String {
        let lines: Vec<_> = self.entries.iter().map(entry_to_csv).collect();
        lines.join("\n") + "\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv() {
        let sbat = Sbat::new();
        assert_eq!(
            sbat.to_csv(),
            "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"
        );
    }
}
