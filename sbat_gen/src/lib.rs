//! Utility for generating SBAT metadata from `build.rs`.
//!
//! See <https://github.com/rhboot/shim/blob/main/SBAT.md> for details
//! of what SBAT is and what it's used for.

#![warn(missing_docs)]

pub use sbat;
pub use sbat::{Component, Entry, Vendor};

use sbat::ascii::AsciiStr;
use sbat::Generation;
use std::env;
use std::fs;
use std::path::PathBuf;

/// Create an [`AsciiStr`] from a [`str`]. Panics if the input is not
/// ASCII.
pub fn ascii(s: &str) -> &AsciiStr {
    AsciiStr::from_ascii(s).expect("input is not ASCII")
}

/// Create a [`Generation`] from a [`u32`]. Panics if the input is zero.
pub fn generation(gen: u32) -> Generation {
    Generation::new(gen).expect("generation is zero")
}

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

    /// Write Rust code to a file that, when included in a binary, will
    /// add an `.sbat` section.
    ///
    /// The file is written to `sbat_section.rs` in the target output
    /// directory, and can be included like this:
    ///
    /// ```no_compile
    /// include!(concat!(env!("OUT_DIR"), "/sbat_section.rs"));
    /// ```
    pub fn write_rust_file(&self) {
        let dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let out_path = dir.join("sbat_section.rs");

        let code = self.rust_link_section();

        fs::write(&out_path, &code).unwrap();
    }

    /// Format the SBAT data as CSV.
    pub fn to_csv(&self) -> String {
        let lines: Vec<_> = self.entries.iter().map(entry_to_csv).collect();
        lines.join("\n") + "\n"
    }

    /// Generate Rust code for adding an `.sbat` section to a file.
    pub fn rust_link_section(&self) -> String {
        let csv = self.to_csv();

        format!(
            r#"#[no_mangle]
#[link_section = ".sbat"]
static SBAT: [u8; {}] = *b"{}";
"#,
            csv.len(),
            csv
        )
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

    #[test]
    fn test_rust_link_section() {
        let mut sbat = Sbat::new();
        // Duplicate the initial entry to check what multiple records
        // look like.
        sbat.entries.push(sbat.entries[0].clone());
        assert_eq!(
            sbat.rust_link_section(),
            r#"#[no_mangle]
#[link_section = ".sbat"]
static SBAT: [u8; 152] = *b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
";
"#
        );
    }
}
