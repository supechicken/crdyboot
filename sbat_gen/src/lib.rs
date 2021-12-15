//! Utility for generating SBAT metadata from build.rs.
//!
//! See https://github.com/rhboot/shim/blob/main/SBAT.md for details of
//! what SBAT is and what it's used for.

use std::fs;
use std::path::Path;

/// A single SBAT entry.
pub struct SbatEntry<'a> {
    pub component_name: &'a str,
    pub component_generation: u32,
    pub vendor_name: &'a str,
    pub vendor_package_name: &'a str,
    pub vendor_version: &'a str,
    pub vendor_url: &'a str,
}

impl<'a> SbatEntry<'a> {
    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.component_name,
            self.component_generation,
            self.vendor_name,
            self.vendor_package_name,
            self.vendor_version,
            self.vendor_url,
        )
    }
}

/// Collection of SBAT entries.
#[derive(Default)]
pub struct Sbat<'a> {
    entries: Vec<SbatEntry<'a>>,
}

impl<'a> Sbat<'a> {
    /// Create a new SBAT that already contains the entry for SBAT itself.
    pub fn new() -> Self {
        Self {
            entries: vec![SbatEntry {
                component_name: "sbat",
                component_generation: 1,
                vendor_name: "SBAT Version",
                vendor_package_name: "sbat",
                vendor_version: "1",
                vendor_url: "https://github.com/rhboot/shim/blob/main/SBAT.md",
            }],
        }
    }

    /// Add an SBAT entry.
    pub fn add(&mut self, entry: SbatEntry<'a>) {
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
        let lines: Vec<_> =
            self.entries.iter().map(SbatEntry::to_csv).collect();
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
