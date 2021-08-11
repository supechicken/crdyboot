//! Generate an sbat.csv file that gets added as a section of the crdyboot
//! executable.
//!
//! See https://github.com/rhboot/shim/blob/main/SBAT.md for details of what
//! SBAT is and what it's used for.

use std::path::PathBuf;
use std::{env, fs};

struct SbatEntry<'a> {
    component_name: &'a str,
    component_generation: u32,
    vendor_name: &'a str,
    vendor_package_name: &'a str,
    vendor_version: &'a str,
    vendor_url: &'a str,
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

struct Sbat<'a> {
    entries: Vec<SbatEntry<'a>>,
}

impl<'a> Sbat<'a> {
    fn to_csv(&self) -> String {
        let lines: Vec<_> =
            self.entries.iter().map(SbatEntry::to_csv).collect();
        lines.join("\n") + "\n"
    }
}

fn main() {
    let crdyboot_name = "crdyboot";
    let crdyboot_generation = 1;
    let crdyboot_version = env::var("CARGO_PKG_VERSION").unwrap();
    let crdyboot_url = env::var("CARGO_PKG_REPOSITORY").unwrap();

    let mut sbat = Sbat {
        entries: Vec::new(),
    };
    sbat.entries.push(SbatEntry {
        component_name: "sbat",
        component_generation: 1,
        vendor_name: "SBAT Version",
        vendor_package_name: "sbat",
        vendor_version: "1",
        vendor_url: "https://github.com/rhboot/shim/blob/main/SBAT.md",
    });
    sbat.entries.push(SbatEntry {
        component_name: crdyboot_name,
        component_generation: crdyboot_generation,
        vendor_name: "Google",
        vendor_package_name: crdyboot_name,
        vendor_version: &crdyboot_version,
        vendor_url: &crdyboot_url,
    });

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("sbat.csv");
    let csv = sbat.to_csv();
    fs::write(&out_path, &csv).unwrap();

    let out_path = out_dir.join("sbat.csv.len");
    fs::write(out_path, csv.len().to_string()).unwrap();
}
