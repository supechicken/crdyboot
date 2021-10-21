//! Generate an sbat.csv file that gets added as a section of the crdyboot
//! executable.

use sbat_gen::{Sbat, SbatEntry};
use std::env;
use std::path::PathBuf;

fn main() {
    let crdyboot_name = "crdyboot";
    let crdyboot_generation = 1;
    let crdyboot_version = env::var("CARGO_PKG_VERSION").unwrap();
    let crdyboot_url = env::var("CARGO_PKG_REPOSITORY").unwrap();

    let mut sbat = Sbat::new();
    sbat.add(SbatEntry {
        component_name: crdyboot_name,
        component_generation: crdyboot_generation,
        vendor_name: "Google",
        vendor_package_name: crdyboot_name,
        vendor_version: &crdyboot_version,
        vendor_url: &crdyboot_url,
    });

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    sbat.write_files(&out_dir);
}
