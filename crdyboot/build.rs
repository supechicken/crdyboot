//! Generate an sbat.csv file that gets added as a section of the crdyboot
//! executable.

use sbat_gen::{ascii, generation, Component, Entry, Sbat, Vendor};
use std::env;
use std::path::PathBuf;

fn main() {
    let crdyboot_name = "crdyboot";
    let crdyboot_generation = generation(1);
    let crdyboot_version = env::var("CARGO_PKG_VERSION").unwrap();
    let crdyboot_url = env::var("CARGO_PKG_REPOSITORY").unwrap();

    let mut sbat = Sbat::new();
    sbat.add(Entry::new(
        Component::new(ascii(crdyboot_name), crdyboot_generation),
        Vendor {
            name: Some(ascii("Google")),
            package_name: Some(ascii(crdyboot_name)),
            version: Some(ascii(&crdyboot_version)),
            url: Some(ascii(&crdyboot_url)),
        },
    ));

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    sbat.write_rust_file(&out_dir);
}
