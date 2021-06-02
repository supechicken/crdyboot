use std::{
    env,
    path::{Path, PathBuf},
};

fn gen_fwlib_bindings(firmware: &Path) {
    let header_path = "src/bindgen.h";

    println!("cargo:rerun-if-changed={}", header_path);

    // TODO: this is a hack to work around missing headers for some
    // targets. We are only using bindgen to create Rust definitions
    // of some packed structures of numeric types, so it should be
    // safe to just use the host system's target here. The expected
    // size of structures is checked before using them. It would be
    // nice to fix this properly though.
    let target = env::var("TARGET").unwrap();
    let target = if matches!(
        target.as_str(),
        "x86_64-unknown-uefi" | "i686-unknown-uefi"
    ) {
        "x86_64-unknown-linux-gnu"
    } else {
        &target
    };

    let bindings = bindgen::Builder::default()
        .header(header_path)
        .clang_arg(format!("--target={}", target))
        // TODO: check for what is still needed
        .clang_arg(format!("-I{}", firmware.join("2lib/include").display()))
        .allowlist_type("LoadKernelParams")
        .allowlist_type("VbDiskInfo")
        .allowlist_type("VbExStream_t")
        .allowlist_type("vb2_context")
        .allowlist_type("vb2_crypto_algorithm")
        .allowlist_type("vb2_error_t")
        .allowlist_type("vb2_keyblock")
        .allowlist_type("vb2_packed_key")
        .allowlist_type("vb2_public_key")
        .allowlist_type("vb2_return_code")
        .allowlist_type("vb2_signature")
        .allowlist_type("vb2_signature_algorithm")
        .allowlist_var("VB2_KEYBLOCK_HASH_OFFSET")
        .allowlist_var("VB2_KEYBLOCK_KEY_OFFSET")
        .allowlist_var("VB2_KEYBLOCK_SIGNATURE_OFFSET")
        .derive_partialeq(true)
        .impl_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
        })
        .translate_enum_integer_types(true)
        // Block-listing these types avoids some unnecessary
        // generation of ctype typedefs.
        .blocklist_type("__uint8_t")
        .blocklist_type("__uint32_t")
        .blocklist_type("__uint64_t")
        .use_core()
        .ctypes_prefix("crate::vboot_sys")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("vboot_bindgen.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let firmware = Path::new("../third_party/vboot_reference/firmware");

    gen_fwlib_bindings(firmware);
}
