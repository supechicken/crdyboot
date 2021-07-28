use camino::{Utf8Path, Utf8PathBuf};
use std::env;

fn gen_fwlib_bindings(vboot_ref: &Utf8Path, target: &str) {
    let header_path = "src/bindgen.h";

    println!("cargo:rerun-if-changed={}", header_path);

    let mut builder = bindgen::Builder::default();
    builder = builder
        .header(header_path)
        .clang_arg(format!("--target={}", target))
        // TODO: check for what is still needed
        .clang_arg(format!("-I{}", vboot_ref))
        .clang_arg(format!("-I{}", vboot_ref.join("firmware/2lib/include")))
        .allowlist_type("LoadKernelParams")
        .allowlist_type("VbDiskInfo")
        .allowlist_type("vb2_context")
        .allowlist_type("vb2_crypto_algorithm")
        .allowlist_type("vb2_error_t")
        .allowlist_type("vb2_kernel_preamble")
        .allowlist_type("vb2_keyblock")
        .allowlist_type("vb2_packed_key")
        .allowlist_type("vb2_public_key")
        .allowlist_type("vb2_return_code")
        .allowlist_type("vb2_signature")
        .allowlist_type("vb2_signature_algorithm")
        .allowlist_var("CROS_CONFIG_SIZE")
        .allowlist_var("CROS_PARAMS_SIZE")
        .allowlist_var("VB2_KERNEL_PREAMBLE_HEADER_VERSION_MAJOR")
        .allowlist_var("VB2_KERNEL_PREAMBLE_HEADER_VERSION_MINOR")
        .allowlist_var("VB2_KEYBLOCK_VERSION_MAJOR")
        .allowlist_var("VB2_KEYBLOCK_VERSION_MINOR")
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
        // Turn off a bunch of layout tests because they generate
        // "reference to packed field is unaligned" warnings.
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks));

    // Not sure why, but setting the sysroot is needed for the clang
    // windows targets. And it must not be set for the host target as
    // it causes compilation to fail there.
    if target.ends_with("windows-gnu") {
        builder = builder.clang_args(&["--sysroot", "/usr"]);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = Utf8PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("vboot_bindgen.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let vboot_ref = Utf8Path::new("../third_party/vboot_reference");

    let target = env::var("TARGET").unwrap();
    let target = match target.as_str() {
        // UEFI target builds. There are a couple reasons why these are
        // "-windows-gnu" rather than just "-windows":
        //
        // 1. The 32-bit target must be i686-unknown-windows-gnu rather than
        //    just i686-unknown-windows due to a missing intrinsic. See the
        //    long comment in
        //    compiler/rustc_target/src/spec/i686_unknown_uefi.rs in the
        //    rustlang repo for details.
        //
        // 2. It's easier to get the appropriate standard C headers for
        //    these targets with "-windows-gnu", see README.md for the apt
        //    packages containing these headers.
        "i686-unknown-uefi" => "i686-unknown-windows-gnu",
        "x86_64-unknown-uefi" => "x86_64-unknown-windows-gnu",

        // For everything else (e.g. a host build like "cargo test")
        // use the same target as rustc.
        target => target,
    };

    gen_fwlib_bindings(vboot_ref, target);
}
