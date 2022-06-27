// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use std::{env, fs, process};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Target {
    UefiI686,
    UefiX86_64,
    Host,
}

impl Target {
    /// Read the target from the `TARGET` env var.
    fn from_env() -> Target {
        let target = env::var("TARGET").unwrap();
        match target.as_str() {
            "i686-unknown-uefi" => Self::UefiI686,
            "x86_64-unknown-uefi" => Self::UefiX86_64,
            // For everything else, assume it's a host build
            // (e.g. "cargo test").
            _ => Self::Host,
        }
    }

    /// True if this is a UEFI target, false if it's a host target.
    fn is_uefi(self) -> bool {
        match self {
            Self::UefiI686 | Self::UefiX86_64 => true,
            Self::Host => false,
        }
    }

    /// Get a target triple to override the default C compiler
    /// target. Returns None if this is a host build so that the default
    /// target is used in that case.
    fn c_target_override(self) -> Option<&'static str> {
        match self {
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
            Self::UefiI686 => Some("i686-unknown-windows-gnu"),
            Self::UefiX86_64 => Some("x86_64-unknown-windows-gnu"),
            Self::Host => None,
        }
    }
}

fn rerun_if_changed<P: AsRef<Utf8Path>>(path: P) {
    println!("cargo:rerun-if-changed={}", path.as_ref());
}

fn build_vboot_lib(
    vboot_ref: &Utf8Path,
    include_dirs: &[Utf8PathBuf],
    target: Target,
) {
    let firmware = vboot_ref.join("firmware");
    let source_files = [
        "src/bridge.c".into(),
        firmware.join("2lib/2api.c"),
        firmware.join("2lib/2common.c"),
        firmware.join("2lib/2context.c"),
        firmware.join("2lib/2crc8.c"),
        firmware.join("2lib/2crypto.c"),
        firmware.join("2lib/2firmware.c"),
        firmware.join("2lib/2gbb.c"),
        firmware.join("2lib/2misc.c"),
        firmware.join("2lib/2nvstorage.c"),
        firmware.join("2lib/2packed_key.c"),
        firmware.join("2lib/2recovery_reasons.c"),
        firmware.join("2lib/2rsa.c"),
        firmware.join("2lib/2secdata_firmware.c"),
        firmware.join("2lib/2secdata_fwmp.c"),
        firmware.join("2lib/2secdata_kernel.c"),
        firmware.join("2lib/2sha1.c"),
        firmware.join("2lib/2sha256.c"),
        firmware.join("2lib/2sha512.c"),
        firmware.join("2lib/2sha_utility.c"),
        firmware.join("2lib/2struct.c"),
        firmware.join("2lib/2tpm_bootmode.c"),
        firmware.join("lib/cgptlib/cgptlib.c"),
        firmware.join("lib/cgptlib/cgptlib_internal.c"),
        firmware.join("lib/cgptlib/crc32.c"),
        firmware.join("lib/gpt_misc.c"),
        firmware.join("lib/vboot_kernel.c"),
        // Stubs
        firmware.join("2lib/2stub_hwcrypto.c"),
        firmware.join("stub/vboot_api_stub_stream.c"),
    ];

    for path in &source_files {
        rerun_if_changed(path);
    }

    let mut builder = cc::Build::new();
    builder
        .compiler("clang")
        .flag("-Wno-address-of-packed-member")
        .flag("-Wno-int-to-pointer-cast")
        .flag("-Wno-sign-compare")
        .flag("-Wno-unused-parameter")
        .warnings_into_errors(true)
        .includes(include_dirs)
        .files(source_files);
    if let Some(target) = target.c_target_override() {
        builder.target(target);
    }
    builder.compile("vboot_c");
}

fn gen_fwlib_bindings(include_dirs: &[Utf8PathBuf], target: Target) {
    let header_path = "src/bindgen.h";

    rerun_if_changed(header_path);

    let mut builder = bindgen::Builder::default();
    builder = builder
        .header(header_path)
        .allowlist_function("LoadKernel")
        .allowlist_function("crdyboot_set_kernel_key")
        .allowlist_function("vb2_workbuf_alloc")
        .allowlist_function("vb2_workbuf_from_ctx")
        .allowlist_function("vb2api_init")
        .allowlist_function("vb2api_init_ctx_for_kernel_verification_only")
        .allowlist_type("VbDiskInfo")
        .allowlist_type("vb2_context")
        .allowlist_type("vb2_return_code")
        .allowlist_type("vb2_workbuf")
        .allowlist_var("CROS_CONFIG_SIZE")
        .allowlist_var("CROS_PARAMS_SIZE")
        .allowlist_var("VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE")
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
        })
        .translate_enum_integer_types(true)
        // Block-listing these types avoids some unnecessary
        // generation of ctype typedefs.
        .blocklist_type("__uint8_t")
        .blocklist_type("__uint16_t")
        .blocklist_type("__uint32_t")
        .blocklist_type("__uint64_t")
        .use_core()
        .ctypes_prefix("cty")
        // Turn off a bunch of layout tests because they generate
        // "reference to packed field is unaligned" warnings.
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks));

    if let Some(target) = target.c_target_override() {
        builder = builder.clang_arg(format!("--target={}", target));
    }

    for include_dir in include_dirs {
        builder = builder.clang_arg(format!("-I{}", include_dir));
    }

    // Not sure why, but setting the sysroot is needed for the clang
    // windows targets. And it must not be set for the host target as
    // it causes compilation to fail there.
    if target.is_uefi() {
        builder = builder.clang_args(&["--sysroot", "/usr"]);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = Utf8PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("vboot_bindgen.rs"))
        .expect("Couldn't write bindings!");
}

/// Clang AST node.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AstNode {
    kind: String,
    name: Option<String>,
    #[serde(default)]
    inner: Vec<AstNode>,
}

/// Generate a Rust function that converts from a vb2_return_code integer
/// value to a somewhat human-readable string.
fn gen_return_code_strings(vboot_ref: &Utf8Path) {
    let header_path = vboot_ref.join("firmware/2lib/include/2return_codes.h");
    rerun_if_changed(&header_path);

    // Use clang to get an AST in JSON.
    let output = process::Command::new("clang")
        .args(&[
            "-Xclang",
            "-ast-dump=json",
            "-fsyntax-only",
            header_path.as_str(),
        ])
        .output()
        .expect("failed to get AST (clang not found)");
    assert!(output.status.success(), "failed to get AST (clang failed)");

    // Parse the JSON.
    let ast: AstNode = serde_json::from_slice(&output.stdout)
        .expect("failed to parse AST JSON");

    // Find the vb2_return_code enum.
    let enum_node = ast
        .inner
        .iter()
        .find(|node| {
            node.kind == "EnumDecl"
                && node.name.as_deref() == Some("vb2_return_code")
        })
        .expect("failed to find vb2_return_code");

    // Get an iterator of enum member names.
    let members = enum_node.inner.iter().map(|node| {
        assert_eq!(node.kind, "EnumConstantDecl");
        node.name.as_ref().expect("missing node name")
    });

    // Generate conversion code.
    let mut lines = vec![
        "pub fn return_code_to_str(code: vb2_return_code) -> &'static str {"
            .to_string(),
    ];
    for name in members {
        lines.push(format!("  if code == vb2_return_code::{} {{", name));
        lines.push(format!("    return \"{}\";", name));
        lines.push("  }".to_string());
    }
    lines.push("  \"unknown return code\"".to_string());
    lines.push("}".to_string());

    // Write to a file.
    let out_dir = Utf8PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("vboot_return_codes.rs");
    fs::write(&out_path, lines.join("\n")).unwrap();
}

fn main() {
    let vboot_ref = Utf8Path::new("../third_party/vboot_reference");

    let include_dirs = vec![
        Utf8PathBuf::from("src"),
        Utf8PathBuf::from("src/libc"),
        vboot_ref.to_path_buf(),
        vboot_ref.join("firmware/2lib/include"),
        vboot_ref.join("firmware/include"),
        vboot_ref.join("firmware/lib/cgptlib/include"),
        vboot_ref.join("firmware/lib/include"),
        vboot_ref.join("firmware/lib20/include"),
    ];

    let target = Target::from_env();

    build_vboot_lib(vboot_ref, &include_dirs, target);
    gen_fwlib_bindings(&include_dirs, target);
    gen_return_code_strings(vboot_ref);
}
