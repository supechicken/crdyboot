// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use std::path::{Path, PathBuf};
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

    fn vboot_build_subdir(self) -> &'static str {
        self.c_target_override().unwrap_or("host")
    }

    fn fw_arch(self) -> &'static str {
        match self {
            Self::UefiI686 => "i386",
            Self::UefiX86_64 | Self::Host => "amd64",
        }
    }
}

/// Convert a `Path` to a `str`, or panic if the path isn't UTF-8.
fn path_to_str(path: &Path) -> &str {
    if let Some(s) = path.to_str() {
        s
    } else {
        panic!("{} is not a UTF-8 path", path.display());
    }
}

fn rerun_if_changed<P: AsRef<Path>>(path: P) {
    println!("cargo:rerun-if-changed={}", path_to_str(path.as_ref()));
}

/// Build vboot_reference's fwlib.
fn build_vboot_fwlib(vboot_ref: &Path, target: Target, c_compiler: &str) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let vboot_build_dir = out_dir
        .join("vboot_fw_build")
        .join(target.vboot_build_subdir());

    let mut cflags = "-I../../vboot/src/libc".to_string();
    if let Some(target) = target.c_target_override() {
        cflags = format!("{} --target={}", cflags, target);
    }
    if target == Target::Host {
        cflags += " -fPIC";
    }
    println!("CFLAGS={}", cflags);

    let mut make_cmd = process::Command::new("make");
    make_cmd
        .env("CFLAGS", cflags)
        .arg("-C")
        .arg(vboot_ref)
        .arg("V=1")
        .arg(format!("CC={}", c_compiler))
        .arg(format!("FIRMWARE_ARCH={}", target.fw_arch()))
        .arg(format!("BUILD={}", path_to_str(&vboot_build_dir)))
        .arg("fwlib");
    println!("{:?}", make_cmd);
    let status = make_cmd.status().expect("failed to launch make");
    if !status.success() {
        panic!("make failed");
    }

    // Rename the vboot_fw library to match the pattern expected by the
    // linker, then tell cargo to link that library in.
    fs::copy(
        vboot_build_dir.join("vboot_fw.a"),
        vboot_build_dir.join("libvboot_fw.a"),
    )
    .unwrap();
    println!(
        "cargo:rustc-link-search=native={}",
        path_to_str(&vboot_build_dir)
    );
    println!("cargo:rustc-link-lib=static=vboot_fw");
}

fn gen_fwlib_bindings(include_dirs: &[PathBuf], target: Target) {
    let header_path = "src/bindgen.h";

    rerun_if_changed(header_path);

    let mut builder = bindgen::Builder::default();
    builder = builder
        .header(header_path)
        .allowlist_function("vb2api_init")
        .allowlist_function("vb2api_inject_kernel_subkey")
        .allowlist_function("vb2api_load_kernel")
        .allowlist_type("vb2_return_code")
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
        builder = builder.clang_arg(format!("-I{}", path_to_str(include_dir)));
    }

    // Not sure why, but setting the sysroot is needed for the clang
    // windows targets. And it must not be set for the host target as
    // it causes compilation to fail there.
    if target.is_uefi() {
        builder = builder.clang_args(&["--sysroot", "/usr"]);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
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
fn gen_return_code_strings(vboot_ref: &Path, c_compiler: &str) {
    let header_path = vboot_ref.join("firmware/2lib/include/2return_codes.h");
    rerun_if_changed(&header_path);

    // Use clang to get an AST in JSON.
    let output = process::Command::new(c_compiler)
        .args(&[
            "-Xclang",
            "-ast-dump=json",
            "-fsyntax-only",
            path_to_str(&header_path),
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
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("vboot_return_codes.rs");
    fs::write(&out_path, lines.join("\n")).unwrap();
}

fn main() {
    let c_compiler = env::var("CC").unwrap_or_else(|_| "clang".to_owned());

    let vboot_ref = Path::new("../third_party/vboot_reference");

    // Rebuild if the vboot_reference submodule changes.
    rerun_if_changed(vboot_ref);

    let include_dirs = vec![
        PathBuf::from("src/libc"),
        vboot_ref.to_path_buf(),
        vboot_ref.join("firmware/include"),
    ];

    let target = Target::from_env();

    build_vboot_fwlib(vboot_ref, target, &c_compiler);

    gen_fwlib_bindings(&include_dirs, target);
    gen_return_code_strings(vboot_ref, &c_compiler);
}
