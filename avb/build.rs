// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO: This file is mostly a copy of vboot/build.rs
// and contains quite a bit of duplicate code.
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
    ///
    /// The targets chosen here match those in the `cc` crate:
    /// https://github.com/rust-lang/cc-rs/pull/623/files
    fn c_target_override(self) -> Option<&'static str> {
        match self {
            Self::UefiI686 => Some("i686-unknown-windows-gnu"),
            Self::UefiX86_64 => Some("x86_64-unknown-windows-gnu"),
            Self::Host => None,
        }
    }

    fn avb_build_subdir(self) -> &'static str {
        self.c_target_override().unwrap_or("host")
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

/// Build avb verify lib
fn build_avb_lib(avb_ref: &Path, target: Target, c_compiler: &str) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let avb_build_dir = out_dir.join("avb_build").join(target.avb_build_subdir());

    // Delete the output directory if it already exists, to ensure a
    // clean build. This is useful because makefiles are never 100%
    // perfect at incremental rebuilds due to missing dependencies and
    // the like.
    //
    // Note that this doesn't mean avb will be built from scratch on
    // every build of this package; the build script will not be rerun
    // if no changes are detected.
    if avb_build_dir.exists() {
        fs::remove_dir_all(&avb_build_dir).unwrap();
    }

    let mut cflags = "".to_string();
    if let Some(target) = target.c_target_override() {
        cflags = format!("{cflags} --target={target}");
    }
    if target == Target::Host {
        cflags += " -fPIC -fstack-protector-strong ";
    } else {
        // The stack-protector option is not available for the uefi
        // target compilers.
        cflags += " -fno-stack-protector";
    }
    println!("CFLAGS={cflags}");

    let mut make_cmd = process::Command::new("make");
    make_cmd
        .env("CFLAGS", cflags)
        .arg(format!("AVB={}", path_to_str(avb_ref)))
        .arg("V=1")
        .arg(format!("CC={c_compiler}"))
        .arg(format!("BUILD={}", path_to_str(&avb_build_dir)))
        .arg("avblib");
    println!("{make_cmd:?}");
    let status = make_cmd.status().expect("failed to launch make");
    if !status.success() {
        panic!("make failed");
    }

    println!(
        "cargo:rustc-link-search=native={}",
        path_to_str(&avb_build_dir)
    );
    println!("cargo:rustc-link-lib=static=avb");
}

fn gen_avblib_bindings(include_dirs: &[PathBuf], target: Target) {
    let header_path = "src/bindgen.h";

    rerun_if_changed(header_path);

    let mut builder = bindgen::Builder::default();
    builder = builder
        .header(header_path)
        // TODO: allowlist only what is needed here...
        // see allowlist_{function,type,var}
        // TODO review these settings.
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        // Block avb_sysdep.h declarations that are meant
        // to be provided by the caller.
        // See libavb/avb_sysdeps.h and avb/avb_sysdeps.rs
        .blocklist_function("avb_memcmp")
        .blocklist_function("avb_strcmp")
        .blocklist_function("avb_strncmp")
        .blocklist_function("avb_memcpy")
        .blocklist_function("avb_memset")
        .blocklist_function("avb_print")
        .blocklist_function("avb_printv")
        .blocklist_function("avb_printf")
        .blocklist_function("avb_abort")
        .blocklist_function("avb_malloc_")
        .blocklist_function("avb_free")
        .blocklist_function("avb_strlen")
        .blocklist_function("avb_div_by_10")
        .translate_enum_integer_types(true)
        .use_core()
        .ctypes_prefix("core::ffi")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    if let Some(target) = target.c_target_override() {
        builder = builder.clang_arg(format!("--target={target}"));
    }

    for include_dir in include_dirs {
        builder = builder.clang_arg(format!("-I{}", path_to_str(include_dir)));
    }
    // Prevent stdinc includes to force it to use the local stdlib headers.
    builder = builder.clang_arg("-nostdinc");

    // Not sure why, but setting the sysroot is needed for the clang
    // windows targets. And it must not be set for the host target as
    // it causes compilation to fail there.
    if target.is_uefi() {
        builder = builder.clang_args(&["--sysroot", "/usr"]);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("avb_bindgen.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let c_compiler = env::var("CC").unwrap_or_else(|_| "clang".to_owned());

    let avb_ref = Path::new("../third_party/avb");

    rerun_if_changed("build.rs");
    rerun_if_changed("Makefile");

    // Rebuild if the avb submodule changes.
    rerun_if_changed(avb_ref);

    let include_dirs = vec![avb_ref.to_path_buf(), PathBuf::from("src/libc")];

    let target = Target::from_env();

    build_avb_lib(avb_ref, target, &c_compiler);

    gen_avblib_bindings(&include_dirs, target);
}
