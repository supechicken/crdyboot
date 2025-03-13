// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use buildutil::{path_to_str, rerun_if_changed, Target};
use std::path::{Path, PathBuf};
use std::{env, fs, process};

/// Convert `target` to the `FIRMWARE_ARCH` name used in vboot's Makefile.
fn target_to_fw_arch(target: Target) -> &'static str {
    match target {
        Target::UefiI686 => "i386",
        Target::UefiX86_64 | Target::Host => "amd64",
    }
}

/// Build vboot_reference's fwlib.
fn build_vboot_fwlib(vboot_ref: &Path, target: Target, c_compiler: &str) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let vboot_build_dir = out_dir.join("vboot_fw_build").join(target.build_subdir());

    // Delete the output directory if it already exists, to ensure a
    // clean build. This is useful because makefiles are never 100%
    // perfect at incremental rebuilds due to missing dependencies and
    // the like.
    //
    // Note that this doesn't mean vboot will be built from scratch on
    // every build of this package; the build script will not be rerun
    // if no changes are detected.
    if vboot_build_dir.exists() {
        fs::remove_dir_all(&vboot_build_dir).unwrap();
    }

    let mut cflags = "-I../../vboot/src/libc".to_string();
    if let Some(target) = target.c_target_override() {
        cflags = format!("{cflags} --target={target}");
    }
    if target == Target::Host {
        cflags += " -fPIC";
    }
    println!("CFLAGS={cflags}");

    let mut make_cmd = process::Command::new("make");
    make_cmd
        .env("CFLAGS", cflags)
        .arg("-C")
        .arg(vboot_ref)
        .arg("V=1")
        // Per the vboot_reference Makefile, this produces faster (but
        // larger) code.
        .arg("UNROLL_LOOPS=1")
        .arg(format!("CC={c_compiler}"))
        .arg(format!("FIRMWARE_ARCH={}", target_to_fw_arch(target)))
        .arg(format!("BUILD={}", path_to_str(&vboot_build_dir)))
        .arg("fwlib");
    println!("{make_cmd:?}");
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
            is_global: false,
        })
        .translate_enum_integer_types(true)
        // Block-listing these types avoids some unnecessary
        // generation of ctype typedefs.
        .blocklist_type("__uint8_t")
        .blocklist_type("__uint16_t")
        .blocklist_type("__uint32_t")
        .blocklist_type("__uint64_t")
        .use_core()
        .ctypes_prefix("core::ffi")
        // Turn off a bunch of layout tests because they generate
        // "reference to packed field is unaligned" warnings.
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    if let Some(target) = target.c_target_override() {
        builder = builder.clang_arg(format!("--target={target}"));
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
}
