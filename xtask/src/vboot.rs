// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::Config;
use anyhow::Result;
use camino::Utf8PathBuf;
use command_run::Command;
use fs_err as fs;
use tempfile::TempDir;

pub struct VbootKeyPaths {
    pub vbprivk: Utf8PathBuf,
    pub vbpubk: Utf8PathBuf,
    pub keyblock: Option<Utf8PathBuf>,
}

/// Parse the C header containing return codes to get a `Vec` containing
/// all the return code names.
pub fn parse_return_codes(conf: &Config) -> Result<Vec<String>> {
    let header_path = conf
        .vboot_reference_path()
        .join("firmware/2lib/include/2return_codes.h");

    let temp_dir = TempDir::new()?;
    let ast_path = temp_dir.path().join("ast.json");

    // Use clang to get an AST in JSON.
    let output = Command::with_args("clang", ["-Xclang", "-ast-dump=json", "-fsyntax-only"])
        .add_arg(header_path)
        .enable_capture()
        .run()?;
    fs::write(&ast_path, output.stdout)?;

    // Use the `jq` program to parse the output rather than pulling in
    // the `serde_json` crate, since nothing else needs it.
    let output = Command::new("jq")
        .add_arg(
            // Find the enum declaration node named `vb2_return_code`,
            // then get a list of each member's name. This produces a
            // list of double-quoted strings, one per line.
            r#".inner[] | select(.kind=="EnumDecl" and .name=="vb2_return_code") | .inner[].name"#,
        )
        .add_arg(&ast_path)
        .enable_capture()
        .run()?;

    // Convert the output to UTF-8.
    let stdout = std::str::from_utf8(&output.stdout)?;
    // Strip the quotes around each string.
    let stdout = stdout.replace('\"', "");

    let lines: Vec<_> = stdout.lines().map(str::to_string).collect();

    // Smoke test: make sure that a known enum member is in the output.
    assert!(lines.contains(&"VB2_SUCCESS".to_string()));

    Ok(lines)
}

/// Generate a Rust function that converts from a `ReturnCode` numeric
/// value to a somewhat human-readable string.
///
/// This code generation is run on-demand with:
///
///     cargo xtask gen-vboot-return-code-strings
///
/// This operation could be done in the vboot package's `build.rs`, but
/// that could cause unnecessary build breakage if the location or
/// format of the C header changes. So instead, only regenerate the file
/// on demand, and check the result into git.
///
/// The actual return code values are not expected to change often, and
/// having correct strings is not critical, so it's OK if this generated
/// code occasionally drifts behind vboot_reference.
pub fn gen_return_code_strings(conf: &Config) -> Result<()> {
    let return_codes = parse_return_codes(conf)?;

    let preamble = "// This file was generated with `cargo xtask gen-vboot-return-code-strings`.
// Rerun that command to modify this file, do not edit it manually.

use crate::ReturnCode;

/// Stringify a [`ReturnCode`].
#[must_use]
#[expect(clippy::pedantic)]
#[rustfmt::skip]
pub fn return_code_to_str(rc: ReturnCode) -> &'static str {
    match rc {";

    let lines: &mut Vec<String> = &mut preamble.lines().map(|s| s.to_string()).collect();

    let mut push = |line: &str| lines.push(line.to_string());

    for name in return_codes {
        push(&format!(r#"        ReturnCode::{name} => "{name}","#));
    }
    push(r#"        _ => "unknown return code","#);
    push("    }");
    push("}");
    push("");

    // Write to a file.
    let path = "vboot/src/return_codes.rs";
    println!("writing to {path}");
    Ok(fs::write("vboot/src/return_codes.rs", lines.join("\n"))?)
}
