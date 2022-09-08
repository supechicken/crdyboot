// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::Config;
use anyhow::Result;
use camino::Utf8PathBuf;
use command_run::Command;
use fs_err as fs;
use serde::Deserialize;

pub struct VbootKeyPaths {
    pub vbprivk: Utf8PathBuf,
    pub vbpubk: Utf8PathBuf,
    pub keyblock: Option<Utf8PathBuf>,
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

/// Parse the C header containing return codes to get a `Vec` containing
/// all the return code names.
pub fn parse_return_codes(conf: &Config) -> Result<Vec<String>> {
    let header_path = conf
        .vboot_reference_path()
        .join("firmware/2lib/include/2return_codes.h");

    // Use clang to get an AST in JSON.
    let output = Command::with_args(
        "clang",
        &["-Xclang", "-ast-dump=json", "-fsyntax-only"],
    )
    .add_arg(header_path)
    .enable_capture()
    .run()?;
    assert!(output.status.success(), "failed to get AST (clang failed)");

    // Parse the JSON.
    let ast: AstNode = serde_json::from_slice(&output.stdout)?;

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
    Ok(enum_node
        .inner
        .iter()
        .map(|node| {
            assert_eq!(node.kind, "EnumConstantDecl");
            node.name.as_ref().expect("missing node name")
        })
        .cloned()
        .collect())
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
#[allow(clippy::pedantic)]
#[rustfmt::skip]
pub fn return_code_to_str(rc: ReturnCode) -> &'static str {
    match rc {";

    let lines: &mut Vec<String> =
        &mut preamble.lines().map(|s| s.to_string()).collect();

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
