// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{bail, Result};
use command_run::Command;

/// Check all files in the repository for banned patterns, returning an
/// error if any unexpected occurrences are found.
pub fn check_for_banned_patterns() -> Result<()> {
    let banned_patterns = ["PartitionInfo"];
    check_for_banned_patterns_impl(&banned_patterns)
}

fn check_for_banned_patterns_impl(banned_patterns: &[&str]) -> Result<()> {
    let this_source_file = "xtask/src/source_checks.rs";

    for pattern in banned_patterns {
        let mut paths = find_occurrences_of_pattern(pattern)?;

        // If the banned pattern shows up in this source file, it's OK.
        paths.retain(|p| p != this_source_file);

        if !paths.is_empty() {
            bail!("unexpected use of {}: {}", pattern, paths.join(", "));
        }
    }

    Ok(())
}

/// Find all files in the repo that contain `pattern`.
///
/// All paths in the repo should have utf-8 names, so the paths are
/// returned as a `Vec<String>` for convenience (as opposed to `Path` or
/// `Utf8Path`).
fn find_occurrences_of_pattern(pattern: &str) -> Result<Vec<String>> {
    let output = Command::with_args(
        "git",
        [
            "grep",
            // Make paths relative to the repo root.
            "--full-name",
            // Show only file paths, not the matching text.
            "--files-with-matches",
            pattern,
        ],
    )
    .enable_capture()
    .run()?;
    let stdout = std::str::from_utf8(&output.stdout)?;
    Ok(stdout.lines().map(|s| s.to_owned()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_check_for_banned_patterns() {
        assert_eq!(
            check_for_banned_patterns_impl(&["BuildAction"])
                .unwrap_err()
                .to_string(),
            "unexpected use of BuildAction: xtask/src/main.rs"
        );

        assert!(check_for_banned_patterns_impl(&["ThisTextDoesNotExist"]).is_ok());
    }
}
