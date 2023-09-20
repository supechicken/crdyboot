// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{bail, Context, Result};
use camino::Utf8Path;
use command_run::Command;
use std::ops::{Deref, DerefMut};
use std::process::Child;

/// Wrapper around a child process that automatically kills and waits on
/// drop.
pub struct ScopedChild(Child);

impl ScopedChild {
    pub fn new(child: Child) -> Self {
        Self(child)
    }
}

impl Deref for ScopedChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.0
    }
}

impl DerefMut for ScopedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for ScopedChild {
    fn drop(&mut self) {
        // Ignore errors during drop.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Get the SHA-256 hash of the given file.
fn sha256sum(path: &Utf8Path) -> Result<String> {
    // Run the sha256sum program rather than using the sha2 crate, since
    // sha256sum makes it easy to be efficient (avoid loading the full
    // file into memory, etc).
    let output = Command::with_args("sha256sum", [path])
        .enable_capture()
        .run()?;
    let hash = output
        .stdout
        .get(..64)
        .context("invalid sha256sum output")?;
    Ok(String::from_utf8(hash.to_vec())?)
}

/// Validate that the contents of the file at `path` have a SHA-256 hash
/// matching `expected_hash`.
///
/// This is used to ensure that downloaded files have the expected
/// contents.
pub fn check_sha256_hash(path: &Utf8Path, expected_hash: &str) -> Result<()> {
    assert_eq!(expected_hash.len(), 64);
    let actual_hash = sha256sum(path)?;
    if actual_hash != expected_hash {
        bail!("unexpected SHA-256 hash of {path}: {actual_hash} != {expected_hash}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_err as fs;
    use tempfile::TempDir;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_sha256sum() -> Result<()> {
        let tmp_dir = TempDir::new()?;
        let tmp_dir = Utf8Path::from_path(tmp_dir.path()).unwrap();
        let path = tmp_dir.join("file");
        fs::write(&path, "abc")?;
        assert_eq!(
            sha256sum(&path)?,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        Ok(())
    }
}
