// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Result;
use camino::Utf8Path;
use command_run::Command;

const CURL: &str = "curl";
const GSUTIL: &str = "gsutil";

pub struct GsResource {
    bucket: String,
    key: String,
    public: bool,
}

impl GsResource {
    /// Create a new `GsResource`.
    pub fn new(bucket: &str, key: String) -> Self {
        Self {
            bucket: bucket.to_string(),
            key,
            public: false,
        }
    }

    /// Create a new `GsResource` for an object that is known to be
    /// public.
    pub fn new_public(bucket: &str, key: String) -> Self {
        Self {
            bucket: bucket.to_string(),
            key,
            public: true,
        }
    }

    /// Format the resource as a "gs://" URL.
    fn gs_url(&self) -> String {
        format!("gs://{}/{}", self.bucket, self.key)
    }

    /// Format the resource as an "https://" URL. This URL is only valid
    /// for public objects.
    fn https_url(&self) -> String {
        format!(
            "https://storage.googleapis.com/{}/{}",
            self.bucket, self.key
        )
    }

    /// Download a file from GS into a `Vec<u8>`.
    fn download_to_vec(&self) -> Result<Vec<u8>> {
        let output = Command::with_args(GSUTIL, ["cat", &self.gs_url()])
            .enable_capture()
            .run()?;
        Ok(output.stdout)
    }

    /// Download a file from GS into a `String`.
    pub fn download_to_string(&self) -> Result<String> {
        let data = self.download_to_vec()?;
        Ok(String::from_utf8(data)?)
    }

    /// Download a file from GS directly to disk.
    ///
    /// `dst` must be a full file path, not a directory, and it must not
    /// already exist.
    pub fn download_to_file(&self, dst: &Utf8Path) -> Result<()> {
        // Check that we're not accidentally overwriting an existing file.
        assert!(!dst.exists());

        // If the file is public, download it with curl instead of
        // gsutil. This avoids needing to install gsutil at all for the
        // default behavior of `cargo xtask setup`.
        if self.public {
            Command::with_args(
                CURL,
                [
                    "--fail",
                    "--location",
                    "--output",
                    dst.as_str(),
                    &self.https_url(),
                ],
            )
            .run()?;
        } else {
            Command::with_args(GSUTIL, ["cp", &self.gs_url(), dst.as_str()]).run()?;
        }

        Ok(())
    }
}
