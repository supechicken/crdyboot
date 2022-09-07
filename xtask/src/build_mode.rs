// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[derive(Clone, Copy, Debug)]
// TODO: allow setting the build mode on the command-line.
#[allow(dead_code)]
pub enum BuildMode {
    Debug,
    Release,
}

impl BuildMode {
    pub fn dir_name(&self) -> &'static str {
        match self {
            BuildMode::Debug => "debug",
            BuildMode::Release => "release",
        }
    }

    pub fn cargo_args(&self) -> &'static [&'static str] {
        match self {
            BuildMode::Debug => &[],
            BuildMode::Release => &["--release"],
        }
    }
}
