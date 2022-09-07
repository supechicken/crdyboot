// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use camino::Utf8PathBuf;

pub struct VbootKeyPaths {
    pub vbprivk: Utf8PathBuf,
    pub vbpubk: Utf8PathBuf,
    pub keyblock: Option<Utf8PathBuf>,
}
