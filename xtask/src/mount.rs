// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Result;
use camino::Utf8Path;
use command_run::Command;

pub struct Mount {
    mount_point: tempfile::TempDir,
}

impl Mount {
    pub fn new(device: &Utf8Path) -> Result<Mount> {
        let mount_point = tempfile::TempDir::new()?;

        Command::with_args("sudo", ["mount", device.as_str()])
            .add_arg(mount_point.path())
            .run()?;

        Ok(Mount { mount_point })
    }

    pub fn mount_point(&self) -> &Utf8Path {
        Utf8Path::from_path(self.mount_point.path()).unwrap()
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        Command::with_args("sudo", ["umount", self.mount_point().as_str()])
            .run()
            .unwrap();
    }
}
