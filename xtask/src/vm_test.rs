// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::config::Config;
use crate::gen_disk::VerboseRuntimeLogs;
use crate::run_crdyboot_build;
use anyhow::Result;

pub fn run_vm_tests(conf: &Config) -> Result<()> {
    // Ensure the build is up-to-date.
    run_crdyboot_build(conf, VerboseRuntimeLogs(true))?;

    todo!("add VM tests here")
}
