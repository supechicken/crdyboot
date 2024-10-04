// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libcrdy::page_alloc::ScopedPageAllocation;
use uefi::CString16;

/// Allocated buffers from AVB to execute the kernel.
pub struct LoadedBuffersAvb {
    pub kernel_buffer: ScopedPageAllocation,
    pub initramfs_buffer: ScopedPageAllocation,
    pub cmdline: CString16,
}

/// Use AVB to verify the partitions and return buffers
/// including the loaded data from the partitions
/// necessary to boot the kernel.
pub fn do_avb_verify() -> LoadedBuffersAvb {
    todo!("verify, allocate, load and return buffers");
}
