// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::LoadKernelError;
use core::mem;
use log::info;

/// Read a little-endian u32 field from with the kernel data at the
/// given `offset`.
fn get_u32_field(
    kernel_data: &[u8],
    offset: usize,
) -> Result<u32, LoadKernelError> {
    let bytes = kernel_data
        .get(offset..offset + mem::size_of::<u32>())
        .ok_or(LoadKernelError::KernelTooSmall)?;
    // OK to unwrap, the length of the slice is already known to be correct.
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// Check that the kernel buffer is big enough to run the kernel without
/// relocation. This is done by comparing the buffer size with the
/// `init_size` field in the kernel boot header.
///
/// The layout of the header is described here:
/// https://docs.kernel.org/x86/boot.html
pub(crate) fn validate_kernel_buffer_size(
    kernel_buffer: &[u8],
) -> Result<(), LoadKernelError> {
    const SETUP_MAGIC: u32 = 0x53726448; // "HdrS"
    const MAGIC_OFFSET: usize = 0x0202;
    const INIT_SIZE_OFFSET: usize = 0x0260;

    // Check that the correct header magic is present.
    let magic = get_u32_field(kernel_buffer, MAGIC_OFFSET)?;
    if magic != SETUP_MAGIC {
        return Err(LoadKernelError::InvalidKernelMagic);
    }

    // Get the `init_size` field.
    let init_size = get_u32_field(kernel_buffer, INIT_SIZE_OFFSET)?;
    info!("minimum required size: {}", init_size);

    let init_size = usize::try_from(init_size)
        .map_err(|_| LoadKernelError::BadNumericConversion("init_size"))?;

    if init_size <= kernel_buffer.len() {
        Ok(())
    } else {
        Err(LoadKernelError::KernelBufferTooSmall(
            init_size,
            kernel_buffer.len(),
        ))
    }
}
