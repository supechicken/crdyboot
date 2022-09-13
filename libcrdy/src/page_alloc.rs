// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module provides [`ScopedPageAllocation`], which uses the UEFI
//! boot services page allocation function to allocate memory in
//! multiples of the 4KiB page size.
//!
//! uefi-rs has an `alloc` feature that allows allocating through the
//! standard Rust global allocator, but that interface does not allow
//! controlling details of the allocation type. In particular, the
//! memory used to allocate the kernel should be of
//! [`MemoryType::LOADER_CODE`] rather than [`MemoryType::LOADER_DATA`],
//! since it is executable.

use crate::{Error, Result};
use core::ops::{Deref, DerefMut};
use core::slice;
use log::{error, info};
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::table::{Boot, SystemTable};
use uefi::Status;

/// Page-aligned memory allocation that will be freed on drop. This
/// implements [`Deref`] and [`DerefMut`] to provide access to the
/// allocation.
pub struct ScopedPageAllocation<'a> {
    allocation: &'a mut [u8],
    num_pages: usize,
    system_table: SystemTable<Boot>,
}

impl<'a> ScopedPageAllocation<'a> {
    /// UEFI defines the page size as 4KiB in section 7.2.1,
    /// `EFI_BOOT_SERVICES.AllocatePages()`.
    const PAGE_SIZE: usize = 4096;

    /// Allocate `num_bytes` of page-aligned memory.
    pub fn new(
        system_table: SystemTable<Boot>,
        allocate_type: AllocateType,
        memory_type: MemoryType,
        num_bytes: usize,
    ) -> Result<Self> {
        // Reject the allocation if it's not a multiple of the page size.
        if num_bytes % Self::PAGE_SIZE != 0 {
            error!("{} is not an even multiple of page size", num_bytes);
            return Err(Error::Allocation(Status::UNSUPPORTED));
        }

        let num_pages = num_bytes / Self::PAGE_SIZE;

        info!(
            "allocating {} pages ({:?}, {:?})",
            num_pages, allocate_type, memory_type
        );
        let addr = system_table
            .boot_services()
            .allocate_pages(allocate_type, memory_type, num_pages)
            .map_err(|err| Error::Allocation(err.status()))?;
        info!("allocation address: {:#x}", addr);

        // Convert the physical address to a pointer.
        let ptr = addr as *mut u8;

        // Zero-initialize the allocation and convert to a slice.
        //
        // Safety:
        //
        // We zero-initialize the whole allocation using `write_bytes`,
        // so no invalid reference is created. Then it is safe to
        // convert the allocation to a slice.
        let allocation: &mut [u8] = unsafe {
            ptr.write_bytes(0, num_bytes);
            slice::from_raw_parts_mut(ptr, num_bytes)
        };

        Ok(Self {
            allocation,
            num_pages,
            system_table,
        })
    }
}

impl<'a> Drop for ScopedPageAllocation<'a> {
    fn drop(&mut self) {
        let addr = self.allocation.as_mut_ptr() as u64;
        info!("freeing {} pages at {:#x}", self.num_pages, addr);

        // Can't propagate an error from here, so just log it.
        if let Err(err) = self
            .system_table
            .boot_services()
            .free_pages(addr, self.num_pages)
        {
            error!("free_pages failed: {:?}", err.status());
        }
    }
}

impl<'a> Deref for ScopedPageAllocation<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.allocation
    }
}

impl<'a> DerefMut for ScopedPageAllocation<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.allocation
    }
}
