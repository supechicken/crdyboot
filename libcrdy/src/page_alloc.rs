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

use core::fmt::{self, Display, Formatter};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::slice;
use log::info;
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::table::boot::PAGE_SIZE;
use uefi::table::{Boot, SystemTable};
use uefi::Status;

pub enum PageAllocationError {
    /// Allocation request is not an even multiple of the page size.
    InvalidSize(usize),

    /// UEFI page allocator failed.
    AllocationFailed(usize, Status),
}

impl Display for PageAllocationError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::InvalidSize(num_bytes) => {
                write!(
                    f,
                    "{num_bytes} is not an even multiple of page size ({PAGE_SIZE})"
                )
            }
            Self::AllocationFailed(num_pages, status) => {
                write!(f, "failed to allocate {num_pages} pages: {status}")
            }
        }
    }
}

/// Page-aligned memory allocation that will be freed on drop. This
/// implements [`Deref`] and [`DerefMut`] to provide access to the
/// allocation.
pub struct ScopedPageAllocation {
    allocation: NonNull<u8>,
    num_pages: usize,
    num_bytes: usize,

    // TODO(nicholasbishop): this unused arg will be dropped in the
    // following commit.
    #[allow(unused)]
    system_table: SystemTable<Boot>,
}

impl ScopedPageAllocation {
    /// Allocate `num_bytes` of page-aligned memory.
    pub fn new(
        system_table: SystemTable<Boot>,
        allocate_type: AllocateType,
        memory_type: MemoryType,
        num_bytes: usize,
    ) -> Result<Self, PageAllocationError> {
        // Reject the allocation if it's not a multiple of the page size.
        if num_bytes % PAGE_SIZE != 0 {
            return Err(PageAllocationError::InvalidSize(num_bytes));
        }

        let num_pages = num_bytes / PAGE_SIZE;

        info!("allocating {num_pages} pages ({allocate_type:?}, {memory_type:?})");
        let allocation = boot::allocate_pages(allocate_type, memory_type, num_pages)
            .map_err(|err| PageAllocationError::AllocationFailed(num_pages, err.status()))?;
        info!("allocation address: {allocation:#x?}");

        // Zero-initialize the allocation.
        unsafe {
            allocation.as_ptr().write_bytes(0, num_bytes);
        }

        Ok(Self {
            allocation,
            num_pages,
            num_bytes,
            system_table,
        })
    }
}

impl Drop for ScopedPageAllocation {
    fn drop(&mut self) {
        info!(
            "freeing {} pages at {:#x?}",
            self.num_pages, self.allocation
        );

        // Can't propagate an error from here, so just log it.
        //
        // Safety:
        //
        // By the time we call `drop` no other references to the
        // allocation can exist, so it is safe to de-allocate the
        // pages.
        if let Err(err) = unsafe { boot::free_pages(self.allocation, self.num_pages) } {
            info!("free_pages failed: {:?}", err.status());
        }
    }
}

impl Deref for ScopedPageAllocation {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // Safety:
        //
        // The whole allocation was initialized with `write_bytes`, so
        // there is no uninitialized memory.
        unsafe { slice::from_raw_parts(self.allocation.as_ptr(), self.num_bytes) }
    }
}

impl DerefMut for ScopedPageAllocation {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Safety:
        //
        // The whole allocation was initialized with `write_bytes`, so
        // there is no uninitialized memory.
        unsafe { slice::from_raw_parts_mut(self.allocation.as_ptr(), self.num_bytes) }
    }
}
