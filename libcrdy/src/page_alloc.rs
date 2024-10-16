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
use uefi::boot::{AllocateType, MemoryType};
use uefi::table::boot::PAGE_SIZE;
use uefi::Status;

#[derive(Debug, Eq, PartialEq)]
pub enum PageAllocationError {
    /// Allocation request is zero bytes or not an even multiple of the
    /// page size.
    InvalidSize(
        /// Requested size.
        usize,
    ),

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

#[cfg(target_os = "uefi")]
fn allocate_pages(
    allocate_type: AllocateType,
    memory_type: MemoryType,
    num_pages: usize,
) -> uefi::Result<NonNull<u8>> {
    uefi::boot::allocate_pages(allocate_type, memory_type, num_pages)
}

/// Free pages allocated with the UEFI version of `allocate_pages`.
///
/// # Safety
///
/// This must only be called with an allocation created by
/// `allocate_pages`. The caller must ensure that no references into the
/// allocation remain, and that the memory at the allocation is not used
/// after it is freed.
#[cfg(target_os = "uefi")]
unsafe fn free_pages(allocation: NonNull<u8>, num_pages: usize) -> uefi::Result {
    uefi::boot::free_pages(allocation, num_pages)
}

#[cfg(not(target_os = "uefi"))]
#[repr(C, align(4096))]
#[derive(Clone)]
struct Page([u8; PAGE_SIZE]);

#[cfg(not(target_os = "uefi"))]
fn allocate_pages(
    _allocate_type: AllocateType,
    _memory_type: MemoryType,
    num_pages: usize,
) -> uefi::Result<NonNull<u8>> {
    // Create the page-aligned allocation and convert to a boxed slice.
    let b: Box<[Page]> = vec![Page([0; PAGE_SIZE]); num_pages].into_boxed_slice();
    // Leak allocation and convert to a raw pointer.
    let slice = Box::leak(b);
    let ptr: *mut u8 = slice.as_mut_ptr().cast();
    // OK to unwrap: the allocation cannot be null.
    Ok(NonNull::new(ptr).unwrap().cast())
}

/// Free pages allocated with the non-UEFI version of `allocate_pages`.
///
/// # Safety
///
/// This must only be called with an allocation created by
/// `allocate_pages`. The caller must ensure that no references into the
/// allocation remain, and that the memory at the allocation is not used
/// after it is freed.
#[cfg(not(target_os = "uefi"))]
unsafe fn free_pages(allocation: NonNull<u8>, num_pages: usize) -> uefi::Result {
    let ptr: NonNull<[Page]> = NonNull::slice_from_raw_parts(allocation.cast::<Page>(), num_pages);

    // SAFETY: this recreates the box allocated internally by
    // `allocate_pages`. The allocation is valid and contains no
    // uninitialized memory.
    let b = unsafe { Box::from_raw(ptr.as_ptr()) };

    drop(b);
    Ok(())
}

/// Page-aligned memory allocation that will be freed on drop. This
/// implements [`Deref`] and [`DerefMut`] to provide access to the
/// allocation.
///
/// The allocation is guaranteed to be at least one page in size.
#[derive(Debug)]
pub struct ScopedPageAllocation {
    allocation: NonNull<u8>,
    num_pages: usize,
    num_bytes: usize,
}

impl ScopedPageAllocation {
    /// Allocate `num_bytes` of page-aligned memory.
    ///
    /// An error is returned if `num_bytes` is zero, or if `num_bytes`
    /// is not page aligned, or if the allocation fails.
    ///
    /// The allocated memory is fully initialized with zeros.
    pub fn new(
        allocate_type: AllocateType,
        memory_type: MemoryType,
        num_bytes: usize,
    ) -> Result<Self, PageAllocationError> {
        // Reject the allocation if it's empty.
        if num_bytes == 0 {
            return Err(PageAllocationError::InvalidSize(num_bytes));
        }

        // Reject the allocation if it's not a multiple of the page size.
        if num_bytes % PAGE_SIZE != 0 {
            return Err(PageAllocationError::InvalidSize(num_bytes));
        }

        let num_pages = num_bytes / PAGE_SIZE;

        info!("allocating {num_pages} pages ({allocate_type:?}, {memory_type:?})");
        let allocation = allocate_pages(allocate_type, memory_type, num_pages)
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
        if let Err(err) = unsafe { free_pages(self.allocation, self.num_pages) } {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that `ScopedPageAllocation::new` fails with a zero-byte request.
    #[test]
    fn test_scoped_page_allocation_zero() {
        assert_eq!(
            ScopedPageAllocation::new(AllocateType::AnyPages, MemoryType::LOADER_DATA, 0)
                .unwrap_err(),
            PageAllocationError::InvalidSize(0)
        );
    }

    /// Test that `ScopedPageAllocation::new` fails if the requested
    /// size is not page aligned.
    #[test]
    fn test_scoped_page_allocation_unaligned() {
        assert_eq!(
            ScopedPageAllocation::new(
                AllocateType::AnyPages,
                MemoryType::LOADER_DATA,
                PAGE_SIZE + 16
            )
            .unwrap_err(),
            PageAllocationError::InvalidSize(4112)
        );
    }

    /// Test that the non-UEFI implementation of `ScopedPageAllocation::new`
    /// successfully allocates and initializes memory.
    #[test]
    fn test_scoped_page_allocation_new_success() {
        let alloc = ScopedPageAllocation::new(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            3 * PAGE_SIZE,
        )
        .unwrap();
        assert_eq!(*alloc, vec![0; 3 * PAGE_SIZE]);
        assert_eq!(alloc.allocation.align_offset(PAGE_SIZE), 0);
    }
}
