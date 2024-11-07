// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Set up memory protection attributes for the kernel data.
//!
//! Essentially this makes sure that each section of the PE executable
//! is marked appropriately as writable or executable, but never both.
//!
//! See "New UEFI CA memory mitigation requirements for signing" for
//! more information:
//! <https://techcommunity.microsoft.com/t5/hardware-dev-center/new-uefi-ca-memory-mitigation-requirements-for-signing/ba-p/3608714>

use crate::util::round_up_to_page_alignment;
use core::ops::Range;
use log::info;
use object::pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use object::LittleEndian;
use uefi::boot::{self, MemoryAttribute};
use uefi::data_types::PhysicalAddress;
use uefi::proto::security::MemoryProtection;
use uefi::Status;

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum NxError {
    /// Arithmetic overflow occurred due to the PE section bounds.
    #[error("arithmetic overflow occurred due to section bounds")]
    InvalidSectionBounds,

    /// Failed to open the [`MemoryProtection`] protocol.
    ///
    /// If no handles support the protocol, it is not considered an
    /// error. This error is only returned when a handle claims to
    /// support the protocol, but the protocol can't be opened.
    #[error("failed to open protocol: {0}")]
    OpenProtocolFailed(Status),

    /// Failed to clear memory attributes from a region of memory.
    #[error("failed to clear attributes in {1:#016x?}: {0}")]
    ClearAttributesFailed(Status, Range<PhysicalAddress>),

    /// Failed to set memory attributes on a region of memory.
    #[error("failed to set attributes in {1:#016x?}: {0}")]
    SetAttributesFailed(Status, Range<PhysicalAddress>),

    /// The NX-compatability bit is not set in the PE attributes.
    #[error("PE is not NX compat")]
    PeNotNxCompat,

    /// A section in the PE is both writable and executable, which is
    /// not allowed for NX compat.
    #[error("section is both writable and executable")]
    SectionWritableAndExecutable,

    /// A section in the PE is not page aligned. Since memory attributes
    /// are set at page granularity, this is not allowed.
    #[error("section start is not page aligned: {0:#016x}")]
    SectionStartNotPageAligned(PhysicalAddress),
}

/// Check whether the address is aligned to the page size (4KiB).
#[expect(clippy::verbose_bit_mask)]
fn is_page_aligned(addr: PhysicalAddress) -> bool {
    (addr & 0xfff) == 0
}

/// Memory protection attributes that should be cleared/set for a PE
/// section.
struct SectionMemoryAttributes {
    clear: MemoryAttribute,
    set: MemoryAttribute,
}

/// Info about a PE section.
struct NxSectionInfo {
    /// Section's absolute start address.
    address: u64,

    /// Section's size in bytes.
    len: u64,

    /// Whether the section is writable.
    writable: bool,

    /// Whether the section is executable.
    executable: bool,
}

impl NxSectionInfo {
    /// Get the `SectionMemoryAttributes` for this section.
    ///
    /// Attribute explanation:
    ///
    /// * `READ_PROTECT` means the memory can't be read. We always
    ///   clear this bit.
    ///
    /// * `READ_ONLY` means the memory can't be written.
    ///
    /// * `EXECUTE_PROTECT` means the memory can't be executed.
    ///
    /// Although there are other `MemoryAttribute` values, these
    /// three bits are the only ones that can be used with the memory
    /// protection protocol.
    fn memory_attributes(&self) -> Result<SectionMemoryAttributes, NxError> {
        const READ_PROTECT: MemoryAttribute = MemoryAttribute::READ_PROTECT;
        const READ_ONLY: MemoryAttribute = MemoryAttribute::READ_ONLY;
        const EXECUTE_PROTECT: MemoryAttribute = MemoryAttribute::EXECUTE_PROTECT;

        match (self.writable, self.executable) {
            (true, true) => Err(NxError::SectionWritableAndExecutable),
            (true, false) => Ok(SectionMemoryAttributes {
                clear: READ_PROTECT | READ_ONLY,
                set: EXECUTE_PROTECT,
            }),
            (false, true) => Ok(SectionMemoryAttributes {
                clear: READ_PROTECT | EXECUTE_PROTECT,
                set: READ_ONLY,
            }),
            (false, false) => Ok(SectionMemoryAttributes {
                clear: READ_PROTECT,
                set: READ_ONLY | EXECUTE_PROTECT,
            }),
        }
    }

    /// Get the section's byte region aligned to the page size.
    ///
    /// Memory attributes are typically set at the page level, so we
    /// need to align the section's address range accordingly.
    ///
    /// The section start addresses are already required to be page
    /// aligned, so return an error if that requirement isn't
    /// upheld. The section sizes aren't required to be aligned, so
    /// round the end address up.
    fn page_aligned_byte_region(&self) -> Result<Range<PhysicalAddress>, NxError> {
        if is_page_aligned(self.address) {
            let end = self
                .address
                .checked_add(self.len)
                .ok_or(NxError::InvalidSectionBounds)?;

            Ok(self.address
                ..round_up_to_page_alignment(end).ok_or(NxError::InvalidSectionBounds)?)
        } else {
            Err(NxError::SectionStartNotPageAligned(self.address))
        }
    }
}

/// Get an iterator over the PE sections.
fn get_section_iter<'a, N: ImageNtHeaders>(
    pe: &PeFile<'a, N>,
) -> impl Iterator<Item = Result<NxSectionInfo, NxError>> + 'a {
    let data_ptr = pe.data().as_ptr();
    let section_table = pe.section_table();

    let base = data_ptr as u64;

    section_table
        .iter()
        .enumerate()
        .map(move |(index, section)| {
            let c = section.characteristics.get(LittleEndian);

            let (offset, len) = section.pe_address_range();
            info!("section {index}: offset={offset:#x}, len={len:#x}, characteristics={c:#x}");

            let address = base
                .checked_add(u64::from(offset))
                .ok_or(NxError::InvalidSectionBounds)?;

            Ok(NxSectionInfo {
                address,
                len: u64::from(len),
                writable: (c & object::pe::IMAGE_SCN_MEM_WRITE) != 0,
                executable: (c & object::pe::IMAGE_SCN_MEM_EXECUTE) != 0,
            })
        })
}

/// Whether the image's DLL characteristics have the `NX_COMPAT` bit set.
fn is_pe_nx_compat<N: ImageNtHeaders>(pe: &PeFile<N>) -> bool {
    let dll_characteristics = pe.nt_headers().optional_header().dll_characteristics();

    (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0
}

/// Set up memory protection attributes for the kernel data.
pub fn update_mem_attrs<N: ImageNtHeaders>(pe: &PeFile<N>) -> Result<(), NxError> {
    let handle = match boot::get_handle_for_protocol::<MemoryProtection>() {
        Ok(handle) => handle,
        Err(err) => {
            // Only very recent systems will support this protocol, so
            // don't treat it as a hard error.
            info!("memory protection is not supported: {:?}", err.status());
            return Ok(());
        }
    };

    // Check that the executable self-reports NX compatibility.
    if !is_pe_nx_compat(pe) {
        return Err(NxError::PeNotNxCompat);
    }

    let memory_protection = boot::open_protocol_exclusive::<MemoryProtection>(handle)
        .map_err(|err| NxError::OpenProtocolFailed(err.status()))?;

    for section in get_section_iter(pe) {
        let section = section?;
        let attrs = section.memory_attributes()?;
        let byte_region = section.page_aligned_byte_region()?;

        info!(
            "updating memory attributes for section {:#x?}: clear={:?}, set={:?}",
            byte_region, attrs.clear, attrs.set
        );

        memory_protection
            .clear_memory_attributes(byte_region.clone(), attrs.clear)
            .map_err(|err| NxError::ClearAttributesFailed(err.status(), byte_region.clone()))?;
        memory_protection
            .set_memory_attributes(byte_region.clone(), attrs.set)
            .map_err(|err| NxError::SetAttributesFailed(err.status(), byte_region.clone()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_page_aligned() {
        assert!(is_page_aligned(0));
        assert!(!is_page_aligned(1));
        assert!(!is_page_aligned(1024));
        assert!(!is_page_aligned(2048));
        assert!(!is_page_aligned(4095));
        assert!(is_page_aligned(4096));
        assert!(!is_page_aligned(4097));
    }

    #[test]
    fn test_page_aligned_byte_region() {
        let mut s = NxSectionInfo {
            address: 0,
            len: 4096,
            writable: false,
            executable: false,
        };
        assert_eq!(s.page_aligned_byte_region().ok().unwrap(), 0..4096);

        s.address = 1;
        assert!(s.page_aligned_byte_region().is_err());

        s.address = 0;
        s.len = 4095;
        assert_eq!(s.page_aligned_byte_region().ok().unwrap(), 0..4096);
    }
}
