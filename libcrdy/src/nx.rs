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

use crate::pe::{PeInfo, PeSectionInfo};
use core::fmt::{self, Display, Formatter};
use core::ops::Range;
use log::info;
use uefi::data_types::PhysicalAddress;
use uefi::proto::security::MemoryProtection;
use uefi::table::boot::{BootServices, MemoryAttribute, PAGE_SIZE};
use uefi::Status;

pub enum NxError {
    /// Failed to open the [`MemoryProtection`] protocol.
    ///
    /// If no handles support the protocol, it is not considered an
    /// error. This error is only returned when a handle claims to
    /// support the protocol, but the protocol can't be opened.
    OpenProtocolFailed(Status),

    /// Failed to clear memory attributes from a region of memory.
    ClearAttributesFailed(Status, Range<PhysicalAddress>),

    /// Failed to set memory attributes on a region of memory.
    SetAttributesFailed(Status, Range<PhysicalAddress>),

    /// The NX-compatability bit is not set in the PE attributes.
    PeNotNxCompat,

    /// A section in the PE is both writable and executable, which is
    /// not allowed for NX compat.
    SectionWritableAndExecutable,

    /// A section in the PE is not page aligned. Since memory attributes
    /// are set at page granularity, this is not allowed.
    SectionStartNotPageAligned(PhysicalAddress),
}

impl Display for NxError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::OpenProtocolFailed(status) => write!(f, "failed to open protocol: {status}"),
            Self::ClearAttributesFailed(status, region) => {
                write!(f, "failed to clear attributes in {region:#016x?}: {status}")
            }
            Self::SetAttributesFailed(status, region) => {
                write!(f, "failed to set attributes in {region:#016x?}: {status}")
            }
            Self::PeNotNxCompat => write!(f, "PE is not NX compat"),
            Self::SectionWritableAndExecutable => {
                write!(f, "section is both writable and executable")
            }
            Self::SectionStartNotPageAligned(addr) => {
                write!(f, "section start is not page aligned: {addr:#016x}")
            }
        }
    }
}

/// Check whether the address is aligned to the page size (4KiB).
#[allow(clippy::verbose_bit_mask)]
fn is_page_aligned(addr: PhysicalAddress) -> bool {
    (addr & 0xfff) == 0
}

/// Round the address up to the nearest page size (4KiB).
fn round_up_to_page_alignment(addr: PhysicalAddress) -> PhysicalAddress {
    let efi_page_size = u64::try_from(PAGE_SIZE).unwrap();
    let r = addr % efi_page_size;
    if r == 0 {
        addr
    } else {
        // `r` is less than `efi_page_size`, so this unwrap cannot fail.
        let offset = efi_page_size.checked_sub(r).unwrap();

        // Panic on overflow.
        addr.checked_add(offset).unwrap()
    }
}

/// Memory protection attributes that should be cleared/set for a PE
/// section.
pub struct SectionMemoryAttributes {
    pub clear: MemoryAttribute,
    pub set: MemoryAttribute,
}

impl PeSectionInfo {
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
    pub fn memory_attributes(&self) -> Result<SectionMemoryAttributes, NxError> {
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
    pub fn page_aligned_byte_region(&self) -> Result<Range<PhysicalAddress>, NxError> {
        if is_page_aligned(self.address) {
            // Panic on overflow.
            let end = self.address.checked_add(self.len).unwrap();

            Ok(self.address..round_up_to_page_alignment(end))
        } else {
            Err(NxError::SectionStartNotPageAligned(self.address))
        }
    }
}

/// Set up memory protection attributes for the kernel data.
pub fn update_mem_attrs(pe: &PeInfo, boot_services: &BootServices) -> Result<(), NxError> {
    let handle = match boot_services.get_handle_for_protocol::<MemoryProtection>() {
        Ok(handle) => handle,
        Err(err) => {
            // Only very recent systems will support this protocol, so
            // don't treat it as a hard error.
            info!("memory protection is not supported: {:?}", err.status());
            return Ok(());
        }
    };

    // Check that the executable self-reports NX compatibility.
    if !pe.is_nx_compat() {
        return Err(NxError::PeNotNxCompat);
    }

    let memory_protection = boot_services
        .open_protocol_exclusive::<MemoryProtection>(handle)
        .map_err(|err| NxError::OpenProtocolFailed(err.status()))?;

    for section in pe.section_iter() {
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
    fn test_round_up_to_page_alignment() {
        assert_eq!(round_up_to_page_alignment(0), 0);
        assert_eq!(round_up_to_page_alignment(1), 4096);
        assert_eq!(round_up_to_page_alignment(4095), 4096);
        assert_eq!(round_up_to_page_alignment(4096), 4096);
        assert_eq!(round_up_to_page_alignment(4097), 8192);
        assert_eq!(round_up_to_page_alignment(8192), 8192);
        assert_eq!(round_up_to_page_alignment(8193), 12288);
    }

    #[test]
    fn test_page_aligned_byte_region() {
        let mut s = PeSectionInfo {
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
