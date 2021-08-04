//! PE executable parsing.
//!
//! This uses the goblin library to parse a PE executable and find its entry
//! point.
//!
//! When booting from a 64-bit UEFI environment, the normal PE entry point
//! in the PE header can be used.
//!
//! When booting from a 32-bit UEFI environment, newer kernels can provide a
//! compatibility entry point. This requires a kernel with this commit:
//!
//!    efi/x86: Implement mixed mode boot without the handover protocol

use core::convert::TryInto;
pub use goblin::error::Error as PeError;
use goblin::pe::PE;
use scroll::Pread;

/// Valid PE executable.
pub struct PeExecutable<'a> {
    data: &'a [u8],
    parsed: PE<'a>,
}

impl<'a> PeExecutable<'a> {
    /// Parse `data` as a PE executable.
    pub fn parse(data: &[u8]) -> Result<PeExecutable, PeError> {
        Ok(PeExecutable {
            data,
            parsed: PE::parse(data)?,
        })
    }

    /// Get the primary entry point (as an offset) from the PE header.
    pub fn entry_point(&self) -> usize {
        self.parsed.entry
    }

    /// Get an IA32 entry point, if available.
    ///
    /// This looks for a PE header named ".compat", which contains a list of
    /// entries. Each entry can specify a machine type and an entry
    /// point. Search for an IA32 entry and return that entry point if found.
    pub fn get_ia32_compat_entry_point(&self) -> Option<usize> {
        // Look for a section named ".compat".
        let section = self
            .parsed
            .sections
            .iter()
            .find(|s| &s.name == b".compat\0")?;
        let data_start: usize = section.pointer_to_raw_data.try_into().ok()?;
        let data_size: usize = section.size_of_raw_data.try_into().ok()?;
        let section_data = self.data.get(data_start..data_start + data_size)?;

        find_compat_entry_point_in_section(
            section_data,
            goblin::pe::header::COFF_MACHINE_X86,
        )
    }
}

#[derive(Debug, PartialEq)]
struct CompatEntryV1 {
    machine_type: u16,
    entry_point: u32,
}

#[derive(Debug, PartialEq)]
struct CompatEntry {
    entry_type: u8,
    size: u8,
    v1: Option<CompatEntryV1>,
}

struct CompatEntryIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> CompatEntryIter<'a> {
    fn new(section: &[u8]) -> CompatEntryIter {
        CompatEntryIter {
            data: section,
            offset: 0,
        }
    }
}

impl<'a> Iterator for CompatEntryIter<'a> {
    type Item = CompatEntry;

    fn next(&mut self) -> Option<CompatEntry> {
        const ENTRY_TYPE_END_OF_LIST: u8 = 0;
        const ENTRY_TYPE_V1: u8 = 1;

        let mut offset = self.offset;
        let ctx = scroll::LE;

        // Get the entry_type type, end iteration if at the end of the
        // entries.
        let entry_type: u8 = self.data.gread_with(&mut offset, ctx).ok()?;
        if entry_type == ENTRY_TYPE_END_OF_LIST {
            return None;
        }

        // Get the entry size in bytes. End iteration if this is zero to
        // prevent a potential infinite loop.
        let entry_size: u8 = self.data.gread_with(&mut offset, ctx).ok()?;
        if entry_size == 0 {
            return None;
        }

        // Update iterator offset.
        self.offset += usize::from(entry_size);

        let entry_v1 = if entry_type == ENTRY_TYPE_V1 {
            // Known entry type, read machine type and entry point.
            let machine_type: u16 =
                self.data.gread_with(&mut offset, ctx).ok()?;
            let entry_point: u32 =
                self.data.gread_with(&mut offset, ctx).ok()?;

            Some(CompatEntryV1 {
                machine_type,
                entry_point,
            })
        } else {
            // Otherwise return an empty entry.
            None
        };

        Some(CompatEntry {
            entry_type,
            size: entry_size,
            v1: entry_v1,
        })
    }
}

fn find_compat_entry_point_in_section(
    section: &[u8],
    target_machine_type: u16,
) -> Option<usize> {
    for entry in CompatEntryIter::new(section) {
        if let Some(entry) = entry.v1 {
            if entry.machine_type == target_machine_type {
                return entry.entry_point.try_into().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compat_entry() {
        let section = [
            // Small entry of unknown type.
            0x02, 0x02, // ARM entry point.
            0x1, 0x8, 0xc0, 0x01, 0x77, 0x66, 0x55, 0x44,
            // IA32 entry point.
            0x1, 0x8, 0x4c, 0x01, 0x78, 0x56, 0x34, 0x12,
            // Ending entry.
            0x0,
        ];

        let iter = CompatEntryIter::new(&section);
        assert_eq!(
            iter.collect::<Vec<_>>(),
            [
                CompatEntry {
                    entry_type: 2,
                    size: 2,
                    v1: None,
                },
                CompatEntry {
                    entry_type: 1,
                    size: 8,
                    v1: Some(CompatEntryV1 {
                        machine_type: 0x1c0,
                        entry_point: 0x44556677,
                    }),
                },
                CompatEntry {
                    entry_type: 1,
                    size: 8,
                    v1: Some(CompatEntryV1 {
                        machine_type: 0x14c,
                        entry_point: 0x12345678,
                    }),
                }
            ]
        );

        assert_eq!(
            find_compat_entry_point_in_section(&section, 0x14c),
            Some(0x12345678)
        );
    }
}
