// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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

use crate::{Error, Result};
use goblin::pe::section_table::SectionTable;
use goblin::pe::PE;
use scroll::Pread;

/// Info about a PE executable.
pub struct PeInfo {
    /// Primary entry point (as an offset).
    pub entry_point: usize,

    /// IA32 entry point (as an offset).
    pub ia32_compat_entry_point: usize,
}

impl PeInfo {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let pe = PE::parse(data).map_err(Error::InvalidPe)?;

        let section_data = find_section_data(data, &pe.sections, *b".compat\0")
            .ok_or(Error::MissingIa32CompatEntryPoint)?;

        let ia32_compat_entry_point = find_compat_entry_point_in_section(
            section_data,
            goblin::pe::header::COFF_MACHINE_X86,
        )
        .ok_or(Error::MissingIa32CompatEntryPoint)?;

        Ok(Self {
            entry_point: pe.entry,
            ia32_compat_entry_point,
        })
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

/// Search for a section with the specified `name` and return its data (as a
/// slice within `data`).
fn find_section_data<'a>(
    data: &'a [u8],
    sections: &[SectionTable],
    name: [u8; 8],
) -> Option<&'a [u8]> {
    let section = sections.iter().find(|s| s.name == name)?;
    let data_start: usize = section.pointer_to_raw_data.try_into().ok()?;
    let data_size: usize = section.size_of_raw_data.try_into().ok()?;
    data.get(data_start..data_start + data_size)
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
    fn test_find_section_data() {
        let data = &[0xa, 0xb, 0xc, 0xd];
        let sections = &[SectionTable {
            name: *b"abcdefgh",
            real_name: None,
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 2,
            pointer_to_raw_data: 1,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        }];

        assert_eq!(
            find_section_data(data, sections, *b"abcdefgh").unwrap(),
            &[0xb, 0xc]
        );
    }

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
