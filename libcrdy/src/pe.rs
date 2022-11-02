// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! PE executable parsing.
//!
//! This uses the [`object`] library to parse a PE executable and
//! extract data.

use crate::{Error, Result};
use core::{mem, slice};
use log::info;
use object::pe::IMAGE_FILE_MACHINE_I386;
use object::read::pe::PeFile64;
use object::{LittleEndian, Object, ObjectSection};
use uefi::proto::loaded_image::LoadedImage;
use uefi::table::boot::BootServices;

fn u32_to_usize(v: u32) -> usize {
    v.try_into().expect("size of usize is smaller than u32")
}

/// Use the `LoadedImage` protocol to get a pointer to the data of the
/// currently-executing image.
fn get_current_exe_image_ptr(
    boot_services: &BootServices,
) -> Result<*const u8> {
    // Use the `LoadedImage` protocol to get a pointer to the data of
    // the currently-executing image.
    let li = boot_services
        .open_protocol_exclusive::<LoadedImage>(boot_services.image_handle())
        .map_err(|err| Error::LoadedImageProtocolMissing(err.status()))?;
    let (image_ptr, _) = li.info();
    Ok(image_ptr.cast())
}

/// Read the packed public key data from the `.vbpubk` section of the
/// currently-executing image.
///
/// The returned slice is valid for as long as boot services are active
/// (as enforced by the lifetime).
pub fn get_vbpubk_from_image(boot_services: &BootServices) -> Result<&[u8]> {
    // The PE layout is different between the 32-bit and 64-bit targets;
    // make a `PeFile` type alias to the appropriate type.
    #[cfg(target_pointer_width = "32")]
    type PeFile<'a> = object::read::pe::PeFile32<'a>;
    #[cfg(target_pointer_width = "64")]
    type PeFile<'a> = object::read::pe::PeFile64<'a>;

    let image_ptr = get_current_exe_image_ptr(boot_services)?;
    info!("image base: {:x?}", image_ptr);

    // On the IA32 target we can't rely on the image length provided by
    // `LoadedImage`. This is due to a shim ABI issue. See
    // https://github.com/rhboot/shim/issues/515 for more details.
    //
    // To work around this, assume that the image headers fit within the
    // first kilobyte of data. Parse that partial data into a `PeFile`.
    //
    // Note that we could avoid this hack on X86_64, but let's keep the
    // code paths the same on both targets to keep things consistent.
    let estimated_pe_header_len = 1024;
    let image_data =
        unsafe { slice::from_raw_parts(image_ptr, estimated_pe_header_len) };
    let pe = PeFile::parse(image_data).map_err(Error::InvalidPe)?;

    // Find the target section.
    let section_name = ".vbpubk";
    let section = pe
        .section_table()
        .iter()
        .find(|section| section.raw_name() == section_name.as_bytes())
        .ok_or(Error::MissingPubkey)?;

    // Get the section's data range (relative to the image_ptr).
    let (section_addr, section_len) = section.pe_address_range();
    let section_addr = u32_to_usize(section_addr);
    let section_len = u32_to_usize(section_len);
    info!("{section_name} section: offset={section_addr:#x}, len={section_len:#x}");

    // Get the section's data as a slice.
    let section_data: &[u8] = unsafe {
        slice::from_raw_parts(image_ptr.add(section_addr), section_len)
    };

    Ok(section_data)
}

/// Info about a PE executable's entry points.
pub struct PeInfo {
    /// Primary entry point (as an offset).
    pub entry_point: u32,

    /// IA32 entry point (as an offset).
    pub ia32_compat_entry_point: u32,
}

impl PeInfo {
    /// Parse a PE executable and find its entry point.
    ///
    /// When booting from a 64-bit UEFI environment, the normal PE entry
    /// point in the PE header can be used.
    ///
    /// When booting from a 32-bit UEFI environment, newer kernels can
    /// provide a compatibility entry point. This requires a kernel with
    /// this commit:
    ///
    ///    efi/x86: Implement mixed mode boot without the handover protocol
    pub fn parse(data: &[u8]) -> Result<Self> {
        let pe = PeFile64::parse(data).map_err(Error::InvalidPe)?;

        // Get the primary entry point from a field in the PE header.
        let entry_point = pe
            .nt_headers()
            .optional_header
            .address_of_entry_point
            .get(LittleEndian);

        // Get the IA32 entry point for booting from IA32 firmware to a
        // 64-bit kernel.
        let ia32_compat_entry_point = find_ia32_compat_entry_point(&pe)
            .ok_or(Error::MissingIa32CompatEntryPoint)?;

        Ok(Self {
            entry_point,
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

    fn read_bytes<const N: usize>(&mut self) -> Option<[u8; N]> {
        let bytes = self.data.get(self.offset..self.offset + N)?;
        self.offset += N;
        bytes.try_into().ok()
    }

    fn read_u8(&mut self) -> Option<u8> {
        let bytes = self.read_bytes::<{ mem::size_of::<u8>() }>()?;
        Some(bytes[0])
    }

    fn read_u16le(&mut self) -> Option<u16> {
        let bytes = self.read_bytes::<{ mem::size_of::<u16>() }>()?;
        Some(u16::from_le_bytes(bytes))
    }

    fn read_u32le(&mut self) -> Option<u32> {
        let bytes = self.read_bytes::<{ mem::size_of::<u32>() }>()?;
        Some(u32::from_le_bytes(bytes))
    }
}

impl<'a> Iterator for CompatEntryIter<'a> {
    type Item = CompatEntry;

    fn next(&mut self) -> Option<CompatEntry> {
        const ENTRY_TYPE_END_OF_LIST: u8 = 0;
        const ENTRY_TYPE_V1: u8 = 1;

        let orig_offset = self.offset;

        // Get the entry_type type, end iteration if at the end of the
        // entries.
        let entry_type = self.read_u8()?;
        if entry_type == ENTRY_TYPE_END_OF_LIST {
            return None;
        }

        // Get the entry size in bytes. End iteration if this is zero to
        // prevent a potential infinite loop.
        let entry_size = self.read_u8()?;
        if entry_size == 0 {
            return None;
        }

        let entry_v1 = if entry_type == ENTRY_TYPE_V1 {
            // Known entry type, read machine type and entry point.
            let machine_type = self.read_u16le()?;
            let entry_point = self.read_u32le()?;

            Some(CompatEntryV1 {
                machine_type,
                entry_point,
            })
        } else {
            // Otherwise return an empty entry.
            None
        };

        // Update iterator offset to point at the next entry.
        self.offset = orig_offset + usize::from(entry_size);

        Some(CompatEntry {
            entry_type,
            size: entry_size,
            v1: entry_v1,
        })
    }
}

/// Get the IA32 entry point.
///
/// This looks for a PE header named ".compat", which contains a
/// list of entries. Each entry can specify a machine type and an
/// entry point. Search for an IA32 entry and return that entry
/// point if found.
fn find_ia32_compat_entry_point(pe: &PeFile64) -> Option<u32> {
    let section = pe.section_by_name(".compat")?;
    find_compat_entry_point_in_section(
        section.data().ok()?,
        IMAGE_FILE_MACHINE_I386,
    )
}

fn find_compat_entry_point_in_section(
    section: &[u8],
    target_machine_type: u16,
) -> Option<u32> {
    for entry in CompatEntryIter::new(section) {
        if let Some(entry) = entry.v1 {
            if entry.machine_type == target_machine_type {
                return Some(entry.entry_point);
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
