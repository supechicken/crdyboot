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
use object::pe::{IMAGE_DLLCHARACTERISTICS_NX_COMPAT, IMAGE_FILE_MACHINE_I386};
use object::read::pe::{ImageOptionalHeader, PeFile64};
use object::{LittleEndian, Object, ObjectSection};
use uefi::proto::loaded_image::LoadedImage;
use uefi::table::boot::BootServices;

fn u32_to_usize(v: u32) -> usize {
    v.try_into().expect("size of usize is smaller than u32")
}

/// Get the currently-executing image's data.
///
/// The returned slice is valid for as long as boot services are active
/// (as enforced by the lifetime).
fn get_loaded_image_data<'boot>(boot_services: &'boot BootServices) -> Result<&'boot [u8]> {
    // Use the `LoadedImage` protocol to get a pointer to the data of
    // the currently-executing image.
    let li = boot_services
        .open_protocol_exclusive::<LoadedImage>(boot_services.image_handle())
        .map_err(|err| Error::LoadedImageProtocolMissing(err.status()))?;
    let (image_ptr, image_len) = li.info();
    let image_ptr: *const u8 = image_ptr.cast();

    info!("image base: {:x?}", image_ptr);
    info!("image size: {} bytes", image_len);

    // Convert the pointer and length to a byte slice.
    let image_len = usize::try_from(image_len).map_err(|_| Error::Overflow("image_len"))?;
    let image_data: &'boot [u8] = unsafe { slice::from_raw_parts(image_ptr, image_len) };

    Ok(image_data)
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

    let image_data = get_loaded_image_data(boot_services)?;
    let pe = PeFile::parse(image_data).map_err(Error::InvalidPe)?;

    // Find the target section.
    let section_name = ".vbpubk";
    let mut section_iter = pe
        .section_table()
        .iter()
        .filter(|section| section.raw_name() == section_name.as_bytes());
    let section = section_iter.next().ok_or(Error::MissingPubkey)?;
    // Return an error if there's more than one vbpubk section, as that
    // could indicate something wrong with the signer.
    if section_iter.next().is_some() {
        return Err(Error::MultiplePubkey);
    }

    // Get the section's data range (relative to the image_ptr).
    let (section_addr, section_len) = section.pe_address_range();
    let section_addr = u32_to_usize(section_addr);
    let section_len = u32_to_usize(section_len);
    info!("{section_name} section: offset={section_addr:#x}, len={section_len:#x}");

    // Get the section's data as a slice.
    let section_data = image_data
        .get(section_addr..section_addr + section_len)
        .ok_or(Error::OutOfBounds("vbpubk section data"))?;

    Ok(section_data)
}

/// Info about a PE section.
pub struct PeSectionInfo {
    /// Section's absolute start address.
    pub address: u64,

    /// Section's size in bytes.
    pub len: u64,

    /// Whether the section is writable.
    pub writable: bool,

    /// Whether the section is executable.
    pub executable: bool,
}

/// Info about a PE executable.
pub struct PeInfo<'a> {
    pe: PeFile64<'a>,
}

impl<'a> PeInfo<'a> {
    /// Parse a PE executable.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let pe = PeFile64::parse(data).map_err(Error::InvalidPe)?;

        Ok(Self { pe })
    }

    /// Primary entry point (as an offset).
    ///
    /// When booting from a 64-bit UEFI environment, the normal PE entry
    /// point in the PE header can be used.
    pub fn primary_entry_point(&self) -> u32 {
        self.pe
            .nt_headers()
            .optional_header
            .address_of_entry_point()
    }

    /// IA32 entry point (as an offset).
    ///
    /// When booting from a 32-bit UEFI environment, newer kernels can
    /// provide a compatibility entry point. This requires a kernel with
    /// this commit:
    ///
    ///    efi/x86: Implement mixed mode boot without the handover protocol
    pub fn ia32_compat_entry_point(&self) -> Result<u32> {
        find_ia32_compat_entry_point(&self.pe).ok_or(Error::MissingIa32CompatEntryPoint)
    }

    /// Whether the image's DLL characteristics have the `NX_COMPAT` bit set.
    pub fn is_nx_compat(&self) -> bool {
        let c = self
            .pe
            .nt_headers()
            .optional_header
            .dll_characteristics
            .get(LittleEndian);
        (c & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0
    }

    /// Get an iterator over the PE sections.
    pub fn section_iter(&self) -> impl Iterator<Item = PeSectionInfo> + 'a {
        // Convert the image data pointer to a u64.
        let base = self.pe.data().as_ptr() as u64;

        self.pe
            .section_table()
            .iter()
            .enumerate()
            .map(move |(index, section)| {
                let c = section.characteristics.get(LittleEndian);

                let (offset, len) = section.pe_address_range();
                info!("section {index}: offset={offset:#x}, len={len:#x}, characteristics={c:#x}");

                PeSectionInfo {
                    address: base + u64::from(offset),
                    len: u64::from(len),
                    writable: (c & object::pe::IMAGE_SCN_MEM_WRITE) != 0,
                    executable: (c & object::pe::IMAGE_SCN_MEM_EXECUTE) != 0,
                }
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
    find_compat_entry_point_in_section(section.data().ok()?, IMAGE_FILE_MACHINE_I386)
}

fn find_compat_entry_point_in_section(section: &[u8], target_machine_type: u16) -> Option<u32> {
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
            0x1, 0x8, 0xc0, 0x01, 0x77, 0x66, 0x55, 0x44, // IA32 entry point.
            0x1, 0x8, 0x4c, 0x01, 0x78, 0x56, 0x34, 0x12, // Ending entry.
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
