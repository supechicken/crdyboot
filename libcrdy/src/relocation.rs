// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module provides [`relocate_pe_into`] to transform PE file data
//! into the format needed to actually execute it. In particular, this
//! ensures that sections are properly aligned and relocations are
//! applied.
//!
//! For more details of the PE format, see
//! <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
//!
//! When loading an image via UEFI's [`LoadImage`] function these
//! transformations are applied automatically, and that's what happens
//! when crdyshim is loaded. However, crdyshim cannot use [`LoadImage`]
//! to load the second-stage bootloader because when secure boot is
//! enabled [`LoadImage`] verifies that the image data was signed by a
//! key known to the firmware. Since the point of crdyshim (and shim) is
//! to verify with an embedded key rather than a key known to the
//! firmware, [`LoadImage`] would fail.
//!
//! [`LoadImage`]: https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#efi-boot-services-loadimage

use crate::util::u32_to_usize;
use core::fmt::{self, Display, Formatter};
use log::info;
use object::pe::{IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW};
use object::read::pe::{
    ImageNtHeaders, ImageOptionalHeader, PeFile, Relocation, RelocationBlockIterator,
};
use object::LittleEndian;

#[derive(Clone, Copy, Debug)]
pub enum RelocationError {
    /// The image base caused overflow.
    ImageBase(u64),

    /// A section in the image caused overflow.
    SectionBounds { addr: usize, len: usize },

    /// Failed to parse relocation blocks.
    RelocationBlocks(object::Error),

    /// A relocation block is invalid.
    Block(usize, object::Error),

    /// Failed to apply a relocation.
    Relocation {
        block_index: usize,
        relocation_index: usize,
    },

    /// The destination buffer is not large enough to hold the relocated
    /// executable.
    DestinationTooSmall,
}

impl Display for RelocationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageBase(image_base) => write!(f, "invalid image base: {image_base}"),
            Self::SectionBounds { addr, len } => {
                write!(f, "invalid section bounds: addr={addr}, len={len}")
            }
            Self::RelocationBlocks(err) => write!(f, "invalid relocation blocks: {err}"),
            Self::Block(index, err) => write!(f, "invalid relocation block {index}: {err}"),
            Self::Relocation {
                block_index,
                relocation_index,
            } => write!(
                f,
                "invalid relocation {relocation_index} in block {block_index}"
            ),
            Self::DestinationTooSmall => write!(f, "relocation buffer is not large enough"),
        }
    }
}

/// Apply a single relocation onto the PE image data contained in `dst`.
///
/// See [`apply_relocations`] for the meaning of the `adjust` arg.
fn apply_one_relocation(relocation: Relocation, dst: &mut [u8], adjust: i64) -> Option<()> {
    match relocation.typ {
        IMAGE_REL_BASED_DIR64 => {
            let offset = u32_to_usize(relocation.virtual_address);
            let end = offset.checked_add(8)?;
            let bytes = dst.get_mut(offset..end)?;

            let val = i64::from_le_bytes(bytes.try_into().unwrap()).checked_add(adjust)?;
            bytes.copy_from_slice(&val.to_le_bytes());
        }
        IMAGE_REL_BASED_HIGHLOW => {
            let offset = u32_to_usize(relocation.virtual_address);
            let end = offset.checked_add(4)?;
            let bytes = dst.get_mut(offset..end)?;

            let adjust = i32::try_from(adjust).ok()?;
            let val = i32::from_le_bytes(bytes.try_into().unwrap()).checked_add(adjust)?;
            bytes.copy_from_slice(&val.to_le_bytes());
        }
        IMAGE_REL_BASED_ABSOLUTE => {
            // Nothing to do.
        }
        _ => return None,
    }

    // Success.
    Some(())
}

/// Apply all relocations contained in `blocks` onto the PE image data
/// contained in `dst`.
///
/// The `adjust` arg contains `ImageBase - dst.ptr()`. `ImageBase` is
/// defined in the win32 PE format: "The preferred address of the first
/// byte of image when loaded into memory". In other words, `adjust` is
/// the offset between where the PE expected to be loaded in memory and
/// where it is actually located.
fn apply_relocations(
    mut blocks: RelocationBlockIterator,
    dst: &mut [u8],
    adjust: i64,
) -> Result<(), RelocationError> {
    let mut block_index = 0;
    while let Some(block) = blocks
        .next()
        .map_err(|err| RelocationError::Block(block_index, err))?
    {
        for (relocation_index, relocation) in block.enumerate() {
            apply_one_relocation(relocation, dst, adjust).ok_or(RelocationError::Relocation {
                block_index,
                relocation_index,
            })?;
        }
        block_index = block_index.checked_add(1).unwrap();
    }

    Ok(())
}

/// Copy the PE image data in `src` to `dst` while applying all
/// modifications needed to actually run the image.
///
/// The `src` data contains the original PE file data loaded from
/// disk. To fill in `dst`, the following operations occur:
///
/// 1. The image headers are copied over unmodified.
/// 2. Each section's data are copied to the appropriate virtual
///    address. This is needed because sections in the file data may be
///    aligned differently than what is needed at runtime.
/// 3. Relocations from the `.reloc` section are applied.
///
/// For more details of the PE format, see
/// <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
///
/// Precondition: the `dst` buffer should be initialized to all zero
/// bytes to ensure there's no junk data in the result.
#[allow(clippy::missing_panics_doc)]
pub fn relocate_pe_into<N: ImageNtHeaders>(
    src: &PeFile<N>,
    dst: &mut [u8],
) -> Result<(), RelocationError> {
    let header = src.nt_headers().optional_header();
    let image_base = header.image_base();
    let image_base_err = RelocationError::ImageBase(image_base);
    let image_base = i64::try_from(image_base).map_err(|_| image_base_err)?;
    let size_of_headers = header.size_of_headers();

    let size_of_headers = u32_to_usize(size_of_headers);

    // OK to unwrap: the PE parsed successfully, so the header data does exist.
    let src_headers = src.data().get(..size_of_headers).unwrap();
    let dst_headers = dst
        .get_mut(..size_of_headers)
        .ok_or(RelocationError::DestinationTooSmall)?;
    dst_headers.copy_from_slice(src_headers);

    // Copy over sections.
    for src_section in src.section_table().iter() {
        let virtual_address = u32_to_usize(src_section.virtual_address.get(LittleEndian));

        let src_section_data = src_section.pe_data(src.data()).unwrap();

        let virtual_address_end = virtual_address.checked_add(src_section_data.len()).ok_or(
            RelocationError::SectionBounds {
                addr: virtual_address,
                len: src_section_data.len(),
            },
        )?;
        let dst_section_data = dst
            .get_mut(virtual_address..virtual_address_end)
            .ok_or(RelocationError::DestinationTooSmall)?;
        dst_section_data.copy_from_slice(src_section_data);
    }

    if let Some(blocks) = src
        .data_directories()
        .relocation_blocks(src.data(), &src.section_table())
        .map_err(RelocationError::RelocationBlocks)?
    {
        let dst_base = dst.as_ptr() as i64;
        let adjust = dst_base.checked_sub(image_base).ok_or(image_base_err)?;
        info!("relocation adjustment: {adjust:#x}");

        apply_relocations(blocks, dst, adjust)?;
    } else {
        info!("no relocations");
    }

    Ok(())
}
