// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::fmt::{self, Display, Formatter};
use core::slice;
use libcrdy::arch::PeFileForCurrentArch;
use libcrdy::util::u32_to_usize;
use log::info;
use uefi::proto::loaded_image::LoadedImage;
use uefi::table::boot::BootServices;
use uefi::Status;

#[derive(Clone, Copy)]
pub enum VbpubkError {
    ImageTooBig(u64),
    InvalidPe(object::Error),
    InvalidSectionBounds { addr: usize, len: usize },
    MissingSection,
    MultipleSections,
    OpenLoadedImageProtocolFailed(Status),
}

impl Display for VbpubkError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::ImageTooBig(size) => write!(f, "image is larger than usize: {size}"),
            Self::InvalidPe(error) => write!(f, "invalid PE: {error}"),
            Self::InvalidSectionBounds { addr, len } => {
                write!(f, "invalid section bounds: addr={addr:#016x}, len={len:#x}")
            }
            Self::MissingSection => write!(f, "missing .vbpubk section"),
            Self::MultipleSections => write!(f, "multiple .vbpubk sections"),
            Self::OpenLoadedImageProtocolFailed(status) => {
                write!(f, "failed to open LoadedImage protocol: {status}")
            }
        }
    }
}

/// Get the currently-executing image's data.
///
/// The returned slice is valid for as long as boot services are active
/// (as enforced by the lifetime).
fn get_loaded_image_data<'boot>(
    boot_services: &'boot BootServices,
) -> Result<&'boot [u8], VbpubkError> {
    // Use the `LoadedImage` protocol to get a pointer to the data of
    // the currently-executing image.
    let li = boot_services
        .open_protocol_exclusive::<LoadedImage>(boot_services.image_handle())
        .map_err(|err| VbpubkError::OpenLoadedImageProtocolFailed(err.status()))?;
    let (image_ptr, image_len) = li.info();
    let image_ptr: *const u8 = image_ptr.cast();

    info!("image base: {:x?}", image_ptr);
    info!("image size: {} bytes", image_len);

    // Convert the pointer and length to a byte slice.
    let image_len = usize::try_from(image_len).map_err(|_| VbpubkError::ImageTooBig(image_len))?;
    let image_data: &'boot [u8] = unsafe { slice::from_raw_parts(image_ptr, image_len) };

    Ok(image_data)
}

/// Read the packed public key data from the `.vbpubk` section of the
/// currently-executing image.
///
/// The returned slice is valid for as long as boot services are active
/// (as enforced by the lifetime).
pub fn get_vbpubk_from_image(boot_services: &BootServices) -> Result<&[u8], VbpubkError> {
    let image_data = get_loaded_image_data(boot_services)?;
    let pe = PeFileForCurrentArch::parse(image_data).map_err(VbpubkError::InvalidPe)?;

    // Find the target section.
    let section_name = ".vbpubk";
    let mut section_iter = pe
        .section_table()
        .iter()
        .filter(|section| section.raw_name() == section_name.as_bytes());
    let section = section_iter.next().ok_or(VbpubkError::MissingSection)?;
    // Return an error if there's more than one vbpubk section, as that
    // could indicate something wrong with the signer.
    if section_iter.next().is_some() {
        return Err(VbpubkError::MultipleSections);
    }

    // Get the section's data range (relative to the image_ptr).
    let (section_addr, section_len) = section.pe_address_range();
    let section_addr = u32_to_usize(section_addr);
    let section_len = u32_to_usize(section_len);
    info!("{section_name} section: offset={section_addr:#x}, len={section_len:#x}");

    // Get the section's data as a slice.
    let err = VbpubkError::InvalidSectionBounds {
        addr: section_addr,
        len: section_len,
    };
    let section_end = section_addr.checked_add(section_len).ok_or(err)?;
    let section_range = section_addr..section_end;
    let section_data = image_data.get(section_range).ok_or(err)?;

    Ok(section_data)
}
