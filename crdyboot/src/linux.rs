use crate::handover;
use crate::result::{Error, Result};
use core::convert::TryInto;
use core::ffi::c_void;
use core::mem;
use log::{error, info};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::table::boot::MemoryType;
use uefi::table::{Boot, SystemTable};
use uefi::{Char16, Handle, Status};

type Entrypoint = unsafe extern "efiapi" fn(Handle, SystemTable<Boot>);

// TODO, copied from uefi-rs so that we can set some of the non-public
// options. Should just make them public...
#[repr(C)]
struct MyLoadedImage {
    revision: u32,
    parent_handle: Handle,
    system_table: *const c_void,

    // Source location of the image
    device_handle: Handle,
    _file_path: *const c_void,
    _reserved: *const c_void,

    // Image load options
    load_options_size: u32,
    load_options: *const Char16,

    // Location where image was loaded
    image_base: *const c_void,
    image_size: u64,
    image_code_type: MemoryType,
    image_data_type: MemoryType,

    unload: extern "efiapi" fn(image_handle: Handle) -> Status,
}

fn get_pe_entry_point(data: &[u8]) -> Result<Entrypoint> {
    // Check the magic bytes in the DOS header.
    let dos_magic = data.get(0..2).ok_or(Error::PeHeaderTooSmall)?;
    if dos_magic != [0x4d, 0x5a] {
        error!("invalid DOS header magic: {:x?}", dos_magic);
        return Err(Error::InvalidPeMagic);
    }

    // Get `size_of(T)` bytes starting at `offset` from `data`.
    fn get_slice<T>(data: &[u8], offset: usize) -> Result<&[u8]> {
        data.get(offset..offset + mem::size_of::<T>())
            .ok_or(Error::PeHeaderTooSmall)
    }

    // Get a little-endian u32 from `data` at `offset` and convert to a
    // `usize`.
    fn get_u32_as_usize(data: &[u8], offset: usize) -> Result<usize> {
        let bytes = get_slice::<u32>(data, offset)?;

        let val = u32::from_le_bytes(
            // OK to unwrap because we just got 4 bytes.
            bytes.try_into().expect("not enough bytes"),
        );

        // OK to unwrap because usize is always at least as big as a u32 on
        // our targets.
        Ok(val.try_into().expect("usize too small"))
    }

    // Get the offset of the PE header. This is stored as a u32 at offset
    // 0x3c.
    let pe_header_offset = get_u32_as_usize(data, 0x3c)?;

    let pe_header = &data
        .get(pe_header_offset..)
        .ok_or(Error::PeHeaderTooSmall)?;

    // Check the magic bytes in the PE header.
    let pe_magic = pe_header.get(0..4).ok_or(Error::PeHeaderTooSmall)?;
    if pe_magic != [0x50, 0x45, 0x00, 0x00] {
        error!("invalid PE header magic: {:x?}", pe_magic);
        return Err(Error::InvalidPeMagic);
    }

    // Get the entry point offset (relative to the start of the kernel
    // data), which is stored as a u32 at offset 0x28 within the PE header.
    let entry_point_offset = get_u32_as_usize(pe_header, 0x28)?;

    let entry_point_address = (data.as_ptr() as usize) + entry_point_offset;
    info!("entry_point_address: 0x{:x}", entry_point_address);

    // Convert the address back to a pointer and transmute to the desired
    // function pointer type.
    let entry_point = entry_point_address as *const ();
    unsafe {
        let entry_point: Entrypoint = mem::transmute(entry_point);
        Ok(entry_point)
    }
}

fn modify_loaded_image(
    image: Handle,
    system_table: &SystemTable<Boot>,
    kernel_data: &[u8],
    cmdline_ucs2: &[Char16],
) -> Result<()> {
    let bt = system_table.boot_services();

    let li = bt
        .handle_protocol::<LoadedImage>(image)
        .log_warning()
        .map_err(|err| Error::LoadedImageProtocolMissing(err.status()))?;
    let li: &mut LoadedImage = unsafe { &mut *li.get() };
    let li: &mut MyLoadedImage =
        unsafe { &mut *((li as *mut LoadedImage).cast::<MyLoadedImage>()) };

    li.image_base = kernel_data.as_ptr().cast::<c_void>();
    li.image_size = if let Ok(size) = kernel_data.len().try_into() {
        size
    } else {
        return Err(Error::KernelDataTooBig(kernel_data.len()));
    };

    li.load_options = cmdline_ucs2.as_ptr();
    let load_options_size = 2 * cmdline_ucs2.len();
    li.load_options_size = if let Ok(size) = load_options_size.try_into() {
        size
    } else {
        return Err(Error::CommandLineTooBig(load_options_size));
    };

    Ok(())
}

/// Hand off control to the Linux EFI stub.
///
/// As mentioned in [1], the preferred method for loading the kernel
/// on UEFI is to build in the EFI stub and run it as a normal PE/COFF
/// executable. This is indeed much simpler than trying to use the EFI
/// handover protocol, which is not fully documented. The kernel's PE
/// header does not require any relocations to be performed, so the
/// only thing we need to get from the header is the entry point.
///
/// Note that we can't use LoadImage+StartImage for this, because with
/// secure boot enabled it would try to verify the signature of the
/// kernel which would fail unless we signed the kernel in the way
/// UEFI expects. Since we have already verified the kernel via the
/// vboot structures (as well as the command line parameters), this
/// would be an unnecessary verification.
///
/// [1]: kernel.org/doc/html/latest/x86/boot.html#efi-handover-protocol-deprecated
pub fn execute_linux_efi_stub(
    kernel_data: &[u8],
    crdyboot_image: Handle,
    system_table: SystemTable<Boot>,
    cmdline_ucs2: &[Char16],
) -> Result<()> {
    let entry_point = get_pe_entry_point(kernel_data)?;

    // Ideally we could create a new image here, but I'm not sure
    // there's any way to do that without calling LoadImage, which we
    // can't do due to secure boot. This is the same method shim uses:
    // modify the existing image's parameters.
    modify_loaded_image(
        crdyboot_image,
        &system_table,
        kernel_data,
        cmdline_ucs2,
    )?;

    unsafe {
        (entry_point)(crdyboot_image, system_table);
    }

    Err(Error::KernelDidNotTakeControl)
}

pub fn execute_linux_kernel(
    kernel_data: &[u8],
    crdyboot_image: Handle,
    system_table: SystemTable<Boot>,
    cmdline: &str,
    cmdline_ucs2: &[Char16],
) -> Result<()> {
    let is_64bit = match mem::size_of::<usize>() {
        8 => true,
        4 => false,
        other => panic!("invalid size of usize: {}", other),
    };

    if is_64bit {
        execute_linux_efi_stub(
            kernel_data,
            crdyboot_image,
            system_table,
            cmdline_ucs2,
        )
    } else {
        info!("using handover!");
        handover::execute_linux_kernel_32(
            kernel_data,
            crdyboot_image,
            system_table,
            cmdline,
        )
    }
}
