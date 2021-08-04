use crate::handover;
use crate::result::{Error, Result};
use core::convert::TryInto;
use core::ffi::c_void;
use core::mem;
use log::info;
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

fn is_64bit() -> bool {
    match mem::size_of::<usize>() {
        8 => true,
        4 => false,
        other => panic!("invalid size of usize: {}", other),
    }
}

fn get_pe_entry_point(data: &[u8]) -> Result<Entrypoint> {
    let pe = goblin::pe::PE::parse(data).map_err(Error::InvalidPe)?;

    let entry_point_offset = pe.entry;
    info!("entry_point_offset: 0x{:x}", entry_point_offset);

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
    if is_64bit() {
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
