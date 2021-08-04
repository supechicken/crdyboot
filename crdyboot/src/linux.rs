use crate::handover;
use crate::result::{Error, Result};
use core::convert::TryInto;
use core::ffi::c_void;
use core::mem;
use goblin::pe::PE;
use log::info;
use scroll::Pread;
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

fn get_ia32_compat_entry_point(data: &[u8], pe: &PE) -> Option<usize> {
    // Look for a section named ".compat".
    let section = pe.sections.iter().find(|s| &s.name == b".compat\0")?;
    let data_start: usize = section.pointer_to_raw_data.try_into().ok()?;
    let data_size: usize = section.size_of_raw_data.try_into().ok()?;
    let section_data = data.get(data_start..data_start + data_size)?;

    const ELEM_TYPE_END_OF_LIST: u8 = 0;
    const ELEM_TYPE_V1: u8 = 1;

    let mut outer_offset: usize = 0;
    loop {
        let mut offset = outer_offset;

        // Get the elem_type type.
        let elem_type: u8 = section_data.gread(&mut offset).ok()?;
        if elem_type == ELEM_TYPE_END_OF_LIST {
            break;
        }

        // Get the element size in bytes.
        let elem_size: u8 = section_data.gread(&mut offset).ok()?;
        let elem_size: usize = elem_size.into();

        // Known element type.
        if elem_type == ELEM_TYPE_V1 {
            // Read the machine type and check if it matches IA32.
            let machine_type: u16 = section_data.gread(&mut offset).ok()?;
            if machine_type == goblin::pe::header::COFF_MACHINE_X86 {
                // Read the entry point offset and return it.
                let entry_point: u32 = section_data.gread(&mut offset).ok()?;
                return entry_point.try_into().ok();
            }
        }

        // Continue to next element.
        outer_offset += elem_size;
    }

    // No matching compat entry found.
    None
}

fn entry_point_from_offset(
    data: &[u8],
    entry_point_offset: usize,
) -> Entrypoint {
    info!("entry_point_offset: 0x{:x}", entry_point_offset);

    let entry_point_address = (data.as_ptr() as usize) + entry_point_offset;
    info!("entry_point_address: 0x{:x}", entry_point_address);

    // Convert the address back to a pointer and transmute to the desired
    // function pointer type.
    let entry_point = entry_point_address as *const ();
    unsafe {
        let entry_point: Entrypoint = mem::transmute(entry_point);
        entry_point
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
    entry_point: Entrypoint,
    crdyboot_image: Handle,
    system_table: SystemTable<Boot>,
    cmdline_ucs2: &[Char16],
) -> Result<()> {
    info!("booting the EFI stub");

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
    let pe = PE::parse(kernel_data).map_err(Error::InvalidPe)?;

    let execute_linux_efi_stub = |system_table, entry_point_offset| {
        execute_linux_efi_stub(
            kernel_data,
            entry_point_from_offset(kernel_data, entry_point_offset),
            crdyboot_image,
            system_table,
            cmdline_ucs2,
        )
    };

    if is_64bit() {
        execute_linux_efi_stub(system_table, pe.entry)
    } else if let Some(entry) = get_ia32_compat_entry_point(kernel_data, &pe) {
        execute_linux_efi_stub(system_table, entry)
    } else {
        handover::execute_linux_kernel_32(
            kernel_data,
            crdyboot_image,
            system_table,
            cmdline,
        )
    }
}
