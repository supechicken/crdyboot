//! This module implements running the Linux kernel via the handover
//! protocol.
//!
//! This is only needed on 32-bit UEFI. Hopefully it can be dropped once we're
//! on a kernel new enough to include "efi/x86: Implement mixed mode boot
//! without the handover protocol":
//! https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=17054f492dfd4d91e093ebb87013807812ec42a4

use crate::result::{Error, Result};
use alloc::vec;
use core::convert::TryInto;
use core::{mem, ptr};
use uefi::table::{Boot, SystemTable};
use uefi::Handle;
use vboot::struct_from_bytes;

#[repr(C, packed)]
struct setup_header {
    setup_sects: u8,
    root_flags: u16,
    syssize: u32,
    ram_size: u16,
    vid_mode: u16,
    root_dev: u16,
    boot_flag: u16,
    jump: u16,
    header: u32,
    version: u16,
    realmode_swtch: u32,
    start_sys_seg: u16,
    kernel_version: u16,
    type_of_loader: u8,
    loadflags: u8,
    setup_move_size: u16,
    code32_start: u32,
    ramdisk_image: u32,
    ramdisk_size: u32,
    bootsect_kludge: u32,
    heap_end_ptr: u16,
    ext_loader_ver: u8,
    ext_loader_type: u8,
    cmd_line_ptr: u32,
    initrd_addr_max: u32,
    kernel_alignment: u32,
    relocatable_kernel: u8,
    min_alignment: u8,
    xloadflags: u16,
    cmdline_size: u32,
    hardware_subarch: u32,
    hardware_subarch_data: u64,
    payload_offset: u32,
    payload_length: u32,
    setup_data: u64,
    pref_address: u64,
    init_size: u32,
    handover_offset: u32,
}

#[repr(C, packed)]
struct boot_params {
    screen_info: [u8; 64],
    apm_bios_info: [u8; 20],
    _pad2: [u8; 4],
    tboot_addr: u64,
    ist_info: [u8; 16],
    _pad3: [u8; 16],
    hd0_info: [u8; 16],
    hd1_info: [u8; 16],
    sys_desc_table: [u8; 16],
    olpc_ofw_header: [u8; 16],
    ext_ramdisk_image: u32,
    ext_ramdisk_size: u32,
    ext_cmd_line_ptr: u32,
    _pad4: [u8; 116],
    edid_info: [u8; 128],
    efi_info: [u8; 32],
    alt_mem_k: u32,
    scratch: u32,
    e820_entries: u8,
    eddbuf_entries: u8,
    edd_mbr_sig_buf_entries: u8,
    kbd_status: u8,
    secure_boot: u8,
    _pad5: [u8; 2],
    sentinel: u8,
    _pad6: [u8; 1],
    hdr: setup_header,
    _pad7: [u8; 40],
    edd_mbr_sig_buffer: [u32; 16],
    e820_table: [u8; 2560],
    _pad8: [u8; 48],
    eddbuf: [u8; 492],
    _pad9: [u8; 276],
}

const SETUP_MAGIC: u32 = 0x53726448; // "HdrS"

/// Run the kernel using the EFI handover protocol.
///
/// - https://www.kernel.org/doc/html/latest/x86/boot.html#efi-handover-protocol-deprecated
/// - linux/arch/x86/include/uapi/asm/bootparam.h
/// - https://lwn.net/Articles/589193/
/// - https://lwn.net/Articles/632528/
pub fn execute_linux_kernel_32(
    kernel_data: &[u8],
    crdyboot_image: Handle,
    system_table: SystemTable<Boot>,
    cmdline: &str,
) -> Result<()> {
    let image_params = if let Some(image_params) =
        unsafe { struct_from_bytes::<boot_params>(kernel_data) }
    {
        image_params
    } else {
        return Err(Error::KernelTooSmall);
    };

    if image_params.hdr.boot_flag != 0xAA55
        || image_params.hdr.header != SETUP_MAGIC
        || image_params.hdr.version < 0x20b
        || image_params.hdr.relocatable_kernel == 0
    {
        return Err(Error::InvalidBootParameters);
    }

    let mut boot_params_raw = vec![0; 0x4000];
    let boot_params: &mut boot_params =
        unsafe { &mut *(boot_params_raw.as_mut_ptr() as *mut boot_params) };

    unsafe {
        ptr::copy(&image_params.hdr, &mut boot_params.hdr, 1);
    }
    boot_params.hdr.type_of_loader = 0xff;

    let setup_sectors: u32 = if image_params.hdr.setup_sects > 0 {
        image_params.hdr.setup_sects as u32
    } else {
        4
    };

    boot_params.hdr.code32_start =
        (kernel_data.as_ptr() as u64).try_into().map_err(|_| {
            Error::BadNumericConversion("boot_params.hdr.code32_start")
        })?;
    boot_params.hdr.code32_start += (setup_sectors + 1) * 512;

    let mut cmdline = cmdline.as_bytes().to_vec();
    cmdline.push(0);

    boot_params.hdr.cmd_line_ptr =
        (cmdline.as_ptr() as u64).try_into().map_err(|_| {
            Error::BadNumericConversion("boot_params.hdr.cmd_line_ptr")
        })?;

    let start = boot_params.hdr.code32_start + image_params.hdr.handover_offset;

    type Handover =
        unsafe extern "sysv64" fn(Handle, SystemTable<Boot>, *mut boot_params);

    let start_ptr = start as *const ();

    let handover: Handover = unsafe { mem::transmute(start_ptr) };
    unsafe {
        (handover)(crdyboot_image, system_table, boot_params);
    }

    Err(Error::KernelDidNotTakeControl)
}
