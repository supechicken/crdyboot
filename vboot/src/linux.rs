//! Header structures at the beginning of the Linux kernel data.

#![allow(missing_docs)]

#[repr(C, packed)]
pub struct SetupHeader {
    pub setup_sects: u8,
    root_flags: u16,
    syssize: u32,
    ram_size: u16,
    vid_mode: u16,
    root_dev: u16,
    pub boot_flag: u16,
    jump: u16,
    header: u32,
    pub version: u16,
    realmode_swtch: u32,
    start_sys_seg: u16,
    kernel_version: u16,
    pub type_of_loader: u8,
    loadflags: u8,
    setup_move_size: u16,
    pub code32_start: u32,
    ramdisk_image: u32,
    ramdisk_size: u32,
    bootsect_kludge: u32,
    heap_end_ptr: u16,
    ext_loader_ver: u8,
    ext_loader_type: u8,
    pub cmd_line_ptr: u32,
    initrd_addr_max: u32,
    kernel_alignment: u32,
    pub relocatable_kernel: u8,
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
    pub handover_offset: u32,
}

#[repr(C, packed)]
pub struct BootParams {
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
    pub hdr: SetupHeader,
    _pad7: [u8; 40],
    edd_mbr_sig_buffer: [u32; 16],
    e820_table: [u8; 2560],
    _pad8: [u8; 48],
    eddbuf: [u8; 492],
    _pad9: [u8; 276],
}

const SETUP_MAGIC: u32 = 0x53726448; // "HdrS"

pub enum LinuxError {
    InputTooSmall,
    InvalidMagic,
}

/// Get `BootParams` from `kernel_data`. Returns an error if the input is
/// not big enough or if the expected magic bytes aren't found.
pub fn kernel_data_as_boot_params(
    kernel_data: &[u8],
) -> Result<&BootParams, LinuxError> {
    let params = unsafe { crate::struct_from_bytes::<BootParams>(kernel_data) }
        .ok_or(LinuxError::InputTooSmall)?;

    if params.hdr.header == SETUP_MAGIC {
        Ok(params)
    } else {
        Err(LinuxError::InvalidMagic)
    }
}
