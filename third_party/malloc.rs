// Code in this file was adapted from https://shift.click/blog/on-dealloc,
// which is tri-licensed under CC0/MIT/Apache (https://shift.click/about).

use alloc::alloc::Layout;
use core::mem;

#[derive(Copy, Clone)]
struct AllocInfo {
    layout: Layout,
    ptr: *mut u8,
}

#[no_mangle]
unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    let align = 8;
    let layout =
        Layout::from_size_align(size, align).expect("failed to create layout");

    // Compute a layout sufficient to store `AllocInfo`
    // immediately before it.
    let header_layout = Layout::new::<AllocInfo>();

    let (to_request, offset) = header_layout
        .extend(layout)
        .expect("failed to extend header layout");

    let orig_ptr = alloc::alloc::alloc(to_request);
    if orig_ptr.is_null() {
        return orig_ptr;
    }

    let result_ptr = orig_ptr.add(offset);
    // Write `AllocInfo` immediately prior to the pointer we return.
    // This way, we always know where to get it for passing to
    // `underlying_dealloc`.
    // `write_unaligned` is used, so unaligned ptr is OK.
    #[allow(clippy::cast_ptr_alignment)]
    let info_ptr =
        result_ptr.sub(mem::size_of::<AllocInfo>()).cast::<AllocInfo>();
    info_ptr.write_unaligned(AllocInfo {
        layout: to_request,
        ptr: orig_ptr,
    });
    result_ptr
}

#[no_mangle]
unsafe extern "C" fn free(ptr: *mut u8) {
    assert!(!ptr.is_null());
    // Read the `AllocInfo` we wrote in `malloc`, and pass it into `dealloc`.
    // `read_unaligned` is used, so unaligned ptr is OK.
    #[allow(clippy::cast_ptr_alignment)]
    let info_ptr = ptr.sub(mem::size_of::<AllocInfo>()) as *const AllocInfo;
    let info = info_ptr.read_unaligned();
    alloc::alloc::dealloc(info.ptr, info.layout);
}
