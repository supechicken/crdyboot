use alloc::alloc::{
    alloc as underlying_alloc, dealloc as underlying_dealloc, Layout,
};
use core::mem::size_of;

// Adapted from https://shift.click/blog/on-dealloc/

#[derive(Copy, Clone)]
struct AllocInfo {
    layout: Layout,
    ptr: *mut u8,
}

unsafe fn wrapped_alloc(layout: Layout) -> *mut u8 {
    // Compute a layout sufficient to store `AllocInfo`
    // immediately before it.
    let header_layout = Layout::new::<AllocInfo>();

    let (to_request, offset) = header_layout
        .extend(layout)
        .expect("real code should probably return null");

    let orig_ptr = underlying_alloc(to_request);
    if orig_ptr.is_null() {
        return orig_ptr;
    }

    let result_ptr = orig_ptr.add(offset);
    // Write `AllocInfo` immediately prior to the pointer we return.
    // This way, we always know where to get it for passing to
    // `underlying_dealloc`.
    let info_ptr = result_ptr.sub(size_of::<AllocInfo>()) as *mut AllocInfo;
    info_ptr.write_unaligned(AllocInfo {
        layout: to_request,
        ptr: orig_ptr,
    });
    result_ptr
}

unsafe fn wrapped_dealloc(ptr: *mut u8) {
    assert!(!ptr.is_null());
    // Simply read the AllocInfo we wrote in `alloc`, and pass it into dealloc.
    let info_ptr = ptr.sub(size_of::<AllocInfo>()) as *const AllocInfo;
    let info = info_ptr.read_unaligned();
    underlying_dealloc(info.ptr, info.layout);
}

#[no_mangle]
unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    let align = 8;
    let layout = Layout::from_size_align(size, align).unwrap();
    wrapped_alloc(layout)
}

#[no_mangle]
unsafe extern "C" fn free(p: *mut u8) {
    wrapped_dealloc(p)
}
