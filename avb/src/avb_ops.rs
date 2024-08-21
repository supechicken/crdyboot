// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides an interface to implement `AvbOps` that can be passed to `libavb`'s
//! `avb_slot_verify` function.
//!
//! See [avb_ops.h](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_ops.h)
//! for a description of the functions that must be implemented for
//! [`avb_slot_verify`](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_slot_verify.h).
use crate::avb_sys::{AvbIOResult, AvbOps};
use core::ffi::{c_char, c_void};

#[no_mangle]
unsafe extern "C" fn read_from_partition(
    _ops: *mut AvbOps,
    _partition: *const c_char,
    _offset: i64,
    _num_bytes: usize,
    _buffer: *mut c_void,
    _out_num_read: *mut usize,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn get_preloaded_partition(
    _ops: *mut AvbOps,
    _partition: *const c_char,
    _num_bytes: usize,
    _out_pointer: *mut *mut u8,
    _out_num_bytes_preloaded: *mut usize,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn write_to_partition(
    _ops: *mut AvbOps,
    _partition: *const c_char,
    _offset: i64,
    _num_bytes: usize,
    _buffer: *const c_void,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn validate_vbmeta_public_key(
    _ops: *mut AvbOps,
    _public_key_data: *const u8,
    _public_key_length: usize,
    _public_key_metadata: *const u8,
    _public_key_metadata_length: usize,
    _out_is_trusted: *mut bool,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn read_rollback_index(
    _ops: *mut AvbOps,
    _rollback_index_location: usize,
    _out_rollback_index: *mut u64,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn write_rollback_index(
    _ops: *mut AvbOps,
    _rollback_index_location: usize,
    _rollback_index: u64,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn read_is_device_unlocked(
    _ops: *mut AvbOps,
    _out_is_unlocked: *mut bool,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn get_unique_guid_for_partition(
    _ops: *mut AvbOps,
    _partition: *const c_char,
    _guid_buf: *mut c_char,
    _guid_buf_size: usize,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn get_size_of_partition(
    _ops: *mut AvbOps,
    _partition: *const c_char,
    _out_size_num_bytes: *mut u64,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn read_persistent_value(
    _ops: *mut AvbOps,
    _name: *const c_char,
    _buffer_size: usize,
    _out_buffer: *mut u8,
    _out_num_bytes_read: *mut usize,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn write_persistent_value(
    _ops: *mut AvbOps,
    _name: *const c_char,
    _value_size: usize,
    _value: *const u8,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn validate_public_key_for_partition(
    _ops: *mut AvbOps,
    _partition: *const c_char,
    _public_key_data: *const u8,
    _public_key_length: usize,
    _public_key_metadata: *const u8,
    _public_key_metadata_length: usize,
    _out_is_trusted: *mut bool,
    _out_rollback_index_location: *mut u32,
) -> AvbIOResult {
    todo!()
}
