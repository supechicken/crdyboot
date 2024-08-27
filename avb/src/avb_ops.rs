// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides an interface to implement `AvbOps` that can be passed to `libavb`'s
//! `avb_slot_verify` function.
//!
//! See [avb_ops.h] for a description of the functions that must be implemented for
//! [`avb_slot_verify`].
//!
//! [`avb_slot_verify`]: https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_slot_verify.h#391
//! [avb_ops.h]: https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_ops.h
use crate::avb_sys::{AvbIOResult, AvbOps};
use core::ffi::{c_char, c_void, CStr};
use core::{ptr, str};
use log::info;

/// Wrapper around a `&mut AvbDiskOps`. A pointer to this type is thin,
/// unlike a pointer to `AvbDiskOps`, allowing it to be used in
/// `AvbOps.user_data`.
pub struct AvbDiskOpsRef<'a>(pub &'a mut dyn AvbDiskOps);

/// Trait implementing the necessary functions required to process
/// the callbacks necessary from libavb's `avb_ops.h`
pub trait AvbDiskOps {
    /// Read data from the partition with `name` into `dst`.
    /// `start_byte` is the offset from the start of the partition
    /// where the read starts.
    ///
    /// # Errors
    ///
    /// * `AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION` if the partition is not found.
    /// * `AVB_IO_RESULT_ERROR_IO` if there is an IO error from the underlying device.
    /// * `AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION` if the `start_byte` is out of
    ///   range for the partition.
    fn read_from_partition(
        &mut self,
        name: &str,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), AvbIOResult>;

    /// Write data from `buffer` into the partition with `name` starting
    /// at `offset` from the beginning of the partition.
    ///
    /// # Errors
    ///
    /// * `AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION` if the partition is not found.
    /// * `AVB_IO_RESULT_ERROR_IO` if there is an IO error from the underlying device.
    /// * `AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION` if the `offset` is out of
    ///   range for the partition.
    fn write_to_partition(
        &mut self,
        name: &str,
        offset: u64,
        buffer: &[u8],
    ) -> Result<(), AvbIOResult>;

    /// Get the size of the partition with `name`.
    ///
    /// # Errors
    ///
    /// * `AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION` if the partition is not found.
    fn get_size_of_partition(&mut self, name: &str) -> Result<u64, AvbIOResult>;

    /// Get the unique partition GUID for the partition with `name`.
    ///
    /// # Errors
    ///
    /// * `AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION` if the partition is not found.
    fn get_unique_guid_for_partition(
        &mut self,
        name: &str,
        dest: &mut [u8; 36],
    ) -> Result<(), AvbIOResult>;
}

/// Create `AvbOps` to pass into libavb's `avb_slot_verify` function.
pub fn create_ops(ops_impl: &mut AvbDiskOpsRef) -> AvbOps {
    AvbOps {
        // pointer to the AvbDiskOps that will be called
        user_data: ptr::from_mut(ops_impl).cast(),
        // ab_ops is optional and not needed.
        ab_ops: ptr::null_mut(),
        // cert_ops is optional and not needed.
        cert_ops: ptr::null_mut(),
        read_from_partition: Some(read_from_partition),
        // Could be NULL but probably should be considered for use.
        get_preloaded_partition: Some(get_preloaded_partition),
        write_to_partition: Some(write_to_partition),
        validate_vbmeta_public_key: Some(validate_vbmeta_public_key),
        read_rollback_index: Some(read_rollback_index),
        write_rollback_index: Some(write_rollback_index),
        read_is_device_unlocked: Some(read_is_device_unlocked),
        get_unique_guid_for_partition: Some(get_unique_guid_for_partition),
        get_size_of_partition: Some(get_size_of_partition),
        read_persistent_value: Some(read_persistent_value),
        write_persistent_value: Some(write_persistent_value),
        validate_public_key_for_partition: Some(validate_public_key_for_partition),
    }
}

/// Cast the avbops `user_data` pointer to the expected contained
/// value set by `create_ops`.
unsafe fn ops_to_dimpl<'a>(ops: *mut AvbOps) -> &'a mut dyn AvbDiskOps {
    let user_data: *mut AvbDiskOpsRef = (*ops).user_data.cast();
    (*user_data).0
}

// `AvbOps` callback functions:
#[no_mangle]
/// Read `num_bytes` from the `offset` from the partition
/// with the name `partition` into `buffer`.
///
/// Positive `offset` values specify the offset from
/// the beginning of the of the partition to start reading.
/// Negative `offset` values indicate an offset from
/// the end of the partition to read.
/// A partial read can occur if reading past the end of the
/// partition. In this case `out_num_read` will be less
/// than `num_bytes`
///
/// See [read_from_partition](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_ops.h#129)
///
/// # Returns
///
/// * The number of bytes read into `out_num_read`.
/// * `AVB_IO_RESULT_OK` on success.
///
/// # Errors
///
/// * `AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION` if the partition is not found.
/// * `AVB_IO_RESULT_ERROR_IO` if there is an IO error from the underlying device.
/// * `AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION` if the `start_byte` is out of
///   range for the partition.
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
/// Write `num_bytes` of data from `buffer` into the partition with the
/// name `partition` at the `offset`.
///
/// A negative `offset` indicates an offset from the end of the partition.
/// If the full `buffer` is not able to be written a failure is returned.
/// There are no partial writes.
/// This function does not do partial I/O, all of `num_bytes` must be
/// transfered.
///
/// Returns `AVB_IO_RESULT_OK` on success.
///
/// See
/// [write_to_partition](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_ops.h#173)
///
/// # Errors
///
/// * `AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION` if the partition is not found.
/// * `AVB_IO_RESULT_ERROR_IO` if there is an IO error from the underlying device.
/// * `AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION` if the `offset` is out of
///   range for the partition.
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
/// See
/// [get_unique_guid_for_partition](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_ops.h#249)
unsafe extern "C" fn get_unique_guid_for_partition(
    _ops: *mut AvbOps,
    _partition: *const c_char,
    _guid_buf: *mut c_char,
    _guid_buf_size: usize,
) -> AvbIOResult {
    todo!()
}

#[no_mangle]
/// [get_size_of_partition](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_ops.h#263)
unsafe extern "C" fn get_size_of_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    out_size_num_bytes: *mut u64,
) -> AvbIOResult {
    let Ok(pname) = CStr::from_ptr(partition).to_str() else {
        return AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
    };

    #[cfg(test)]
    println!("get_size_of_partition: {pname}");
    info!("get_size_of_partition: {pname}");

    let dimpl = ops_to_dimpl(ops);

    let size = match dimpl.get_size_of_partition(pname) {
        Err(e) => return e,
        Ok(f) => f,
    };

    *out_size_num_bytes = size;
    AvbIOResult::AVB_IO_RESULT_OK
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
    // This is only needed if AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION is being
    // used with slot_verify.
    panic!("validate public key for partition was called, must use vbmeta")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::avb_sys::{
        avb_slot_verify, AvbHashtreeErrorMode, AvbSlotVerifyData, AvbSlotVerifyFlags,
        AvbSlotVerifyResult,
    };

    #[derive(Debug)]
    struct TestAvbOps;

    impl<'a> AvbDiskOps for TestAvbOps {
        fn read_from_partition(
            &mut self,
            _name: &str,
            _start_byte: u64,
            _dst: &mut [u8],
        ) -> Result<(), AvbIOResult> {
            todo!();
        }

        fn write_to_partition(
            &mut self,
            _name: &str,
            _offset: u64,
            _buffer: &[u8],
        ) -> Result<(), AvbIOResult> {
            todo!();
        }

        fn get_size_of_partition(&mut self, _name: &str) -> Result<u64, AvbIOResult> {
            todo!();
        }

        fn get_unique_guid_for_partition(
            &mut self,
            _name: &str,
            _dest: &mut [u8; 36],
        ) -> Result<(), AvbIOResult> {
            todo!();
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_create_ops() {
        let mut ops_impl = TestAvbOps;

        let mut avbops_ref = AvbDiskOpsRef(&mut ops_impl);

        let mut avbops = create_ops(&mut avbops_ref);

        let requested_partitions = [c"boot", c"vendor_boot", c"init_boot"];
        // Null-pointer terminated list of partitions for
        // the call to verify.
        let ptrs = [
            requested_partitions[0].as_ptr(),
            requested_partitions[1].as_ptr(),
            requested_partitions[2].as_ptr(),
            ptr::null(),
        ];

        let slot = c"_a";

        let mut data: *mut AvbSlotVerifyData = ptr::null_mut();

        // TODO: Improve (add more useful) tests.
        unsafe {
            let res = avb_slot_verify(
                &mut avbops,
                ptrs.as_ptr(),
                slot.as_ptr(),
                AvbSlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_NONE,
                AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_LOGGING,
                &mut data,
            );
            assert_eq!(
                res,
                AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT
            );
        }
    }
}
