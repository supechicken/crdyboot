// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::uefi::{Uefi, UefiImpl};
use crate::util::{u32_to_usize, usize_to_u64};
use core::ffi::c_void;
use core::mem;
use log::info;
use uefi::{boot, table, Handle, Status};

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum LaunchError {
    /// The system table is not set.
    #[error("system table is not set")]
    SystemTableNotSet,

    /// The entry point offset is outside the image bounds.
    #[error("entry point offset is out of bounds: {0:#08x}")]
    InvalidEntryPointOffset(u32),

    /// Failed to open the [`LoadedImage`] protocol.
    #[error("failed to open LoadedImage protocol: {0}")]
    OpenLoadedImageProtocolFailed(Status),

    /// The load options (aka command line) size does not fit in a [`u32`].
    #[error("load options are too big: {0}")]
    LoadOptionsTooBig(usize),
}

type EntryPointFn = unsafe extern "efiapi" fn(Handle, *mut c_void);

pub struct NextStage<'a> {
    /// Raw executable image data.
    pub image_data: &'a [u8],

    /// Command line or other data passed to the executable.
    pub load_options: &'a [u8],

    /// Offset within `image_data` of the executable entry point.
    pub entry_point_offset: u32,
}

impl<'a> NextStage<'a> {
    fn entry_point_from_offset(&self) -> Result<EntryPointFn, LaunchError> {
        info!("entry_point_offset: {:#08x}", self.entry_point_offset);

        let entry_point_offset = u32_to_usize(self.entry_point_offset);

        // Ensure that the entry point is somewhere in the image data.
        if entry_point_offset >= self.image_data.len() {
            return Err(LaunchError::InvalidEntryPointOffset(
                self.entry_point_offset,
            ));
        }

        unsafe {
            let entry_point = self.image_data.as_ptr().add(entry_point_offset);
            info!("entry_point: {:x?}", entry_point);

            // Transmute is needed to convert from a regular pointer to a
            // function pointer:
            // rust-lang.github.io/unsafe-code-guidelines/layout/function-pointers.html
            let entry_point: EntryPointFn = mem::transmute(entry_point);
            Ok(entry_point)
        }
    }

    /// Modify an existing image's `LoadedImage` data.
    ///
    /// Normally a new image is created with UEFI's `LoadImage` function,
    /// and that image has its own `LoadedImage` protocol. But with secure
    /// boot enabled, `LoadImage` will fail if it can't validate that the
    /// image was signed properly. Since the image being loaded here is
    /// signed with different keys than the ones secure boot knows about,
    /// `LoadImage` would fail.
    ///
    /// To work around this, reuse an existing image's `LoadedImage`
    /// protocol to point at a different image and commandline. This is
    /// the same technique that shim uses.
    ///
    /// # Safety
    ///
    /// The caller must ensure that that `self.image_data` and
    /// `self.load_options` remain valid for as long as the image is in
    /// use.
    unsafe fn modify_loaded_image(
        &self,
        uefi: &dyn Uefi,
        image_handle: Handle,
    ) -> Result<(), LaunchError> {
        let mut li = uefi
            .open_loaded_image(image_handle)
            .map_err(|err| LaunchError::OpenLoadedImageProtocolFailed(err.status()))?;

        // Set load options (aka command line).
        let load_options_size = self.load_options.len();
        let load_options_size = u32::try_from(load_options_size)
            .map_err(|_| LaunchError::LoadOptionsTooBig(load_options_size))?;
        unsafe {
            li.set_load_options(self.load_options.as_ptr().cast(), load_options_size);
        }

        // Set image data.
        let image_size = usize_to_u64(self.image_data.len());
        unsafe {
            li.set_image(self.image_data.as_ptr().cast(), image_size);
        }

        Ok(())
    }

    /// Launch the next executable stage. Once the new image is
    /// launched, it is not expected to ever return; if it does then
    /// this function will panic.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the image data and entry point
    /// provide a valid UEFI target to execute.
    pub unsafe fn launch(self) -> Result<(), LaunchError> {
        let uefi = &UefiImpl;

        let image_handle = boot::image_handle();
        self.modify_loaded_image(uefi, image_handle)?;

        let entry_point = self.entry_point_from_offset()?;

        let system_table = table::system_table_raw().ok_or(LaunchError::SystemTableNotSet)?;

        (entry_point)(image_handle, system_table.as_ptr().cast());

        // We do not expect the next stage to ever exit back to our
        // code, so that code path is not tested. To avoid anything
        // unexpected happening if the entry point somehow does return,
        // panic here.
        unreachable!("the next stage should not return control")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uefi::{MockUefi, ScopedLoadedImage};
    use core::ptr;
    use uefi::boot::MemoryType;
    use uefi::proto::loaded_image::LoadedImage;
    use uefi::Error;
    use uefi_raw::protocol::loaded_image::LoadedImageProtocol;

    fn get_image_handle() -> Handle {
        static IMAGE_HANDLE: u8 = 123u8;
        unsafe { Handle::from_ptr(ptr::from_ref(&IMAGE_HANDLE).cast_mut().cast()) }.unwrap()
    }

    fn create_next_stage() -> NextStage<'static> {
        NextStage {
            image_data: b"image data",
            load_options: b"load options",
            entry_point_offset: 3,
        }
    }

    /// Test that `modify_loaded_image` propagates the error if the
    /// protocol can't be opened.
    #[test]
    fn test_modify_loaded_image_protocol_error() {
        let ns = create_next_stage();

        let mut uefi = MockUefi::new();
        uefi.expect_open_loaded_image()
            .returning(|_handle| Err(Error::from(Status::UNSUPPORTED)));

        assert_eq!(
            unsafe { ns.modify_loaded_image(&uefi, get_image_handle()) },
            Err(LaunchError::OpenLoadedImageProtocolFailed(
                Status::UNSUPPORTED
            ))
        );
    }

    /// Test that `modify_loaded_image` successfully modifies the
    /// `LoadedImage` protocol.
    #[test]
    fn test_modify_loaded_image() {
        let ns = create_next_stage();

        let li = LoadedImageProtocol {
            revision: 0,
            parent_handle: ptr::null_mut(),
            system_table: ptr::null_mut(),
            device_handle: ptr::null_mut(),
            file_path: ptr::null(),
            reserved: ptr::null(),
            load_options_size: 0,
            load_options: ptr::null(),
            image_base: ptr::null(),
            image_size: 0,
            image_code_type: MemoryType::LOADER_CODE,
            image_data_type: MemoryType::LOADER_DATA,
            unload: None,
        };
        let mut li: LoadedImage = unsafe { mem::transmute(li) };

        let li_ptr = ptr::addr_of_mut!(li);

        // Extra block to make clear how long the `uefi` object is live.
        {
            let mut uefi = MockUefi::new();
            uefi.expect_open_loaded_image()
                .return_once_st(move |_handle| {
                    // SAFETY: this pointer remains valid until after
                    // the `uefi` object is dropped, and the pointer is
                    // not dereferenced except through the
                    // ScopedLoadedImage wrapper.
                    unsafe { Ok(ScopedLoadedImage::for_test_unsafe(li_ptr)) }
                });

            unsafe { ns.modify_loaded_image(&uefi, get_image_handle()) }.unwrap();
        }

        assert_eq!(
            li.info(),
            (
                ns.image_data.as_ptr().cast(),
                u64::try_from(ns.image_data.len()).unwrap()
            )
        );
        assert_eq!(li.load_options_as_bytes().unwrap(), b"load options",);
    }
}
