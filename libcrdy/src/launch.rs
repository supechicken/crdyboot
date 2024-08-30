// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::util::{u32_to_usize, usize_to_u64};
use core::ffi::c_void;
use core::fmt::{self, Display, Formatter};
use core::mem;
use log::info;
use uefi::proto::loaded_image::LoadedImage;
use uefi::table::boot::BootServices;
use uefi::table::{self, Boot, SystemTable};
use uefi::{Handle, Status};

pub enum LaunchError {
    /// The system table is not set.
    SystemTableNotSet,

    /// The entry point offset is outside the image bounds.
    InvalidEntryPointOffset(u32),

    /// Failed to open the [`LoadedImage`] protocol.
    OpenLoadedImageProtocolFailed(Status),

    /// The load options (aka command line) size does not fit in a [`u32`].
    LoadOptionsTooBig(usize),
}

impl Display for LaunchError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::SystemTableNotSet => write!(f, "system table is not set"),
            Self::InvalidEntryPointOffset(offset) => {
                write!(f, "entry point offset is out of bounds: {offset:#08x}")
            }
            Self::OpenLoadedImageProtocolFailed(status) => {
                write!(f, "failed to open LoadedImage protocol: {status}")
            }
            Self::LoadOptionsTooBig(size) => write!(f, "load options are too big: {size}"),
        }
    }
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
        bt: &BootServices,
        image_handle: Handle,
    ) -> Result<(), LaunchError> {
        let mut li = bt
            .open_protocol_exclusive::<LoadedImage>(image_handle)
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
    // TODO(nicholasbishop): the system_table param will be removed in
    // the following commit.
    #[allow(clippy::needless_pass_by_value)]
    pub unsafe fn launch(self, system_table: SystemTable<Boot>) -> Result<(), LaunchError> {
        let image_handle = system_table.boot_services().image_handle();
        self.modify_loaded_image(system_table.boot_services(), image_handle)?;

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
