// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::proto::device_path::DevicePath;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::disk::DiskIo;
use uefi::proto::media::partition::{self, GptPartitionEntry, MbrPartitionRecord};
use uefi::runtime::{self, Time, VariableAttributes, VariableVendor};
use uefi::{CStr16, CString16, Handle, Status};

/// Interface for accessing UEFI boot services and UEFI runtime services.
///
/// The implementation used at runtime is normally `UefiImpl`; unit
/// tests can use `MockUefi` instead.
#[cfg_attr(feature = "test_util", mockall::automock)]
pub trait Uefi {
    fn get_time(&self) -> uefi::Result<Time>;

    /// Get an iterator over all UEFI variable keys.
    fn variable_keys(&self) -> VariableKeys;

    /// Read a UEFI variable into `buf`.
    ///
    /// If successful, returns the size of the variable and the variable
    /// attributes.
    ///
    /// If the buffer is not large enough, the error value contains the
    /// required size.
    fn get_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        buf: &mut [u8],
    ) -> uefi::Result<(usize, VariableAttributes), Option<usize>>;

    fn get_variable_boxed(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
    ) -> uefi::Result<(Box<[u8]>, VariableAttributes)>;

    /// Set a UEFI variable, or delete it if `data` is empty.
    fn set_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> uefi::Result;

    fn delete_variable(&self, name: &CStr16, vendor: &VariableVendor) -> uefi::Result;

    fn find_block_io_handles(&self) -> uefi::Result<Vec<Handle>>;

    fn find_partition_info_handles(&self) -> uefi::Result<Vec<Handle>>;

    fn device_path_for_handle(&self, handle: Handle) -> uefi::Result<ScopedDevicePath>;

    /// Find the [`Handle`] corresponding to the ESP partition that this
    /// executable is running from.
    fn find_esp_partition_handle(&self) -> uefi::Result<Option<Handle>>;

    fn partition_info_for_handle(&self, handle: Handle) -> uefi::Result<PartitionInfo>;

    /// Open the Block IO protocol for `handle`.
    ///
    /// # Safety
    ///
    /// This is `unsafe` because the protocol is opened in non-exclusive
    /// mode. Opening disk handles in exclusive mode can be very slow --
    /// on the x1cg9, it takes over 800ms.
    unsafe fn open_block_io(&self, handle: Handle) -> uefi::Result<ScopedBlockIo>;

    /// Open the Disk IO protocol for `handle`.
    ///
    /// # Safety
    ///
    /// This is `unsafe` because the protocol is opened in non-exclusive
    /// mode. Opening disk handles in exclusive mode can be very slow --
    /// on the x1cg9, it takes over 800ms.
    unsafe fn open_disk_io(&self, handle: Handle) -> uefi::Result<ScopedDiskIo>;
}

pub struct UefiImpl;

impl Uefi for UefiImpl {
    fn get_time(&self) -> uefi::Result<Time> {
        runtime::get_time()
    }

    fn variable_keys(&self) -> VariableKeys {
        VariableKeys::Real(uefi::runtime::variable_keys())
    }

    fn get_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        buf: &mut [u8],
    ) -> uefi::Result<(usize, VariableAttributes), Option<usize>> {
        runtime::get_variable(name, vendor, buf)
            // Map from buf to buf.len to avoid needing a buffer
            // lifetime tying input to output; that wouldn't work with
            // mockall.
            .map(|(buf, attr)| (buf.len(), attr))
    }

    fn get_variable_boxed(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
    ) -> uefi::Result<(Box<[u8]>, VariableAttributes)> {
        runtime::get_variable_boxed(name, vendor)
    }

    fn set_variable(
        &self,
        name: &CStr16,
        vendor: &VariableVendor,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> uefi::Result {
        runtime::set_variable(name, vendor, attributes, data)
    }

    fn delete_variable(&self, name: &CStr16, vendor: &VariableVendor) -> uefi::Result {
        runtime::delete_variable(name, vendor)
    }

    fn find_partition_info_handles(&self) -> uefi::Result<Vec<Handle>> {
        boot::find_handles::<partition::PartitionInfo>()
    }

    fn find_block_io_handles(&self) -> uefi::Result<Vec<Handle>> {
        boot::find_handles::<BlockIO>()
    }

    fn device_path_for_handle(&self, handle: Handle) -> uefi::Result<ScopedDevicePath> {
        // Safety: this protocol cannot be opened in exclusive
        // mode. This is OK here as device paths are immutable.
        unsafe {
            boot::open_protocol(
                OpenProtocolParams {
                    handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .map(ScopedDevicePath::Protocol)
    }

    fn find_esp_partition_handle(&self) -> uefi::Result<Option<Handle>> {
        // Get the LoadedImage protocol for the image handle. This provides
        // a device handle which should correspond to the partition that the
        // image was loaded from.
        let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;
        Ok(loaded_image.device())
    }

    fn partition_info_for_handle(&self, handle: Handle) -> uefi::Result<PartitionInfo> {
        // Use non-exclusive mode because opening disk handles in
        // exclusive mode can be slow.
        //
        // Safety: the protocol is closed within this function, and
        // there is no risk of it being mutated by other code during
        // this function call.
        let info = unsafe {
            boot::open_protocol::<partition::PartitionInfo>(
                OpenProtocolParams {
                    handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }?;

        if let Some(gpt) = info.gpt_partition_entry() {
            Ok(PartitionInfo::Gpt(*gpt))
        } else if let Some(mbr) = info.mbr_partition_record() {
            Ok(PartitionInfo::Mbr(*mbr))
        } else {
            // This should never happen in practice.
            Err(Status::UNSUPPORTED.into())
        }
    }

    unsafe fn open_block_io(&self, handle: Handle) -> uefi::Result<ScopedBlockIo> {
        boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map(ScopedBlockIo::Protocol)
    }

    unsafe fn open_disk_io(&self, handle: Handle) -> uefi::Result<ScopedDiskIo> {
        boot::open_protocol::<DiskIo>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map(ScopedDiskIo::Protocol)
    }
}

/// Wrapper around `ScopedProtocol<DevicePath>` that allows for mocking.
#[derive(Debug)]
pub enum ScopedDevicePath {
    Protocol(ScopedProtocol<DevicePath>),
    #[cfg(feature = "test_util")]
    Boxed(Box<DevicePath>),
}

impl Deref for ScopedDevicePath {
    type Target = DevicePath;

    fn deref(&self) -> &DevicePath {
        match self {
            Self::Protocol(p) => p,
            #[cfg(feature = "test_util")]
            Self::Boxed(b) => b,
        }
    }
}

/// Wrapper around `ScopedProtocol<BlockIO>` that allows for mocking.
///
/// uefi-rs is a little inconsistent about `IO` vs `Io` (e.g. `DiskIo`
/// vs `BlockIO`). For this code, consistently use `Io` in the public
/// interface.
#[derive(Debug)]
pub enum ScopedBlockIo {
    Protocol(ScopedProtocol<BlockIO>),
    #[cfg(feature = "test_util")]
    ForTest(BlockIO),
}

impl Deref for ScopedBlockIo {
    type Target = BlockIO;

    fn deref(&self) -> &BlockIO {
        match self {
            Self::Protocol(p) => p,
            #[cfg(feature = "test_util")]
            Self::ForTest(b) => b,
        }
    }
}

impl DerefMut for ScopedBlockIo {
    fn deref_mut(&mut self) -> &mut BlockIO {
        match self {
            Self::Protocol(p) => p,
            #[cfg(feature = "test_util")]
            Self::ForTest(b) => b,
        }
    }
}

/// Wrapper around `ScopedProtocol<DiskIo>` that allows for mocking.
#[derive(Debug)]
pub enum ScopedDiskIo {
    Protocol(ScopedProtocol<DiskIo>),
    #[cfg(feature = "test_util")]
    ForTest(DiskIo),
}

impl Deref for ScopedDiskIo {
    type Target = DiskIo;

    fn deref(&self) -> &DiskIo {
        match self {
            Self::Protocol(p) => p,
            #[cfg(feature = "test_util")]
            Self::ForTest(d) => d,
        }
    }
}

#[derive(Clone)]
pub enum PartitionInfo {
    Mbr(MbrPartitionRecord),
    Gpt(GptPartitionEntry),
}

// TODO(b/365817661): after the next uefi-rs upgrade, we can drop this
// struct and use `uefi::runtime::VariableKey` directly.
#[derive(Clone, Debug)]
pub struct VariableKey {
    pub vendor: VariableVendor,
    pub name: CString16,
}

#[cfg(feature = "test_util")]
impl VariableKey {
    pub fn new(name: &CStr16, vendor: VariableVendor) -> Self {
        Self {
            name: name.to_owned(),
            vendor,
        }
    }
}

/// Iterator over all UEFI variable keys.
pub enum VariableKeys {
    Real(uefi::runtime::VariableKeys),
    #[cfg(feature = "test_util")]
    ForTest(Vec<uefi::Result<VariableKey>>),
}

impl Iterator for VariableKeys {
    type Item = uefi::Result<VariableKey>;

    fn next(&mut self) -> Option<uefi::Result<VariableKey>> {
        match self {
            Self::Real(iter) => iter.next().map(|r| match r {
                Ok(key) => {
                    if let Ok(name) = key.name() {
                        Ok(VariableKey {
                            vendor: key.vendor,
                            name: name.to_owned(),
                        })
                    } else {
                        Err(Status::UNSUPPORTED.into())
                    }
                }
                Err(err) => Err(err),
            }),
            #[cfg(feature = "test_util")]
            Self::ForTest(v) => {
                if v.is_empty() {
                    None
                } else {
                    Some(v.remove(0))
                }
            }
        }
    }
}
