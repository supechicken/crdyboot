// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::fmt::{self, Display, Formatter};
use uefi::proto::media::file::{Directory, File, FileAttribute, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{BootServices, ScopedProtocol};
use uefi::{cstr16, CStr16, Status};

pub enum FsError {
    /// The buffer is too small to hold the file data. The `u64` value
    /// is the size of the file.
    BufferTooSmall(u64),

    /// The file is a directory, but a regular file was expected.
    IsADirectory,

    /// The file is a regular file, but a directory was expected.
    NotADirectory,

    /// Failed to open the [`SimpleFileSystem`] protocol for the
    /// partition that the curent executable was booted from.
    OpenBootFileSystemFailed(Status),

    /// Failed to open a file.
    OpenFailed(Status),

    /// Failed to read a file.
    ReadFailed(Status),

    /// Reading a file did not return the expected amount of data.
    ReadTruncated,

    /// Failed to get the position of a file handle.
    GetPositionFailed(Status),

    /// Failed to set the position of a file handle.
    SetPositionFailed(Status),
}

impl Display for FsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall(size) => write!(f, "buffer too small, file size is {size} bytes"),
            Self::IsADirectory => write!(f, "file is a directory"),
            Self::NotADirectory => write!(f, "file is not a directory"),
            Self::OpenBootFileSystemFailed(status) => {
                write!(f, "failed to open the boot file system: {status}")
            }
            Self::OpenFailed(status) => write!(f, "file open failed: {status}"),
            Self::ReadFailed(status) => write!(f, "file read failed: {status}"),
            Self::ReadTruncated => write!(f, "failed to read the entire file"),
            Self::GetPositionFailed(status) => {
                write!(f, "failed to get the file position: {status}")
            }
            Self::SetPositionFailed(status) => {
                write!(f, "failed to set the file position: {status}")
            }
        }
    }
}

/// Open the file system protocol for the partition that the current
/// executable was booted from.
pub fn open_boot_file_system(
    boot_services: &BootServices,
) -> Result<ScopedProtocol<SimpleFileSystem>, FsError> {
    boot_services
        .get_image_file_system(boot_services.image_handle())
        .map_err(|err| FsError::OpenBootFileSystemFailed(err.status()))
}

/// Open the `\efi\boot` directory on the file system.
pub fn open_efi_boot_directory(sfs: &mut SimpleFileSystem) -> Result<Directory, FsError> {
    let mut root = sfs
        .open_volume()
        .map_err(|err| FsError::OpenFailed(err.status()))?;
    root.open(
        cstr16!(r"\efi\boot"),
        FileMode::Read,
        FileAttribute::empty(),
    )
    .map_err(|err| FsError::OpenFailed(err.status()))?
    .into_directory()
    .ok_or(FsError::NotADirectory)
}

/// Read the contents of a file named `file_name` in directory `dir`
/// into `buffer`. Returns the subslice of `buffer` into which data was
/// read.
///
/// An error is returned if:
/// * The file could not be opened as a regular file
/// * The buffer is not large enough to hold the entire file
/// * Any error occurs when reading the file's data
pub fn read_file<'buf>(
    dir: &mut Directory,
    file_name: &CStr16,
    buffer: &'buf mut [u8],
) -> Result<&'buf mut [u8], FsError> {
    let mut file = dir
        .open(file_name, FileMode::Read, FileAttribute::empty())
        .map_err(|err| FsError::OpenFailed(err.status()))?
        .into_regular_file()
        .ok_or(FsError::IsADirectory)?;

    // Get the size of the file.
    file.set_position(RegularFile::END_OF_FILE)
        .map_err(|err| FsError::SetPositionFailed(err.status()))?;
    let file_size_u64 = file
        .get_position()
        .map_err(|err| FsError::GetPositionFailed(err.status()))?;

    // Reset the file position to the beginning.
    file.set_position(0)
        .map_err(|err| FsError::SetPositionFailed(err.status()))?;

    let file_size =
        usize::try_from(file_size_u64).map_err(|_| FsError::BufferTooSmall(file_size_u64))?;
    if file_size > buffer.len() {
        return Err(FsError::BufferTooSmall(file_size_u64));
    }

    // Read the file data.
    match file.read(buffer) {
        Ok(read_size) => {
            if read_size == file_size {
                Ok(buffer.get_mut(..file_size).unwrap())
            } else {
                Err(FsError::ReadTruncated)
            }
        }
        Err(err) => Err(FsError::ReadFailed(err.status())),
    }
}
