// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use log::info;
use uefi::boot::{self, ScopedProtocol};
use uefi::proto::media::file::RegularFile;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, Status};

#[derive(Debug, thiserror::Error)]
pub enum FsError {
    /// Failed to open the [`SimpleFileSystem`] protocol for the
    /// partition that the curent executable was booted from.
    #[error("failed to open the boot file system: {0}")]
    OpenBootFileSystemFailed(Status),

    /// Failed to open a file.
    #[error("file open failed: {0}")]
    OpenFailed(Status),

    /// The file is a directory, but a regular file was expected.
    #[error("file is a directory")]
    IsADirectory,

    /// Reading a file did not return the expected amount of data.
    #[error("failed to read the entire file")]
    ReadTruncated,

    /// Failed to get the position of a file handle.
    #[error("failed to get the file position: {0}")]
    GetPositionFailed(Status),

    /// The file size is larger than a `usize`.
    #[error("file size too big to fit in usize: {0}")]
    FileLargerThanUsize(
        /// Size of the file in bytes.
        u64,
    ),

    /// Failed to read the file.
    #[error("failed to read file: {0}")]
    ReadFileFailed(Status),

    /// Failed to set the position of a file handle.
    #[error("failed to set the file position: {0}")]
    SetPositionFailed(Status),
}

#[cfg_attr(feature = "test_util", mockall::automock)]
pub trait FileLoader {
    /// Read the contents of `path` into `buffer`. On success, the
    /// number of bytes read is returned.
    ///
    /// An error is returned if:
    /// * The file could not be opened as a regular file
    /// * The buffer is not large enough to hold the entire file
    /// * Any error occurs when reading the file's data
    fn read_file_into(&mut self, path: &CStr16, buffer: &mut [u8]) -> Result<usize, FsError>;
}

pub struct FileLoaderImpl {
    file_system: ScopedProtocol<SimpleFileSystem>,
}

impl FileLoaderImpl {
    /// Open the file system for the partition that the current
    /// executable was booted from.
    pub fn open_boot_file_system() -> Result<Self, FsError> {
        let file_system = boot::get_image_file_system(boot::image_handle())
            .map_err(|err| FsError::OpenBootFileSystemFailed(err.status()))?;

        Ok(Self { file_system })
    }
}

impl FileLoader for FileLoaderImpl {
    fn read_file_into(&mut self, path: &CStr16, buffer: &mut [u8]) -> Result<usize, FsError> {
        info!("reading file {path}");
        let mut root = self
            .file_system
            .open_volume()
            .map_err(|err| FsError::OpenFailed(err.status()))?;
        let mut file = root
            .open(path, FileMode::Read, FileAttribute::empty())
            .map_err(|err| FsError::OpenFailed(err.status()))?
            .into_regular_file()
            .ok_or(FsError::IsADirectory)?;

        // Get the size of the file.
        let file_size = get_file_size(&mut file)?;

        // Read the file data.
        match file.read(buffer) {
            Ok(read_size) => {
                if read_size == file_size {
                    Ok(file_size)
                } else {
                    Err(FsError::ReadTruncated)
                }
            }
            Err(err) => Err(FsError::ReadFileFailed(err.status())),
        }
    }
}

/// Return the size (in bytes) of a regular file.
pub fn get_file_size(file: &mut RegularFile) -> Result<usize, FsError> {
    file.set_position(RegularFile::END_OF_FILE)
        .map_err(|err| FsError::SetPositionFailed(err.status()))?;
    let file_size_u64 = file
        .get_position()
        .map_err(|err| FsError::GetPositionFailed(err.status()))?;

    // Reset the file position to the beginning.
    file.set_position(0)
        .map_err(|err| FsError::SetPositionFailed(err.status()))?;

    let file_size =
        usize::try_from(file_size_u64).map_err(|_| FsError::FileLargerThanUsize(file_size_u64))?;

    Ok(file_size)
}

/// Read the contents of a file when a regular file handle is passed. The buffer
/// is updated with raw data from the file.
///
/// An error is returned when:
///  * The amount of data read does not match the buffer size
///  * An error occurs when reading the file data
pub fn read_regular_file(file: &mut RegularFile, buffer: &mut [u8]) -> Result<(), FsError> {
    match file.read(buffer) {
        Ok(read_size) => {
            if read_size == buffer.len() {
                return Ok(());
            }
            Err(FsError::ReadTruncated)
        }
        Err(err) => Err(FsError::ReadFileFailed(err.status())),
    }
}
