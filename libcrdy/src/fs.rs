// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::fmt::{self, Display, Formatter};
use uefi::proto::media::file::RegularFile;
use uefi::Status;

pub enum FsError {
    /// Reading a file did not return the expected amount of data.
    ReadTruncated,

    /// Failed to get the position of a file handle.
    GetPositionFailed(Status),

    /// The file size is too big to fit in usize. The `u64` value is the size
    /// of the file.
    FileSizeTooBig(u64),

    /// Failed to read the file.
    ReadFileFailed(Status),

    /// Failed to set the position of a file handle.
    SetPositionFailed(Status),
}

impl Display for FsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadTruncated => write!(f, "failed to read the entire file"),
            Self::FileSizeTooBig(file_size_u64) => {
                write!(f, "file size too big to fit in usize: {file_size_u64}")
            }
            Self::GetPositionFailed(status) => {
                write!(f, "failed to get the file position: {status}")
            }
            Self::ReadFileFailed(status) => write!(f, "Failed to read file: {status}"),
            Self::SetPositionFailed(status) => {
                write!(f, "failed to set the file position: {status}")
            }
        }
    }
}

/// Return the size of a file when a regular file handle is passed.
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
        usize::try_from(file_size_u64).map_err(|_| FsError::FileSizeTooBig(file_size_u64))?;

    Ok(file_size)
}

/// Read the contents of a file when a regular file handle is passed. The buffer
/// is updated with raw data from the file.
///
/// An error is returned when:
///  * The file could not be fully read
///  * An error occurs when reading the file data
pub fn read_regular_file(
    file: &mut RegularFile,
    file_size: usize,
    buffer: &mut [u8],
) -> Result<(), FsError> {
    match file.read(buffer) {
        Ok(read_size) => {
            if read_size == file_size {
                return Ok(());
            }
            Err(FsError::ReadTruncated)
        }
        Err(err) => Err(FsError::ReadFileFailed(err.status())),
    }
}
