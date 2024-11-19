// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libcrdy::fs::get_file_size;
use log::info;
use uefi::boot::{self, ScopedProtocol};
use uefi::data_types::chars::NUL_16;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, CString16, Status};

#[derive(Debug, thiserror::Error)]
pub enum FsError {
    /// The file is a directory, but a regular file was expected.
    #[error("file is a directory")]
    IsADirectory,

    /// The file is a regular file, but a directory was expected.
    #[error("file is not a directory")]
    NotADirectory,

    /// Failed to open the [`SimpleFileSystem`] protocol for the
    /// partition that the curent executable was booted from.
    #[error("failed to open the boot file system: {0}")]
    OpenBootFileSystemFailed(Status),

    /// Failed to open a file.
    #[error("file open failed: {0}")]
    OpenFailed(Status),

    /// Failed to read a file.
    #[error("file read failed: {0}")]
    ReadFailed(Status),

    /// Reading a file did not return the expected amount of data.
    #[error("failed to read the entire file")]
    ReadTruncated,

    /// Failed to get the file size.
    #[error("failed to get the file size")]
    GetFileSizeFailed(#[source] libcrdy::fs::FsError),
}

#[cfg_attr(test, mockall::automock)]
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
        let file_size = get_file_size(&mut file).map_err(FsError::GetFileSizeFailed)?;

        // Read the file data.
        match file.read(buffer) {
            Ok(read_size) => {
                if read_size == file_size {
                    Ok(file_size)
                } else {
                    Err(FsError::ReadTruncated)
                }
            }
            Err(err) => Err(FsError::ReadFailed(err.status())),
        }
    }
}

/// Create a copy of `file_name` with the final extension (i.e. the
/// string after the final period character) replaced with
/// `new_extension`.
///
/// The string in `new_extension` should not start with a period
/// character.
///
/// Returns `None` if `file_name` does not contain period character.
#[must_use]
pub fn replace_final_extension(file_name: &CStr16, new_extension: &CStr16) -> Option<CString16> {
    // Convert the file name to vec. Note that this does not include the
    // trailing null char.
    let mut chars = file_name.as_slice().to_vec();

    // Find the last '.' and remove everything after it.
    if let Some(rev_dot_index) = chars.iter().rev().position(|c| *c == '.') {
        let dot_index = chars.len().checked_sub(rev_dot_index)?;
        chars.truncate(dot_index);
    } else {
        return None;
    }

    // Add the new extension.
    chars.extend(new_extension.as_slice());

    // Append trailing null.
    chars.push(NUL_16);

    let output = CStr16::from_char16_with_nul(&chars).ok()?;
    Some(CString16::from(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uefi::cstr16;

    #[test]
    fn test_replace_final_extension() {
        assert_eq!(
            replace_final_extension(cstr16!("crdybootx64.efi"), cstr16!("sig")),
            Some(cstr16!("crdybootx64.sig").into())
        );

        assert_eq!(
            replace_final_extension(cstr16!("crdybootx64.longextension"), cstr16!("sig")),
            Some(cstr16!("crdybootx64.sig").into())
        );

        assert_eq!(
            replace_final_extension(cstr16!("crdybootx64"), cstr16!("sig")),
            None
        );
    }
}
