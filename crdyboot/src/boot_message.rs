// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use core::ffi::CStr;
use zerocopy::{FromBytes, FromZeroes};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BcbError {
    /// The buffer was not the correct size for the `BootloaderMessage`.
    #[error("buffer is not the correct size, requires: {required}, got: {got}")]
    BufferWrongSize { required: usize, got: usize },

    /// The command field is not null-terminated.
    #[error("BootloaderMessage command is not null-terminated")]
    CommandNotTerminated(#[from] core::ffi::FromBytesUntilNulError),

    /// The command field is not valid UTF-8.
    #[error("BootloaderMessage command is not valid UTF-8")]
    CommandInvalidUtf8(#[from] core::str::Utf8Error),
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum AndroidBootMode {
    Normal,
    Recovery,
}

impl AndroidBootMode {
    #[cfg_attr(not(test), expect(unused))]
    pub fn from_command_str(command: &str) -> Option<Self> {
        Some(match command {
            "" => Self::Normal,
            "boot-recovery" => Self::Recovery,
            // Ignore commands that aren't being considered by
            // this bootloader.
            _ => return None,
        })
    }
}

/// `struct bootloader_message` from [recovery bootloader_message]
///
/// [recovery bootloader_message]: https://android.googlesource.com/platform/bootable/recovery/+/refs/heads/main/bootloader_message/include/bootloader_message/bootloader_message.h#67
#[repr(C)]
#[derive(FromBytes, FromZeroes, Debug, Copy, Clone)]
pub struct BootloaderMessage {
    command: [u8; 32],
    status: [u8; 32],
    recovery: [u8; 768],
    stage: [u8; 32],
    reserved: [u8; 1184],
}

impl BootloaderMessage {
    #[cfg_attr(not(test), expect(unused))]
    pub fn parse(source: &[u8]) -> Result<&BootloaderMessage, BcbError> {
        Self::ref_from(source).ok_or(BcbError::BufferWrongSize {
            required: Self::buffer_size(),
            got: source.len(),
        })
    }

    #[cfg_attr(not(test), expect(unused))]
    pub fn command(&self) -> Result<&str, BcbError> {
        CStr::from_bytes_until_nul(&self.command)
            .map_err(BcbError::CommandNotTerminated)?
            .to_str()
            .map_err(BcbError::CommandInvalidUtf8)
    }

    pub const fn buffer_size() -> usize {
        core::mem::size_of::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootloader_message() {
        let buffer = [0u8; BootloaderMessage::buffer_size()];

        let bm = BootloaderMessage::parse(&buffer).unwrap();

        assert_eq!(bm.command().unwrap(), "");
    }

    #[test]
    fn test_bootloader_command() {
        let mut buffer = [0u8; BootloaderMessage::buffer_size()];
        let test = b"test-command";

        buffer[..test.len()].copy_from_slice(test);

        let bm = BootloaderMessage::parse(&buffer).unwrap();

        assert_eq!(bm.command().unwrap(), "test-command");
    }

    #[test]
    fn test_no_command_termination() {
        let buffer = [b'z'; BootloaderMessage::buffer_size()];

        let bm = BootloaderMessage::parse(&buffer).unwrap();

        assert!(matches!(
            bm.command(),
            Err(BcbError::CommandNotTerminated(_))
        ));
    }

    #[test]
    fn test_command_bad_utf8() {
        let mut buffer = [0u8; BootloaderMessage::buffer_size()];
        buffer[0] = 0xFF;

        let bm = BootloaderMessage::parse(&buffer).unwrap();

        assert!(matches!(bm.command(), Err(BcbError::CommandInvalidUtf8(_))));
    }

    #[test]
    fn test_small_buffer() {
        assert_eq!(
            BootloaderMessage::parse(&[0u8; 25]).unwrap_err(),
            BcbError::BufferWrongSize {
                required: 2048,
                got: 25
            }
        );
    }

    #[test]
    fn test_big_buffer() {
        assert_eq!(
            BootloaderMessage::parse(&[0u8; 2049]).unwrap_err(),
            BcbError::BufferWrongSize {
                required: 2048,
                got: 2049
            }
        );
    }

    #[test]
    fn test_boot_mode_normal() {
        assert_eq!(
            AndroidBootMode::from_command_str("").unwrap(),
            AndroidBootMode::Normal
        );
    }

    #[test]
    fn test_boot_mode_recovery() {
        assert_eq!(
            AndroidBootMode::from_command_str("boot-recovery").unwrap(),
            AndroidBootMode::Recovery
        );
    }
}
