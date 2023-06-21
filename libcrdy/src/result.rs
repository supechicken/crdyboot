// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::GptDiskError;
use crate::nx::NxError;
use crate::revocation::RevocationError;
use core::fmt;
use uefi::Status;
use vboot::LoadKernelError;

pub enum Error {
    /// An arithmetic operation or a numeric conversion overflowed.
    Overflow(&'static str),

    /// Failed to allocate memory.
    Allocation(Status),

    UefiServicesInitFailed(Status),

    /// Self-revocation check failed.
    Revocation(RevocationError),

    GetCommandLineFailed,
    CommandLineUcs2ConversionFailed,

    LoadedImageProtocolMissing(Status),

    GptDisk(GptDiskError),

    LoadKernelFailed(LoadKernelError),

    /// Attempted to access out-of-bounds data.
    OutOfBounds(&'static str),

    /// Parse error from the [`object`] crate.
    InvalidPe(object::Error),

    /// The boot image is missing the ".vbpubk" section.
    MissingPubkey,

    /// The boot image has multiple ".vbpubk" sections.
    MultiplePubkey,

    /// The kernel does not have an entry point for booting from 32-bit
    /// firmware.
    MissingIa32CompatEntryPoint,

    /// An error occurred while updating memory attributes.
    MemoryProtection(NxError),

    CommandLineTooBig(usize),

    /// An error occurred when measuring the kernel into the TPM.
    Tpm(&'static str, Status),

    KernelDidNotTakeControl,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        let mut write_with_status = |msg, status| write!(f, "{msg}: {status:?}");

        match self {
            Overflow(info) => {
                write!(f, "overflow: {info}")
            }

            Allocation(status) => write_with_status("failed to allocate memory", status),

            UefiServicesInitFailed(status) => {
                write_with_status("failed to initialize UEFI services", status)
            }

            Revocation(err) => {
                write!(f, "self-revocation check failed: {err}")
            }

            GetCommandLineFailed => {
                write!(f, "failed to get kernel command line")
            }
            CommandLineUcs2ConversionFailed => {
                write!(f, "failed to convert kernel command line to UCS-2")
            }

            LoadedImageProtocolMissing(status) => {
                write_with_status("failed to get UEFI LoadedImage protocol", status)
            }

            GptDisk(error) => {
                write!(f, "failed to open GPT disk: {error}")
            }

            LoadKernelFailed(err) => {
                write!(f, "failed to load kernel: {err}")
            }

            OutOfBounds(info) => {
                write!(f, "out of bounds: {info}")
            }

            InvalidPe(err) => {
                write!(f, "invalid PE: {err}")
            }
            MissingPubkey => {
                write!(f, "missing .vbpubk section")
            }
            MultiplePubkey => {
                write!(f, "multiple .vbpubk sections")
            }
            MissingIa32CompatEntryPoint => {
                write!(f, "missing ia32 compatibility entry point")
            }

            CommandLineTooBig(size) => {
                write!(f, "kernel command line is too large: {size}")
            }

            MemoryProtection(error) => {
                write!(f, "failed to set up memory protection: {error}")
            }

            Tpm(msg, status) => {
                write!(f, "TPM error ({status}): {msg}")
            }

            KernelDidNotTakeControl => {
                write!(f, "failed to transfer control to the kernel")
            }
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
