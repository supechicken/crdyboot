// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::fmt;
use uefi::Status;
use vboot::LoadKernelError;

pub enum Error {
    /// An arithmetic operation or a numeric conversion overflowed.
    Overflow(&'static str),

    /// Failed to allocate memory.
    Allocation(Status),

    UefiServicesInitFailed(Status),

    GetCommandLineFailed,
    CommandLineUcs2ConversionFailed,

    BlockIoProtocolMissing(Status),
    DevicePathProtocolMissing(Status),
    LoadedImageProtocolMissing(Status),

    ParentDiskNotFound,

    /// The disk block size is zero.
    InvalidBlockSize,

    LoadKernelFailed(LoadKernelError),

    /// Attempted to access out-of-bounds data.
    OutOfBounds(&'static str),

    /// Kernel's `SetupHeader` doesn't contain the expected magic bytes.
    InvalidKernelMagic,

    /// The buffer allocated to hold the kernel is not big enough.
    KernelBufferTooSmall(usize, usize),

    /// Parse error from the [`object`] crate.
    InvalidPe(object::Error),

    /// The boot image is missing the ".vbpubk" section.
    MissingPubkey,

    /// The kernel does not have an entry point for booting from 32-bit
    /// firmware.
    MissingIa32CompatEntryPoint,

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

            GetCommandLineFailed => {
                write!(f, "failed to get kernel command line")
            }
            CommandLineUcs2ConversionFailed => {
                write!(f, "failed to convert kernel command line to UCS-2")
            }

            BlockIoProtocolMissing(status) => {
                write_with_status("failed to get UEFI BlockIO protocol", status)
            }
            DevicePathProtocolMissing(status) => {
                write_with_status("failed to get UEFI DevicePath protocol", status)
            }
            LoadedImageProtocolMissing(status) => {
                write_with_status("failed to get UEFI LoadedImage protocol", status)
            }

            ParentDiskNotFound => {
                write!(f, "failed to get parent disk")
            }

            InvalidBlockSize => {
                write!(f, "disk block size is zero")
            }

            LoadKernelFailed(err) => {
                write!(f, "failed to load kernel: {err}")
            }

            OutOfBounds(info) => {
                write!(f, "out of bounds: {info}")
            }
            InvalidKernelMagic => {
                write!(f, "invalid magic in the kernel setup header")
            }
            KernelBufferTooSmall(required, allocated) => {
                write!(
                    f,
                    "allocated kernel buffer not big enough: {required}b > {allocated}b",
                )
            }

            InvalidPe(err) => {
                write!(f, "invalid PE: {err}")
            }
            MissingPubkey => {
                write!(f, "missing .vbpubk section")
            }
            MissingIa32CompatEntryPoint => {
                write!(f, "missing ia32 compatibility entry point")
            }

            CommandLineTooBig(size) => {
                write!(f, "kernel command line is too large: {size}")
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
