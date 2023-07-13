// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::disk::GptDiskError;
use crate::launch::LaunchError;
use crate::nx::NxError;
use crate::page_alloc::PageAllocationError;
use crate::revocation::RevocationError;
use crate::tpm::TpmError;
use crate::vbpubk::VbpubkError;
use core::fmt;
use vboot::LoadKernelError;

pub enum Error {
    /// Failed to allocate memory.
    Allocation(PageAllocationError),

    /// Self-revocation check failed.
    Revocation(RevocationError),

    GetCommandLineFailed,
    CommandLineUcs2ConversionFailed,

    Vbpubk(VbpubkError),

    GptDisk(GptDiskError),

    LoadKernelFailed(LoadKernelError),

    /// Parse error from the [`object`] crate.
    InvalidPe(object::Error),

    /// The kernel does not have an entry point for booting from 32-bit
    /// firmware.
    MissingIa32CompatEntryPoint,

    /// An error occurred while updating memory attributes.
    MemoryProtection(NxError),

    Launch(LaunchError),

    /// An error occurred when measuring the kernel into the TPM.
    Tpm(TpmError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match self {
            Allocation(err) => write!(f, "failed to allocate memory: {err}"),

            Revocation(err) => {
                write!(f, "self-revocation check failed: {err}")
            }

            GetCommandLineFailed => {
                write!(f, "failed to get kernel command line")
            }
            CommandLineUcs2ConversionFailed => {
                write!(f, "failed to convert kernel command line to UCS-2")
            }

            Vbpubk(error) => {
                write!(f, "failed to get packed public key: {error}")
            }

            GptDisk(error) => {
                write!(f, "failed to open GPT disk: {error}")
            }

            LoadKernelFailed(err) => {
                write!(f, "failed to load kernel: {err}")
            }

            InvalidPe(err) => {
                write!(f, "invalid PE: {err}")
            }
            MissingIa32CompatEntryPoint => {
                write!(f, "missing ia32 compatibility entry point")
            }

            MemoryProtection(error) => {
                write!(f, "failed to set up memory protection: {error}")
            }

            Launch(error) => {
                write!(f, "failed to launch next stage: {error}")
            }

            Tpm(error) => {
                write!(f, "TPM error: {error}")
            }
        }
    }
}
