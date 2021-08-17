use core::fmt;
use uefi::Status;
use vboot::{LoadKernelError, PeError};

pub enum Error {
    UefiServicesInitFailed(Status),

    GetCommandLineFailed,
    CommandLineUcs2ConversionFailed,

    BlockIoProtocolMissing(Status),
    DevicePathProtocolMissing(Status),
    LoadedImageProtocolMissing(Status),

    ParentDiskNotFound,

    LoadKernelFailed(LoadKernelError),

    InvalidPe(PeError),
    CommandLineTooBig(usize),
    KernelTooOld,

    KernelDidNotTakeControl,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        let mut write_with_status =
            |msg, status| write!(f, "{}: {:?}", msg, status);

        match self {
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
            DevicePathProtocolMissing(status) => write_with_status(
                "failed to get UEFI DevicePath protocol",
                status,
            ),
            LoadedImageProtocolMissing(status) => write_with_status(
                "failed to get UEFI LoadedImage protocol",
                status,
            ),

            ParentDiskNotFound => {
                write!(f, "failed to get parent disk")
            }

            LoadKernelFailed(err) => {
                write!(f, "failed to load kernel: {}", err)
            }

            InvalidPe(err) => {
                write!(f, "invalid PE: {}", err)
            }
            CommandLineTooBig(size) => {
                write!(f, "kernel command line is too large: {}", size)
            }
            KernelTooOld => {
                write!(f, "firmware is 32-bit but kernel doesn't have compatible entry point")
            }

            KernelDidNotTakeControl => {
                write!(f, "failed to transfer control to the kernel")
            }
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
