use core::fmt;
use uefi::Status;

pub enum Error {
    UefiServicesInitFailed(Status),

    GetCommandLineFailed,
    CommandLineIsNotAscii,

    BlockIoProtocolMissing(Status),
    DevicePathProtocolMissing(Status),
    LoadedImageProtocolMissing(Status),

    ParentDiskNotFound,

    LoadKernelFailed(vboot::return_code),

    GetPeEntryPointFailed,
    KernelTooSmall,
    InvalidBootParameters,
    KernelDataTooBig(usize),
    CommandLineTooBig(usize),

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
            CommandLineIsNotAscii => {
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

            LoadKernelFailed(code) => {
                // TODO: print human-readable error names.
                write!(f, "failed to load kernel: {:x}", code.0)
            }

            GetPeEntryPointFailed => {
                write!(f, "failed to get PE entry point")
            }

            KernelTooSmall => {
                write!(f, "kernel data is too small to contain boot parameters")
            }
            InvalidBootParameters => {
                write!(f, "invalid boot parameters")
            }
            KernelDataTooBig(size) => {
                write!(f, "kernel data is too large: {}", size)
            }
            CommandLineTooBig(size) => {
                write!(f, "kernel command line is too large: {}", size)
            }

            KernelDidNotTakeControl => {
                write!(f, "failed to transfer control to the kernel")
            }
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
