use core::fmt;
use uefi::Status;

#[derive(Debug)]
pub enum Error {
    UefiServicesInitFailed(Status),

    GetCommandLineFailed,

    CommandLineIsNotAscii,

    DevicePathProtocolMissing(Status),
    LoadedImageProtocolMissing(Status),
    BlockIoProtocolMissing(Status),

    ParentDiskNotFound,

    // TODO: think about how to print better errors
    LoadKernelFailed(vboot::return_code),

    // TODO: break into more specific errors?
    RunKernelFailed(Status),

    KernelDidNotTakeControl,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match self {
            UefiServicesInitFailed(status) => {
                write!(f, "failed to initialize UEFI services: {:?}", status)
            }
            // TODO
            err => write!(f, "error: {:?}", err),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
