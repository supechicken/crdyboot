// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::error::Error;
use core::fmt::{self, Write};
use log::error;
use uefi::runtime::{self, ResetType};
use uefi::{boot, system, Status};

/// Print a fatal error and shut down the machine.
///
/// The error message will include the executable name and version.
///
/// This is public so that it can be called through the
/// `fail_with_fatal_error` macro, but it should not be called directly.
pub fn fail_with_fatal_error_impl(exe: &str, version: &str, err: &dyn Error) -> ! {
    // Print the error.
    system::with_stdout(|stdout| {
        let _ = write!(stdout, "Boot error in {exe}-{version}: ");

        if write_err(stdout, err).is_err() {
            // If printing the error fails, use the logger to make one
            // last-ditch effort to output something.
            error!("fatal error");
        }
    });

    // Pause for 10s to give the operator time to see the message.
    boot::stall(10_000_000);

    // Power off.
    runtime::reset(ResetType::SHUTDOWN, Status::ABORTED, None)
}

/// Print a fatal error and shut down the machine.
///
/// The error message will include the executable name and version,
/// automatically read from Cargo variables.
///
/// This is implemented as a macro rather than a function so that it can
/// automatically grab the correct package name/version from the
/// environment. A function would only be able to get the libcrdy
/// package name/version.
#[macro_export]
macro_rules! fail_with_fatal_error {
    ($err:ident) => {
        $crate::fail_with_fatal_error_impl(env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"), &$err)
    };
}

/// Format an error.
///
/// If the error has an underlying cause, format the error chain as well.
fn write_err(writer: &mut dyn Write, mut err: &dyn Error) -> fmt::Result {
    writeln!(writer, "{err}")?;

    let mut first = true;
    while let Some(source) = err.source() {
        if first {
            writeln!(writer, "\nCaused by:")?;
            first = false;
        }

        writeln!(writer, "    {source}")?;

        err = source;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    enum Err {
        #[error("problem 1 occurred")]
        E1,

        #[error("problem 2 occurred")]
        E2(#[source] Box<Err>),
    }

    /// Test that `write_err` formats an error with no source errors
    /// correctly.
    #[test]
    fn test_write_err_depth0() {
        let mut s = String::new();
        write_err(&mut s, &Err::E1).unwrap();
        assert_eq!(s, "problem 1 occurred\n");
    }

    /// Test that `write_err` formats an error with one source error
    /// correctly.
    #[test]
    fn test_write_err_depth1() {
        let mut s = String::new();
        write_err(&mut s, &Err::E2(Box::new(Err::E1))).unwrap();
        assert_eq!(
            s,
            "problem 2 occurred

Caused by:
    problem 1 occurred
"
        );
    }

    /// Test that `write_err` formats an error with two source errors
    /// correctly.
    #[test]
    fn test_write_err_depth2() {
        let mut s = String::new();
        write_err(&mut s, &Err::E2(Box::new(Err::E2(Box::new(Err::E1))))).unwrap();
        assert_eq!(
            s,
            "problem 2 occurred

Caused by:
    problem 2 occurred
    problem 1 occurred
"
        );
    }
}
