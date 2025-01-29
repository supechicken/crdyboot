// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use alloc::format;
use alloc::string::String;
use core::fmt::Write;
use log::{info, LevelFilter, Metadata, Record};
use uefi::prelude::cstr16;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::{boot, println, CStr16, Status};

/// Check if `efi\boot\crdyboot_verbose` exists on the boot
/// filesystem. If any error occurs when checking for this file, `false`
/// is returned.
#[must_use]
pub fn does_verbose_file_exist() -> bool {
    let mut sfs = match boot::get_image_file_system(boot::image_handle()) {
        Ok(sfs) => sfs,
        Err(err) => {
            info!("failed to open SimpleFileSystem: {err:?}");
            return false;
        }
    };

    let mut root = match sfs.open_volume() {
        Ok(root) => root,
        Err(err) => {
            info!("failed to open volume: {err:?}");
            return false;
        }
    };

    let path: &CStr16 = cstr16!(r"efi\boot\crdyboot_verbose");
    match root.open(path, FileMode::Read, FileAttribute::empty()) {
        Ok(_) => true,
        Err(err) => {
            if err.status() != Status::NOT_FOUND {
                info!("unexpected error when opening {path}: {err:?}");
            }
            false
        }
    }
}

struct Logger;

static LOGGER: Logger = Logger;

impl log::Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if record.level() <= log::max_level() {
            println!("{}", format_record(record));
        }
    }

    fn flush(&self) {}
}

fn format_record(record: &Record) -> String {
    let mut output = format!(
        "{}: [{}",
        record.level(),
        record.file().unwrap_or("<unknown>")
    );
    if let Some(line) = record.line() {
        // OK to unwrap: writing to a string cannot fail.
        write!(output, "({line})").unwrap();
    }

    // OK to unwrap: writing to a string cannot fail.
    write!(output, "] {}", record.args()).unwrap();

    output
}

/// Initialize logging at the specified level.
///
/// # Panics
///
/// Panics if called more than once.
pub fn initialize_logging_with_level(level: LevelFilter) {
    log::set_logger(&LOGGER).expect("logger must not be initialized twice");
    log::set_max_level(level);
}

/// Initialize logging.
///
/// By default the log level is set to `Warn` so that only warnings and
/// errors are shown. In a normal boot, this will result in no
/// output. If a file named `crdyboot_verbose` exists in the same
/// directory as the bootloader executable, the log level will be set to
/// `Debug`.
///
/// # Panics
///
/// Panics if called more than once.
pub fn initialize_logging() {
    let level = if does_verbose_file_exist() {
        LevelFilter::Debug
    } else {
        LevelFilter::Warn
    };
    initialize_logging_with_level(level);
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;

    #[test]
    fn test_record_format() {
        let record = Record::builder()
            .args(format_args!("log message"))
            .level(Level::Error)
            .file(Some("file.rs"))
            .line(Some(123))
            .build();
        assert_eq!(format_record(&record), "ERROR: [file.rs(123)] log message");
    }

    #[test]
    fn test_record_format_missing_location() {
        let record = Record::builder()
            .args(format_args!("log message"))
            .level(Level::Error)
            .file(None)
            .line(None)
            .build();
        assert_eq!(format_record(&record), "ERROR: [<unknown>] log message");
    }
}
