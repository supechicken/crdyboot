// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::uefi::{Uefi, UefiImpl, CRDYBOOT_VAR_VENDOR};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use core::cell::RefCell;
use core::fmt::Write;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use log::{info, LevelFilter, Metadata, Record};
use uefi::prelude::cstr16;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::runtime::VariableAttributes;
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

struct LoggerInner {
    /// Log level filter controlling whether a log is printed to the screen.
    display_level: LevelFilter,

    /// Recent log lines. This includes verbose logs and does not
    /// respect `display_level`.
    history: LogHistory,
}

struct Logger(
    /// Use an `AtomicPtr` so that the contents can be mutated. `static
    /// mut` would work as well since UEFI is not multithreaded, but
    /// atomics make it easier to avoid UB.
    ///
    /// The inner refcell is not strictly necessary, but simplifies safety
    /// by not requiring a mutable dereference of the pointer.
    AtomicPtr<RefCell<LoggerInner>>,
);

static LOGGER: Logger = Logger(AtomicPtr::new(ptr::null_mut()));

impl Logger {
    /// Call a function `f` with the logger's inner value mutably borrowed.
    ///
    /// # Panics
    ///
    /// This will panic if `f` calls any function that would recursively
    /// lead to `with_inner` being called again. In particular, `f` must
    /// not:
    /// * Do any logging through the `log` crate (e.g. calling `info!`
    ///   or `error!` macros)
    /// * Call `write_log_history` or `store_log_history_to_var`.
    fn with_inner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut LoggerInner) -> R,
    {
        let inner: *const RefCell<LoggerInner> = self.0.load(Ordering::Relaxed);
        assert!(!inner.is_null());
        // SAFETY:
        // * The pointer is set to a valid allocation in
        //   `initialize_logging`, and never unset.
        // * We know that initialization has occurred because the pointer
        //   is not null (see above assert).
        // * The pointer is not dereferenced by any other code.
        // * The pointer is never mutably dereferenced.
        // * Even if two borrows were created in the call stack, it
        //   would not be UB. The inner `RefCell` would panic on the
        //   call to `borrow_mut` below if that occurred.
        // * UEFI is single-threaded so there is no other thread that
        //   could violate assumptions.
        let inner = unsafe { &*inner };
        f(&mut inner.borrow_mut())
    }
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let line = format_record(record);

        self.with_inner(|inner| {
            if record.level() <= inner.display_level {
                println!("{}", line);
            }

            inner.history.push(line);
        });
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

struct LogHistory {
    lines: VecDeque<String>,
    max_lines: usize,
}

impl LogHistory {
    fn new(max_lines: usize) -> Self {
        Self {
            lines: VecDeque::with_capacity(max_lines),
            max_lines,
        }
    }

    fn push(&mut self, line: String) {
        if self.lines.len() >= self.max_lines {
            self.lines.pop_front();
        }

        self.lines.push_back(line);
        assert!(self.lines.len() <= self.max_lines);
    }

    /// Write the end of the log history to `writer`.
    ///
    /// Up to `max_lines_to_write` lines are written. If the number of
    /// history lines is less than `max_lines_to_write`, all lines are
    /// written.
    fn write(&self, writer: &mut dyn Write, max_lines_to_write: usize) {
        // Get the index of the first line to print. If the number of
        // lines is less than `max_lines_to_write`, this will be 0.
        let first_line = self.lines.len().saturating_sub(max_lines_to_write);

        // Starting at `first_line`, print the rest of the lines.
        for line in self.lines.iter().skip(first_line) {
            let _ = writeln!(writer, "{line}");
        }
    }

    /// Write the entire log history to a UEFI variable.
    ///
    /// The variable key will be `CRDYBOOT_VAR_VENDOR` and the given
    /// `name`. The variable is accessible at runtime, and is _not_ in
    /// nvram.
    fn store_to_var(&self, uefi: &dyn Uefi, name: &CStr16) {
        let mut data = String::new();
        self.write(&mut data, self.lines.len());

        let attributes =
            VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
        if let Err(err) = uefi.set_variable(name, &CRDYBOOT_VAR_VENDOR, attributes, data.as_bytes())
        {
            info!("failed to store logs: {err}");
        }
    }
}

/// Write the end of the log history to `writer`.
///
/// See `LogHistory::write` for details.
pub(crate) fn write_log_history(writer: &mut dyn Write, max_lines_to_write: usize) {
    LOGGER.with_inner(|inner| {
        inner.history.write(writer, max_lines_to_write);
    });
}

/// Write the entire log history to a UEFI variable.
///
/// See `LogHistory::store_to_var` for details.
pub(crate) fn store_log_history_to_var(name: &CStr16) {
    LOGGER.with_inner(|inner| {
        inner.history.store_to_var(&UefiImpl, name);
    });
}

/// Initialize logging at the specified level.
///
/// # Panics
///
/// Panics if called more than once.
pub fn initialize_logging_with_level(display_level: LevelFilter) {
    // The number of history lines is somewhat arbitrary, but it should
    // be small enough that memory usage isn't too high if some bug
    // causes a large amount of log spam.
    let max_lines = 20;

    // Allocate logger data on the heap and leak it. This data needs to
    // live as long as the program, so it's OK that nothing ever frees
    // it.
    let inner = Box::into_raw(Box::new(RefCell::new(LoggerInner {
        history: LogHistory::new(max_lines),
        display_level,
    })));
    LOGGER.0.store(inner, Ordering::Relaxed);
    log::set_logger(&LOGGER).expect("logger must not be initialized twice");

    // Allow messages at the `Debug` level and lower to be passed to
    // `Logger`. This filtering occurs in the `log` crate macros,
    // whereas the `display_level` filtering occurs in the `Logger`
    // implementation.
    log::set_max_level(LevelFilter::Debug);
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
    use crate::uefi::MockUefi;
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

    #[test]
    fn test_log_history() {
        let mut history = LogHistory::new(3);
        assert!(history.lines.is_empty());

        history.push("0".to_owned());
        assert_eq!(history.lines, ["0"]);

        history.push("1".to_owned());
        assert_eq!(history.lines, ["0", "1"]);

        history.push("2".to_owned());
        assert_eq!(history.lines, ["0", "1", "2"]);

        history.push("3".to_owned());
        assert_eq!(history.lines, ["1", "2", "3"]);

        history.push("4".to_owned());
        assert_eq!(history.lines, ["2", "3", "4"]);

        history.push("5".to_owned());
        assert_eq!(history.lines, ["3", "4", "5"]);
    }

    #[test]
    fn test_log_history_write() {
        let mut history = LogHistory::new(3);
        history.push("a".to_owned());
        history.push("b".to_owned());
        history.push("c".to_owned());

        // Limit is zero: no lines are written.
        let mut s = String::new();
        let max_lines_to_write = 0;
        history.write(&mut s, max_lines_to_write);
        assert_eq!(s, "");

        let mut s = String::new();
        let max_lines_to_write = 1;
        history.write(&mut s, max_lines_to_write);
        assert_eq!(s, "c\n");

        let mut s = String::new();
        let max_lines_to_write = 2;
        history.write(&mut s, max_lines_to_write);
        assert_eq!(s, "b\nc\n");

        let mut s = String::new();
        let max_lines_to_write = 3;
        history.write(&mut s, max_lines_to_write);
        assert_eq!(s, "a\nb\nc\n");

        // Limit is larger than the number of lines: all lines are written.
        let mut s = String::new();
        let max_lines_to_write = 4;
        history.write(&mut s, max_lines_to_write);
        assert_eq!(s, "a\nb\nc\n");
    }

    #[test]
    fn test_log_history_store_to_var() {
        let mut history = LogHistory::new(3);
        history.push("a".to_owned());
        history.push("b".to_owned());
        history.push("c".to_owned());

        let mut uefi = MockUefi::new();
        uefi.expect_set_variable()
            .times(1)
            .withf(|name, vendor, attr, data| {
                name == cstr16!("name")
                    && vendor == &CRDYBOOT_VAR_VENDOR
                    && *attr
                        == VariableAttributes::BOOTSERVICE_ACCESS
                            | VariableAttributes::RUNTIME_ACCESS
                    && data == "a\nb\nc\n".as_bytes()
            })
            .return_once(|_, _, _, _| Ok(()));
        history.store_to_var(&uefi, cstr16!("name"));
    }
}
