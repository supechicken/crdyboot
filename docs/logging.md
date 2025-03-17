# Logging

Log input is handled by the standard [`log`] crate. Log output is
written by the [`logging.rs`] module to UEFI's stdout handle. On most
machines this will appear on the screen, but there are exceptions (such
as Macbooks) where the logs won't be printed anywhere.

The default log level is set to `Warn`, meaning that only warnings and
errors will be logged. With a normal successful boot all logs should be
at the info level, so nothing will be printed to the screen.

To alter the log level at runtime, create an empty file called
`crdyboot_verbose` in the same directory as the bootloader
(`/efi/boot`). This will set the log level to `Debug`.

## Flexor

When booting flexor, the kernel log level will be increased if
`crdyboot_verbose` exists.

[`log`]: https://docs.rs/log
[`logging.rs`]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/HEAD:src/platform/crdyboot/libcrdy/src/logging.rs
