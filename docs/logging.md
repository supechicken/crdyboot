# Logging

Log input is handled by the standard [`log`] crate. Log output is
written by the [`uefi-services`] crate to UEFI's stdout handle. On most
machines this will appear on the screen, but there are exceptions (such
as Macbooks) where the logs won't be printed anywhere.

The default log level is set to `Warn`, meaning that only warnings and
errors will be logged. With a normal successful boot all logs should be
at the info level, so nothing will be printed to the screen.

To alter the log level at runtime, create an empty file called
`crdyboot_verbose` in the same directory as the bootloader
(`/efi/boot`).

[`log`]: https://docs.rs/log
[`uefi-services`]: https://docs.rs/uefi-services
