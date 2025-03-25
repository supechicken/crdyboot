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

## Accessing logs from the OS

Crdyboot writes logs to a temporary UEFI variable just prior to
launching the kernel. The variable does _not_ have the non-volatile flag
set, so it does not use flash storage.

To view the logs from the OS:

```
cat /sys/firmware/efi/efivars/CrdybootLog-2a6f93c9-29ea-46bf-b618-271b63baacf3
```

This includes debug logging, regardless of whether `crdyboot_verbose` is
enabled. The variable is limited to the most recent 200 lines, which
should ordinarily be more than enough to hold the entire log.

There is a similar variable for crdyshim logs, but note that this will
not exist for release images until such time as we get a new version of
crdyshim signed.

## Flexor

When booting flexor, the kernel log level will be increased if
`crdyboot_verbose` exists.

[`log`]: https://docs.rs/log
[`logging.rs`]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/HEAD:src/platform/crdyboot/libcrdy/src/logging.rs
