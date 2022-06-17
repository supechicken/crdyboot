# libc stub

This directory contains a small subset of the C standard headers, just
enough to provide everything that vboot_reference needs when compiling
with clang and the `i686-unknown-windows-gnu` and
`x86_64-unknown-windows-gnu` targets.

See `vboot_reference/firmware/2lib/include/2sysincludes.h` for where
these headers get included.
