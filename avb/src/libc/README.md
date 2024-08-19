# libc stub

This directory contains a small subset of the C standard headers, just
enough to provide everything that `avb` needs when compiling
with clang and the `i686-unknown-windows-gnu` and
`x86_64-unknown-windows-gnu` targets.

See `avb/libavb/avb_sysdeps.h` for where these get included.
See also `avb/libavb/avb_util.c` for where `stdarg.h` is included.
