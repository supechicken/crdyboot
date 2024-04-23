# `uefi_test_tool`

This package contains an executable used in some VM tests. In these
tests, the `uefi_test_tool` is launched as the first bootloader. The
test tool can then make modifications to the system to test a particular
scenario. Then it launches crdyshim and boot proceeds as normal.

The behavior of `uefi_test_tool` is controlled by a file on the [ESP]:
`\efi\boot\crdy_test_control`. The VM tests write a string out to that
file, and the test tool reads it on launch to determine what system
modifications to make.

[ESP]: https://en.wikipedia.org/wiki/EFI_system_partition
