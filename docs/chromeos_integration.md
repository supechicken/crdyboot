# ChromeOS integration

This document describes how crdyboot is integrated into [ChromeOS
Flex]. Although crdyboot can be built in isolation for ease of
development, its intended use is as part of ChromeOS Flex.

## Build

The [crdyboot ebuild] in chromiumos-overlay is used to build the
crdyboot executables (one for 64-bit UEFI, one for 32-bit UEFI). In the
chroot, it can be built with:

```
emerge-<board> crdyboot
```

The executables will be installed under `/boot` in the board root, and
[`build_image`] will copy everything under `/boot` to the [EFI system
partition].

When building the `reven` board, crdyboot can be enabled with:
```
USE=crdyboot build_packages
```

## Sign

Image signing handled by scripts in `vboot_reference`. The
[`sign_uefi.py`] script has special handling for crdyboot. Each crdyboot
file gets the appropriate `vbpubk` injected into it, then the file is
signed in the usual way with `sbsign`.

[ChromeOS Flex]: https://chromeenterprise.google/os/chromeosflex/
[EFI system partition]: https://en.wikipedia.org/wiki/EFI_system_partition
[`build_image`]: https://chromium.googlesource.com/chromiumos/chromite/+/refs/heads/main/scripts/build_image.py
[crdyboot ebuild]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/sys-boot/crdyboot
[`sign_uefi.py`]: https://chromium.googlesource.com/chromiumos/platform/vboot_reference/+/HEAD/scripts/image_signing/sign_uefi.py
