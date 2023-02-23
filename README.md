# crdyboot

Pronounced CUR-dee-boot.

Crdyboot is a UEFI bootloader for ChromeOS Flex. It is not yet in use.

Crdyboot acts as a bridge between UEFI firmware and the Chromebook style
of booting. It uses [vboot] to select and validate an appropriate
[kernel partition], then launches that kernel using the Linux [EFI stub].

[TOC]

## Features

* Well documented and as simple as possible.
* Broad hardware support. Any amd64 machine with UEFI should be able to
  use crdyboot. This includes 32-bit UEFI environments.
* Uses vboot to:
  * Verify that both the kernel and the kernel command-line have been
    signed with a trusted key, which in turn allows verifying that the
    rootfs has not been modified. (Note that this can only be fully
    relied on if using custom Secure Boot keys, otherwise a different OS
    signed with the Microsoft keys could be used to avoid verifying the
    rootfs.)
  * Automatically roll back from a bad OS update by swapping between the
    A and B partitions.

## License

[BSD]

## Code layout

The project is organized as a Rust [workspace] containing several
packages:

* The `vboot` package is a thin wrapper around the C [vboot] library. It
  also exposes a `DiskIo` trait through which it can read and write
  blocks to a disk. This package is `no_std`, and can be built for both
  the UEFI targets and the host target. Building for the host allows
  tests to be run on the host.
* The `libcrdy` package is where most of the bootloader is
  implemented. It implements the `DiskIo` trait using the [uefi crate],
  and uses the `vboot` package to load and verify a kernel. It then
  boots into that kernel using the EFI stub. This package is also
  `no_std` and can also be built for both UEFI targets and the host
  target for testing purposes.
* The `crdyboot` package provides the actual bootloader executable. It
  contains the embedded key used to verify the kernel data, the SBAT
  data used for revocation, and sets up logging and allocation. Then it
  uses `libcrdy` to load, verify, and run the kernel.
* The `xtask` package contains a host executable that provides the
  various `xtask` commands shown below. It's like a fancy Makefile for
  running various dev and test operations.
* The `enroller` subdirectory contains a small UEFI application that
  enrolls a test key in the `PK`, `KEK`, and `db` variables. This is
  used to set up the test VM, and can also be used on real hardware (see
  the "Testing on real hardware" section).

## Dependencies

Install Rust: <https://rustup.rs>

Install tools used for image signing and running in a VM:

    sudo apt install clang efitools gdisk ovmf ovmf-ia32 podman \
        qemu-system-x86 sbsigntool swtpm

After installing qemu, add your user to the `kvm` group. You will need
to log out and back in for this to take effect:

    sudo adduser ${USER} kvm

## Building and testing

Before running any other commands in the repository, run this setup
command:

    cargo xtask setup <reven-verity-image-path>

This will copy the reven image to a local directory and run various
setup commands. The image must have rootfs verification enabled
(i.e. `build_image` must be run _without_ `-r` or
`--no-enable-rootfs-verification`). Any kind of image (`base`, `dev`, or
`test`) is allowed.

To check formatting, lint, test, build crdyboot, and install to the image:

    cargo xtask check [--vm-tests]

The `--vm-tests` option enables slow tests that run under QEMU.

To just build crdyboot and install to the image (a quicker subset of `check`):

    cargo xtask build

Then run it in QEMU:

    cargo xtask qemu [--ia32] [--no-secure-boot] [--tpm1|--tpm2]

## Testing on real hardware

To test secure boot with real hardware you will need to enroll custom
keys. Write `workspace/enroller.bin` to a USB, and write
`workspace/disk.bin` to a second USB, e.g. using [writedisk].

Boot the DUT and enter the boot setup. Find the secure boot settings and change
it to setup mode. (The details will vary from one vendor to another.)

Plug in the enroller USB and reboot. Use the boot menu to select the USB and
wait for it to complete.

Unplug the enroller USB and plug in the cloudready USB, then reboot. Use the
boot menu to select the USB.

## Documentation

See the [docs](docs) subdirectory.

[BSD]: LICENSE
[EFI stub]: https://docs.kernel.org/admin-guide/efi-stub.html
[kernel partition]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/disk_format.md#Kernel-partition-format
[uefi crate]: https://docs.rs/uefi/latest/uefi/
[vboot]: https://chromium.googlesource.com/chromiumos/platform/vboot_reference/+/HEAD/README
[workspace]: https://doc.rust-lang.org/cargo/reference/workspaces.html
[writedisk]: https://crates.io/crates/writedisk
