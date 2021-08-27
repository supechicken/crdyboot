# crdyboot

Pronounced CUR-dee-boot.

This is a UEFI bootloader for CloudReady. Crdyboot handles loading,
verifying, and running the Linux kernel.

Goals:

* Well documented and as simple as possible.
* Ensure that when secure boot is enabled, dm-verity is enabled for
  the rootfs. (Note that this can only be fully verified if using
  custom Secure Boot keys, otherwise a different OS signed with the
  Microsoft keys could be used to avoid verifying the rootfs.)
* Use UEFI features as little as possible. We need to run on a lot of
  hardware, and not all UEFI implementations work well.
* Use the ChromeOS GPT-attribute mechanism for determining which
  kernel to boot.
* Use the ChromeOS kernel partitions rather than loading the kernel
  from the EFI partition. The kernel partitions include both the
  kernel data and command-line, as well as data structures to verify
  the signature of everything being loaded.
* Verify the signature of everything loaded from the kernel partition.
* Only support 64-bit CPUs, but support both 32- and 64-bit UEFI
  environments.

## License

[BSD]

## Code layout

The `vboot` subdirectory is a `no_std` library that handles loading and
verifying the kernel. Internally it uses the `LoadKernel` function from
`third_party/vboot_reference`. This crate can be built for the host target
so that tests can run.

The `crdyboot` subdirectory contains the actual bootloader. It can
only be built for the `x86_64-unknown-uefi` and `i686-unknown-uefi`
targets.

The `xtask` subdirectory contains a single binary that is used by the
various `xtask` commands shown below.

The `enroller` subdirectory contains a small UEFI application that
enrolls a test key in the `PK`, `KEK`, and `db` variables. This only
works if the machine is in secure boot custom mode.

## Dependencies

Install nightly Rust:

    rustup install nightly
    rustup component add rust-src --toolchain nightly

Provides headers needed for compiling C code compatible with the
Rust UEFI targets.

    sudo apt install mingw-w64-i686-dev mingw-w64-x86-64-dev

For building OVMF:

    sudo apt install acpica-tools nasm uuid-dev

Other tools used for image signing and running in a VM:

    sudo apt install efitools gdisk qemu-system-x86 sbsigntool

## Building and testing

To check formatting, lint, test, and build both vboot and crdyboot:

    cargo xtask check

To build crdyboot for both 64-bit and 32-bit UEFI targets:

    cargo xtask build

One-time step to build OVMF:

    cargo xtask build-ovmf

One-time step to enroll custom secure-boot keys:

    cargo xtask secure-boot-setup

One-time step to copy in an existing cloudready image:

    cp /path/to/cloudready.bin workspace/disk.bin

One-time step to prepare the image:

    cargo xtask prep-disk

To copy the latest crdyboot build to the image:

    cargo xtask update-disk

Then run it in QEMU:

    cargo xtask qemu [--ia32] [--secure-boot]

Some additional build options can be set in `crdyboot.conf` (in the root of
the repo). This file will be created automatically if it doesn't already
exist by copying `xtask/default.conf`. The defaults are appropriate for
development. In a release build, verbose logging and the test key should be
turned off.

## Testing on real hardware

To test secure boot with real hardware you will need to enroll custom
keys. First build the enroller image (`workspace/enroller.bin`):

    cargo xtask build-enroller

Write `workspace/enroller.bin` to a USB, and write `workspace/disk.bin` to a
second USB, e.g. using [writedisk][writedisk].

Boot the DUT and enter the boot setup. Find the secure boot settings and change
it to setup mode. (The details will vary from one vendor to another.)

Plug in the enroller USB and reboot. Use the boot menu to select the USB and
wait for it to complete.

Unplug the enroller USB and plug in the cloudready USB, then reboot. Use the
boot menu to select the USB.

## Developer notes

An older pure-Rust version can be found in the `pure-rust-20210729`
branch. Since then we have switched to building the C vboot library and
loading/verifying the kernel through that library.

[BSD]: LICENSE
[writedisk]: https://crates.io/crates/writedisk
