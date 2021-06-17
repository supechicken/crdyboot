# crdyboot

This is a work-in-progress UEFI bootloader for CloudReady. It is
intended to be run either as a second-stage bootloader after
[shim](https://github.com/rhboot/shim) when using the Microsoft keys,
or as the first-stage bootloader when using custom keys. Then crdyboot
will handle loading, verifying, and running the Linux kernel.

Goals:

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
   
## Code layout

The `vboot` subdirectory is a `no_std` library that implements just
the necessary parts of vboot in Rust. It uses bindgen to access
structs and constants from `vboot_reference`, but does not directly
build any of the C code. This crate can be built for the host target
so that tests can run.

The `crdyboot` subdirectory contains the actual bootloader. It can
only be built for the `x86_64-unknown-uefi` and `i686-unknown-uefi`
targets.

## Building and testing

First make sure submodules are initialized:

    git submodule update --init
    
To format, lint, test, and build both vboot and crdyboot:

    ./check.sh

The main bootloader code is in the `crdyboot` subdirectory:

    cd crdyboot

To build both 64-bit and 32-bit UEFI targets:

    ./build.py
    
To generate a bootable test image:

    cp /path/to/cloudready.bin volatile/disk.bin
    ./gen_disk.py
    
Then run it in QEMU:

    runvm.py --snapshot --efi volatile/disk.bin

    # With custom firmware, e.g. for 32-bit UEFI:
    runvm.py --snapshot --efi myovmf.bin volatile/disk.bin

## TODO

* Verify that vboot is properly checking the signatures of all data
  that gets used.
* Verify that the unsafe code is correct.
