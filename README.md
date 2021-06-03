# crdyboot

This is a work-in-progress UEFI bootloader for CloudReady. It is
intended to be run by [shim](https://github.com/rhboot/shim), then
crdyboot will handle verifying and running the Linux kernel.

Goals:

1. Ensure that when secure boot is enabled, dm-verity is enabled for
   the rootfs.
2. Use the ChromeOS GPT-attribute mechanism for determining which
   kernel to boot. Do not rely on writing BootOrder, which doesn't
   seem to work well on some machines.
3. Use the ChromeOS kernel partitions rather than loading the kernel
   from the EFI partition. The kernel partitions include both the
   kernel data and command-line, as well as data structures to verify
   the signature of everything being loaded.
4. Verify the signature of everything loaded from the kernel
   partition.
5. Only support 64-bit CPUs, but support both 32- and 64-bit UEFI
   environments.

## Building and testing

First make sure submodules are initialized:

    git submodule update --init

The main firmware code is in the `crdyboot` subdirectory:

    cd crdyboot

To build both 64-bit and 32-bit UEFI targets:

    ./build.py
    
To generate a bootable test image:

    cp /path/to/cloudready.bin volatile/disk.bin
    ./gen_disk.py <efi-partition>
    
Then run it in QEMU:

    runvm.py --snapshot --efi volatile/disk.bin

    # With custom firmware, e.g. for 32-bit UEFI:
    runvm.py --snapshot --efi myovmf.bin volatile/disk.bin
