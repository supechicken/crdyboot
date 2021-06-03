# crdyboot

To build both x86_64 and i686 UEFI targets:

    ./build.py
    
To generate a bootable test image:

    cp /path/to/cloudready.bin volatile/disk.bin
    ./gen_disk.py <efi-partition>
    
Then run it in QEMU:

    runvm.py --snapshot --efi volatile/disk.bin

    # With custom firmware, e.g. for 32-bit UEFI:
    runvm.py --snapshot --efi myovmf.bin volatile/disk.bin
