# crdyboot

To build both x86_64 and i686 UEFI targets:

    ./build.py
    
To generate a bootable test image:

    cp /path/to/cloudready.bin volatile/disk.bin
    ./gen_disk.py
    
Then run it in QEMU:

    runvm.py --snapshot --efi volatile/disk.bin
