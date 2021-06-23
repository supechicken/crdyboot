#!/usr/bin/env python3
# pylint: disable=missing-docstring

import argparse
import subprocess


def run(*cmd):
    print(' '.join(cmd))
    subprocess.run(cmd, check=True)


def main():
    """Run crdyboot under QEMU."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--ia32',
                        action='store_true',
                        help='use 32-bit UEFI instead of 64-bit')
    args = parser.parse_args()

    qemu = 'qemu-system-x86_64'
    disk = 'volatile/disk.bin'

    if args.ia32:
        ovmf = 'volatile/ovmf32.fd'
    else:
        ovmf = 'volatile/ovmf64.fd'

    # yapf: disable
    run(qemu,
        # These options are needed for SMM as described in
        # edk2/OvmfPkg/README.
        '-machine', 'q35,smm=on,accel=kvm',
        '-global', 'ICH9-LPC.disable_s3=1',

        '-enable-kvm',
        '-m', '1G',
        '-vga', 'virtio',
        '-serial', 'stdio',
        '-nodefaults',
        '-drive', 'if=pflash,format=raw,readonly,file=' + ovmf,
        '-drive', 'format=raw,file=' + disk)
    # yapf: enable


if __name__ == '__main__':
    main()
