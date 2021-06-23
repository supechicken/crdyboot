#!/usr/bin/env python3
# pylint: disable=missing-docstring

import argparse
import os
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
        ovmf_dir = 'volatile/uefi32'
    else:
        ovmf_dir = 'volatile/uefi64'
    ovmf_code = os.path.join(ovmf_dir, 'OVMF_CODE.fd')
    orig_ovmf_vars = os.path.join(ovmf_dir, 'OVMF_VARS.fd')
    new_ovmf_vars = os.path.join(ovmf_dir, 'OVMF_VARS.copy.fd')
    run('cp', orig_ovmf_vars, new_ovmf_vars)

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
        '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=' + ovmf_code,
        '-drive', 'if=pflash,format=raw,unit=1,readonly=on,file=' + new_ovmf_vars,
        '-drive', 'format=raw,file=' + disk)
    # yapf: enable


if __name__ == '__main__':
    main()
