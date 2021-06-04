#!/usr/bin/env python3

import contextlib
import os
import subprocess
import tempfile

def run(*cmd, capture_output=False):
    print(' '.join(cmd))
    return subprocess.run(cmd, check=True, text=True, capture_output=capture_output)


@contextlib.contextmanager
def set_up_loopback_device(disk_image_path):
    cmd = ('sudo', 'losetup', '--find', '--show', '--partscan',
           disk_image_path)
    dev_path = run(*cmd, capture_output=True).stdout.strip()
    try:
        yield dev_path
    finally:
        run('sudo', 'losetup', '--detach', dev_path)


@contextlib.contextmanager
def mount(dev):
    with tempfile.TemporaryDirectory(prefix='crdyboot') as mountpoint:
        run('sudo', 'mount', dev, mountpoint)
        try:
            yield mountpoint
        finally:
            run('sudo', 'umount', mountpoint)


def is_disk_using_partition_layout_27(lo_dev):
    p27 = lo_dev + 'p27'
    return os.path.exists(p27)


def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    volatile_dir = os.path.join(script_dir, 'volatile')

    disk_bin = os.path.join(volatile_dir, 'disk.bin')

    with set_up_loopback_device(disk_bin) as lo_dev:
        layout27 = is_disk_using_partition_layout_27(lo_dev)
        if layout27:
            efi_partnum = 27
        else:
            efi_partnum = 12

        efi_partition_dev = '{}p{}'.format(lo_dev, efi_partnum)

        with mount(efi_partition_dev) as mountpoint:
            run('sudo', 'ls', '-lR', mountpoint)
            targets = {
                'x86_64-unknown-uefi': 'grubx64.efi',
                'i686-unknown-uefi': 'grubia32.efi',
            }
            for target, dstname in targets.items():
                src = os.path.join(script_dir, 'target', target,
                                       'release/crdyboot.efi')
                dst = os.path.join(mountpoint, 'efi/boot', dstname)
                run('sudo', 'cp', src, dst)

            run('sudo', 'ls', '-lR', mountpoint)


if __name__ == '__main__':
    main()
