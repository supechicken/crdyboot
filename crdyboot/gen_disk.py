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
    vboot_reference_dir = os.path.join(
        script_dir, '../third_party/vboot_reference')
    futility = os.path.join(vboot_reference_dir, 'build/futility/futility')
    # TODO: for now just use a pregenerated test key.
    private_signing_key = os.path.join(
        script_dir, '../vboot/test_data/kernel_key.vbprivk')

    # Ensure the vboot_reference "futility" tool has been built.
    run('make', '-C', vboot_reference_dir, 'futil')

    disk_bin = os.path.join(volatile_dir, 'disk.bin')

    with set_up_loopback_device(disk_bin) as lo_dev:
        layout27 = is_disk_using_partition_layout_27(lo_dev)
        efi_partnum = 12
        kern_a_partnum = 2
        kern_b_partnum = 4
        if layout27:
            offset = 15
            efi_partnum += offset
            kern_a_partnum += offset
            kern_b_partnum += offset

        efi_partition_dev = '{}p{}'.format(lo_dev, efi_partnum)

        # Replace both grub executables with crdyboot.
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

        # Sign both kernel partitions.
        with tempfile.TemporaryDirectory(prefix='crdyboot') as tmpdir:
            for partnum in (kern_a_partnum, kern_b_partnum):
                unsigned_kernel_partition = os.path.join(
                    tmpdir, 'kernel_partition')
                signed_kernel_partition = unsigned_kernel_partition + '.signed'

                # Copy the whole partition to a temporary file.
                part_dev = '{}p{}'.format(lo_dev, partnum)
                run('sudo', 'cp', part_dev, unsigned_kernel_partition)

                # Sign it.
                run('sudo', futility, 'vbutil_kernel',
                    '--repack', signed_kernel_partition,
                    '--signprivate', private_signing_key,
                    '--oldblob', unsigned_kernel_partition)

                # Copy it back to the partition.
                run('sudo', 'cp', signed_kernel_partition, part_dev)


if __name__ == '__main__':
    main()
