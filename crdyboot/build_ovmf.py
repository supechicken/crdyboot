#!/usr/bin/env python3
# pylint: disable=missing-docstring

import os
import subprocess


def run(*cmd, cwd=None):
    print(' '.join(cmd))
    subprocess.run(cmd, check=True, cwd=cwd)


def main():
    """Build UEFI firmware."""
    script_dir = os.path.dirname(os.path.realpath(__file__))
    volatile_dir = os.path.join(script_dir, 'volatile')
    edk2_dir = os.path.join(volatile_dir, 'edk2')
    edk2_url = 'https://github.com/tianocore/edk2.git'

    # Clone edk2 if not already cloned, otherwise just fetch.
    if os.path.exists(edk2_dir):
        run('git', '-C', edk2_dir, 'fetch')
    else:
        run('git', 'clone', edk2_url, edk2_dir)

    # Check out a known-working commit.
    run('git', '-C', edk2_dir, 'checkout',
        '75e9154f818a58ffc3a28db9f8c97279e723f02d')

    # Init/update submodules.
    run('git', '-C', edk2_dir, 'submodule', 'update', '--init')

    # Build 64-bit UEFI for a 64-bit CPU.
    run('OvmfPkg/build.sh', '-a', 'X64', cwd=edk2_dir)

    # Build 32-bit UEFI for a 64-bit CPU.
    run('OvmfPkg/build.sh', '-a', 'IA32', '-a', 'X64', cwd=edk2_dir)

    # Copy the outputs to a more convenient location.
    compiler = 'DEBUG_GCC5'
    outputs = {
        'Ovmf3264': 'ovmf32.fd',
        'OvmfX64': 'ovmf64.fd',
    }
    for src_name, dst_name in outputs.items():
        src = os.path.join(edk2_dir, 'Build', src_name, compiler, 'FV/OVMF.fd')
        dst = os.path.join(volatile_dir, dst_name)
        run('cp', src, dst)


if __name__ == '__main__':
    main()
