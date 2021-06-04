#!/usr/bin/env python3

import os
import subprocess

def run(*cmd):
    print(' '.join(cmd))
    return subprocess.run(cmd, check=True)


class KeyName:
    def __init__(self, base_name):
        self.base_name = base_name

    def pem(self):
        return self.base_name + '.pem'

    def pub_pem(self):
        return self.base_name + '.pub.pem'

    def vbprivk(self):
        return self.base_name + '.vbprivk'

    def vbpubk(self):
        return self.base_name + '.vbpubk'

    def keyblock(self):
        return self.base_name + '.keyblock'


def gen_key(key_name):
    file_name = key_name.pem()
    # Key generation takes a while, so don't do it if the key
    # already exists.
    if os.path.exists(file_name):
        print(file_name, 'already exists')
    else:
        run('openssl', 'genrsa', '-F4', '-out', file_name, '8192')
    # Also generate the public key in PEM format. This isn't used by
    # vboot utilities, but is used in the Rust tests.
    run('openssl', 'rsa', '-pubout', '-in', file_name,
        '-out', key_name.pub_pem())


def gen_keypair(futility_path, key_name):
    """Generate .vbprivk and .vbpubk files from a .pem file."""
    run(futility_path, '--vb1', 'create', key_name.pem())


def gen_keyblock(futility_path, kernel_key, kernel_data_key):
    # Copied from vboot_reference/firmware/2lib/include/2struct.h
    VB2_KEYBLOCK_FLAG_DEVELOPER_0 = 0x1
    VB2_KEYBLOCK_FLAG_RECOVERY_0 = 0x4
    flags = VB2_KEYBLOCK_FLAG_DEVELOPER_0 | VB2_KEYBLOCK_FLAG_RECOVERY_0

    run(futility_path, '--vb1', 'sign',
        '--signprivate', kernel_key.vbprivk(),
        '--flags', str(flags),
        kernel_data_key.vbpubk(),
        kernel_data_key.keyblock())


def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))

    # Run from within the test_keys subdirectory.
    os.chdir(script_dir)

    futility_path = '../../third_party/vboot_reference/build/futility/futility'

    # Key used to sign the kernel keyblock which contains the public
    # part of the kernel_data_key.
    kernel_key = KeyName('kernel_key')
    gen_key(kernel_key)

    # Key used to sign the kernel data.
    kernel_data_key = KeyName('kernel_data_key')
    gen_key(kernel_data_key)

    gen_keypair(futility_path, kernel_key)
    gen_keypair(futility_path, kernel_data_key)
    gen_keyblock(futility_path, kernel_key, kernel_data_key)


if __name__ == '__main__':
    main()
