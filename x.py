#!/usr/bin/env python3
# pylint: disable=missing-docstring

import os
import subprocess
import sys


def main():
    repo_dir = os.path.dirname(os.path.realpath(__file__))
    tools_manifest = os.path.join(repo_dir, 'tools/Cargo.toml')

    cmd = ['cargo', 'run', '--quiet', '--manifest-path', tools_manifest, '--']
    cmd += ['--repo', repo_dir]
    cmd += sys.argv[1:]

    subprocess.run(cmd, check=True)


if __name__ == '__main__':
    main()
