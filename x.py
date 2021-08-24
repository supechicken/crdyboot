#!/usr/bin/env python3
# pylint: disable=missing-docstring

import os
import subprocess
import sys


def main():
    repo_dir = os.path.dirname(os.path.realpath(__file__))

    cmd = ['cargo', 'run', '--quiet', '--package', 'crdyboot_tools', '--']
    cmd += ['--repo', repo_dir]
    cmd += sys.argv[1:]

    res = subprocess.run(cmd, check=False)
    # Exit with the child's return code. Do it this way instead of
    # using check=True because we don't want a stack trace.
    if res.returncode != 0:
        sys.exit(res.returncode)


if __name__ == '__main__':
    main()
