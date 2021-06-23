#!/usr/bin/env python3
# pylint: disable=missing-docstring

import os
import subprocess
import sys


def main():
    repo_dir = os.path.dirname(os.path.realpath(__file__))
    tools_dir = os.path.join(repo_dir, 'tools')

    cmd = ['cargo', 'run', '--quiet', '--']
    cmd += ['--repo', repo_dir]
    cmd += sys.argv[1:]

    subprocess.run(cmd, cwd=tools_dir, check=True)


if __name__ == '__main__':
    main()
