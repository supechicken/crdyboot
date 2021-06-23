#!/usr/bin/env python3
# pylint: disable=missing-docstring

import os
import subprocess
import sys


def main():
    repo_dir = os.path.dirname(os.path.realpath(__file__))
    tools_dir = os.path.join(repo_dir, 'tools')
    tools_manifest = os.path.join(tools_dir, 'Cargo.toml')

    cmd = ['cargo', 'run', '--quiet', '--manifest-path', tools_manifest, '--']
    cmd += ['--repo', repo_dir]
    cmd += sys.argv[1:]

    # Make rustc use absolute paths for messages.
    var_name = 'RUSTFLAGS'
    env = dict(os.environ)
    flags = env.get(var_name, '')
    flags += ' --remap-path-prefix=src={}/src'.format(tools_dir)
    env[var_name] = flags

    res = subprocess.run(cmd, check=False, env=env)
    # Exit with the child's return code. Do it this way instead of
    # using check=True because we don't want a stack trace.
    if res.returncode != 0:
        sys.exit(res.returncode)


if __name__ == '__main__':
    main()
