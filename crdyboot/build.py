#!/usr/bin/env python3

import subprocess

def run(*cmd):
    print(' '.join(cmd))
    return subprocess.run(cmd, check=True)


def main():
    targets = ('x86_64-unknown-uefi',
               'i686-unknown-uefi')

    for target in targets:
        run('cargo', '+nightly', 'build',
            # TODO: for now always use release mode to avoid this error:
            # "LLVM ERROR: Do not know how to split the result of this operator!"
            '--release',
            '-Zbuild-std=core,compiler_builtins,alloc',
            '-Zbuild-std-features=compiler-builtins-mem',
            '--target', target)


if __name__ == '__main__':
    main()
