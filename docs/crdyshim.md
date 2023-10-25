# crdyshim

Pronounced CUR-dee-shim.

Crdyshim is a UEFI bootloader intended as an alternative to
[`shim`]. Its purpose is to load, verify, and run a more complicated
bootloader such as crdyboot. Since crdyshim is a first-stage bootloader
(meaning it is run directly by the firmware), it will need to be signed
by Microsoft for use on most PCs. By keeping crdyshim very simple, we
aim to make updates infrequent. This is important so that we don't have
to go through the full testing and signing process often.

This bootloader is in the same repo as crdyboot so that they can share
code and tests, but they are not inherently tied together other than
crdyshim hardcoding the filename of crdyboot.

## Features

* Well documented and as simple as possible.
* Broad hardware support. Any amd64 machine with UEFI should be able to
  use crdyshim. This includes 32-bit UEFI environments.
* 100% Rust.

[`shim`]: https://github.com/rhboot/shim
