# Crdyshim Changelog

## 1.0.1

* Update `uefi` and `uefi-services` deps. <http://crrev.com/c/5385531>
* Check that TPM is valid before using it. <http://crrev.com/c/5413794>, <http://crrev.com/c/5413795>
* Treat all TPM errors as non-fatal. <http://crrev.com/c/5413796>
* Change logging of non-fatal errors to the info level. <http://crrev.com/c/5413797>
* If secure boot is off, allow signature file to be missing. <http://crrev.com/c/5415295>
* Version bump. <http://crrev.com/c/5413798>

## 1.0.0

* Initial release. Everything up to (and including)
  [d3dfc4ff5c][d3dfc4ff5c].

[d3dfc4ff5c]: https://chromium.googlesource.com/chromiumos/platform/crdyboot/+/d3dfc4ff5c
