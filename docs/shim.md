# shim

For testing purposes, the test disk that crdyboot builds includes
[shim]. This makes the test disk look more like a real deployment,
rather than using crdyboot as a first-stage bootloader.

Using shim with crdyboot requires setting `DISABLE_EBS_PROTECTION=y` in
the shim build. EBS protection is a shim feature that hooks the
`ExitBootServices` function so that shim can verify that the
second-stage bootloader properly used shim's verification protocol to
check the signature of the next stage. Since crdyboot verifies the next
stage through vboot, the EBS check would fail if enabled.

Shim itself is built automatically during `cargo xtask setup`. See
[`shim.rs`] for details.

## Logging

Verbose runtime logging can be enabled for shim by setting the
`SHIM_VERBOSE` UEFI variable. This can be done with the enroller. To
enable verbose mode, first `touch workspace/shim_verbose`. Then rebuild
the setup to rebuild the enroller and update the VM vars: `cargo xtask
setup`. Alternatively, to just rebuild the enroller: `cargo xtask
build-enroller.`

[shim]: https://github.com/rhboot/shim
[`shim.rs`]: ../xtask/src/shim.rs
