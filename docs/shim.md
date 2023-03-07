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

Shim itself is built automatically during `cargo xtask setup`. This
requires podman, because we build from the [ChromeOS Flex
shim-review][shim-review] repo to match our real shim as closely as
possible. See [`shim.rs`] for details.

[shim]: https://github.com/rhboot/shim
[`shim.rs`]: ../xtask/src/shim.rs
[shim-review]: https://chromium.googlesource.com/chromiumos/shim-review
