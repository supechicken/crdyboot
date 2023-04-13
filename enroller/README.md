# Enroller

This is a small UEFI application that enrolls a test key in the `PK`,
`KEK`, and `db` variables. This is used to set up the test VM, and can
also be used on real hardware (see the "Testing on real hardware"
section in the top-level README).

This code is not used in any way for a production build of ChromeOS
Flex; it's purely used for testing.
