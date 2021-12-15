# sbat_gen

This library generates Rust code for adding an [SBAT][SBAT.md] metadata
section to a binary.

The dependency should be added to the `[build-dependencies]` section of
`Cargo.toml`, and then called from `build.rs`. A Rust file will be
generated at compile time, which can then be included in the binary like
this:

```rust
include!(concat!(env!("OUT_DIR"), "/sbat_section.rs"));
```

This will create a new section in the binary named `.sbat` containing
the SBAT CSV metadata. To verify that the section has been correctly
added, run `objdump` against the binary. For example:

```
objdump -j .sbat -s path/to/some/binary.efi
```

[SBAT.md]: https://github.com/rhboot/shim/blob/main/SBAT.md
