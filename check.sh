#!/bin/sh

set -eux

# Format
cargo fmt --manifest-path vboot/Cargo.toml
cargo fmt --manifest-path crdyboot/Cargo.toml

# Lint
(cd vboot && cargo clippy)
(cd crdyboot && cargo +nightly clippy)

# Test
cargo test --manifest-path vboot/Cargo.toml

# Build
(cd crdyboot && ./build.py)
