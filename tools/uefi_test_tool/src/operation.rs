// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// `Operation` definition, shared between `uefi_test_tool` and `xtask`.

use alloc::format;
use alloc::string::String;
use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Operation {
    #[allow(dead_code)]
    Unset = 0,
    Tpm1Deactivated,
    Tpm1ExtendFail,
}

impl Display for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // Delegate to the `Debug` implementation.
        write!(f, "{self:?}")
    }
}

impl FromStr for Operation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Note that `Unset` is intentionally not included.
        for op in [Operation::Tpm1Deactivated, Operation::Tpm1ExtendFail] {
            if s == format!("{op}") {
                return Ok(op);
            }
        }
        Err(format!("invalid operation: {s}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test serialization and deserialization.
    #[test]
    fn test_operation() {
        assert_eq!(Operation::Tpm1Deactivated.to_string(), "Tpm1Deactivated");
        assert_eq!(
            "Tpm1Deactivated".parse::<Operation>().unwrap(),
            Operation::Tpm1Deactivated
        );
        assert!("invalid".parse::<Operation>().is_err(),);
        assert!("Unset".parse::<Operation>().is_err(),);
    }
}
