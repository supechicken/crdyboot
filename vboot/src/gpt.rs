// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::convert::TryInto;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// a struct containing available attributes for a GPT entry
/// see: <https://www.chromium.org/chromium-os/developer-library/reference/device/disk-format/>
pub struct CgptAttributes {
    /// true if the system has successfully booted from this partition, false otherwise.
    pub successful: bool,
    /// if `!successful`, is the number of times system can attempt to boot this partition.
    pub tries: u8,
    /// 15 = highest, 1 = lowest, 0 = not bootable.
    pub priority: u8,
}

impl CgptAttributes {
    /// Get `CgptAttributes` from a u64.
    ///
    ///  bits | meaning
    /// ==================
    ///    56 | successful
    /// 55-52 | tries
    /// 51-48 | priority
    ///
    /// Based on:
    /// `vboot_reference/firmware/lib/cgptlib/include/cgptlib_internal`.*
    ///
    /// # Panics
    ///
    /// Will never panic because values are guaranteed to fit in `u8`
    #[must_use]
    pub fn from_u64(num: u64) -> CgptAttributes {
        let successful_offset = 56;
        let max_successful = 0b1;
        let successful_mask = max_successful << successful_offset;
        let tries_offset = 52;
        let max_tries = 0b1111;
        let tries_mask = max_tries << tries_offset;
        let priority_offset = 48;
        let max_priority = 0b1111;
        let priority_mask = max_priority << priority_offset;
        let successful = (num & successful_mask) >> successful_offset;
        let tries = (num & tries_mask) >> tries_offset;
        let priority = (num & priority_mask) >> priority_offset;
        CgptAttributes {
            successful: successful == 1,
            tries: tries.try_into().unwrap(),
            priority: priority.try_into().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u64() {
        assert_eq!(
            CgptAttributes::from_u64(
                0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
            ),
            CgptAttributes {
                successful: false,
                tries: 0,
                priority: 0,
            }
        );

        assert_eq!(
            CgptAttributes::from_u64(
                0b0000_0001_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
            ),
            CgptAttributes {
                successful: true,
                tries: 0,
                priority: 0,
            }
        );

        assert_eq!(
            CgptAttributes::from_u64(
                0b0000_0000_1111_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
            ),
            CgptAttributes {
                successful: false,
                tries: 15,
                priority: 0,
            }
        );

        assert_eq!(
            CgptAttributes::from_u64(
                0b0000_0000_0000_1111_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
            ),
            CgptAttributes {
                successful: false,
                tries: 0,
                priority: 15,
            }
        );
    }
}
