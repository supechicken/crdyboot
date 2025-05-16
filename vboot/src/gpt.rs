// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::convert::TryInto;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// a struct containing available attributes for a GPT entry
/// see: <https://www.chromium.org/chromium-os/developer-library/reference/device/disk-format/>
pub struct CgptAttributes {
    /// underlying attributes value.
    data: u64,
}

impl CgptAttributes {
    /// `CgptAttributes` from a u64.
    ///
    ///  bits | meaning
    /// ==================
    /// 63-57 | reserved, unmodified by any methods.
    ///    56 | successful
    /// 55-52 | tries
    /// 51-48 | priority
    /// 47-00 | reserved, unmodified by any methods.
    ///
    /// Based on:
    /// `vboot_reference/firmware/lib/cgptlib/include/cgptlib_internal`.*
    /// This struct manages the gpt attributes for vboot and preserves the rest of the data as-is.
    const SUCCESSFUL_OFFSET: u64 = 56;
    const MAX_SUCCESSFUL: u8 = 0b1;
    const SUCCESSFUL_MASK: u64 = (Self::MAX_SUCCESSFUL as u64) << Self::SUCCESSFUL_OFFSET;
    const TRIES_OFFSET: u64 = 52;
    const MAX_TRIES: u8 = 0b1111;
    const TRIES_MASK: u64 = (Self::MAX_TRIES as u64) << Self::TRIES_OFFSET;
    const PRIORITY_OFFSET: u64 = 48;
    const MAX_PRIORITY: u8 = 0b1111;
    const PRIORITY_MASK: u64 = (Self::MAX_PRIORITY as u64) << Self::PRIORITY_OFFSET;
    const ATTRIBUTES_MASK: u64 = Self::SUCCESSFUL_MASK | Self::TRIES_MASK | Self::PRIORITY_MASK;

    /// Creates a new `CgptAttributes` from `u64`, which is expected to be the GPT attributes for a
    /// partition.
    #[must_use]
    pub fn from_u64(num: u64) -> CgptAttributes {
        CgptAttributes { data: num }
    }

    /// Returns the `data` field (u64), which can be used as the GPT attributes for a partition.
    #[must_use]
    pub fn to_u64(&self) -> u64 {
        self.data
    }
    /// Returns the value of the `successful` field (bool).
    /// true if the system has successfully booted from this partition, false otherwise.
    #[must_use]
    pub fn successful(&self) -> bool {
        (self.data & Self::SUCCESSFUL_MASK) != 0
    }

    /// Returns the value of the `tries` field (u8).
    /// if `!successful`, is the number of times system can attempt to boot this partition.
    /// 15 = highest, 0 = no attempts remaining.
    /// The value is extracted from its 4-bit field.
    /// # Panics
    ///
    /// Will never panic because values are guaranteed to fit in `u8`
    #[must_use]
    pub fn tries(&self) -> u8 {
        ((self.data & Self::TRIES_MASK) >> Self::TRIES_OFFSET)
            .try_into()
            .unwrap()
    }

    /// Returns the value of the `priority` field (u8).
    /// 15 = highest, 1 = lowest, 0 = not bootable.
    /// The value is extracted from its 4-bit field.
    /// # Panics
    ///
    /// Will never panic because values are guaranteed to fit in `u8`
    #[must_use]
    pub fn priority(&self) -> u8 {
        ((self.data & Self::PRIORITY_MASK) >> Self::PRIORITY_OFFSET)
            .try_into()
            .unwrap()
    }

    /// Sets the value of the `successful` field (bool).
    pub fn set_successful(&mut self, successful: bool) {
        if successful {
            self.data |= Self::SUCCESSFUL_MASK;
        } else {
            self.data &= !Self::SUCCESSFUL_MASK;
        }
    }

    /// Sets the value of the `tries` field (u8).
    /// The input value will be clamped to `MAX_TRIES` (0-15).
    pub fn set_tries(&mut self, tries: u8) {
        self.data &= !Self::TRIES_MASK;
        self.data |= u64::from(tries.min(Self::MAX_TRIES)) << Self::TRIES_OFFSET;
    }

    /// Sets the value of the `priority` field (u8).
    /// The input value will be clamped to `MAX_PRIORITY` (0-15).
    pub fn set_priority(&mut self, priority: u8) {
        self.data &= !Self::PRIORITY_MASK;
        self.data |= u64::from(priority.min(Self::MAX_PRIORITY)) << Self::PRIORITY_OFFSET;
    }

    /// Sets the value of all of the vboot attributes to 0, marking the partition as unbootable.
    pub fn make_unbootable(&mut self) {
        self.data &= !Self::ATTRIBUTES_MASK;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u64() {
        let attributes = CgptAttributes::from_u64(
            0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
        );
        assert_eq!(
            attributes.to_u64(),
            0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
        );

        let attributes = CgptAttributes::from_u64(
            0b0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101,
        );
        assert_eq!(
            attributes.to_u64(),
            0b0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101
        );
    }

    #[test]
    fn test_get_values() {
        let attributes = CgptAttributes::from_u64(
            0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
        );

        assert_eq!(false, attributes.successful());
        assert_eq!(0, attributes.tries());
        assert_eq!(0, attributes.priority());

        let attributes = CgptAttributes::from_u64(
            0b0000_0001_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
        );

        assert_eq!(true, attributes.successful());
        assert_eq!(0, attributes.tries());
        assert_eq!(0, attributes.priority());

        let attributes = CgptAttributes::from_u64(
            0b0000_0000_1111_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
        );

        assert_eq!(false, attributes.successful());
        assert_eq!(15, attributes.tries());
        assert_eq!(0, attributes.priority());

        let attributes = CgptAttributes::from_u64(
            0b0000_0000_0000_1111_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
        );

        assert_eq!(false, attributes.successful());
        assert_eq!(0, attributes.tries());
        assert_eq!(15, attributes.priority());

        let attributes = CgptAttributes::from_u64(
            0b0101_0001_1111_1111_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101,
        );

        assert_eq!(true, attributes.successful());
        assert_eq!(15, attributes.tries());
        assert_eq!(15, attributes.priority());
    }

    #[test]
    fn test_set_values() {
        let mut attributes = CgptAttributes::from_u64(
            0b0000_0001_1111_1111_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
        );
        attributes.set_successful(false);
        attributes.set_tries(0);
        attributes.set_priority(0);
        assert_eq!(
            attributes.to_u64(),
            0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
        );

        let mut attributes = CgptAttributes::from_u64(
            0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
        );
        attributes.set_successful(true);
        attributes.set_tries(15);
        attributes.set_priority(15);
        assert_eq!(
            attributes.to_u64(),
            0b0000_0001_1111_1111_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
        );

        let mut attributes = CgptAttributes::from_u64(
            0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
        );
        attributes.set_successful(true);
        attributes.set_tries(5);
        attributes.set_priority(10);
        assert_eq!(
            attributes.to_u64(),
            0b0000_0001_0101_1010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
        );

        let mut attributes = CgptAttributes::from_u64(
            0b0101_0101_1111_1111_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101,
        );
        attributes.set_successful(false);
        attributes.set_tries(0);
        attributes.set_priority(0);
        assert_eq!(
            attributes.to_u64(),
            0b0101_0100_0000_0000_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101
        );

        let mut attributes = CgptAttributes::from_u64(
            0b0101_0101_1111_1111_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101,
        );
        attributes.make_unbootable();
        assert_eq!(
            attributes.to_u64(),
            0b0101_0100_0000_0000_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101
        );
    }
}
