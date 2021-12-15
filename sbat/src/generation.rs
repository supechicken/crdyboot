use crate::{Error, Result};
use ascii::AsciiStr;
use core::str::FromStr;

/// SBAT component generation.
///
/// This is the machine-comparable version number of a component. It is
/// always a positive integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Generation(u32);

impl Default for Generation {
    fn default() -> Generation {
        Generation(1)
    }
}

impl Generation {
    /// Create a `Generation` from a [`u32`]. An error is returned if
    /// the input is zero.
    pub fn new(val: u32) -> Result<Self> {
        if val == 0 {
            Err(Error::InvalidGeneration)
        } else {
            Ok(Self(val))
        }
    }

    /// Parse an ASCII string as a `Generation`.
    pub fn from_ascii(s: &AsciiStr) -> Result<Self> {
        let val =
            u32::from_str(s.as_str()).map_err(|_| Error::InvalidGeneration)?;
        Self::new(val)
    }
}
