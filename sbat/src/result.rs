use ascii::AsciiChar;

/// SBAT errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// CSV field is not ASCII. According to the SBAT spec, all fields
    /// must be ASCII.
    InvalidAscii,

    /// CSV field contains a special character. The characters allowed
    /// are alphabetic, numeric, and [`ALLOWED_SPECIAL_CHARS`]. This is
    /// to keep parsing simple. In particular, double-quote and escape
    /// characters are not allowed, so a field cannot contain a comma.
    ///
    /// [`ALLOWED_SPECIAL_CHARS`]: crate::ALLOWED_SPECIAL_CHARS
    SpecialChar(AsciiChar),

    /// CSV field is not a valid [`Generation`] number.
    ///
    /// [`Generation`]: crate::Generation
    InvalidGeneration,

    /// CSV has more records than allowed.
    TooManyRecords,

    /// CSV record has two few fields.
    TooFewFields,
}

/// SBAT [`Result`] type alias.
///
/// [`Result`]: `core::result::Result`
pub type Result<T> = core::result::Result<T, Error>;
