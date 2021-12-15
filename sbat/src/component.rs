use crate::Generation;
use ascii::AsciiStr;

/// SBAT component. This is the machine-readable portion of SBAT that is
/// actually used for revocation (other fields are human-readable and
/// not used for comparisons).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Component<'a> {
    /// Component name.
    pub name: &'a AsciiStr,

    /// Component generation.
    pub generation: Generation,
}

impl<'a> Component<'a> {
    /// Create a `Component`.
    pub fn new(name: &AsciiStr, generation: Generation) -> Component {
        Component { name, generation }
    }
}
