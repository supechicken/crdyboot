use core::convert::TryInto;
pub use goblin::error::Error as PeError;
use goblin::pe::PE;
use scroll::Pread;

/// Valid PE executable.
pub struct PeExecutable<'a> {
    data: &'a [u8],
    parsed: PE<'a>,
}

impl<'a> PeExecutable<'a> {
    /// Parse `data` as a PE executable.
    pub fn parse(data: &[u8]) -> Result<PeExecutable, PeError> {
        Ok(PeExecutable {
            data,
            parsed: PE::parse(data)?,
        })
    }

    /// Get the primary entry point (as an offset) from the PE header.
    pub fn entry_point(&self) -> usize {
        self.parsed.entry
    }

    /// Get an IA32 entry point, if available.
    pub fn get_ia32_compat_entry_point(&self) -> Option<usize> {
        // Look for a section named ".compat".
        let section = self
            .parsed
            .sections
            .iter()
            .find(|s| &s.name == b".compat\0")?;
        let data_start: usize = section.pointer_to_raw_data.try_into().ok()?;
        let data_size: usize = section.size_of_raw_data.try_into().ok()?;
        let section_data = self.data.get(data_start..data_start + data_size)?;

        const ELEM_TYPE_END_OF_LIST: u8 = 0;
        const ELEM_TYPE_V1: u8 = 1;

        let mut outer_offset: usize = 0;
        loop {
            let mut offset = outer_offset;

            // Get the elem_type type.
            let elem_type: u8 = section_data.gread(&mut offset).ok()?;
            if elem_type == ELEM_TYPE_END_OF_LIST {
                break;
            }

            // Get the element size in bytes.
            let elem_size: u8 = section_data.gread(&mut offset).ok()?;
            let elem_size: usize = elem_size.into();

            // Known element type.
            if elem_type == ELEM_TYPE_V1 {
                // Read the machine type and check if it matches IA32.
                let machine_type: u16 = section_data.gread(&mut offset).ok()?;
                if machine_type == goblin::pe::header::COFF_MACHINE_X86 {
                    // Read the entry point offset and return it.
                    let entry_point: u32 =
                        section_data.gread(&mut offset).ok()?;
                    return entry_point.try_into().ok();
                }
            }

            // Continue to next element.
            outer_offset += elem_size;
        }

        // No matching compat entry found.
        None
    }
}
