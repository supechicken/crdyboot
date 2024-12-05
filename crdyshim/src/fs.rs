// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use uefi::data_types::chars::NUL_16;
use uefi::{CStr16, CString16};

/// Create a copy of `file_name` with the final extension (i.e. the
/// string after the final period character) replaced with
/// `new_extension`.
///
/// The string in `new_extension` should not start with a period
/// character.
///
/// Returns `None` if `file_name` does not contain period character.
#[must_use]
pub fn replace_final_extension(file_name: &CStr16, new_extension: &CStr16) -> Option<CString16> {
    // Convert the file name to vec. Note that this does not include the
    // trailing null char.
    let mut chars = file_name.as_slice().to_vec();

    // Find the last '.' and remove everything after it.
    if let Some(rev_dot_index) = chars.iter().rev().position(|c| *c == '.') {
        let dot_index = chars.len().checked_sub(rev_dot_index)?;
        chars.truncate(dot_index);
    } else {
        return None;
    }

    // Add the new extension.
    chars.extend(new_extension.as_slice());

    // Append trailing null.
    chars.push(NUL_16);

    let output = CStr16::from_char16_with_nul(&chars).ok()?;
    Some(CString16::from(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uefi::cstr16;

    #[test]
    fn test_replace_final_extension() {
        assert_eq!(
            replace_final_extension(cstr16!("crdybootx64.efi"), cstr16!("sig")),
            Some(cstr16!("crdybootx64.sig").into())
        );

        assert_eq!(
            replace_final_extension(cstr16!("crdybootx64.longextension"), cstr16!("sig")),
            Some(cstr16!("crdybootx64.sig").into())
        );

        assert_eq!(
            replace_final_extension(cstr16!("crdybootx64"), cstr16!("sig")),
            None
        );
    }
}
