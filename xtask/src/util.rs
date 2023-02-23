// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::{Deref, DerefMut};
use std::process::Child;

/// Wrapper around a child process that automatically kills and waits on
/// drop.
pub struct ScopedChild(Child);

impl ScopedChild {
    pub fn new(child: Child) -> Self {
        Self(child)
    }
}

impl Deref for ScopedChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.0
    }
}

impl DerefMut for ScopedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for ScopedChild {
    fn drop(&mut self) {
        // Ignore errors during drop.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
