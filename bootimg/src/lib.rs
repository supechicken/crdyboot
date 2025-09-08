// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The public interface for bootimg structs
//! See [AOSP boot image header](https://source.android.com/docs/core/architecture/bootloader/boot-image-header) for information about the on disk format.
// Includes the [mkbootimg](https://android.googlesource.com/platform/system/tools/mkbootimg) bootimg rust module in a way that it can be used by this cargo based consumer.
#![allow(non_camel_case_types)]
// allow(deprecated) is required for the LayoutVerified for zerocopy from bootimg.
// example failure:
//  use of deprecated type alias `zerocopy::LayoutVerified`: LayoutVerified has been renamed to Ref
// TODO(b/377330887): Resolve this deprecation and include workaround with upstream changes.
#![allow(deprecated)]
#![allow(dead_code)]
#![cfg_attr(not(test), no_std)]

// Due to https://github.com/rust-lang/rust/issues/66920 this can't simply
// include the bootimg.rs directly because it has an //! inner comment which
// breaks the compile due to E0753.
// Workaround this issue by including the build.rs pre-processed source file.
// Include the public interface for bootimg structs.
include!(concat!(env!("OUT_DIR"), "/bootimg.rs"));

/// Generated bindings required to be in the module `bootimg_private` for
/// `bootimg.rs` included above.
mod bootimg_private {
    include!("../../third_party/mkbootimg/rust/bootimg_priv.rs");
}
// Subset of the generated items that are required externally.
pub use bootimg_private::{
    vendor_ramdisk_table_entry_v4, VENDOR_RAMDISK_TYPE_DLKM, VENDOR_RAMDISK_TYPE_PLATFORM,
    VENDOR_RAMDISK_TYPE_RECOVERY,
};
