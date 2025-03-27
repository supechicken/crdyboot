// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VBOOT_SRC_LIBC_ENDIAN_H_
#define VBOOT_SRC_LIBC_ENDIAN_H_

#if __BYTE_ORDER__ == __LITTLE_ENDIAN

#define le32toh(x) (x)
#define le16toh(x) (x)

#else

#define le32toh(x) __builtin_bswap32 (x)
#define le16toh(x) __builtin_bswap16 (x)

#endif

#endif  // VBOOT_SRC_LIBC_ENDIAN_H_
