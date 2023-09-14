// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VBOOT_SRC_LIBC_STRING_H_
#define VBOOT_SRC_LIBC_STRING_H_

int memcmp(const void *, const void *, size_t);
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
char *strcpy(char *dest, const char *src);  // NOLINT

#endif  // VBOOT_SRC_LIBC_STRING_H_
