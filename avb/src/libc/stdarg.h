// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AVB_SRC_LIBC_STDARG_H_
#define AVB_SRC_LIBC_STDARG_H_

// https://clang.llvm.org/docs/LanguageExt
typedef __builtin_va_list va_list;
#define va_arg(a, b) __builtin_va_arg(a, b)
#define va_end(a) __builtin_va_end(a)
#define va_start(a, b) __builtin_va_start(a, b)

#endif  // AVB_SRC_LIBC_STDARG_H_
