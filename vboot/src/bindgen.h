// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vb2_api.h>

#include <futility/kernel_blob.h>
#include <vboot_api.h>

/**
 * TODO: proposed new entry point to be added to vboot_reference.
 *
 * This takes a context initialized with `vb2api_init` and a packed
 * kernel verification key. The packed key starts with a `struct
 * vb2_packed_key` header, followed by the actual key data.
 */
vb2_error_t vb2api_inject_kernel_subkey(
    struct vb2_context *ctx, const uint8_t *kernel_packed_key_data,
    uint32_t kernel_packed_key_data_size);
