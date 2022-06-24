// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <2common.h>

#include "bindgen.h"

vb2_error_t vb2api_init_ctx_for_kernel_verification_only(
    struct vb2_context *ctx, const uint8_t *kernel_packed_key_data,
    uint32_t kernel_packed_key_data_size) {
  /* TODO: add new VB2 error codes for the errors returned by this
   * function. */

  struct vb2_shared_data *sd;
  struct vb2_workbuf wb;
  struct vb2_packed_key *kernel_packed_key;
  uint32_t kernel_packed_key_size;
  void *dst_packed_key;

  sd = vb2_get_sd(ctx);
  vb2_workbuf_from_ctx(ctx, &wb);

  /* Validate that the key data is at least as big as the header struct. */
  if (kernel_packed_key_data_size < sizeof(struct vb2_packed_key)) {
    return VB2_ERROR_UNPACK_KEY_SIZE;
  }

  /* Get the total size of the packed key data by inspecting the packed
   * key header. Validate that the input key data is at least as large
   * as the total size of the data. */
  kernel_packed_key = (struct vb2_packed_key *)kernel_packed_key_data;
  kernel_packed_key_size =
      kernel_packed_key->key_offset + kernel_packed_key->key_size;
  if (kernel_packed_key_size > kernel_packed_key_data_size) {
    return VB2_ERROR_UNPACK_KEY_SIZE;
  }

  /* Allocate space in the workbuf to copy the packed key into. */
  dst_packed_key = vb2_workbuf_alloc(&wb, kernel_packed_key_size);
  if (!dst_packed_key) {
    return VB2_ERROR_WORKBUF_SMALL;
  }

  /* Copy the packed key data into the workbuf. */
  memcpy(dst_packed_key, kernel_packed_key_data, kernel_packed_key_size);

  /* Set the location of the kernel key data in the context. */
  sd->kernel_key_offset = vb2_offset_of(sd, dst_packed_key);
  sd->kernel_key_size = kernel_packed_key_size;

  vb2_set_workbuf_used(ctx, sd->kernel_key_offset + kernel_packed_key_size);

  return VB2_SUCCESS;
}
