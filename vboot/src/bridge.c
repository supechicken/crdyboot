// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bindgen.h"

// Update the shared data struct to point at the packed kernel key. Also
// take care of calling vb2_set_workbuf_used.
//
// This code is written in C instead of Rust since it calls macros and
// inline functions.
void crdyboot_set_kernel_key(struct vb2_context *ctx,
                             const struct vb2_packed_key *packed_key,
                             const struct vb2_workbuf *wb) {
  struct vb2_shared_data *sd = vb2_get_sd(ctx);
  sd->kernel_key_offset = vb2_offset_of(sd, packed_key);
  sd->kernel_key_size = packed_key->key_offset + packed_key->key_size;
  vb2_set_workbuf_used(ctx, vb2_offset_of(sd, wb->buf));
}
