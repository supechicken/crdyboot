#include "bindgen.h"

// TODO: clean up
#include "2api.h"
#include "2common.h"
#include "2secdata.h"
#include "2sysincludes.h"
#include "vboot_api.h"

void crdyboot_set_kernel_key(struct vb2_context *ctx,
                             const struct vb2_packed_key *packed_key,
                             const struct vb2_workbuf *wb) {
  struct vb2_shared_data *sd = vb2_get_sd(ctx);
  sd->kernel_key_offset = vb2_offset_of(sd, packed_key);
  sd->kernel_key_size = packed_key->key_offset + packed_key->key_size;

  // TODO
  vb2_set_workbuf_used(ctx, vb2_offset_of(sd, wb->buf));
}
