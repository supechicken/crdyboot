// TODO: cleanup
#include <2common.h>
#include <2misc.h>
#include <2nvstorage.h>
#include <2secdata.h>
#include <2struct.h>
#include <futility/kernel_blob.h>
#include <vboot_kernel.h>

void crdyboot_set_kernel_key(struct vb2_context *ctx,
                             const struct vb2_packed_key *packed_key,
                             const struct vb2_workbuf *wb);
