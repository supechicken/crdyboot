// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <2common.h>
#include <2nvstorage.h>
#include <2secdata.h>

#include "bindgen.h"

vb2_error_t vb2api_inject_kernel_subkey(
			   struct vb2_context *ctx,
			   const uint8_t *kernel_packed_key_data,
			   uint32_t kernel_packed_key_data_size) {
	struct vb2_shared_data *sd;
	struct vb2_workbuf wb;
	struct vb2_packed_key *kernel_packed_key;
	uint32_t kernel_packed_key_size;
	void *dst_packed_key;

	sd = vb2_get_sd(ctx);
	vb2_workbuf_from_ctx(ctx, &wb);

	/* Fully initialize the context and shared data. */
	sd->flags = 0;
	/* Not in recovery. */
	sd->recovery_reason = 0;
	/* FW not used. */
	sd->last_fw_slot = 0;
	sd->last_fw_result = 0;
	sd->fw_slot = 0;
	sd->fw_version = 0;
	sd->fw_version_secdata = 0;
	/* Clear status field. */
	sd->status = 0;
	/* Invalid offset indicating GBB data is not available. */
	sd->gbb_offset = 0;
	sd->kernel_version = 0;
	sd->kernel_version_secdata = 0;
	/* Clear all temporary variables. */
	sd->vblock_preamble_offset = 0;
	sd->data_key_offset = 0;
	sd->data_key_size = 0;
	sd->preamble_offset = 0;
	sd->preamble_size = 0;
	sd->hash_offset = 0;
	sd->hash_size = 0;
	sd->hash_tag = 0;
	sd->hash_remaining_size = 0;
	/* The kernel key will be filled in properly if this function
	 * succeeds. */
	sd->kernel_key_offset = 0;
	sd->kernel_key_size = 0;
	ctx->flags = 0;
	vb2_nv_init(ctx);
	vb2api_secdata_kernel_create(ctx);
	VB2_TRY(vb2_secdata_kernel_init(ctx));
	/* Set the boot mode and validate that the mode is normal. */
	vb2_set_boot_mode(ctx);
	if (ctx->boot_mode != VB2_BOOT_MODE_NORMAL)
		VB2_DIE("Unexpected boot mode: %d\n", ctx->boot_mode);

	/* Make sure passed buffer is big enough for the packed key. */
	kernel_packed_key = (struct vb2_packed_key *)kernel_packed_key_data;
	VB2_TRY(vb2_verify_packed_key_inside(kernel_packed_key_data,
				      kernel_packed_key_data_size,
				      kernel_packed_key));

	/* Allocate space in the workbuf in which to copy the key. */
	kernel_packed_key_size =
		kernel_packed_key->key_offset + kernel_packed_key->key_size;
	dst_packed_key = vb2_workbuf_alloc(&wb, kernel_packed_key_size);
	if (!dst_packed_key)
		return VB2_ERROR_WORKBUF_SMALL;

	/* Copy the packed key data into the workbuf. */
	memcpy(dst_packed_key, kernel_packed_key_data, kernel_packed_key_size);

	/* Set the location of the kernel key data in the context. */
	sd->kernel_key_offset = vb2_offset_of(sd, dst_packed_key);
	sd->kernel_key_size = kernel_packed_key_size;

	vb2_set_workbuf_used(ctx, sd->kernel_key_offset +
				      kernel_packed_key_size);

	return VB2_SUCCESS;
}
