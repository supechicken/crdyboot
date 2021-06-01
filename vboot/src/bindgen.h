#include <stddef.h>

// TODO: clean this list up
#include <2api.h>
#include <2nvstorage.h>
#include <2struct.h>
#include <2rsa.h>
#include <2secdata.h>
#include <load_kernel_fw.h>

const size_t VB2_KEYBLOCK_SIGNATURE_OFFSET =
    offsetof(struct vb2_keyblock, keyblock_signature);
const size_t VB2_KEYBLOCK_HASH_OFFSET =
    offsetof(struct vb2_keyblock, keyblock_hash);
const size_t VB2_KEYBLOCK_KEY_OFFSET =
    offsetof(struct vb2_keyblock, data_key);
