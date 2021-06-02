#include <stddef.h>

#include <2struct.h>

const size_t VB2_KEYBLOCK_SIGNATURE_OFFSET =
    offsetof(struct vb2_keyblock, keyblock_signature);
const size_t VB2_KEYBLOCK_HASH_OFFSET =
    offsetof(struct vb2_keyblock, keyblock_hash);
const size_t VB2_KEYBLOCK_KEY_OFFSET =
    offsetof(struct vb2_keyblock, data_key);
