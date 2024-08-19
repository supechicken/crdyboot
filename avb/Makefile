# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Source directory of the libavb checkout.
AVB ?= ../third_party/avb

# Caller should pass in a BUILD dir.
BUILD ?= $(shell pwd)/build

# static library that will be created
AVBLIB = ${BUILD}/libavb.a

.DEFAULT_GOAL .PHONY: avblib
avblib: ${AVBLIB} | ${BUILD}

# from Android.bp avb_sources
AVBLIB_SRCS = \
    libavb/avb_chain_partition_descriptor.c \
    libavb/avb_cmdline.c \
    libavb/avb_crypto.c \
    libavb/avb_descriptor.c \
    libavb/avb_footer.c \
    libavb/avb_hash_descriptor.c \
    libavb/avb_hashtree_descriptor.c \
    libavb/avb_kernel_cmdline_descriptor.c \
    libavb/avb_property_descriptor.c \
    libavb/avb_rsa.c \
    libavb/avb_slot_verify.c \
    libavb/avb_util.c \
    libavb/avb_vbmeta_image.c \
    libavb/avb_version.c

# Include sources for the sha implementation.
# By default Anrdoid.bp uses boringssl but that requires
# additional depenencies.
# TODO which one should be used here?
AVBLIB_SRCS += \
    libavb/sha/sha256_impl.c \
    libavb/sha/sha512_impl.c
# Includes for sha
INCLUDES += -I$(AVB)/libavb/sha/

# Headers necessary for building with -nostdinc
INCLUDES += -I../avb/src/libc/
CFLAGS += -nostdinc

# Most of the following were taken from Android.bp.
# TODO: Review as to what is needed or could be changed.
CFLAGS += \
    -D_FILE_OFFSET_BITS=64 \
    -D_POSIX_C_SOURCE=199309L \
    -Wa,--noexecstack \
    -Werror \
    -Wall \
    -Wextra \
    -Wformat=2 \
    -Wmissing-prototypes \
    -Wno-psabi \
    -Wno-unused-parameter \
    -Wno-format \
    -ffunction-sections \
    -g \
    -DAVB_COMPILATION

# Force AVB_USER_PRINTF_LOGS so that avb_printf is used
# instead of avb_printv.
# Only one of the avb_print* functions needs to be implemented.
CFLAGS += -DAVB_USE_PRINTF_LOGS

# TODO: Baremetal from android.bp does not include debug.
# However for dev perhaps this will be more useful early on?
CFLAGS += -DAVB_ENABLE_DEBUG

# Macro to add an explicit dependency between
# the object file and the source to create it.
# Pass in the source file as $1
define add-avblib-obj-rule =
AVBLIB_OBJS += $(addprefix ${BUILD}/, $(notdir $(patsubst %.c,%.o,$(1))))
$$(lastword $$(AVBLIB_OBJS)) : $$(AVB)/$(1) | ${BUILD}
	$$(CC) $$(CFLAGS) $$(INCLUDES) -o $$@ -c $$<
endef

# Define explicit dependencies for each source file.
$(foreach source,$(AVBLIB_SRCS),\
    $(eval $(call add-avblib-obj-rule,$(source))))

$(AVBLIB): $(AVBLIB_OBJS) | ${BUILD}
	ar qc $@ $^

${BUILD}:
	mkdir -p ${BUILD}
