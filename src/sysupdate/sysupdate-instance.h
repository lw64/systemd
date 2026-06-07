/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "sysupdate-forward.h"
#include "sysupdate-partition.h"

typedef struct TargetInstanceMetadata {
        /* Various bits of metadata for each instance, that is either derived from the filename/GPT label or
         * from metadata of the file/partition itself */
        char *version;

        union {
                struct {
                        sd_id128_t partition_uuid;
                        bool partition_uuid_set;
                        uint64_t partition_flags;          /* GPT partition flags */
                        bool partition_flags_set;
                } partition;

                struct {
                        usec_t mtime;
                        mode_t mode;
                } filesystem;
        };

        uint64_t size;                     /* uncompressed size of the file */
        uint64_t tries_done, tries_left;   /* for boot assessment counters */
        int no_auto;
        int read_only;
        int growfs;
        uint8_t sha256sum[32];             /* SHA256 sum of the download (i.e. compressed) file */
        bool sha256sum_set;
} TargetInstanceMetadata;

typedef struct SourceInstanceMetadata {
        //
} SourceInstanceMetadata;

#define TARGET_INSTANCE_METADATA_NULL           \
        {                                       \
                .mtime = USEC_INFINITY,         \
                .mode = MODE_INVALID,           \
                .size = UINT64_MAX,             \
                .tries_done = UINT64_MAX,       \
                .tries_left = UINT64_MAX,       \
                .no_auto = -1,                  \
                .read_only = -1,                \
                .growfs = -1,                   \
        }

struct TargetInstance {
        /* A pointer back to the resource this belongs to */
        TargetResource *resource;

        /* Metadata of this version */
        TargetInstanceMetadata metadata;

        /* Where we found the instance */
        char *name;  /* path = resource->path + name, if applicable */
        PartitionInfo partition_info;

        bool is_partial;
        bool is_pending;
};

struct SourceInstance {
        SourceResource *resource;

        SourceInstanceMetadata metadata;

        char *name;
};

void instance_metadata_destroy(TargetInstanceMetadata *m);

int instance_new(Resource *rr, const InstanceMetadata *f, TargetInstance **ret);
TargetInstance *instance_free(TargetInstance *i);

DEFINE_TRIVIAL_CLEANUP_FUNC(TargetInstance*, instance_free);
