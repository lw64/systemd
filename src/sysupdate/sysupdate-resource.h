/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "gpt.h"
#include "sysupdate-forward.h"

typedef enum SourceType {
        SOURCE_URL_FILE,
        SOURCE_URL_TAR,
        SOURCE_URL_DIRECTORY,
        _SOURCE_TYPE_MAX,
        _SOURCE_TYPE_INVALID = -EINVAL,
} SourceType;

typedef enum TargetType {
        TARGET_PARTITION,
        TARGET_REGULAR_FILE,
        TARGET_DIRECTORY,
        TARGET_SUBVOLUME,
        TARGET_TYPE_MAX,
        _TARGET_TYPE_INVALID = -EINVAL,
} TargetType;

static inline bool RESOURCE_IS_SOURCE(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_URL_FILE,
                      RESOURCE_URL_TAR,
                      RESOURCE_TAR,
                      RESOURCE_REGULAR_FILE,
                      RESOURCE_DIRECTORY,
                      RESOURCE_SUBVOLUME);
}

static inline bool RESOURCE_IS_TARGET(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_PARTITION,
                      RESOURCE_REGULAR_FILE,
                      RESOURCE_DIRECTORY,
                      RESOURCE_SUBVOLUME);
}

/* Returns true for all resources that deal with file system objects, i.e. where we operate on top of the
 * file system layer, instead of below. */
static inline bool RESOURCE_IS_FILESYSTEM(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_TAR,
                      RESOURCE_REGULAR_FILE,
                      RESOURCE_DIRECTORY,
                      RESOURCE_SUBVOLUME);
}

static inline bool RESOURCE_IS_TAR(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_TAR,
                      RESOURCE_URL_TAR);
}

static inline bool RESOURCE_IS_URL(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_URL_TAR,
                      RESOURCE_URL_FILE);
}

typedef enum PathRelativeTo {
        /* Please make sure to follow the naming of the corresponding PartitionDesignator enum values,
         * where this makes sense, like for the following three. */
        PATH_RELATIVE_TO_ROOT,
        PATH_RELATIVE_TO_ESP,
        PATH_RELATIVE_TO_XBOOTLDR,
        PATH_RELATIVE_TO_BOOT, /* Refers to $BOOT from the BLS. No direct counterpart in PartitionDesignator */
        PATH_RELATIVE_TO_EXPLICIT,
        _PATH_RELATIVE_TO_MAX,
        _PATH_RELATIVE_TO_INVALID = -EINVAL,
} PathRelativeTo;

typedef struct SourceResource {
        SourceType type;

        /* Where to look for instances, and what to match precisely */
        char *url;
        char **patterns;

        /* All instances of this resource we found */
        SourceInstance **instances;
        size_t n_instances;
} SourceResource;

typedef struct TargetResource {
        TargetType type;

        union {
                struct {
                        bool path_auto; /* automatically find root path */
                        GptPartitionType partition_type;
                        bool partition_type_set;

                        /* how many partition slots are currently unassigned, that we can use */
                        size_t n_empty;
                } partition;

                struct {
                        PathRelativeTo path_relative_to;

                } filesystem;
        };

        /* Where to look for instances, and what to match precisely */
        char *path;
        char **patterns;

        /* All instances of this resource we found */
        TargetInstance **instances;
        size_t n_instances;
} TargetResource;

void resource_destroy(Resource *rr);

int resource_load_instances(Resource *rr, bool verify, Hashmap **web_cache);

Instance* resource_find_instance(Resource *rr, const char *version);

int resource_resolve_path(Resource *rr, const char *root, const char *relative_to_directory, const char *node);

DECLARE_STRING_TABLE_LOOKUP(resource_type, ResourceType);
DECLARE_STRING_TABLE_LOOKUP(path_relative_to, PathRelativeTo);
