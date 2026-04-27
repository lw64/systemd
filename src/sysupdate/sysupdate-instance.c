/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "log.h"
#include "path-util.h"
#include "sd-varlink.h"
#include "sysupdate-cache.h"
#include "sysupdate-instance.h"
#include "sysupdate-resource.h"
#include "sysupdate-transfer.h"
#include "sysupdate-util.h"
#include "varlink-util.h"

void instance_metadata_destroy(InstanceMetadata *m) {
        assert(m);
        free(m->version);
        safe_close(m->enhanced_blob);
}

int instance_new(
                Resource *rr,
                const char *path,
                const InstanceMetadata *f,
                Instance **ret) {

        _cleanup_(instance_freep) Instance *i = NULL;
        _cleanup_free_ char *p = NULL, *v = NULL;

        assert(rr);
        assert(path);
        assert(f);
        assert(f->version);
        assert(ret);

        p = strdup(path);
        if (!p)
                return log_oom();

        v = strdup(f->version);
        if (!v)
                return log_oom();

        i = new(Instance, 1);
        if (!i)
                return log_oom();

        *i = (Instance) {
                .resource = rr,
                .metadata = *f,
                .path = TAKE_PTR(p),
                .partition_info = PARTITION_INFO_NULL,
        };

        i->metadata.version = TAKE_PTR(v);

        *ret = TAKE_PTR(i);
        return 0;
}

Instance *instance_free(Instance *i) {
        if (!i)
                return NULL;

        instance_metadata_destroy(&i->metadata);

        free(i->path);
        freep(&i->name);
        partition_info_destroy(&i->partition_info);

        return mfree(i);
}

// mostly copied from pull_file_job_begin from pull-worker-varlink.c
static int prepare(const char *source, const char *resource, int blob, int output, uint64_t offset, uint64_t max_size, int *ret_enhanced_blob, uint64_t *ret_size) {
        int r;

        assert(source);
        assert(resource);
        assert(ret_enhanced_blob);
        assert(ret_size);

        const char *protocol;
        r = url_get_protocol(source, &protocol);
        if (r < 0)
                return log_error_errno(r, "Failed to parse protocol from URL %s: %m", source);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl;
        r = sd_varlink_connect_address(&vl, path_join(SYSTEMD_UPDATER_DIRECTORY_PATH, protocol));
        if (r < 0)
                return log_error_errno(r, "Failed to connect to '%s' updater backend: %m", protocol);

        r = sd_varlink_set_allow_fd_passing_input(vl, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable varlink fd passing for write: %m");

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable varlink fd passing for read: %m");

        int blob_fd_index = sd_varlink_push_dup_fd(vl, blob);
        if (blob_fd_index < 0)
                return log_error_errno(blob_fd_index, "Failed to push blob fd into varlink socket: %m");

        int output_fd_index = sd_varlink_push_dup_fd(vl, output);
        if (blob_fd_index < 0)
                return log_error_errno(blob_fd_index, "Failed to push output fd into varlink socket: %m");

        sd_json_variant *reply = NULL, *d = NULL;
        r = varlink_callbo_and_log(
                vl,
                "io.systemd.Updater.PrepareUpdate",
                &reply,
                SD_JSON_BUILD_PAIR_STRING("source", source),
                SD_JSON_BUILD_PAIR_STRING("resource", resource),
                SD_JSON_BUILD_PAIR_INTEGER("blobFileDescriptor", blob_fd_index),
                SD_JSON_BUILD_PAIR_OBJECT("output",
                        SD_JSON_BUILD_PAIR_UNSIGNED("locationFileDescriptor", output_fd_index),
                        SD_JSON_BUILD_PAIR_CONDITION(offset != UINT64_MAX, "offset", SD_JSON_BUILD_UNSIGNED(offset)),
                        SD_JSON_BUILD_PAIR_CONDITION(max_size != UINT64_MAX, "maxSize", SD_JSON_BUILD_UNSIGNED(max_size))));
        if (r < 0)
                return r;

        d = sd_json_variant_by_key(reply, "enhancedBlobFileDescriptor");
        if (!d)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "PrepareUpdate() response is missing 'enhancedBlobFileDescriptor' key.");

        if (!sd_json_variant_is_integer(d))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "PrepareUpdate() response 'enhancedBlobFileDescriptor' field not an integer");

        *ret_enhanced_blob = sd_varlink_take_fd(vl, sd_json_variant_integer(d));
        if (*ret_enhanced_blob < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "PrepareUpdate() response enhanced blob file descriptor is invalid.");

        d = sd_json_variant_by_key(reply, "size");
        if (!d)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "PrepareUpdate() response is missing 'size' key.");

        if (!sd_json_variant_is_unsigned(d))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "PrepareUpdate() response 'size' field not an unsigned integer");

        *ret_size = sd_json_variant_unsigned(d);

        return 0;
}

int instance_acquire_blob_and_size(Instance *i, Transfer* t, Hashmap *web_cache, bool verified) {
        int r;

        WebCacheItem *cache_item = web_cache_get_item(web_cache, i->resource->path, verified);
        if (!cache_item || cache_item->blob < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Web Cache does not provide the required blob.");

        int output_fd = -EBADF;
        uint64_t max_size = UINT64_MAX, offset = UINT64_MAX;
        if (RESOURCE_IS_FILESYSTEM(t->target.type)) {
                output_fd = open(t->temporary_partial_path, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
                if (output_fd < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Output fd could not be acquired: '%s'", t->temporary_partial_path);
        }
        if (t->target.type == RESOURCE_PARTITION) {
                max_size = t->partition_info.size;
                offset = t->partition_info.start;
                output_fd = open(t->target.path, O_RDWR|O_NOCTTY|O_CLOEXEC|(offset == UINT64_MAX ? O_TRUNC|O_CREAT : 0), 0664);
                if (output_fd < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                               "Output fd could not be acquired: '%s'", t->partition_info.device);
        }

        int enhanced_blob = -EBADF;
        uint64_t size = UINT64_MAX;
        r = prepare(i->resource->path, i->name, cache_item->blob, output_fd, offset, max_size, &enhanced_blob, &size);
        if (r < 0)
                return r;

        return 0;
}
