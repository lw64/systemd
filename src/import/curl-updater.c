/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>

#include "curl-util.h"
#include "fd-util.h"
#include "json-util.h"
#include "io-util.h"
#include "import-common.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "pull-job.h"
#include "sd-event.h"
#include "set.h"
#include "strv.h"
#include "signal-util.h"
#include "varlink-io.systemd.Updater.h"
#include "varlink-util.h"
#include "web-util.h"

typedef struct LocalInstance {
        unsigned fd_index;
        int fd;
        uint64_t offset;
        uint64_t size_max;
}

static LocalInstance* local_instance_free(LocalInstance *i) {
        if (!i)
                return NULL;

        safe_close(i->fd);

        return mfree(i);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        local_instance_hash_ops,
        void,
        trivial_hash_func,
        trivial_compare_func,
        LocalInstance,
        local_instance_free);

static int dispatch_local_instance(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field local_instance_dispatch_table[] = {
                { "locationFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,   offsetof(LocalInstance, fd_index), SD_JSON_MANDATORY },
                { "offset",                 SD_JSON_VARIANT_NUMBER,        sd_json_dispatch_uint64, offsetof(LocalInstance, offset),   0 },
                { "maxSize",                SD_JSON_VARIANT_NUMBER,        sd_json_dispatch_uint64, offsetof(LocalInstance, size_max), 0 },
                {},
        }

        LocalInstance **ret = ASSERT_PTR(userdata);
        _cleanup_(local_instance_freep) LocalInstance *i = NULL;
        int r;

        i = new0(LocalInstance, 1);
        if (!i)
                return log_oom();

        r = sd_json_dispatch(variant, local_instance_dispatch_table, flags, i);
        if (r < 0)
                return r;

        if (i->offset != UINT64_MAX && !FILE_SIZE_VALID(i->offset))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Dispatched offset is not valid");

        if (i->size_max != UINT64_MAX && (!FILE_SIZE_VALID(i->size_max) || (i->size_max % 1024) != 0))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Dispatched maxSize is not valid");

        /* Make sure offset+size is still in the valid range if both set */
        if (i->offset != UINT64_MAX && i->size_max != UINT64_MAX &&
            ((i->size_max > (UINT64_MAX - i->offset)) ||
             !FILE_SIZE_VALID(i->offset + i->size_max)))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Dispatched maxSize and offset are invalid together");

        *ret = TAKE_PTR(i);

        return 0;
}

static int dispatch_local_instances_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Set **ret = ASSERT_PTR(userdata);
        _cleanup_set_free_ Set *local_instances = NULL;
        sd_json_variant *v;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                _cleanup_(local_instance_freep) LocalInstance *i = NULL;

                r = dispatch_local_instance(name, v, flags, &i);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid LocalInstance.");

                r = set_ensure_consume(&local_instances, &local_instance_hash_ops, TAKE_PTR(i));
                if (r < 0)
                        return r;
        }

        set_free_and_replace(*ret, local_instances);

        return 0;
}

// copied from sysupdate-resource.c
static int download_manifest(
                const char *url,
                bool verify_signature,
                char **ret_buffer,
                size_t *ret_size) {

        _cleanup_free_ char *buffer = NULL, *suffixed_url = NULL;
        _cleanup_close_ int manifest = -EBADF;
        size_t size = 0;
        pid_t pid;
        int r;

        assert(url);
        assert(ret_buffer);
        assert(ret_size);

        /* Download a SHA256SUMS file as manifest */

        r = import_url_append_component(url, "SHA256SUMS", &suffixed_url);
        if (r < 0)
                return log_error_errno(r, "Failed to append SHA256SUMS to URL: %m");

        manifest = memfd_new ("manifest");
        if (manifest < 0)
                return log_error_errno(r, "Failed to create memfd for manifest: %m");
        char *manifest_path = FORMAT_PROC_PID_FD_PATH(0, manifest);

        log_info("%s Acquiring manifest file %s%s", glyph(GLYPH_DOWNLOAD),
                 suffixed_url, glyph(GLYPH_ELLIPSIS));

        r = safe_fork_full("(sd-pull)",
                           (int[]) { -EBADF, -EBADF, STDERR_FILENO },
                           NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG,
                           &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                const char *cmdline[] = {
                        SYSTEMD_PULL_PATH,
                        "raw",
                        "--direct",                        /* just download the specified URL, don't download anything else */
                        "--verify", verify_signature ? "signature" : "no", /* verify the manifest file */
                        "--sync=no", /* syncing fails when writing to the memfd */
                        suffixed_url,
                        manifest_path,
                        NULL
                };

                r = invoke_callout_binary(SYSTEMD_PULL_PATH, (char *const*) cmdline);
                log_error_errno(r, "Failed to execute %s tool: %m", SYSTEMD_PULL_PATH);
                _exit(EXIT_FAILURE);
        };

        /* We'll first load the entire manifest into memory before parsing it. That's because the
         * systemd-pull tool can validate the download only after its completion, but still pass the data to
         * us as it runs. We thus need to check the return value of the process *before* parsing, to be
         * reasonably safe. */

        r = wait_for_terminate_and_check("(sd-pull)", pid, WAIT_LOG);
        if (r < 0)
                return r;
        if (r != 0)
                return -EPROTO;

        r = read_full_file(manifest_path, &buffer, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read manifest file: %m");

        *ret_buffer = TAKE_PTR(buffer);
        *ret_size = size;

        return 0;
}

// a lot copied from resource_load_from_web from sysupdate-resource.c
static int parse_manifest_instances(
                char ***ret,
                char *manifest,
                size_t manifest_size) {

        size_t left = 0;
        const char *p;
        size_t line_nr = 1;
        int r;

        assert(ret);
        assert(manifest);

        if (memchr(manifest, 0, manifest_size))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Manifest file has embedded NUL byte, refusing.");
        if (!utf8_is_valid_n(manifest, manifest_size))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Manifest file is not valid UTF-8, refusing.");

        p = manifest;
        left = manifest_size;

        _cleanup_strv_free_ char **available_instances = NULL;

        while (left > 0) {
                _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
                _cleanup_free_ char *fn = NULL;
                _cleanup_free_ void *h = NULL;
                Instance *instance;
                const char *e;
                size_t hlen;

                /* 64 character hash + separator + filename + newline */
                if (left < 67)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Corrupt manifest at line %zu, refusing.", line_nr);

                if (p[0] == '\\')
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "File names with escapes not supported in manifest at line %zu, refusing.", line_nr);

                r = unhexmem_full(p, 64, /* secure = */ false, &h, &hlen);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse digest at manifest line %zu, refusing.", line_nr);

                p += 64, left -= 64;

                if (*p != ' ')
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing space separator at manifest line %zu, refusing.", line_nr);
                p++, left--;

                if (!IN_SET(*p, '*', ' '))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing binary/text input marker at manifest line %zu, refusing.", line_nr);
                p++, left--;

                e = memchr(p, '\n', left);
                if (!e)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Truncated manifest file at line %zu, refusing.", line_nr);
                if (e == p)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty filename specified at manifest line %zu, refusing.", line_nr);

                fn = strndup(p, e - p);
                if (!fn)
                        return log_oom();

                if (!filename_is_valid(fn))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid filename specified at manifest line %zu, refusing.", line_nr);
                if (string_has_cc(fn, NULL))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Filename contains control characters at manifest line %zu, refusing.", line_nr);

                r = strv_consume(&available_instances, fn);
                if (r < 0)
                        return log_oom();

                left -= (e - p) + 1;
                p = e + 1;

                line_nr++;
        }

        *ret = TAKE_PTR(available_instances);
        return 0;
}

typedef struct ListInstancesParameters {
        const char *source;
        sd_event *event;
} ListInstancesParameters;

static void list_instances_parameters_done(ListInstancesParameters *p) {
        sd_event_unref(p->event);
}

static int vl_method_list_instances(sd_varlink *link, sd_json_variant *json_parameters, sd_varlink_method_flags_t flags, void *userdata) {

        // parse only the parameters used by the curl updater

        static const sd_json_dispatch_field dispatch_table[] = {
                { "source", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(ListInstancesParameters, source), SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(list_instances_parameters_done) ListInstancesParameters p;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, json_parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!http_url_is_valid(p.source) && !file_url_is_valid(p.source))
                return sd_varlink_error_invalid_parameter(link, "source is not a valid url");

        _cleanup_free_ char *manifest;
        size_t manifest_size;
        r = download_manifest(p.source, /* verify= */ false, &manifest, &manifest_size);
        if (r < 0)
                return sd_varlink_error_errno(link, r);

        _cleanup_strv_free_ char **instances;
        r = parse_manifest_instances(&instances, manifest, manifest_size);

        return sd_varlink_replybo(link,
                                  SD_JSON_BUILD_PAIR_STRV("instances", instances),
                                  SD_JSON_BUILD_PAIR_STRING("blob", manifest));
}

// mostly copied from pull_file_job_begin from pull-worker-varlink.c
int pull_file_job_begin(const char *url, const char *resource, const char *expected_checksum, LocalInstance *output, char **ret_checksum) {
        int r;

        assert(url);
        assert(resource);
        assert(output);
        assert(ret_checksum);

        const char *protocol;
        r = url_get_protocol(url, &protocol);
        if (r < 0)
                return log_error_errno(r, "Failed to parse protocol from URL %s: %m", url);

        _cleanup_free_ char *suffixed_url;
        r = import_url_append_component(url, resource, &suffixed_url);
        if (r < 0)
                return log_error_errno(r, "Failed to append resource '%s' to URL: %m", resource);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl;
        r = sd_varlink_connect_address(vl, path_join(SYSTEMD_PULL_WORKER_DIRECTORY_PATH, protocol));
        if (r < 0)
                return log_error_errno(r, "Failed to connect to systemd-pull '%s' backend: %m", protocol);

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable varlink fd passing for write: %m");

        int destination_fd_index = sd_varlink_push_dup_fd(vl, output->fd);
        if (destination_fd_index < 0)
                return log_error_errno(destination_fd_index, "Failed to push destination fd into varlink socket: %m");

        const char *error_id = NULL;
        sd_json_variant *reply = NULL, *d = NULL;
        r = varlink_callbo_and_log(
                vl,
                &reply,
                &error_id,
                "io.systemd.PullJob.PullFile",
                SD_JSON_BUILD_PAIR_CONDITION(expected_checksum, "expectedChecksum", SD_JSON_BUILD_STRING (expected_checksum)),
                SD_JSON_BUILD_PAIR_STRING("source", suffixed_url),
                SD_JSON_BUILD_PAIR_UNSIGNED("destinationFileDescriptor", destination_fd_index),
                SD_JSON_BUILD_PAIR_CONDITION(FILE_SIZE_VALID(output->offset), "offset", SD_JSON_BUILD_UNSIGNED(output->offset)),
                SD_JSON_BUILD_PAIR_CONDITION(FILE_SIZE_VALID(output->size_max), "maxSize", SD_JSON_BUILD_UNSIGNED(output->size_max)));
        if (r < 0)
                return r;

        d = sd_json_variant_by_key(reply, "checksum");
        if (!d)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "PullFile() response is missing 'checksum' key.");

        if (!sd_json_variant_is_string(d))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "PullFile() response 'checksum' field not a string");

        *ret_checksum = strdup(sd_json_variant_string(d));
        if (!*ret_checksum)
                return log_oom();

        return 0;
}

// mostly copied from pull_file_job_begin from pull-worker-varlink.c
int pull_file_job_begin_prepare(const char *url, const char *resource, int *ret_size) {
        int r;

        assert(url);
        assert(resource);
        assert(ret_size);

        const char *protocol;
        r = url_get_protocol(url, &protocol);
        if (r < 0)
                return log_error_errno(r, "Failed to parse protocol from URL %s: %m", url);

        _cleanup_free_ char *suffixed_url;
        r = import_url_append_component(url, resource, &suffixed_url);
        if (r < 0)
                return log_error_errno(r, "Failed to append resource '%s' to URL: %m", resource);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl;
        r = sd_varlink_connect_address(vl, path_join(SYSTEMD_PULL_WORKER_DIRECTORY_PATH, protocol));
        if (r < 0)
                return log_error_errno(r, "Failed to connect to systemd-pull '%s' backend: %m", protocol);

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable varlink fd passing for write: %m");

        int destination_fd_index = sd_varlink_push_dup_fd(vl, output->fd);
        if (destination_fd_index < 0)
                return log_error_errno(destination_fd_index, "Failed to push destination fd into varlink socket: %m");

        const char *error_id = NULL;
        sd_json_variant *reply = NULL, *d = NULL;
        r = varlink_callbo_and_log(
                vl,
                &reply,
                &error_id,
                "io.systemd.PullJob.PreparePull",
                SD_JSON_BUILD_PAIR_STRING("source", suffixed_url));
        if (r < 0)
                return r;

        d = sd_json_variant_by_key(reply, "size");
        if (!d)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "PullFile() response is missing 'size' key.");

        if (!sd_json_variant_is_int(d))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "PullFile() response 'size' field not an integer");

        *ret_size = sd_json_variant_int(d);
        return 0;
}

typedef struct PrepareUpdateParameters {
        const char *source;
        const char *resource;
        const char *blob;
        LocalInstance *output;
        sd_event *event;
} PrepareUpdateParameters;

static void prepare_update_parameters_done(PrepareUpdateParameters *p) {
        local_instance_freep(&p->output);
        sd_event_unref(p->event);
}

static int vl_method_prepare_update(sd_varlink *link, sd_json_variant *json_parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "source",   SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(PrepareUpdateParameters, source),   SD_JSON_MANDATORY },
                { "resource", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(PrepareUpdateParameters, resource), SD_JSON_MANDATORY },
                { "blob",     SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(PrepareUpdateParameters, blob),     SD_JSON_MANDATORY },
                { "output",   SD_JSON_VARIANT_OBJECT, json_dispatch_local_instance,  offsetof(PrepareUpdateParameters, output),   SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(method_prepare_update_parameters_done) PrepareUpdateParameters p;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, json_parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!http_url_is_valid(p.source) && !file_url_is_valid(p.source))
                return sd_varlink_error_invalid_parameter(link, "source is not a valid url");

        int size = 0;
        r = pull_file_job_begin_prepare(p.source, p.resource, &size);
        if (r < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Downloading http header to get the size failed");

        if (!FILE_SIZE_VALID(size)) /* is this the right check here? */
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Size of file is invalid");

        // don't do anything with the blob
        return sd_varlink_replybo(link,
                                  SD_JSON_BUILD_PAIR_INTEGER("size", size),
                                  SD_JSON_BUILD_PAIR_STRING("enhancedBlob", p.blob));
}

typedef struct UpdateParameters {
        const char *source;
        const char *resource;
        const char *enhanced_blob;
        LocalInstance *output;
        sd_event *event;
} UpdateParameters;

static void update_parameters_done(UpdateParameters *p) {
        local_instance_donep (&p->output);
        sd_event_unref(p->event);
}

static int vl_method_update(sd_varlink *link, sd_json_variant *json_parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "source",           SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(PullParameters, source),          SD_JSON_MANDATORY },
                { "resource",         SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(PullParameters, resource),        SD_JSON_MANDATORY },
                { "enhancedBlob",     SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(PullParameters, enhanced_blob),   SD_JSON_MANDATORY },
                { "output",           SD_JSON_VARIANT_OBJECT, json_dispatch_local_instance,  offsetof(PrepareUpdateParameters, output), SD_JSON_MANDATORY },
                // dont need instances
                {}
        };

        _cleanup_(method_update_parameters_done) UpdateParameters  p;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, json_parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!http_url_is_valid(p.source) && !file_url_is_valid(p.source))
                return sd_varlink_error_invalid_parameter(link, "source is not a valid url");

        // parse manifest from blob, get checksum

        r = pull_file_job_begin(p.source, p.resource, p.output);

        // compare checksum

        return sd_varlink_reply(link, NULL);
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        r = varlink_server_new(&varlink_server, SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_Updater);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.Updater.ListInstances", vl_method_list_instances);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.Updater.Update", vl_method_update);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.Updater.PrepareUpdate", vl_method_prepare_update);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        (void) ignore_signals(SIGPIPE);

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                return vl_server(); /* Invocation as Varlink service */

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
