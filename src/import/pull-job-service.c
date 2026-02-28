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
#include "signal-util.h"
#include "varlink-io.systemd.PullJob.h"
#include "varlink-util.h"

typedef struct MethodPullParameters {
        const char *source;
        unsigned destination_fd_index;
        int destination_fd;
        uint64_t offset;
        uint64_t size_max;
        const char *expected_checksum;
        struct iovec checksum;
        sd_event *event;
        PullJob *job;
        char **old_etags;
} MethodPullParameters;

static void method_pull_parameters_free(MethodPullParameters *p) {
        sd_event_unref(p->event);
        pull_job_unref(p->job);
}

static void method_pull_parameters_init(MethodPullParameters *p) {
        *p = (MethodPullParameters) {
                .destination_fd_index = UINT_MAX,
                .destination_fd = -EBADF,
                .offset = UINT64_MAX,
                .size_max = UINT64_MAX,
                .expected_checksum = NULL,
                .old_etags = NULL,
        };
}

static void pull_job_on_finished(PullJob *job) {
        int r = 0;

        assert(job);

        MethodPullParameters *p = job->userdata;

        if (job->error != 0) {
                /* Only the main job and the checksum job are fatal if they fail. The other fails are just
                 * "decoration", that we'll download if we can. The signature job isn't fatal here because we
                 * might not actually need it in case Suse style signatures are used, that are inline in the
                 * checksum file. */

                if (job->error == ENOMEDIUM) /* HTTP 404 */
                        r = log_error_errno(job->error, "Failed to retrieve image file. (Wrong URL?)");
                else
                        r = log_error_errno(job->error, "Failed to retrieve image file.");
        }
        else
                log_info("Operation completed successfully.");

        sd_event_exit(p->event, ABS(r));
}

//static int pull_job_on_open_disk(PullJob *job) {
//        return 0;
//}

static void pull_job_on_progress(PullJob *job) {
        //
}

static int pull_file(MethodPullParameters *parameters, bool header_only) {
        _cleanup_(curl_glue_unrefp) CurlGlue *glue = NULL;
        int r;

        r = import_allocate_event_with_signals(&parameters->event);
        if (r < 0)
                return r;

        r = curl_glue_new(&glue, parameters->event);
        if (r < 0)
                return r;
        glue->on_finished = pull_job_curl_on_finished;

        pull_job_new (&parameters->job, parameters->source, TAKE_PTR(glue), /* userdata= */ parameters);

        parameters->job->on_finished = pull_job_on_finished;
        //pull_job->on_open_disk = pull_job_on_open_disk;
        parameters->job->calc_checksum = true;
        parameters->job->force_memory = false;

        if (parameters->size_max != UINT64_MAX)
                parameters->job->uncompressed_max = parameters->size_max;
        if (parameters->offset != UINT64_MAX)
                parameters->job->offset = parameters->offset;

        parameters->job->on_progress = pull_job_on_progress;
        parameters->job->sync = false; //do on the caller side

        parameters->job->disk_fd = parameters->destination_fd;
        parameters->job->old_etags = TAKE_PTR(parameters->old_etags);

        parameters->job->header_only = header_only;

        r = pull_job_begin(parameters->job);
        if (r < 0)
                return r;

        r = sd_event_loop(parameters->event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static int parse_checksum(const char *checksum, struct iovec *c) {
        int r;
        _cleanup_free_ void *h = NULL;
        size_t n;

        r = unhexmem(checksum, &h, &n);
        if (r < 0 || n == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid verification setting: %s", checksum);
        if (n != 32)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "64 hex character SHA256 hash required when specifying explicit checksum, %zu specified", n * 2);

        iovec_done(c);
        c->iov_base = TAKE_PTR(h);
        c->iov_len = n;

        return 0;
}

static int vl_method_pull_file(sd_varlink *link, sd_json_variant *json_parameters, sd_varlink_method_flags_t flags, void *userdata) {

        // parse only the parameters used by systemd-pull

        static const sd_json_dispatch_field dispatch_table[] = {
                { "source",                    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(MethodPullParameters, source),               SD_JSON_MANDATORY },
                { "destinationFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         offsetof(MethodPullParameters, destination_fd_index), SD_JSON_MANDATORY },
                { "instances",                 SD_JSON_VARIANT_ARRAY,         NULL,                          0,                                                    0 },
                { "offset",                    SD_JSON_VARIANT_NUMBER,        sd_json_dispatch_uint64,       offsetof(MethodPullParameters, offset),               0 },
                { "maxSize",                   SD_JSON_VARIANT_NUMBER,        sd_json_dispatch_uint64,       offsetof(MethodPullParameters, size_max),             0 },
                { "expectedChecksum",          SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,       offsetof(MethodPullParameters, expected_checksum),    0 },
                { "oldEtags",                  SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,         offsetof(MethodPullParameters, old_etags),            0 },
                {}
        };

        _cleanup_(method_pull_parameters_free) MethodPullParameters parameters;
        int r;

        assert(link);

        method_pull_parameters_init (&parameters);

        r = sd_varlink_dispatch(link, json_parameters, dispatch_table, &parameters);
        if (r != 0)
                return r;

        parameters.destination_fd = sd_varlink_take_fd(link, parameters.destination_fd_index);
        if (parameters.destination_fd < 0)
                return sd_varlink_error_invalid_parameter_name(link, "destinationFileDescriptor");

        if (parameters.offset != UINT64_MAX && !FILE_SIZE_VALID(parameters.offset))
                return sd_varlink_error_invalid_parameter_name(link, "offset");

        if (parameters.size_max != UINT64_MAX && (!FILE_SIZE_VALID(parameters.size_max) || (parameters.size_max % 1024) != 0))
                return sd_varlink_error_invalid_parameter_name(link, "maxSize");

        /* Make sure offset+size is still in the valid range if both set */
        if (parameters.offset != UINT64_MAX && parameters.size_max != UINT64_MAX &&
            ((parameters.size_max > (UINT64_MAX - parameters.offset)) ||
             !FILE_SIZE_VALID(parameters.offset + parameters.size_max))) {
                log_error("maxSize and offset are invalid together");
                return sd_varlink_error_invalid_parameter_name(link, "maxSize");
       }

        if (parameters.expected_checksum) {
                r = parse_checksum(parameters.expected_checksum, &parameters.checksum);
                if (r < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "expectedChecksum");
        }

        r = pull_file(&parameters, /* header_only */ false);
        if (r < 0)
                return sd_varlink_error_errno(link, parameters.job->error);

        return sd_varlink_replybo(link,
                                  SD_JSON_BUILD_PAIR_BOOLEAN("etagExists", parameters.job->etag_exists),
                                  SD_JSON_BUILD_PAIR_CONDITION(parameters.job->etag != NULL, "etag", SD_JSON_BUILD_STRING(parameters.job->etag)),
                                  SD_JSON_BUILD_PAIR_STRING("checksum", hexmem(parameters.job->checksum.iov_base, parameters.job->checksum.iov_len)));
}

static int vl_method_prepare_pull(sd_varlink *link, sd_json_variant *json_parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "source", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(MethodPullParameters, source), SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(method_pull_parameters_free) MethodPullParameters parameters;
        int r;

        assert(link);

        method_pull_parameters_init (&parameters);

        r = sd_varlink_dispatch(link, json_parameters, dispatch_table, &parameters);
        if (r != 0)
                return r;

        r = pull_file(&parameters, /* header_only */ true);
        if (r < 0)
                return sd_varlink_error_errno(link, parameters.job->error);

        return sd_varlink_replybo(link,
                                  SD_JSON_BUILD_PAIR_INTEGER("size", parameters.job->content_length));
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        r = varlink_server_new(&varlink_server, SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_PullJob);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.PullJob.PullFile", vl_method_pull_file);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.PullJob.PreparePull", vl_method_prepare_pull);
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
