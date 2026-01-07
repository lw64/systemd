/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"


#include "varlink-io.systemd.PullJob.h"


static SD_VARLINK_DEFINE_STRUCT_TYPE(
                PullInstance,
                SD_VARLINK_FIELD_COMMENT("Path to the location of the instance on the system"),
                SD_VARLINK_DEFINE_FIELD(locationFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(offset, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(maxSize, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                PullFile,
                SD_VARLINK_FIELD_COMMENT("URL to download from"),
                SD_VARLINK_DEFINE_INPUT(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Destination for download"),
                SD_VARLINK_DEFINE_INPUT(destinationFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Instances to reuse data from for delta-updating"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(instances, PullInstance, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Start offset for data in destination"),
                SD_VARLINK_DEFINE_INPUT(offset, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Maximum size of written data"),
                SD_VARLINK_DEFINE_INPUT(maxSize, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(expectedChecksum, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(InvalidParameters);
static SD_VARLINK_DEFINE_ERROR(PullError);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PullJob,
                "io.systemd.PullJob",
                SD_VARLINK_INTERFACE_COMMENT("An interface for directly downloading data"),
                SD_VARLINK_SYMBOL_COMMENT("Instances to reuse data from for delta-updating"),
                &vl_type_PullInstance,
                SD_VARLINK_SYMBOL_COMMENT("Download from a URL into your system"),
                &vl_method_PullFile,
                SD_VARLINK_SYMBOL_COMMENT("A parameter is invalid"),
                &vl_error_InvalidParameters,
                SD_VARLINK_SYMBOL_COMMENT("An error occured while pulling the data"),
                &vl_error_PullError);
