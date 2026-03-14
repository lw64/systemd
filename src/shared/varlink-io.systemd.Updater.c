/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"


#include "varlink-io.systemd.Updater.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                LocalUpdateInstance,
                SD_VARLINK_FIELD_COMMENT("Path to the location of the instance on the system"),
                SD_VARLINK_DEFINE_FIELD(locationFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(offset, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(maxSize, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ListInstances,
                SD_VARLINK_FIELD_COMMENT("URL path to update from"),
                SD_VARLINK_DEFINE_INPUT(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("available instances"),
                SD_VARLINK_DEFINE_OUTPUT(size, SD_VARLINK_STRING, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("cached blob"),
                SD_VARLINK_DEFINE_OUTPUT(blob, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                PrepareUpdate,
                SD_VARLINK_FIELD_COMMENT("URL path to update from"),
                SD_VARLINK_DEFINE_INPUT(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("selected resource to update (filename)"),
                SD_VARLINK_DEFINE_INPUT(resource, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("cached blob"),
                SD_VARLINK_DEFINE_INPUT(blob, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Instance to update into (read-only, to check for a paused update)"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(output, LocalUpdateInstance, 0),
                SD_VARLINK_FIELD_COMMENT("size of the instance to download"),
                SD_VARLINK_DEFINE_OUTPUT(size, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("enhanced blob"),
                SD_VARLINK_DEFINE_OUTPUT(enhancedBlob, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                Update,
                SD_VARLINK_FIELD_COMMENT("URL path to update from"),
                SD_VARLINK_DEFINE_INPUT(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("selected resource to update (filename)"),
                SD_VARLINK_DEFINE_INPUT(resource, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("cached enhanced blob"),
                SD_VARLINK_DEFINE_INPUT(enhancedBlob, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Instances to reuse data from for delta-updating"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(instances, LocalUpdateInstance, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Instance to update into"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(output, LocalUpdateInstance, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Updater,
                "io.systemd.Updater",
                SD_VARLINK_INTERFACE_COMMENT("An interface for updating"),
                &vl_type_LocalUpdateInstance,
                SD_VARLINK_SYMBOL_COMMENT("List available update instances"),
                &vl_method_ListInstances,
                SD_VARLINK_SYMBOL_COMMENT("Prepare update (returns expected size)"),
                &vl_method_PrepareUpdate,
                SD_VARLINK_SYMBOL_COMMENT("Update"),
                &vl_method_Update);
