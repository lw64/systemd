/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "log.h"
#include "pull-varlink.h"
#include "sd-varlink.h"
#include "varlink-io.systemd.PullWorker.h"
#include "varlink-util.h"


extern int pull_rust(const char *parameters);

static int vl_method_pull(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
  _cleanup_free_ char *formatted_json = NULL;

  int r = sd_json_variant_format(parameters, 0, &formatted_json);
  if (r < 0)
    return log_error_errno (r, "Failed to format json: %m");

  r = pull_rust(formatted_json);
  if (r < 0)
    return sd_varlink_error(link, "io.systemd.PullWorker.PullError", NULL);

  return sd_varlink_reply(link, NULL);
}

int vl_server(void) {
  _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
  int r;

  r = sd_varlink_server_new(&varlink_server, SD_VARLINK_SERVER_ROOT_ONLY);
  if (r < 0)
    return log_error_errno(r, "Failed to allocate Varlink server: %m");

  r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_PullWorker);
  if (r < 0)
    return log_error_errno(r, "Failed to add Varlink interface: %m");

  r = sd_varlink_server_bind_method(varlink_server, "io.systemd.PullWorker.Pull", vl_method_pull);
  if (r < 0)
    return log_error_errno(r, "Failed to bind Varlink method: %m");

  r = sd_varlink_server_loop_auto(varlink_server);
  if (r < 0)
    return log_error_errno(r, "Failed to run Varlink event loop: %m");

  return 0;
}
