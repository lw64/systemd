/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sysupdate-forward.h"

typedef struct WebCacheItem {
        char *url;
        bool verified;
        int blob;
        char **instances;
} WebCacheItem;

/* A simple in-memory cache for downloaded manifests. Very likely multiple transfers will use the same
 * manifest URLs, hence let's make sure we only download them once within each sysupdate invocation. */

int web_cache_add_item(Hashmap **cache, const char *url, bool verified, int blob, char **instances);

WebCacheItem* web_cache_get_item(Hashmap *cache, const char *url, bool verified);
