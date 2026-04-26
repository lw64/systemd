/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "memory-util.h"
#include "sysupdate-cache.h"
#include "strv.h"

#define WEB_CACHE_ENTRIES_MAX 64U
#define WEB_CACHE_ITEM_SIZE_MAX (64U*1024U*1024U)

static WebCacheItem* web_cache_item_free(WebCacheItem *i) {
        if (!i)
                return NULL;

        free(i->url);
        safe_close(i->blob);
        strv_freep(&i->instances);
        return mfree(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(WebCacheItem*, web_cache_item_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(web_cache_hash_ops, char, string_hash_func, string_compare_func, WebCacheItem, web_cache_item_free);

int web_cache_add_item(
                Hashmap **web_cache,
                const char *url,
                bool verified,
                int blob,
                char **instances) {

        _cleanup_(web_cache_item_freep) WebCacheItem *item = NULL;
        _cleanup_free_ char *u = NULL;
        int r;

        assert(web_cache);
        assert(url);
        assert(blob > 0);
        assert(instances);

        item = web_cache_get_item(*web_cache, url, verified);
        if (item && item->blob == blob)
                return 0;

        if (hashmap_size(*web_cache) >= (size_t) (WEB_CACHE_ENTRIES_MAX + hashmap_contains(*web_cache, url)))
                return -ENOSPC;

        r = hashmap_ensure_allocated(web_cache, &web_cache_hash_ops);
        if (r < 0)
                return r;

        u = strdup(url);
        if (!u)
                return -ENOMEM;

        item = malloc(sizeof(WebCacheItem));
        if (!item)
                return -ENOMEM;

        *item = (WebCacheItem) {
                .url = TAKE_PTR(u),
                .blob = blob,
                .instances = strv_copy(instances),
                .verified = verified,
        };

        web_cache_item_free(hashmap_remove(*web_cache, url));

        r = hashmap_put(*web_cache, item->url, item);
        if (r < 0)
                return r;

        TAKE_PTR(item);
        return 1;
}

WebCacheItem* web_cache_get_item(Hashmap *web_cache, const char *url, bool verified) {
        WebCacheItem *i;

        i = hashmap_get(web_cache, url);
        if (!i)
                return NULL;

        if (i->verified != verified)
                return NULL;

        return i;
}
