/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PCAPdroid is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PCAPdroid.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2025-26 - Emanuele Faranda
 */

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include "http2.h"
#include "common/utils.h"
#include "common/memtrack.h"

static http2_context_map_t *g_http2_contexts = NULL;
static pending_response_t *g_pending_responses = NULL;
static size_t g_total_pending_data = 0;
static http2_data_output_fn g_output_fn = NULL;

static inline uint64_t make_response_key(uint32_t conv_id, uint32_t stream_id) {
    return ((uint64_t)conv_id << 32) | stream_id;
}

static inline uint32_t extract_conv_id(uint64_t key) {
    return (uint32_t)(key >> 32);
}

static http2_conn_ctx_t* create_http2_context(uint32_t conv_id) {
    http2_conn_ctx_t *ctx = pd_calloc(sizeof(http2_conn_ctx_t), 1);
    if (!ctx)
        return NULL;

    ctx->conv_id = conv_id;
    ctx->pending_stream_ids = pd_malloc(INITIAL_HTTP2_PENDING_CAPACITY * sizeof(uint32_t));
    if (!ctx->pending_stream_ids) {
        pd_free(ctx);
        return NULL;
    }

    ctx->pending_capacity = INITIAL_HTTP2_PENDING_CAPACITY;

    return ctx;
}

static void free_http2_context(http2_conn_ctx_t *ctx) {
    if (!ctx)
        return;

    // Free pending responses for this connection from global hash
    pending_response_t *resp, *tmp;
    HASH_ITER(hh, g_pending_responses, resp, tmp) {
        if (extract_conv_id(resp->key) == ctx->conv_id) {
            g_total_pending_data -= resp->data_len;
            if (resp->data)
                pd_free(resp->data);
            HASH_DEL(g_pending_responses, resp);
            pd_free(resp);
        }
    }

    if (ctx->pending_stream_ids)
        pd_free(ctx->pending_stream_ids);

    pd_free(ctx);
}

static http2_conn_ctx_t* get_http2_context(uint32_t conv_id, bool create) {
    http2_context_map_t *map_entry;
    HASH_FIND_INT(g_http2_contexts, &conv_id, map_entry);

    if (map_entry)
        return map_entry->ctx;

    if (!create)
        return NULL;

    // Create new context
    http2_conn_ctx_t *ctx = create_http2_context(conv_id);
    if (!ctx)
        return NULL;

    map_entry = pd_malloc(sizeof(http2_context_map_t));
    if (!map_entry) {
        free_http2_context(ctx);
        return NULL;
    }

    map_entry->conv_id = conv_id;
    map_entry->ctx = ctx;
    HASH_ADD_INT(g_http2_contexts, conv_id, map_entry);

    return ctx;
}

static ssize_t find_stream_position(http2_conn_ctx_t *ctx, uint32_t stream_id) {
    for (size_t i = 0; i < ctx->pending_count; i++) {
        if (ctx->pending_stream_ids[i] == stream_id)
            return (ssize_t)i;
    }
    return -1;
}

static bool add_pending_stream(http2_conn_ctx_t *ctx, uint32_t stream_id) {
    // Check for stream ID reuse (HTTP/2 protocol violation - RFC 7540 § 5.1.1)
    // Stream IDs must be unique and monotonically increasing per connection
    if (find_stream_position(ctx, stream_id) >= 0) {
        log_e("[HTTP2][conv:%u stream:%u] Stream already pending, discard",
              ctx->conv_id, stream_id);
        return false;
    }

    // Grow array if needed
    if (ctx->pending_count >= ctx->pending_capacity) {
        size_t new_capacity = ctx->pending_capacity * 2;
        uint32_t *new_arr = pd_realloc(ctx->pending_stream_ids,
                                       new_capacity * sizeof(uint32_t));
        if (!new_arr)
            return false;
        ctx->pending_stream_ids = new_arr;
        ctx->pending_capacity = new_capacity;
    }

    ctx->pending_stream_ids[ctx->pending_count++] = stream_id;
    return true;
}

static void remove_pending_stream(http2_conn_ctx_t *ctx, size_t pos) {
    if (pos >= ctx->pending_count)
        return;

    // Shift remaining elements
    for (size_t i = pos; i < ctx->pending_count - 1; i++) {
        ctx->pending_stream_ids[i] = ctx->pending_stream_ids[i + 1];
    }
    ctx->pending_count--;
}

static bool buffer_response(http2_conn_ctx_t *ctx, uint32_t stream_id,
                           bool is_tx, uint64_t ms,
                           const unsigned char *data, size_t data_len) {
    uint64_t key = make_response_key(ctx->conv_id, stream_id);

    // Check if already buffered (edge case: duplicate response)
    pending_response_t *existing;
    HASH_FIND(hh, g_pending_responses, &key, sizeof(uint64_t), existing);
    if (existing) {
        if (data_len == 0)
            // e.g. HTTP req -> HTTP res -> RST (client)
            log_d("[HTTP2][conv:%u stream:%u] RST for already-buffered response, ignoring",
                  ctx->conv_id, stream_id);
        else
            log_w("[HTTP2][conv:%u stream:%u] Response already buffered, ignoring",
                  ctx->conv_id, stream_id);
        return false;
    }

    pending_response_t *resp = pd_malloc(sizeof(pending_response_t));
    if (!resp)
        return false;

    resp->key = key;
    resp->data_len = data_len;
    resp->is_tx = is_tx;
    resp->ms = ms;

    if ((data_len > 0) && data) {
        resp->data = pd_malloc(data_len);
        if (!resp->data) {
            pd_free(resp);
            return false;
        }
        memcpy(resp->data, data, data_len);
    } else {
        resp->data = NULL;  // RST case
    }

    HASH_ADD(hh, g_pending_responses, key, sizeof(uint64_t), resp);
    g_total_pending_data += data_len;

    return true;
}

static void remove_buffered_response(http2_conn_ctx_t *ctx, uint32_t stream_id) {
    uint64_t key = make_response_key(ctx->conv_id, stream_id);
    pending_response_t *resp;
    HASH_FIND(hh, g_pending_responses, &key, sizeof(uint64_t), resp);
    if (!resp)
        return;

    g_total_pending_data -= resp->data_len;

    if (resp->data)
        pd_free(resp->data);
    HASH_DEL(g_pending_responses, resp);
    pd_free(resp);
}

static void process_pending_responses(http2_conn_ctx_t *ctx) {
    while (ctx->pending_count > 0) {
        uint32_t first_stream = ctx->pending_stream_ids[0];
        uint64_t key = make_response_key(ctx->conv_id, first_stream);
        pending_response_t *resp;
        HASH_FIND(hh, g_pending_responses, &key, sizeof(uint64_t), resp);

        if (!resp)
            // No response for first pending request
            break;

        // Response found, output it
        if (g_output_fn)
            g_output_fn(resp->is_tx, resp->ms, resp->data, resp->data_len);

        remove_buffered_response(ctx, first_stream);
        remove_pending_stream(ctx, 0);
    }
}

// Evict stalled requests from the current connection only,
// to avoid mixing data of different connections. This is quite limiting in the eviction
// effectiveness, but necessary. Eviction should not occur on a standard execution, because it will
// cause missing data
static void evict_stalled_requests(http2_conn_ctx_t *ctx, bool is_tx, uint64_t ms) {
    while (g_total_pending_data > MAX_HTTP2_PENDING_SIZE &&
           ctx->pending_count > 0)
    {
        uint32_t first_stream = ctx->pending_stream_ids[0];

        log_w("[HTTP2][conv:%u stream:%u] Evicting stalled request",
              ctx->conv_id, first_stream);

        if (g_output_fn)
            // consider it a RST
            g_output_fn(is_tx, ms, NULL, 0);

        // precondition: there is no pending_response_t for this stream ID
        remove_pending_stream(ctx, 0);
        process_pending_responses(ctx);
    }
}

/* ******************************************************* */
/* Public API implementation                               */
/* ******************************************************* */

void http2_init(http2_data_output_fn output_fn) {
    http2_cleanup();
    g_output_fn = output_fn;
}

void http2_cleanup(void) {
    http2_context_map_t *map_entry, *tmp;
    HASH_ITER(hh, g_http2_contexts, map_entry, tmp) {
        free_http2_context(map_entry->ctx);
        HASH_DEL(g_http2_contexts, map_entry);
        pd_free(map_entry);
    }

    // Clean up any remaining pending responses in global hash
    pending_response_t *resp, *tmp_resp;
    HASH_ITER(hh, g_pending_responses, resp, tmp_resp) {
        if (resp->data)
            pd_free(resp->data);
        HASH_DEL(g_pending_responses, resp);
        pd_free(resp);
    }

    g_http2_contexts = NULL;
    g_pending_responses = NULL;
    g_total_pending_data = 0;
    g_output_fn = NULL;
}

void http2_handle_request(uint32_t conv_id, uint32_t stream_id, bool is_tx, uint64_t ms,
                          const unsigned char *plain_data, size_t data_len) {
    // Add to pending queue for response matching
    http2_conn_ctx_t *ctx = get_http2_context(conv_id, true);
    if (!ctx) {
        log_e("[HTTP2][conv:%u stream:%u] Failed to create context, dropping request",
              conv_id, stream_id);
        return;
    }

    if (!add_pending_stream(ctx, stream_id)) {
        log_e("[HTTP2][conv:%u stream:%u] Failed to add pending stream, dropping request",
              conv_id, stream_id);
        return;
    }

    // Requests are always output immediately
    // HTTPReassembly.java takes care of associating them to their reply
    if (g_output_fn)
        g_output_fn(is_tx, ms, plain_data, data_len);
}

void http2_handle_response(uint32_t conv_id, uint32_t stream_id, bool is_tx, uint64_t ms,
                           const unsigned char *plain_data, size_t data_len) {
    // Responses need to be output honoring the request ordering,
    // so that HTTPReassembly.java can associate them to the correct Request
    // HTTP/2 multiplexes the connections, so responses will need to be buffered when they are
    // out of sequence
    http2_conn_ctx_t *ctx = get_http2_context(conv_id, false);
    if (!ctx) {
        // Edge case: Response without request
        log_w("[HTTP2][conv:%u stream:%u] Response for unknown stream, ignoring",
              conv_id, stream_id);
        return;
    }

    ssize_t pos = find_stream_position(ctx, stream_id);
    if (pos < 0) {
        // Edge case: Response for non-pending stream
        log_w("[HTTP2][conv:%u stream:%u] Response for non-pending stream, ignoring",
              conv_id, stream_id);
        return;
    }

    if (pos == 0) {
        // First in queue - output immediately
        if (g_output_fn)
            g_output_fn(is_tx, ms, plain_data, data_len);
        remove_pending_stream(ctx, 0);
        process_pending_responses(ctx);
    } else {
        // Not first, buffer it
        if (!buffer_response(ctx, stream_id, is_tx, ms, plain_data, data_len)) {
            log_e("[HTTP2][conv:%u stream:%u] Failed to buffer response",
                  conv_id, stream_id);
            return;
        }

        if (g_total_pending_data > MAX_HTTP2_PENDING_SIZE) {
            log_w("[HTTP2][conv:%u stream:%u] Pending size exceeded (%zu bytes), evicting streams",
                  conv_id, stream_id, g_total_pending_data);
            evict_stalled_requests(ctx, is_tx, ms);
        }
    }
}

void http2_handle_reset(uint32_t conv_id, uint32_t stream_id, bool is_tx, uint64_t ms) {
    http2_conn_ctx_t *ctx = get_http2_context(conv_id, false);
    if (!ctx) {
        // Edge case: RST before request
        if (g_output_fn)
            g_output_fn(is_tx, ms, NULL, 0);
        return;
    }

    ssize_t pos = find_stream_position(ctx, stream_id);
    if (pos < 0) {
        // e.g. HTTP req -> HTTP res -> RST (client)
        log_d("[HTTP2][conv:%u stream:%u] RST for non-pending stream, ignoring",
              conv_id, stream_id);
        return;
    }

    if (pos == 0) {
        // First in queue - output RST now
        if (g_output_fn)
            g_output_fn(is_tx, ms, NULL, 0);
        remove_pending_stream(ctx, 0);
        process_pending_responses(ctx);
    } else {
        // Buffer empty response
        if (!buffer_response(ctx, stream_id, is_tx, ms, NULL, 0))
            // e.g. HTTP req -> HTTP res -> RST (client)
            log_d("[HTTP2][conv:%u stream:%u] Discarding RST", conv_id, stream_id);
    }
}
