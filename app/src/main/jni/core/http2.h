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
 * Copyright 2025 - Emanuele Faranda
 */

#ifndef PCAPDROID_HTTP2_H
#define PCAPDROID_HTTP2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "uthash.h"

/* ******************************************************* */
/* HTTP2 multiplexing support structures                   */
/* ******************************************************* */

#define MAX_HTTP2_PENDING_SIZE (32 * 1024 * 1024)  // 32 MB
#define INITIAL_HTTP2_PENDING_CAPACITY 8

// Hash table entry for buffered HTTP2 responses
typedef struct pending_response_t {
    uint64_t key;                  // Hash key: (conv_id << 32) | stream_id
    unsigned char *data;           // Response data (NULL for RST)
    size_t data_len;
    bool is_tx;
    uint64_t ms;
    UT_hash_handle hh;
} pending_response_t;

// Per-connection HTTP2 context
typedef struct http2_conn_ctx {
    uint32_t conv_id;              // ushark conversation ID
    uint32_t *pending_stream_ids;  // Dynamic array of pending stream IDs waiting for response
    size_t pending_count;
    size_t pending_capacity;
} http2_conn_ctx_t;

// Global mapping of connection ID → http2_conn_ctx_t*
typedef struct http2_context_map_t {
    uint32_t conv_id;              // Hash key
    http2_conn_ctx_t *ctx;
    UT_hash_handle hh;
} http2_context_map_t;

/* ******************************************************* */
/* Public API                                              */
/* ******************************************************* */

// Callback for outputting decrypted data
typedef void (*http2_data_output_fn)(bool is_tx, uint64_t ms, const unsigned char *plain_data, unsigned int data_len);

// Initialize HTTP2 tracking with output callback
void http2_init(http2_data_output_fn output_fn);

// Cleanup all HTTP2 contexts
void http2_cleanup(void);

// HTTP2 callback handlers
void http2_handle_request(uint32_t conv_id, uint32_t stream_id, bool is_tx, uint64_t ms,
                          const unsigned char *plain_data, size_t data_len);
void http2_handle_response(uint32_t conv_id, uint32_t stream_id, bool is_tx, uint64_t ms,
                           const unsigned char *plain_data, size_t data_len);
void http2_handle_reset(uint32_t conv_id, uint32_t stream_id, bool is_tx, uint64_t ms);

#endif // PCAPDROID_HTTP2_H
