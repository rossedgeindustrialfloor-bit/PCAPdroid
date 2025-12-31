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

/*
 * HTTP/2 reader utility
 *
 * This utility processes PCAP files containing HTTP/2 traffic and outputs
 * HTTP/2 messages in a deterministic text format for regression testing.
 *
 * Output format:
 *   [HTTP2.DATA tx:X ts:timestamp len:length body:<Y>]
 *   -----------------------
 *   <HTTP headers only - request or response>
 *   -----------------------
 *
 *   [HTTP2.RST tx:X ts:timestamp]
 *   -----------------------
 *
 * Where:
 *   - HTTP2.DATA: HTTP/2 request or response message
 *   - HTTP2.RST: HTTP/2 stream reset
 *   - X: 0 for RX, 1 for TX
 *   - timestamp: milliseconds since epoch
 *   - length: total message length in bytes
 *   - Y: 16 bytes of HTTP body data in hex, in the "first..last" truncated format if > 16
 */

#include "test_utils.h"
#include "common/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>

static size_t g_message_count = 0;

/* ******************************************************* */

static void bytes_to_hex(const unsigned char *data, size_t len, char *hex_out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_out + (i * 2), "%02x", data[i]);
    }
    hex_out[len * 2] = '\0';
}

/* ******************************************************* */

// HTTP/2 data output callback - outputs messages in text format
static void http2_output_callback(bool is_tx, uint64_t ms, const unsigned char *plain_data, unsigned int data_len) {
    g_message_count++;

    if (plain_data == NULL) {
        // RST_STREAM
        printf("[HTTP2.RST tx:%d ts:%llu]\n", is_tx ? 1 : 0,
               (unsigned long long)ms);
        printf("-----------------------\n");
        return;
    }

    char body_buf[64] = {0};

    // Find the end of headers
    const unsigned char *headers_end = (const unsigned char *) memmem(plain_data, data_len, "\r\n\r\n", 4);
    if (headers_end) {
        headers_end += 2; // Include first \r\n, exclude second

        if ((headers_end + 2 - plain_data) < data_len) {
            char *body_out = body_buf;
            const unsigned char *body_start = headers_end + 2;
            unsigned int body_len = data_len - (body_start - plain_data);

            if (body_len <= 16) {
                // message is 16 bytes or less - show entire message
                bytes_to_hex(body_start, body_len, body_out);
            } else {
                // show first and last 8 bytes (16 hex)
                bytes_to_hex(body_start, 8, body_out);
                body_out += 16;
                *body_out++ = '.';
                *body_out++ = '.';
                bytes_to_hex(body_start + (body_len - 8), 8, body_out);
            }
        }
    }

    printf("[HTTP2.DATA tx:%d ts:%llu len:%u body:<%s>]\n",
           is_tx ? 1 : 0, (unsigned long long)ms,
           data_len, body_buf);
    printf("-----------------------\n");

    size_t print_len = headers_end ? (size_t)(headers_end - plain_data) : data_len;

    // Replace non-printable chars with '.'
    unsigned char *buf = malloc(print_len);
    if (buf) {
        memcpy(buf, plain_data, print_len);

        for (size_t i = 0; i < print_len; i++) {
            if (!isprint(buf[i]) && !isspace(buf[i]))
                buf[i] = '.';
        }

        printf("%.*s\n", (int)print_len, buf);
        free(buf);
    } else {
        fprintf(stderr, "malloc failed: %d", errno);
        exit(EXIT_FAILURE);
    }

    printf("-----------------------\n");
}


/* ******************************************************* */

static void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s <pcap_file>\n", progname);
    fprintf(stderr, "\nArguments:\n");
    fprintf(stderr, "  <pcap_file>    Path to PCAP file containing HTTP/2 traffic\n");
    fprintf(stderr, "\nNote: TLS keylog file should be named <pcap_file>.keys if needed\n");
    fprintf(stderr, "\nOutput format:\n");
    fprintf(stderr, "  [HTTP2.DATA/RST tx:X ts:timestamp len:length body_start:hex body_end:hex]\n");
    fprintf(stderr, "  -----------------------\n");
    fprintf(stderr, "  <HTTP headers only>\n");
    fprintf(stderr, "  -----------------------\n");
}

/* ******************************************************* */

int main(int argc, char **argv) {
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    char *pcap_path = argv[1];

    set_log_level(ANDROID_LOG_WARN);

    // Initialize PCAPdroid in test mode
    pcapdroid_t *pd = pd_init_test(pcap_path);
    if (!pd) {
        fprintf(stderr, "Failed to initialize PCAPdroid\n");
        return 1;
    }

    // Check for TLS keylog file (replaces .pcap with .keys)
    static char keys_path[512];
    snprintf(keys_path, sizeof(keys_path), "%s", pcap_path);
    char *ext = strrchr(keys_path, '.');
    if (ext && strcmp(ext, ".pcap") == 0) {
        strcpy(ext, ".keys");
        if (access(keys_path, F_OK) == 0) {
            log_d("Setting keylog_path_override to: %s\n", keys_path);
            pd->keylog_path_override = keys_path;
        }
    }

    // Run the capture (this will process the PCAP file and call our callback)
    pd->http2_output_callback = http2_output_callback;
    int rv = pd_run(pd);

    pd_free_test(pd);

    return (rv == 0) ? 0 : 1;
}
