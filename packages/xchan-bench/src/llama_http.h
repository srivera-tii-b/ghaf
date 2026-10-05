/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* llama_http.h, streaming client for llama-server's `/completion`
 * endpoint (HTTP/1.1, chunked or length-delimited body, Server-Sent Events).
 * Implementation and its limits: llama_http.c. */
#ifndef LLAMA_HTTP_H
#define LLAMA_HTTP_H

#include <stddef.h>
#include <stdint.h>

/* Decoded response body is read in pieces of at most this many bytes. Any
 * HTTP chunk size works, larger or smaller; the tests use this to put chunk
 * boundaries on and around it. */
#define LLAMA_HTTP_READ_CAP 16384

typedef struct {
    const char *host;
    int port;
    /* Prefix for the one diagnostic llama_stream_completion() logs (the
     * HTTP status of a failed request). NULL means "llama". */
    const char *log_prefix;
    /* > 0: SO_RCVTIMEO/SO_SNDTIMEO on the llama-server connection, so a
     * stalled server fails the request after this many seconds of silence.
     * 0: fully blocking. */
    int io_timeout_sec;
} llama_target_t;

/* Runs one streaming completion against llama-server. Invokes
 * on_chunk(ctx, text, text_len) for each generated content fragment the
 * moment it is parsed from the wire, this is what makes forwarding
 * genuinely incremental rather than buffered. on_chunk returns 0 to go on,
 * anything else to abort: the connection is closed at once, which makes
 * llama-server cancel the generation and free its slot rather than run on
 * to n_predict for a reader that is gone. Returns 0 on a clean stop, -1 on
 * any I/O/protocol error or an abort (errno-ish reporting via stderr). */
int llama_stream_completion(const llama_target_t *tgt,
                            const char *prompt, size_t prompt_len,
                            uint32_t n_predict,
                            int (*on_chunk)(void *ctx, const char *text, size_t len),
                            void *ctx);

#endif /* LLAMA_HTTP_H */
