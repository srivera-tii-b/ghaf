/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* proto.h, wire protocol for the inference benchmark client/server.
 *
 * Design goals:
 *  - Fixed-layout, self-describing messages (no pointers, no serialization
 *    library) so the exact same bytes can cross a unix socket or an xchan
 *    channel unchanged.
 *  - Each message is sent/received as ONE transport-level unit. On xchan
 *    that's native (xchan_recv always returns one complete message). On a
 *    stream socket we frame it ourselves (see transport_sock.c) so the two
 *    backends present an identical "whole message in, whole message out"
 *    contract to everything above transport.h.
 *  - Messages are variable-length on the wire: a fixed header followed by a
 *    payload whose *actual* used length is transmitted (via the transport's
 *    length, not the struct's sizeof), so we don't pay to move ~4KB over
 *    the wire for a 3-byte token. The receiver always provides a
 *    max-size buffer to recv into and trusts the byte count the transport
 *    call returns, not sizeof(the union).
 */
#ifndef BENCH_PROTO_H
#define BENCH_PROTO_H

#include <stddef.h>
#include <stdint.h>

#define BENCH_MAGIC 0x58424e43u /* "XBNC" */

#define BENCH_MAX_PROMPT   4096
#define BENCH_MAX_CHUNK    256

typedef enum {
    MSG_REQUEST = 1,  /* client -> server: one inference request */
    MSG_CHUNK   = 2,  /* server -> client: one generated token/text chunk */
    MSG_DONE    = 3,  /* server -> client: stream finished successfully */
    MSG_ERROR   = 4,  /* server -> client: stream aborted with an error */
} bench_msg_type_t;

/* client -> server */
typedef struct {
    uint32_t magic;
    uint32_t type;         /* MSG_REQUEST */
    uint32_t request_id;
    uint32_t max_tokens;
    uint32_t temperature_milli;  /* temperature * 1000, integer on the wire */
    uint32_t prompt_len;         /* bytes of prompt[] actually used */
    char     prompt[BENCH_MAX_PROMPT];
} bench_request_t;

/* server -> client, one per generated token/chunk, first one is what TTFT
 * is measured against. */
typedef struct {
    uint32_t magic;
    uint32_t type;         /* MSG_CHUNK */
    uint32_t request_id;
    uint32_t token_index;  /* 0-based index of this chunk in the stream */
    uint32_t text_len;     /* bytes of text[] actually used */
    char     text[BENCH_MAX_CHUNK];
} bench_chunk_t;

/* server -> client, terminates a stream (success or error) */
typedef struct {
    uint32_t magic;
    uint32_t type;         /* MSG_DONE or MSG_ERROR */
    uint32_t request_id;
    uint32_t total_tokens; /* number of MSG_CHUNK messages sent for this request */
    int32_t  error_code;   /* 0 on MSG_DONE; errno-like value on MSG_ERROR */
} bench_done_t;

/* Generic buffer big enough for any message type, used as the recv target
 * by both backends, neither backend ever needs to know in advance which
 * message it's about to receive. */
typedef union {
    /* All three variants start with {uint32_t magic; uint32_t type;},
     * this is a C "common initial sequence" (C11 6.5.2.3p6), so peeking
     * hdr.magic/hdr.type is well-defined no matter which variant was last
     * written into the union, which is exactly what we need before we know
     * which variant we've received. */
    struct { uint32_t magic; uint32_t type; } hdr;
    bench_request_t   request;
    bench_chunk_t     chunk;
    bench_done_t      done;
} bench_msg_t;

#define BENCH_MSG_MAX_SIZE ((size_t)sizeof(bench_msg_t))

/* Byte length actually used on the wire for each message variant,
 * header up to and including the payload's stated length, nothing past it.
 * These are what gets passed to transport_send()/expected back from
 * transport_recv(), never sizeof(bench_msg_t). */
static inline size_t bench_request_wire_len(const bench_request_t *r) {
    return offsetof(bench_request_t, prompt) + r->prompt_len;
}
static inline size_t bench_chunk_wire_len(const bench_chunk_t *c) {
    return offsetof(bench_chunk_t, text) + c->text_len;
}
static inline size_t bench_done_wire_len(void) {
    return sizeof(bench_done_t);
}

#endif /* BENCH_PROTO_H */
