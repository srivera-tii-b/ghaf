/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* demo_session.h, what runs INSIDE the secure channel of demo_crypto.h:
 * the bench request/chunk/done messages of proto.h, one per APP record,
 * plus the CLOSE record. Kept apart from the two mains so the tests can run
 * the exact server and client logic over a socketpair, with a fake model
 * and an intercepting "host" in between.
 */
#ifndef DEMO_SESSION_H
#define DEMO_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "demo_crypto.h"
#include "proto.h"

/* One line to stderr with a single write(), so lines from concurrent
 * channel threads never interleave. */
void xd_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* ---- server ----------------------------------------------------------- */

/* The model. Same shape as llama_stream_completion(), plus a context:
 * calls on_chunk() once per generated fragment and must stop generating as
 * soon as on_chunk() returns non-zero (the client is gone); returns 0 on a
 * clean stop or -1 on failure or such an abort. */
typedef int (*xd_generate_fn)(void *gen_ctx, const char *prompt, size_t prompt_len,
                              uint32_t n_predict,
                              int (*on_chunk)(void *ctx, const char *text, size_t len),
                              void *cb_ctx);

/* n_predict above this is clamped: an authenticated client is still not
 * allowed to ask for an unbounded generation. */
#define XD_MAX_PREDICT 2048u

typedef struct {
    const uint8_t *sk;                /* server Ed25519 secret key */
    const xd_client_key_t *clients;   /* pinned client keys */
    size_t n_clients;
    xd_generate_fn generate;
    void *gen_ctx;
    int handshake_timeout_ms;         /* per handshake step */
    int idle_timeout_ms;              /* longest wait for the next request */
    /* Longest wait for a fresh channel's first message (the HELLO) before
     * the handshake and its per-step timeout start: < 0 waits for ever,
     * 0 skips the wait. See xd_serve_channel(). */
    int hello_wait_ms;
} xd_server_cfg_t;

typedef struct {
    xd_err_t end;        /* why the channel ended; XD_OK = CLOSE requested */
    int      authenticated;
    size_t   client;     /* index into cfg->clients when authenticated */
    unsigned requests;   /* requests fully answered */
} xd_serve_result_t;

/* Handshake, then requests until the peer closes, sends CLOSE, or anything
 * fails. Logs "DEMO-SERVER client=<name> ..." lines. Does NOT close c->fd:
 * the caller does, on every return. */
void xd_serve_channel(const xd_server_cfg_t *cfg, xd_chan_t *c, unsigned channel_id,
                      xd_serve_result_t *res);

/* ---- client ----------------------------------------------------------- */

#define XD_REPLY_CAP 1024 /* reply bytes kept for display */

typedef struct {
    int      ok;
    xd_err_t err;          /* XD_OK when ok, or when the server reported an error */
    char     why[96];      /* human-readable failure reason */
    double   ttft_ms;
    double   tok_s;        /* (tokens-1) / (t_last - t_first), as client.c */
    int      tok_s_defined;
    unsigned tokens;
    char     reply[XD_REPLY_CAP];
    size_t   reply_len;
} xd_req_result_t;

/* One request/response over an established session. Timing follows
 * client.c: TTFT from just before the request is sealed and sent to just
 * after the first chunk is received and opened. Returns 0 on success, -1
 * on failure (out->why says why; the session is dead unless the failure
 * was an authenticated MSG_ERROR from the server). */
int xd_client_request(xd_chan_t *c, xd_session_t *s, uint32_t request_id,
                      const char *prompt, uint32_t n_predict, int timeout_ms,
                      xd_req_result_t *out);

/* Display form of a reply for the DEMO line: at most max_chars UTF-8
 * characters (never splits one), tab/CR/LF become spaces, other control
 * characters (C0, DEL, C1) are dropped, '"' becomes '\'' so the quoted
 * field stays parseable. out must hold 4*max_chars+1 bytes. */
void xd_display_text(const char *in, size_t len, size_t max_chars, char *out);

#endif /* DEMO_SESSION_H */
