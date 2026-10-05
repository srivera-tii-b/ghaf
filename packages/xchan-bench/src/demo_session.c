/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* demo_session.c, request/response logic inside the demo's secure
 * channel. See demo_session.h. */
#include "demo_session.h"

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void xd_log(const char *fmt, ...) {
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n > sizeof(line) - 2) n = (int)sizeof(line) - 2;
    line[n++] = '\n';
    ssize_t w;
    do { w = write(STDERR_FILENO, line, (size_t)n); } while (w < 0 && errno == EINTR);
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ---- server ----------------------------------------------------------- */

typedef struct {
    xd_chan_t *c;
    xd_session_t *s;
    uint32_t request_id;
    uint32_t token_index;
    xd_err_t err; /* first send failure */
} fwd_ctx_t;

/* Forwards one fragment to the client. Once a send has failed the session
 * is dead and nothing more can reach the client, so it returns non-zero:
 * the model stops there instead of generating on to n_predict for nobody,
 * which would hold one of llama-server's --parallel slots (one per client)
 * for the whole time. */
static int fwd_chunk(void *vctx, const char *text, size_t len) {
    fwd_ctx_t *f = vctx;
    if (f->err != XD_OK) return -1;

    bench_chunk_t chunk;
    memset(&chunk, 0, sizeof(chunk));
    chunk.magic = BENCH_MAGIC;
    chunk.type = MSG_CHUNK;
    chunk.request_id = f->request_id;
    chunk.token_index = f->token_index++;
    if (len > BENCH_MAX_CHUNK) len = BENCH_MAX_CHUNK;
    memcpy(chunk.text, text, len);
    chunk.text_len = (uint32_t)len;
    f->err = xd_send_record(f->c, f->s, XD_REC_APP, &chunk, bench_chunk_wire_len(&chunk));
    sodium_memzero(&chunk, sizeof(chunk)); /* plaintext reply text */
    return f->err == XD_OK ? 0 : -1;
}

/* A request record is one bench_request_t, sent with its wire length. */
static int request_valid(const bench_msg_t *m, size_t len) {
    if (len < offsetof(bench_request_t, prompt)) return 0;
    const bench_request_t *r = &m->request;
    if (r->magic != BENCH_MAGIC || r->type != MSG_REQUEST) return 0;
    if (r->prompt_len > BENCH_MAX_PROMPT) return 0;
    if (len != bench_request_wire_len(r)) return 0;
    return 1;
}

void xd_serve_channel(const xd_server_cfg_t *cfg, xd_chan_t *c, unsigned channel_id,
                      xd_serve_result_t *res) {
    xd_session_t s;
    char fp[9];
    size_t which = 0;

    memset(res, 0, sizeof(*res));

    /*
     * A channel usually exists before any client wants it: crosvm
     * re-establishes a client's channel as soon as its previous one closes,
     * and connects a client VM's channel when the VM boots. So an open
     * channel with nobody talking yet is the normal state, not a stalled
     * peer, and timing it out only hands the client a channel that is
     * already dead by the time it runs. Wait for the first message without
     * a deadline (one idle thread per connected client, at most the
     * device's channel count); the per-step handshake timeout starts once
     * the client has actually begun. A detach ends the wait too: poll()
     * reports it, and the handshake's receive then says so.
     */
    if (cfg->hello_wait_ms != 0) {
        struct pollfd p = { .fd = c->fd, .events = POLLIN, .revents = 0 };
        while (poll(&p, 1, cfg->hello_wait_ms < 0 ? -1 : cfg->hello_wait_ms) < 0 &&
               errno == EINTR)
            ;
    }

    xd_err_t err = xd_server_handshake(c, cfg->sk, cfg->clients, cfg->n_clients,
                                       &s, &which, fp, cfg->handshake_timeout_ms);
    if (err != XD_OK) {
        xd_log("DEMO-SERVER client=? channel=%u handshake=fail reason=\"%s\" claimed_fp=%s",
               channel_id, xd_err_str(err), fp);
        res->end = err;
        return;
    }
    const char *name = cfg->clients[which].name;
    res->authenticated = 1;
    res->client = which;
    xd_log("DEMO-SERVER client=%s channel=%u handshake=ok fp=%s", name, channel_id, fp);

    /* Holds each decrypted request, prompt included: wiped once the request
     * is answered and on the way out. */
    bench_msg_t msg;
    for (;;) {
        uint8_t type = 0;
        size_t len = 0;
        err = xd_recv_record(c, &s, &type, &msg, sizeof(msg), &len, cfg->idle_timeout_ms);
        if (err == XD_ERR_PEER_CLOSED) {
            xd_log("DEMO-SERVER client=%s channel=%u closed reason=\"peer closed\" requests=%u",
                   name, channel_id, res->requests);
            break;
        }
        if (err != XD_OK) {
            xd_log("DEMO-SERVER client=%s channel=%u fail reason=\"%s\" requests=%u",
                   name, channel_id, xd_err_str(err), res->requests);
            break;
        }
        if (type == XD_REC_CLOSE) {
            if (len != 0) {
                err = XD_ERR_MALFORMED;
                xd_log("DEMO-SERVER client=%s channel=%u fail reason=\"CLOSE with payload\"",
                       name, channel_id);
            } else {
                err = XD_OK;
                xd_log("DEMO-SERVER client=%s channel=%u closed reason=\"close requested\" requests=%u",
                       name, channel_id, res->requests);
            }
            break;
        }
        if (!request_valid(&msg, len)) {
            err = XD_ERR_MALFORMED;
            xd_log("DEMO-SERVER client=%s channel=%u fail reason=\"malformed request\"",
                   name, channel_id);
            break;
        }

        const bench_request_t *req = &msg.request;
        uint32_t n_predict = req->max_tokens;
        if (n_predict == 0 || n_predict > XD_MAX_PREDICT) n_predict = XD_MAX_PREDICT;

        fwd_ctx_t f = { .c = c, .s = &s, .request_id = req->request_id,
                        .token_index = 0, .err = XD_OK };
        double t0 = now_sec();
        int rc = cfg->generate(cfg->gen_ctx, req->prompt, req->prompt_len, n_predict,
                               fwd_chunk, &f);
        double ms = (now_sec() - t0) * 1000.0;
        if (f.err != XD_OK) {
            err = f.err;
            xd_log("DEMO-SERVER client=%s channel=%u req=%u fail reason=\"%s\" tokens=%u",
                   name, channel_id, req->request_id, xd_err_str(err), f.token_index);
            break;
        }

        bench_done_t done;
        memset(&done, 0, sizeof(done));
        done.magic = BENCH_MAGIC;
        done.type = rc == 0 ? MSG_DONE : MSG_ERROR;
        done.request_id = req->request_id;
        done.total_tokens = f.token_index;
        done.error_code = rc == 0 ? 0 : EIO;
        err = xd_send_record(c, &s, XD_REC_APP, &done, bench_done_wire_len());
        xd_log("DEMO-SERVER client=%s channel=%u req=%u prompt_bytes=%u n_predict=%u tokens=%u "
               "model=%s ms=%.1f%s%s",
               name, channel_id, req->request_id, req->prompt_len, n_predict, f.token_index,
               rc == 0 ? "ok" : "error", ms,
               err == XD_OK ? "" : " send_done=", err == XD_OK ? "" : xd_err_str(err));
        sodium_memzero(&msg, sizeof(msg));
        if (err != XD_OK) break;
        res->requests++;
    }

    /* Nothing of the conversation outlives the channel: the last request
     * (whichever way the loop ended) and the keys are wiped here; the reply
     * text went chunk by chunk in fwd_chunk(), and llama_http.c wipes its
     * own copies of both. */
    sodium_memzero(&msg, sizeof(msg));
    xd_session_kill(&s);
    res->end = err;
}

/* ---- client ----------------------------------------------------------- */

static int fail(xd_req_result_t *out, xd_session_t *s, xd_err_t err, const char *why) {
    out->ok = 0;
    out->err = err;
    snprintf(out->why, sizeof(out->why), "%s", why ? why : xd_err_str(err));
    if (s && err != XD_OK) xd_session_kill(s);
    return -1;
}

int xd_client_request(xd_chan_t *c, xd_session_t *s, uint32_t request_id,
                      const char *prompt, uint32_t n_predict, int timeout_ms,
                      xd_req_result_t *out) {
    memset(out, 0, sizeof(*out));
    if (s->dead) return fail(out, NULL, XD_ERR_CLOSED, "channel closed after an earlier failure");

    bench_request_t req;
    memset(&req, 0, sizeof(req));
    req.magic = BENCH_MAGIC;
    req.type = MSG_REQUEST;
    req.request_id = request_id;
    req.max_tokens = n_predict;
    req.temperature_milli = 800;
    size_t plen = strlen(prompt);
    if (plen > BENCH_MAX_PROMPT) plen = BENCH_MAX_PROMPT;
    memcpy(req.prompt, prompt, plen);
    req.prompt_len = (uint32_t)plen;

    double t_send = now_sec();
    xd_err_t err = xd_send_record(c, s, XD_REC_APP, &req, bench_request_wire_len(&req));
    if (err != XD_OK) return fail(out, s, err, NULL);

    double t_first = 0.0, t_last = 0.0;
    for (;;) {
        bench_msg_t msg;
        uint8_t type = 0;
        size_t len = 0;
        err = xd_recv_record(c, s, &type, &msg, sizeof(msg), &len, timeout_ms);
        double t_now = now_sec();
        if (err != XD_OK) return fail(out, s, err, NULL);
        if (type != XD_REC_APP || len < sizeof(msg.hdr) || msg.hdr.magic != BENCH_MAGIC)
            return fail(out, s, XD_ERR_MALFORMED, "malformed response");

        if (msg.hdr.type == MSG_CHUNK) {
            const bench_chunk_t *ch = &msg.chunk;
            if (len < offsetof(bench_chunk_t, text) || ch->text_len > BENCH_MAX_CHUNK ||
                len != bench_chunk_wire_len(ch) || ch->request_id != request_id ||
                ch->token_index != out->tokens)
                return fail(out, s, XD_ERR_MALFORMED, "malformed chunk");
            if (out->tokens == 0) t_first = t_now;
            t_last = t_now;
            out->tokens++;
            size_t room = sizeof(out->reply) - out->reply_len;
            size_t take = ch->text_len < room ? ch->text_len : room;
            memcpy(out->reply + out->reply_len, ch->text, take);
            out->reply_len += take;
        } else if (msg.hdr.type == MSG_DONE || msg.hdr.type == MSG_ERROR) {
            const bench_done_t *d = &msg.done;
            if (len != bench_done_wire_len() || d->request_id != request_id ||
                d->total_tokens != out->tokens)
                return fail(out, s, XD_ERR_MALFORMED, "malformed done");
            if (msg.hdr.type == MSG_ERROR) {
                /* Authenticated, well-formed: the model failed, the channel
                 * is fine. */
                char why[64];
                snprintf(why, sizeof(why), "server reported model error %d", d->error_code);
                return fail(out, NULL, XD_OK, why);
            }
            if (out->tokens == 0) return fail(out, NULL, XD_OK, "server returned zero tokens");
            out->ok = 1;
            out->ttft_ms = (t_first - t_send) * 1000.0;
            if (out->tokens > 1 && t_last > t_first) {
                out->tok_s_defined = 1;
                out->tok_s = (double)(out->tokens - 1) / (t_last - t_first);
            }
            return 0;
        } else {
            return fail(out, s, XD_ERR_MALFORMED, "unknown message type");
        }
    }
}

void xd_display_text(const char *in, size_t len, size_t max_chars, char *out) {
    size_t o = 0, chars = 0;
    int cont = 3; /* continuation bytes allowed after the current lead byte */
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)in[i];
        if ((ch & 0xC0) == 0x80) {
            /* Continuation byte: kept only as part of a character already
             * counted, and never more than three of them (so the output
             * stays within 4 bytes per character even for invalid UTF-8). */
            if (cont < 3) { out[o++] = (char)ch; cont++; }
            continue;
        }
        if (chars == max_chars) break;
        cont = 3;
        if (ch == '\t' || ch == '\n' || ch == '\r') {
            out[o++] = ' ';
        } else if (ch < 0x20 || ch == 0x7f) {
            continue; /* other control characters: dropped */
        } else if (ch == 0xC2 && i + 1 < len &&
                   (unsigned char)in[i + 1] >= 0x80 && (unsigned char)in[i + 1] <= 0x9F) {
            i++; /* C1 control character (U+0080..U+009F): dropped too */
            continue;
        } else if (ch == '"') {
            out[o++] = '\'';
        } else {
            out[o++] = (char)ch;
            if (ch >= 0x80) cont = 0; /* multi-byte lead */
        }
        chars++;
    }
    out[o] = '\0';
}
