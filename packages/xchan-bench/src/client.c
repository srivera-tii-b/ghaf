/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* client.c, benchmark client. Identical measurement code regardless of
 * which transport backend (sock, vsock, xchan or g2g) was compiled in:
 * everything here talks to a transport_t* through
 * transport_send()/transport_recv() only.
 *
 * ---------------------------------------------------------------------
 * WHAT IS TIMED, EXACTLY (read this before trusting a number):
 *
 *   t_send_start  : CLOCK_MONOTONIC timestamp taken immediately BEFORE the
 *                   transport_send() call that hands the request message
 *                   to the transport (socket write / xchan_send).
 *
 *   t_first_token : CLOCK_MONOTONIC timestamp taken immediately AFTER the
 *                   transport_recv() call that returns the FIRST MSG_CHUNK
 *                   for this request completes.
 *
 *   TTFT = t_first_token - t_send_start
 *
 *   This includes: serializing+sending the request, 100% of server-side
 *   processing up to emitting its first token (prompt processing/prefill,
 *   queueing, etc, or for the mock server the configured --ttft-ms delay),
 *   and receiving that first chunk back. It does NOT include connection
 *   setup (transport_connect() happens once, before the timed loop).
 *
 *   t_last_token  : CLOCK_MONOTONIC timestamp taken immediately AFTER the
 *                   transport_recv() call that returns the LAST MSG_CHUNK
 *                   (the one immediately preceding MSG_DONE) completes.
 *
 *   generation_wall_time = t_last_token - t_first_token
 *
 *   tokens_per_sec: generation throughput is a STEADY-STATE decode rate,
 *   not "total tokens / total time" (that would silently bury TTFT inside
 *   the throughput number and make the two metrics redundant). With N
 *   chunks received for a request, there are N-1 inter-token intervals
 *   between "first token arrived" and "last token arrived", so:
 *
 *       tokens_per_sec = (N - 1) / generation_wall_time     (N > 1)
 *       tokens_per_sec = not defined (reported as NaN/omitted) (N == 1)
 *
 *   A request's end-to-end latency (t_done - t_send_start) is also
 *   recorded for reference but is not one of the two headline metrics.
 * ---------------------------------------------------------------------
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "proto.h"
#include "stats.h"
#include "transport.h"

/* An xchan channel handed out by WAIT_CHANNEL may already be dead: crosvm
 * opens a client's next channel in advance, and a server that stopped since
 * leaves it detached but still handed out. Its first request fails with
 * ECONNRESET before the server has said anything; closing it is what lets
 * crosvm open a fresh one, so take the next channel instead, a bounded
 * number of times, and only before any request has gone through: a server
 * that closes later has died mid-run, and that is a failure. Same rule as
 * xchan-demo-client's. */
#define STALE_CHANNEL_RETRIES 3

/* run_one_request(): the peer closed before sending anything back. */
#define REQ_STALE (-2)

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

typedef struct {
    int    ok;             /* 1 if this request completed successfully */
    double ttft_sec;
    double tokens_per_sec; /* 0.0 if undefined (fewer than 2 tokens) */
    int    tokens_per_sec_defined;
    double e2e_sec;
    int    total_tokens;
} request_result_t;

/* Runs one request/response exchange over `t` and fills *out with the
 * measurements. Returns 0 on success, -1 on a hard failure (out->ok==0),
 * REQ_STALE if the peer closed before its first reply. */
static int run_one_request(transport_t *t, uint32_t request_id,
                            const char *prompt, uint32_t max_tokens,
                            request_result_t *out) {
    memset(out, 0, sizeof(*out));

    bench_request_t req;
    memset(&req, 0, sizeof(req));
    req.magic = BENCH_MAGIC;
    req.type = MSG_REQUEST;
    req.request_id = request_id;
    req.max_tokens = max_tokens;
    req.temperature_milli = 800; /* fixed for reproducibility; not load-bearing here */
    size_t plen = strlen(prompt);
    if (plen > BENCH_MAX_PROMPT) plen = BENCH_MAX_PROMPT;
    memcpy(req.prompt, prompt, plen);
    req.prompt_len = (uint32_t)plen;

    double t_send_start = now_sec();
    ssize_t wn = transport_send(t, &req, bench_request_wire_len(&req));
    if (wn < 0) {
        int e = errno;
        fprintf(stderr, "request %u: send failed: %s\n", request_id, strerror(e));
        return e == ECONNRESET ? REQ_STALE : -1;
    }

    bench_msg_t msg;
    int have_first = 0, got_reply = 0;
    double t_first_token = 0.0, t_last_token = 0.0;
    int tokens = 0;

    for (;;) {
        ssize_t n = transport_recv(t, &msg, sizeof(msg));
        double t_now = now_sec();
        if (n < 0) {
            int e = errno;
            if (e == ECANCELED) {
                fprintf(stderr, "request %u: peer aborted mid-stream (ECANCELED)\n", request_id);
            } else {
                fprintf(stderr, "request %u: recv failed: %s\n", request_id, strerror(e));
            }
            return e == ECONNRESET && !got_reply ? REQ_STALE : -1;
        }
        got_reply = 1;
        if (n < (ssize_t)sizeof(msg.hdr) || msg.hdr.magic != BENCH_MAGIC) {
            fprintf(stderr, "request %u: bad magic/short response\n", request_id);
            return -1;
        }
        uint32_t mtype = msg.hdr.type;

        if (mtype == MSG_CHUNK) {
            if (!have_first) {
                t_first_token = t_now;
                have_first = 1;
            }
            t_last_token = t_now;
            tokens++;
        } else if (mtype == MSG_DONE || mtype == MSG_ERROR) {
            if (mtype == MSG_ERROR) {
                fprintf(stderr, "request %u: server reported error %d\n",
                        request_id, msg.done.error_code);
                return -1;
            }
            double t_done = t_now;
            out->ok = 1;
            out->total_tokens = tokens;
            out->e2e_sec = t_done - t_send_start;
            if (have_first) {
                out->ttft_sec = t_first_token - t_send_start;
                if (tokens > 1) {
                    out->tokens_per_sec_defined = 1;
                    out->tokens_per_sec = (double)(tokens - 1) / (t_last_token - t_first_token);
                }
            } else {
                fprintf(stderr, "request %u: DONE with zero chunks\n", request_id);
                out->ok = 0;
                return -1;
            }
            return 0;
        } else {
            fprintf(stderr, "request %u: unknown message type %u\n", request_id, mtype);
            return -1;
        }
    }
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s -e <endpoint> [-n num_requests] [-t max_tokens] [-p prompt] [-v]\n"
        "  -e endpoint     unix socket path (sock backend) or xchan device (xchan backend)\n"
        "  -n num_requests number of requests to issue (default 10)\n"
        "  -t max_tokens   requested generation length (default 32)\n"
        "  -p prompt       prompt text (default \"benchmark prompt\")\n"
        "  -v              print per-request TTFT/tok-s as they complete\n"
        "backend compiled in: %s\n",
        argv0, transport_backend_name());
}

int main(int argc, char **argv) {
    const char *endpoint = NULL;
    int num_requests = 10;
    uint32_t max_tokens = 32;
    const char *prompt = "benchmark prompt";
    int verbose = 0;

    int opt;
    while ((opt = getopt(argc, argv, "e:n:t:p:vh")) != -1) {
        switch (opt) {
            case 'e': endpoint = optarg; break;
            case 'n': num_requests = atoi(optarg); break;
            case 't': max_tokens = (uint32_t)atoi(optarg); break;
            case 'p': prompt = optarg; break;
            case 'v': verbose = 1; break;
            default: usage(argv[0]); return 2;
        }
    }
    if (!endpoint || num_requests <= 0) {
        usage(argv[0]);
        return 2;
    }

    transport_t *t = transport_connect(endpoint);
    if (!t) {
        fprintf(stderr, "connect to %s (%s backend) failed: %s\n",
                endpoint, transport_backend_name(), strerror(errno));
        return 1;
    }

    double *ttft = calloc((size_t)num_requests, sizeof(double));
    double *tps  = calloc((size_t)num_requests, sizeof(double));
    int n_ttft = 0, n_tps = 0, n_fail = 0, n_stale = 0;

    for (int i = 0; i < num_requests; i++) {
        request_result_t r;
        int rc = run_one_request(t, (uint32_t)(i + 1), prompt, max_tokens, &r);
        if (rc == REQ_STALE && i == 0 && n_stale < STALE_CHANNEL_RETRIES) {
            n_stale++;
            fprintf(stderr, "request 1: the channel closed before the first reply (stale), "
                    "taking the next one\n");
            transport_close(t);
            t = transport_connect(endpoint);
            if (!t) {
                fprintf(stderr, "connect to %s (%s backend) failed: %s\n",
                        endpoint, transport_backend_name(), strerror(errno));
                free(ttft);
                free(tps);
                return 1;
            }
            i--;
            continue;
        }
        if (rc != 0 || !r.ok) {
            n_fail++;
            continue;
        }
        ttft[n_ttft++] = r.ttft_sec;
        if (r.tokens_per_sec_defined) tps[n_tps++] = r.tokens_per_sec;
        if (verbose) {
            if (r.tokens_per_sec_defined)
                printf("req %d: ttft=%.3fms tokens=%d tok/s=%.2f e2e=%.3fms\n",
                       i + 1, r.ttft_sec * 1000.0, r.total_tokens,
                       r.tokens_per_sec, r.e2e_sec * 1000.0);
            else
                printf("req %d: ttft=%.3fms tokens=%d tok/s=n/a e2e=%.3fms\n",
                       i + 1, r.ttft_sec * 1000.0, r.total_tokens, r.e2e_sec * 1000.0);
        }
    }

    transport_close(t);

    printf("backend=%s requests=%d ok=%d failed=%d\n",
           transport_backend_name(), num_requests, n_ttft, n_fail);

    if (n_ttft > 0) {
        bench_stats_t s = bench_compute_stats(ttft, n_ttft);
        printf("TTFT (ms): min=%.3f median=%.3f p99=%.3f max=%.3f mean=%.3f n=%d\n",
               s.min * 1000.0, s.median * 1000.0, s.p99 * 1000.0, s.max * 1000.0,
               s.mean * 1000.0, s.n);
    } else {
        printf("TTFT: no successful requests\n");
    }

    if (n_tps > 0) {
        bench_stats_t s = bench_compute_stats(tps, n_tps);
        printf("tokens/sec: min=%.2f median=%.2f p99=%.2f max=%.2f mean=%.2f n=%d\n",
               s.min, s.median, s.p99, s.max, s.mean, s.n);
    } else {
        printf("tokens/sec: no request produced >1 token\n");
    }

    free(ttft);
    free(tps);
    return n_fail > 0 ? 1 : 0;
}
