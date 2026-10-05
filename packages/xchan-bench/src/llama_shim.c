/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* llama_shim.c, throwaway shim that lets the (already-validated) bench
 * client drive a real llama.cpp `llama-server` instead of mock_server.
 *
 * STATUS: run against a real llama-server (llama.cpp 0.3.0,
 * Qwen2.5-0.5B-Instruct Q4_K_M), it works end to end, the bench client
 * gets the full requested number of chunks and the throughput it computes
 * matches llama-server's own `predicted_per_second` to within a couple of
 * percent.
 *
 * It is a drop-in replacement for mock_server ONLY: same length-prefixed
 * proto.h framing (copy-pasted from mock_server.c/transport_sock.c on
 * purpose, this file must not depend on transport.h/transport_sock.c,
 * which are the client's validated code paths and are not to be touched or
 * reused here).
 *
 * It listens on a unix socket OR on AF_VSOCK (`-e vsock:<port>`). The vsock
 * mode is what the host-model arm needs: with the model on the host, a
 * guest reaches it directly over guest-to-host vsock and no relay is
 * involved, so the shim itself has to be the thing bound to the vsock port.
 * The AF_VSOCK listen is hand-rolled here for the same reason the framing
 * is, keeping this file independent of the client's transport code.
 *
 * For every bench_request_t it receives, it opens a fresh plain-HTTP
 * connection to a llama-server `/completion` endpoint with
 * {"prompt":..., "n_predict":..., "stream":true}, and as each Server-Sent
 * Event arrives it is decoded and forwarded immediately as one
 * bench_chunk_t. No buffering of the whole completion: each decoded SSE
 * "data:" line is turned into a MSG_CHUNK the moment it's fully parsed.
 *
 * Deliberately minimal:
 *  - hand-rolled HTTP/1.1 request (fixed method/path/host, so no general
 *    request-line/URL handling needed)
 *  - hand-rolled response parser: status line + headers, then EITHER
 *    chunked-transfer decoding OR content-length OR read-to-EOF, unified
 *    into one "give me the next bit of decoded body" primitive
 *  - hand-rolled SSE line splitter + tiny flat JSON field extractor
 *    (looks for the literal "\"content\":" / "\"stop\":" keys; llama.cpp's
 *    per-token JSON objects are flat enough that this is safe and does not
 *    need a real JSON parser)
 *  - one connection at a time, one llama-server request at a time,
 *    matches how mock_server and the client are actually used here.
 *
 * The HTTP/SSE/JSON half described above now lives in llama_http.c, moved
 * there unchanged so xchan-demo-server can share it; this file keeps the
 * proto.h framing, the listeners and the per-connection loop.
 *
 * Measurement tooling for the host-model arm of the benchmark only; do not
 * build on it.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/vm_sockets.h>

#include "llama_http.h"
#include "proto.h"

/* ---------------------------------------------------------------------
 * proto.h framing, duplicated from mock_server.c (see file header: the
 * server side intentionally does not share transport.h with the client).
 * ------------------------------------------------------------------- */

static int read_full(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) { errno = ECONNRESET; return -1; }
        got += (size_t)n;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        sent += (size_t)n;
    }
    return 0;
}

static int send_msg(int fd, const void *buf, size_t len) {
    uint32_t be_len = htonl((uint32_t)len);
    if (write_full(fd, &be_len, sizeof(be_len)) != 0) return -1;
    if (len > 0 && write_full(fd, buf, len) != 0) return -1;
    return 0;
}

static int recv_msg(int fd, void *buf, size_t cap, size_t *out_len) {
    uint32_t be_len;
    if (read_full(fd, &be_len, sizeof(be_len)) != 0) return -1;
    uint32_t len = ntohl(be_len);
    if ((size_t)len > cap) { errno = EMSGSIZE; return -1; }
    if (len > 0 && read_full(fd, buf, len) != 0) return -1;
    *out_len = len;
    return 0;
}

/* ---------------------------------------------------------------------
 * bench-protocol server loop.
 * ------------------------------------------------------------------- */

/* Upper bound on the per-request text echo (see forward_ctx_t.echo). Fixed
 * so the context stays a stack object; --echo only lowers the amount used. */
#define ECHO_CAP 256
static size_t echo_bytes = 120;

typedef struct {
    int cfd;
    uint32_t request_id;
    uint32_t token_index;
    int send_failed;
    /* Bounded copy of the start of the completion, logged once per request.
     * The bench client discards chunk text (it only times arrivals), so
     * without this there is nothing anywhere that shows the tokens were real
     * rather than empty strings, and on the target the only readable output
     * is the host journal. */
    char echo[ECHO_CAP];
    size_t echo_len;
} forward_ctx_t;

/* Always returns 0 (go on): unlike xchan-demo-server, the shim lets a
 * request whose client went away run to the end, for the echo log line. */
static int forward_chunk(void *vctx, const char *text, size_t len) {
    forward_ctx_t *fc = vctx;

    /* Accumulate before the send-failure bail-out: even a request whose
     * client went away is worth logging, since it says whether the model
     * produced anything. */
    if (echo_bytes > 0 && fc->echo_len + 1 < echo_bytes) {
        size_t room = echo_bytes - 1 - fc->echo_len;
        size_t take = len < room ? len : room;
        memcpy(fc->echo + fc->echo_len, text, take);
        fc->echo_len += take;
        fc->echo[fc->echo_len] = '\0';
    }

    if (fc->send_failed) return 0;

    bench_chunk_t chunk;
    memset(&chunk, 0, sizeof(chunk));
    chunk.magic = BENCH_MAGIC;
    chunk.type = MSG_CHUNK;
    chunk.request_id = fc->request_id;
    chunk.token_index = fc->token_index++;
    if (len > BENCH_MAX_CHUNK) len = BENCH_MAX_CHUNK; /* truncate defensively */
    memcpy(chunk.text, text, len);
    chunk.text_len = (uint32_t)len;

    if (send_msg(fc->cfd, &chunk, bench_chunk_wire_len(&chunk)) != 0) {
        fprintf(stderr, "llama_shim: send chunk failed: %s\n", strerror(errno));
        fc->send_failed = 1;
    }
    return 0;
}

static void serve_connection(int cfd, const llama_target_t *tgt) {
    bench_msg_t msg;
    for (;;) {
        size_t len;
        if (recv_msg(cfd, &msg, sizeof(msg), &len) != 0) {
            if (errno != ECONNRESET)
                fprintf(stderr, "llama_shim: recv failed: %s\n", strerror(errno));
            return;
        }
        if (len < sizeof(msg.hdr) || msg.hdr.magic != BENCH_MAGIC || msg.hdr.type != MSG_REQUEST) {
            fprintf(stderr, "llama_shim: bad request message\n");
            return;
        }
        bench_request_t req = msg.request;

        forward_ctx_t fc;
        memset(&fc, 0, sizeof(fc));
        fc.cfd = cfd;
        fc.request_id = req.request_id;
        int rc = llama_stream_completion(tgt, req.prompt, req.prompt_len,
                                          req.max_tokens, forward_chunk, &fc);

        if (echo_bytes > 0) {
            /* One line per request, newlines flattened, so the host journal
             * stays readable. */
            for (size_t i = 0; i < fc.echo_len; i++)
                if (fc.echo[i] == '\n' || fc.echo[i] == '\r' || fc.echo[i] == '\t')
                    fc.echo[i] = ' ';
            fprintf(stderr, "llama_shim: req=%u rc=%d tokens=%u text=\"%s\"%s\n",
                    req.request_id, rc, fc.token_index, fc.echo,
                    fc.echo_len + 1 >= echo_bytes ? "..." : "");
        }

        if (fc.send_failed) return; /* client transport already broken */

        bench_done_t done;
        memset(&done, 0, sizeof(done));
        done.magic = BENCH_MAGIC;
        done.request_id = req.request_id;
        if (rc == 0) {
            done.type = MSG_DONE;
            done.total_tokens = fc.token_index;
            done.error_code = 0;
        } else {
            done.type = MSG_ERROR;
            done.total_tokens = fc.token_index;
            done.error_code = EIO;
        }
        if (send_msg(cfd, &done, bench_done_wire_len()) != 0) {
            fprintf(stderr, "llama_shim: send done/error failed: %s\n", strerror(errno));
            return;
        }
    }
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s -e <endpoint> [--host H] [--port P] [--echo N]\n"
        "  -e endpoint      where the bench client reaches this shim:\n"
        "                     <path>        unix socket (removed+recreated)\n"
        "                     vsock:<port>  AF_VSOCK on VMADDR_CID_ANY\n"
        "  --host H         llama-server host (default 127.0.0.1)\n"
        "  --port P         llama-server port (default 8899)\n"
        "  --echo N         log the first N bytes of each completion to stderr\n"
        "                   (default 120, max %d; 0 disables)\n",
        argv0, ECHO_CAP - 1);
}

/* Unix-socket listen: unlinks any stale node first, which is safe here
 * because the path is ours by construction (a bring-up path under /run or
 * /tmp) and a leftover node from a killed shim would otherwise make every
 * restart fail with EADDRINUSE. */
static int listen_unix(const char *path) {
    unlink(path);

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket(AF_UNIX)"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind(AF_UNIX)");
        close(lfd);
        return -1;
    }
    if (listen(lfd, 16) != 0) { perror("listen"); close(lfd); return -1; }
    return lfd;
}

/* AF_VSOCK listen on VMADDR_CID_ANY, so the host accepts from any guest.
 * Guest-to-host is the direction vsock supports natively; the host-model arm
 * puts the model on the host, so this is the whole transport, no relay. */
static int listen_vsock(const char *portstr) {
    char *end = NULL;
    unsigned long port = strtoul(portstr, &end, 10);
    if (!*portstr || (end && *end != '\0') || port > 0xffffffffUL) {
        fprintf(stderr, "llama_shim: -e vsock:<port> needs a numeric port, got \"%s\"\n",
                portstr);
        return -1;
    }

    int lfd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket(AF_VSOCK)"); return -1; }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = (unsigned int)port;

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind(AF_VSOCK)");
        close(lfd);
        return -1;
    }
    if (listen(lfd, 16) != 0) { perror("listen"); close(lfd); return -1; }
    return lfd;
}

int main(int argc, char **argv) {
    const char *endpoint = NULL;
    llama_target_t tgt = { .host = "127.0.0.1", .port = 8899, .log_prefix = "llama_shim" };

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) { endpoint = argv[++i]; }
        else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) { tgt.host = argv[++i]; }
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) { tgt.port = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--echo") == 0 && i + 1 < argc) {
            long v = atol(argv[++i]);
            if (v < 0) v = 0;
            if (v > ECHO_CAP - 1) v = ECHO_CAP - 1;
            echo_bytes = (size_t)v;
        }
        else { usage(argv[0]); return 2; }
    }
    if (!endpoint) { usage(argv[0]); return 2; }

    int is_vsock = strncmp(endpoint, "vsock:", 6) == 0;
    int lfd = is_vsock ? listen_vsock(endpoint + 6) : listen_unix(endpoint);
    if (lfd < 0) return 1;

    fprintf(stderr, "llama_shim: listening on %s, forwarding to http://%s:%d\n",
            endpoint, tgt.host, tgt.port);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        serve_connection(cfd, &tgt);
        close(cfd);
    }

    close(lfd);
    if (!is_vsock) unlink(endpoint);
    return 0;
}
