/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* mock_server.c, backend-agnostic mock inference server for validating the
 * benchmark client's measurements before any real inference server exists.
 *
 * It speaks the wire protocol in proto.h over whichever transport backend it
 * was compiled against, using the same transport.h contract the client uses.
 *
 * This was socket-only until the transport comparison needed a server that
 * could listen on xchan: a unix socket cannot cross guests, so measuring
 * guest-to-guest requires the server to run every backend. Sharing one
 * server implementation across all three arms is also what makes the
 * comparison trustworthy, a measured difference is then the transport,
 * not two different server implementations.
 *
 * For every request it streams `--tokens` chunks:
 *   - waits `--ttft-ms` milliseconds, then sends chunk 0 (this is the
 *     delay the client's TTFT measurement should reproduce almost exactly)
 *   - waits `--itl-ms` milliseconds between each subsequent chunk (this is
 *     the delay that (tokens-1)/generation_wall_time should reproduce as
 *     tokens_per_sec ~= 1000/itl_ms)
 *   - sends MSG_DONE
 *
 * Handles one client connection at a time, sequentially, looping accept();
 * that's all a benchmark harness needs.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "proto.h"
#include "transport.h"

static void sleep_ms(double ms) {
    if (ms <= 0.0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000.0);
    ts.tv_nsec = (long)((ms - (double)ts.tv_sec * 1000.0) * 1e6);
    nanosleep(&ts, NULL);
}

typedef struct {
    double ttft_ms;
    double itl_ms;
    uint32_t tokens_cap;
    const char *chunk_text;
} server_config_t;

/* Serve requests on one connection until the client disconnects or sends a
 * malformed message. Returns when the connection ends. */
static void serve_connection(transport_t *t, const server_config_t *cfg) {
    bench_msg_t msg;
    for (;;) {
        ssize_t len = transport_recv(t, &msg, sizeof(msg));
        if (len < 0) {
            if (errno != ECONNRESET)
                fprintf(stderr, "mock_server: recv failed: %s\n", strerror(errno));
            return;
        }
        if ((size_t)len < sizeof(msg.hdr) || msg.hdr.magic != BENCH_MAGIC || msg.hdr.type != MSG_REQUEST) {
            fprintf(stderr, "mock_server: bad request message\n");
            return;
        }
        bench_request_t req = msg.request;
        uint32_t tokens = req.max_tokens;
        if (tokens > cfg->tokens_cap) tokens = cfg->tokens_cap;
        if (tokens == 0) tokens = 1;

        for (uint32_t i = 0; i < tokens; i++) {
            sleep_ms(i == 0 ? cfg->ttft_ms : cfg->itl_ms);

            bench_chunk_t chunk;
            memset(&chunk, 0, sizeof(chunk));
            chunk.magic = BENCH_MAGIC;
            chunk.type = MSG_CHUNK;
            chunk.request_id = req.request_id;
            chunk.token_index = i;
            int n = snprintf(chunk.text, sizeof(chunk.text), "%s%u ", cfg->chunk_text, i);
            if (n < 0) n = 0;
            if ((size_t)n >= sizeof(chunk.text)) n = sizeof(chunk.text) - 1;
            chunk.text_len = (uint32_t)n;

            if (transport_send(t, &chunk, bench_chunk_wire_len(&chunk)) < 0) {
                fprintf(stderr, "mock_server: send chunk failed: %s\n", strerror(errno));
                return;
            }
        }

        bench_done_t done;
        memset(&done, 0, sizeof(done));
        done.magic = BENCH_MAGIC;
        done.type = MSG_DONE;
        done.request_id = req.request_id;
        done.total_tokens = tokens;
        done.error_code = 0;
        if (transport_send(t, &done, bench_done_wire_len()) < 0) {
            fprintf(stderr, "mock_server: send done failed: %s\n", strerror(errno));
            return;
        }
    }
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s (-e <socket_path> | --vsock <port>) [--ttft-ms N] [--itl-ms N] [--tokens N] [--text STR]\n"
        "  -e socket_path   unix socket path to listen on (removed+recreated)\n"
        "  --vsock port     listen on AF_VSOCK <port> instead, for the vsock arm\n"
        "                   of the transport comparison. Mutually exclusive with -e.\n"
        "\n"
        "  On the xchan backend -e names the device node (e.g. /dev/xchan0).\n"
        "  --ttft-ms N      delay before the first chunk of each response (default 50)\n"
        "  --itl-ms N       delay between subsequent chunks (default 20)\n"
        "  --tokens N       number of chunks to generate per request, capped by client's max_tokens (default 32)\n"
        "  --text STR       text prefix used in each generated chunk (default \"tok\")\n",
        argv0);
}

int main(int argc, char **argv) {
    const char *sock_path = NULL;
    int vsock_port = -1;
    server_config_t cfg = { .ttft_ms = 50.0, .itl_ms = 20.0, .tokens_cap = 32, .chunk_text = "tok" };

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) { sock_path = argv[++i]; }
        else if (strcmp(argv[i], "--vsock") == 0 && i + 1 < argc) { vsock_port = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--ttft-ms") == 0 && i + 1 < argc) { cfg.ttft_ms = atof(argv[++i]); }
        else if (strcmp(argv[i], "--itl-ms") == 0 && i + 1 < argc) { cfg.itl_ms = atof(argv[++i]); }
        else if (strcmp(argv[i], "--tokens") == 0 && i + 1 < argc) { cfg.tokens_cap = (uint32_t)atoi(argv[++i]); }
        else if (strcmp(argv[i], "--text") == 0 && i + 1 < argc) { cfg.chunk_text = argv[++i]; }
        else { usage(argv[0]); return 2; }
    }
    /* Exactly one listening mode. Accepting both would leave the operator
     * guessing which one a measurement actually used. */
    if ((sock_path == NULL) == (vsock_port < 0)) { usage(argv[0]); return 2; }

    /* One endpoint string, whatever the backend: a path for sock, a port for
     * vsock, a device node (or NULL) for xchan. The backend compiled in
     * decides how to read it. */
    char portbuf[16];
    const char *endpoint;
    if (vsock_port >= 0) {
        snprintf(portbuf, sizeof(portbuf), "%d", vsock_port);
        endpoint = portbuf;
    } else {
        endpoint = sock_path;
    }

    transport_listener_t *l = transport_listen(endpoint);
    if (!l) {
        fprintf(stderr, "mock_server: listen on %s (%s backend) failed: %s\n",
                endpoint, transport_backend_name(), strerror(errno));
        return 1;
    }

    fprintf(stderr, "mock_server: listening on %s (%s backend, ttft=%.1fms itl=%.1fms tokens=%u)\n",
            endpoint, transport_backend_name(), cfg.ttft_ms, cfg.itl_ms, cfg.tokens_cap);

    for (;;) {
        transport_t *t = transport_accept(l);
        if (!t) {
            fprintf(stderr, "mock_server: accept failed: %s\n", strerror(errno));
            break;
        }
        serve_connection(t, &cfg);
        transport_close(t);
    }

    transport_listener_close(l);
    return 0;
}
