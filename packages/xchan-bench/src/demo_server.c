/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* demo_server.c, xchan-demo-server: the model side of the encrypted
 * guest-to-guest LLM demo (runs in admin-vm, next to llama-server).
 *
 *   xchan-demo-server -e /dev/xchan0 --key <seed file> --clients <dir>
 *                     --llama http://127.0.0.1:<port>
 *
 * Waits for channels forever: xchan channels on the device, or g2gchan
 * clients with -e g2g. Each channel gets its own thread:
 * handshake (demo_crypto.c), then encrypted requests forwarded to
 * llama-server's /completion and streamed back token by token, until the
 * client closes, sends CLOSE, or anything fails, then the channel fd is
 * closed. The pinned client keys are every <name>.pk in --clients; <name>
 * is what the logs call that client.
 *
 * Bounded waits: each handshake step and the gap between requests are
 * timed (demo_session.h); the llama-server connection has a socket timeout.
 * One exception, an availability matter only: a receive that the host
 * leaves half-delivered (first fragment of a multi-fragment xchan message,
 * then nothing) blocks in the driver's uninterruptible committed wait. That
 * pins that one channel's thread; other channels are unaffected.
 */
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "demo_crypto.h"
#include "demo_session.h"
#include "libxchan.h"
#include "g2gchan.h"
#include "llama_http.h"

#define MAX_CLIENTS 64
#define IDLE_TIMEOUT_MS (10 * 60 * 1000)
#define LLAMA_IO_TIMEOUT_SEC 120

static uint8_t g_pk[XD_PK_BYTES];
static uint8_t g_sk[XD_SK_BYTES];
static xd_client_key_t g_clients[MAX_CLIENTS];
static size_t g_n_clients;
static char g_llama_host[256];
static llama_target_t g_llama;
static xd_server_cfg_t g_cfg;

static ssize_t chan_send(xd_chan_t *c, const void *buf, size_t len) {
    return xchan_send(c->fd, buf, len);
}
static ssize_t chan_recv(xd_chan_t *c, void *buf, size_t cap) {
    return xchan_recv(c->fd, buf, cap);
}

/* -e g2g: guest-to-guest shared memory, no host in the path (g2gchan). */
static ssize_t g2g_chan_send(xd_chan_t *c, const void *buf, size_t len) {
    return g2gc_send(c->user, buf, len);
}
static ssize_t g2g_chan_recv(xd_chan_t *c, void *buf, size_t cap) {
    return g2gc_recv(c->user, buf, cap);
}

static int gen_llama(void *gen_ctx, const char *prompt, size_t prompt_len, uint32_t n_predict,
                     int (*on_chunk)(void *ctx, const char *text, size_t len), void *cb_ctx) {
    return llama_stream_completion(gen_ctx, prompt, prompt_len, n_predict, on_chunk, cb_ctx);
}

typedef struct {
    int fd;
    g2gc_t *g;          /* -e g2g: the channel; fd is then -1 */
    unsigned channel_id;
} chan_job_t;

static void *channel_thread(void *arg) {
    chan_job_t job = *(chan_job_t *)arg;
    free(arg);
    xd_chan_t c = job.g
        ? (xd_chan_t){ .fd = g2gc_fd(job.g), .send = g2g_chan_send, .recv = g2g_chan_recv, .user = job.g }
        : (xd_chan_t){ .fd = job.fd, .send = chan_send, .recv = chan_recv, .user = NULL };
    xd_serve_result_t res;
    xd_serve_channel(&g_cfg, &c, job.channel_id, &res);
    if (job.g) g2gc_close(job.g); else close(job.fd);
    return NULL;
}

static int name_ok(const char *s, size_t n) {
    if (n == 0 || n >= sizeof(g_clients[0].name)) return 0;
    for (size_t i = 0; i < n; i++) {
        char ch = s[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.'))
            return 0;
    }
    return 1;
}

/* Every <name>.pk in dir. A malformed key file is fatal: a silently skipped
 * client is harder to diagnose than a server that refuses to start. */
static int load_clients(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        xd_log("DEMO-SERVER fatal: cannot open --clients %s: %s", dir, strerror(errno));
        return -1;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if (n <= 3 || strcmp(e->d_name + n - 3, ".pk") != 0 || e->d_name[0] == '.') continue;
        if (!name_ok(e->d_name, n - 3)) {
            xd_log("DEMO-SERVER fatal: client key file name not [A-Za-z0-9._-]: %s", e->d_name);
            closedir(d);
            return -1;
        }
        if (g_n_clients == MAX_CLIENTS) {
            xd_log("DEMO-SERVER fatal: more than %d client keys in %s", MAX_CLIENTS, dir);
            closedir(d);
            return -1;
        }
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        xd_client_key_t *k = &g_clients[g_n_clients];
        const char *why = NULL;
        if (xd_read_hex32(path, k->pk, &why) != 0) {
            xd_log("DEMO-SERVER fatal: client key %s: %s", path, why);
            closedir(d);
            return -1;
        }
        memcpy(k->name, e->d_name, n - 3);
        k->name[n - 3] = '\0';
        for (size_t i = 0; i < g_n_clients; i++) {
            if (sodium_memcmp(g_clients[i].pk, k->pk, XD_PK_BYTES) == 0) {
                xd_log("DEMO-SERVER fatal: %s and %s hold the same key", g_clients[i].name, k->name);
                closedir(d);
                return -1;
            }
        }
        g_n_clients++;
    }
    closedir(d);
    if (g_n_clients == 0) {
        xd_log("DEMO-SERVER fatal: no *.pk client keys in %s", dir);
        return -1;
    }
    return 0;
}

/* http://<host>:<port>[/], llama_http.c only needs host and port. */
static int parse_llama_url(const char *url) {
    const char *p = url;
    if (strncmp(p, "http://", 7) != 0) return -1;
    p += 7;
    const char *colon = strrchr(p, ':');
    if (!colon || colon == p || (size_t)(colon - p) >= sizeof(g_llama_host)) return -1;
    memcpy(g_llama_host, p, (size_t)(colon - p));
    g_llama_host[colon - p] = '\0';
    char *end = NULL;
    long port = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || port < 1 || port > 65535) return -1;
    if (*end == '/') end++;
    if (*end != '\0') return -1;
    g_llama.host = g_llama_host;
    g_llama.port = (int)port;
    g_llama.log_prefix = "DEMO-SERVER llama";
    g_llama.io_timeout_sec = LLAMA_IO_TIMEOUT_SEC;
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s -e <xchan device | g2g> --key <seed file> --clients <dir of *.pk>\n"
        "          --llama http://<host>:<port>\n", argv0);
}

int main(int argc, char **argv) {
    const char *dev = NULL, *key = NULL, *clients = NULL, *llama = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) dev = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key = argv[++i];
        else if (strcmp(argv[i], "--clients") == 0 && i + 1 < argc) clients = argv[++i];
        else if (strcmp(argv[i], "--llama") == 0 && i + 1 < argc) llama = argv[++i];
        else { usage(argv[0]); return 2; }
    }
    if (!dev || !key || !clients || !llama) { usage(argv[0]); return 2; }

    /* A llama-server that drops the connection must not kill the server. */
    signal(SIGPIPE, SIG_IGN);

    if (sodium_init() < 0) {
        xd_log("DEMO-SERVER fatal: sodium_init failed");
        return 1;
    }
    const char *why = NULL;
    if (xd_load_identity(key, g_pk, g_sk, &why) != 0) {
        xd_log("DEMO-SERVER fatal: identity %s: %s", key, why);
        return 1;
    }
    if (load_clients(clients) != 0) return 1;
    if (parse_llama_url(llama) != 0) {
        xd_log("DEMO-SERVER fatal: --llama wants http://<host>:<port>, got \"%s\"", llama);
        return 1;
    }

    g_cfg.sk = g_sk;
    g_cfg.clients = g_clients;
    g_cfg.n_clients = g_n_clients;
    g_cfg.generate = gen_llama;
    g_cfg.gen_ctx = &g_llama;
    g_cfg.handshake_timeout_ms = XD_HANDSHAKE_TIMEOUT_MS;
    g_cfg.hello_wait_ms = -1; /* see xd_serve_channel() */
    g_cfg.idle_timeout_ms = IDLE_TIMEOUT_MS;

    char fp[9];
    xd_fingerprint(g_pk, fp);
    char names[MAX_CLIENTS * 72] = "";
    for (size_t i = 0; i < g_n_clients; i++) {
        char one[80], cfp[9];
        xd_fingerprint(g_clients[i].pk, cfp);
        snprintf(one, sizeof(one), "%s%.63s:%s", i ? "," : "", g_clients[i].name, cfp);
        strncat(names, one, sizeof(names) - strlen(names) - 1);
    }
    xd_log("DEMO-SERVER start fp=%s clients=%s llama=%s:%d device=%s",
           fp, names, g_llama.host, g_llama.port, dev);

    if (strcmp(dev, "g2g") == 0) {
        /* One process per VM: EL2's mailbox has one slot and one reader. */
        g2gc_listener_t *l = g2gc_listen();
        unsigned id = 0;
        if (!l) {
            xd_log("DEMO-SERVER fatal: g2g listen: %s", strerror(errno));
            return 1;
        }
        for (;;) {
            g2gc_t *g = g2gc_accept(l, -1);
            if (!g) {
                xd_log("DEMO-SERVER g2g accept failed: %s", strerror(errno));
                sleep(1);
                continue;
            }
            chan_job_t *job = malloc(sizeof(*job));
            if (!job) {
                xd_log("DEMO-SERVER g2g channel dropped: out of memory");
                g2gc_close(g);
                continue;
            }
            job->fd = -1;
            job->g = g;
            job->channel_id = ++id;
            pthread_t th;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            int rc = pthread_create(&th, &attr, channel_thread, job);
            pthread_attr_destroy(&attr);
            if (rc != 0) {
                xd_log("DEMO-SERVER g2g channel=%u dropped: pthread_create: %s", id, strerror(rc));
                free(job);
                g2gc_close(g);
            }
        }
    }

    int devfd = xchan_open(dev);
    if (devfd < 0) {
        xd_log("DEMO-SERVER fatal: open %s: %s", dev, strerror(errno));
        return 1;
    }

    for (;;) {
        struct xchan_channel_info info;
        int fd = xchan_wait_channel(devfd, &info);
        if (fd < 0) {
            int e = errno;
            if (e == EINTR) continue;
            xd_log("DEMO-SERVER wait_channel failed: %s", strerror(e));
            if (e == ENODEV || e == EBADF) return 1; /* device gone: let systemd restart us */
            sleep(1);
            continue;
        }
        chan_job_t *job = malloc(sizeof(*job));
        if (!job) {
            xd_log("DEMO-SERVER channel=%u dropped: out of memory", info.channel_id);
            close(fd);
            continue;
        }
        job->fd = fd;
        job->g = NULL;
        job->channel_id = info.channel_id;

        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int rc = pthread_create(&th, &attr, channel_thread, job);
        pthread_attr_destroy(&attr);
        if (rc != 0) {
            xd_log("DEMO-SERVER channel=%u dropped: pthread_create: %s",
                   info.channel_id, strerror(rc));
            free(job);
            close(fd);
        }
    }
}
