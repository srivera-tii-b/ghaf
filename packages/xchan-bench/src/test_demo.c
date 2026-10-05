/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* test_demo.c, tests for the encrypted demo's secure channel
 * (demo_crypto.c), the request logic inside it (demo_session.c) and the
 * shared llama-server client (llama_http.c).
 *
 *   test-demo <dir with the committed test keys>
 *
 * Runs on any Linux box: AF_UNIX SOCK_SEQPACKET socketpairs stand in for
 * xchan channels (same "one send = one message" shape), a relay thread in
 * the middle plays the untrusted host (reads, rewrites, drops, replays and
 * reorders messages), a fake model stands in for llama-server, and for the
 * HTTP path a fake llama-server listens on 127.0.0.1.
 *
 * Failure checks assert WHICH check rejected the input (xd_err_t), not just
 * that something failed, so disabling one check makes its test fail even
 * when a later check would still have caught the bad input.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "demo_crypto.h"
#include "demo_session.h"
#include "llama_http.h"
#include "proto.h"

static int g_checks, g_failures;

#define CHECK(cond, ...)                                                     \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failures++;                                                    \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);             \
            fprintf(stderr, __VA_ARGS__);                                    \
            fprintf(stderr, "\n");                                           \
        }                                                                    \
    } while (0)

#define CHECK_ERR(got, want)                                                 \
    CHECK((got) == (want), "%s: got \"%s\", want \"%s\"", #got,              \
          xd_err_str(got), xd_err_str(want))

#define TEST(name) static void name(void)
#define RUN(name)                                                            \
    do {                                                                     \
        int before = g_failures;                                             \
        name();                                                              \
        fprintf(stderr, "%s %s\n", g_failures == before ? "ok  " : "FAIL", #name); \
    } while (0)

static const char *g_keydir;

typedef struct {
    const char *name;
    uint8_t pk[XD_PK_BYTES];      /* derived from the seed */
    uint8_t sk[XD_SK_BYTES];
    uint8_t pk_file[XD_PK_BYTES]; /* the committed .pk */
} ident_t;

static ident_t ADMIN = { .name = "admin-vm" };
static ident_t NET = { .name = "net-vm" };
static ident_t CLI = { .name = "client-vm" };

static void load_ident(ident_t *id) {
    char path[1024];
    const char *why = "";
    snprintf(path, sizeof(path), "%s/%s.seed", g_keydir, id->name);
    if (xd_load_identity(path, id->pk, id->sk, &why) != 0) {
        fprintf(stderr, "cannot load %s: %s\n", path, why);
        exit(2);
    }
    snprintf(path, sizeof(path), "%s/%s.pk", g_keydir, id->name);
    if (xd_read_hex32(path, id->pk_file, &why) != 0) {
        fprintf(stderr, "cannot load %s: %s\n", path, why);
        exit(2);
    }
}

/* ---- fake transport: SOCK_SEQPACKET ----------------------------------- */

static ssize_t sp_send(xd_chan_t *c, const void *buf, size_t len) {
    ssize_t n = send(c->fd, buf, len, MSG_NOSIGNAL);
    if (n < 0 && errno == EPIPE) errno = ECONNRESET;
    return n;
}

static ssize_t sp_recv(xd_chan_t *c, void *buf, size_t cap) {
    ssize_t n = recv(c->fd, buf, cap, MSG_TRUNC);
    if (n == 0) { errno = ECONNRESET; return -1; } /* we never send empty messages */
    if (n > (ssize_t)cap) { errno = EMSGSIZE; return -1; }
    return n;
}

static xd_chan_t mkchan(int fd) {
    xd_chan_t c = { .fd = fd, .send = sp_send, .recv = sp_recv, .user = NULL };
    return c;
}

static void sp_pair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) != 0) {
        perror("socketpair");
        exit(2);
    }
}

/* ---- the "host": a relay that can tamper ------------------------------- */

typedef struct relay relay_t;
/* dir 0 = client->server, 1 = server->client; idx counts messages per
 * direction from 0. Return 1 to forward buf/len, 0 to drop it. The hook
 * may also inject: relay_inject(). */
typedef int (*hook_fn)(relay_t *r, int dir, int idx, uint8_t *buf, size_t *len);

struct relay {
    int fd[2];        /* fd[0] faces the client, fd[1] faces the server */
    hook_fn hook;
    int idx[2];
    pthread_t th;
    /* scratch for hooks */
    uint8_t held[XD_REC_MAX];
    size_t held_len;
    int held_valid;
};

static void relay_inject(relay_t *r, int dir, const uint8_t *buf, size_t len) {
    send(r->fd[dir == 0 ? 1 : 0], buf, len, MSG_NOSIGNAL);
}

static void *relay_thread(void *arg) {
    relay_t *r = arg;
    uint8_t buf[XD_REC_MAX + 64];
    for (;;) {
        struct pollfd p[2] = { { r->fd[0], POLLIN, 0 }, { r->fd[1], POLLIN, 0 } };
        if (poll(p, 2, -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        int done = 0;
        for (int side = 0; side < 2 && !done; side++) {
            if (!p[side].revents) continue;
            ssize_t n = recv(r->fd[side], buf, sizeof(buf), 0);
            if (n <= 0) { done = 1; break; }
            size_t len = (size_t)n;
            int dir = side; /* read from the client side = client->server */
            int fwd = r->hook ? r->hook(r, dir, r->idx[dir], buf, &len) : 1;
            r->idx[dir]++;
            if (fwd) send(r->fd[side ^ 1], buf, len, MSG_NOSIGNAL);
        }
        if (done) break;
    }
    /* One side went away: so does the other, like a detach. */
    close(r->fd[0]);
    close(r->fd[1]);
    return NULL;
}

/* Starts a relay; *client_fd / *server_fd are the endpoints to hand to the
 * two parties. */
static void relay_start(relay_t *r, hook_fn hook, int *client_fd, int *server_fd) {
    int a[2], b[2];
    memset(r, 0, sizeof(*r));
    sp_pair(a);
    sp_pair(b);
    *client_fd = a[0];
    r->fd[0] = a[1];
    *server_fd = b[0];
    r->fd[1] = b[1];
    r->hook = hook;
    pthread_create(&r->th, NULL, relay_thread, r);
}

static void relay_join(relay_t *r) { pthread_join(r->th, NULL); }

/* ---- handshake harness ------------------------------------------------- */

typedef struct {
    xd_chan_t chan;
    const uint8_t *sk;
    const xd_client_key_t *clients;
    size_t n_clients;
    xd_session_t sess;
    size_t which;
    char fp[9];
    xd_err_t err;
    int timeout_ms;
    pthread_t th;
} srv_hs_t;

static void *srv_hs_thread(void *arg) {
    srv_hs_t *h = arg;
    h->err = xd_server_handshake(&h->chan, h->sk, h->clients, h->n_clients, &h->sess,
                                 &h->which, h->fp, h->timeout_ms);
    if (h->err != XD_OK) {
        close(h->chan.fd);
        h->chan.fd = -1;
    }
    return NULL;
}

static xd_client_key_t g_clients_all[2];  /* net-vm, client-vm */
static xd_client_key_t g_clients_net[1];  /* net-vm only */

typedef struct {
    xd_err_t cerr, serr;
    xd_session_t cs, ss;
    size_t which;
    char fp[9];
    int cfd, sfd; /* still-open endpoints after success, -1 otherwise */
} hs_out_t;

/* One handshake: server = admin-vm identity with `clients`; client presents
 * client_pk, signs with client_sk, and pins `pinned`. With a hook, through a
 * relay. */
static void run_handshake(const xd_client_key_t *clients, size_t n_clients,
                          const uint8_t *client_pk, const uint8_t *client_sk,
                          const uint8_t *pinned, hook_fn hook, relay_t *relay,
                          hs_out_t *o) {
    int cfd, sfd;
    if (hook) {
        relay_start(relay, hook, &cfd, &sfd);
    } else {
        int fds[2];
        sp_pair(fds);
        cfd = fds[0];
        sfd = fds[1];
    }
    srv_hs_t h;
    memset(&h, 0, sizeof(h));
    h.chan = mkchan(sfd);
    h.sk = ADMIN.sk;
    h.clients = clients;
    h.n_clients = n_clients;
    h.timeout_ms = 2000;
    pthread_create(&h.th, NULL, srv_hs_thread, &h);

    xd_chan_t cc = mkchan(cfd);
    o->cerr = xd_client_handshake(&cc, client_pk, client_sk, pinned, &o->cs, 2000);
    if (o->cerr != XD_OK) {
        close(cfd);
        cfd = -1;
    }
    pthread_join(h.th, NULL);
    o->serr = h.err;
    o->ss = h.sess;
    o->which = h.which;
    memcpy(o->fp, h.fp, sizeof(o->fp));
    o->cfd = cfd;
    o->sfd = h.chan.fd;
}

static void close_hs(hs_out_t *o, relay_t *relay, int with_relay) {
    if (o->cfd >= 0) close(o->cfd);
    if (o->sfd >= 0) close(o->sfd);
    if (with_relay) relay_join(relay);
}

/* ---- tests: identities ------------------------------------------------- */

TEST(test_seed_to_pk) {
    ident_t *ids[] = { &ADMIN, &NET, &CLI };
    for (int i = 0; i < 3; i++) {
        CHECK(memcmp(ids[i]->pk, ids[i]->pk_file, XD_PK_BYTES) == 0,
              "%s: libsodium's pk from the seed differs from the committed .pk", ids[i]->name);
        /* libsodium's sk is seed || pk */
        CHECK(memcmp(ids[i]->sk + 32, ids[i]->pk_file, XD_PK_BYTES) == 0,
              "%s: sk does not embed the committed pk", ids[i]->name);
    }
    CHECK(memcmp(ADMIN.pk, NET.pk, 32) != 0 && memcmp(NET.pk, CLI.pk, 32) != 0,
          "test identities must be distinct");
}

static int write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(content, f);
    fclose(f);
    return 0;
}

TEST(test_key_file_parsing) {
    const char *tmp = getenv("TMPDIR");
    char tdir[512];
    if (tmp) snprintf(tdir, sizeof(tdir), "%s/xdemo-keys-XXXXXX", tmp);
    else snprintf(tdir, sizeof(tdir), "/tmp/xdemo-keys-XXXXXX");
    CHECK(mkdtemp(tdir) != NULL, "mkdtemp");
    const char *hex = "820da03d48deac8eb9926f737286430729d82ee00a1d45f0491c5030e4351d17";
    struct { const char *content; int ok; } cases[] = {
        { "820da03d48deac8eb9926f737286430729d82ee00a1d45f0491c5030e4351d17\n", 1 },
        { "820da03d48deac8eb9926f737286430729d82ee00a1d45f0491c5030e4351d17", 1 },
        { "820da03d48deac8eb9926f737286430729d82ee00a1d45f0491c5030e4351d17\r\n", 1 },
        { "820DA03D48DEAC8EB9926F737286430729D82EE00A1D45F0491C5030E4351D17\n", 1 },
        { "820da03d48deac8eb9926f737286430729d82ee00a1d45f0491c5030e4351d\n", 0 },     /* 62 */
        { "820da03d48deac8eb9926f737286430729d82ee00a1d45f0491c5030e4351d1700\n", 0 }, /* 66 */
        { "820da03d48deac8eb9926f737286430729d82ee00a1d45f0491c5030e4351d1x\n", 0 },
        { "820da03d48deac8eb9926f737286430729d82ee00a1d45f0491c5030e4351d17 x\n", 0 },
        { " 820da03d48deac8eb9926f737286430729d82ee00a1d45f0491c5030e4351d17\n", 0 },
        { "", 0 },
    };
    uint8_t want[32];
    size_t bl;
    sodium_hex2bin(want, 32, hex, 64, NULL, &bl, NULL);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char path[600];
        snprintf(path, sizeof(path), "%s/k%zu", tdir, i);
        write_file(path, cases[i].content);
        uint8_t out[32];
        const char *why = NULL;
        int rc = xd_read_hex32(path, out, &why);
        CHECK((rc == 0) == cases[i].ok, "case %zu: rc=%d why=%s", i, rc, why ? why : "-");
        if (rc == 0 && cases[i].ok) CHECK(memcmp(out, want, 32) == 0, "case %zu: wrong bytes", i);
        unlink(path);
    }
    char big[400];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char path[600];
    snprintf(path, sizeof(path), "%s/big", tdir);
    write_file(path, big);
    uint8_t out[32];
    const char *why = NULL;
    CHECK(xd_read_hex32(path, out, &why) != 0, "oversized key file accepted");
    unlink(path);
    snprintf(path, sizeof(path), "%s/missing", tdir);
    CHECK(xd_read_hex32(path, out, &why) != 0, "missing key file accepted");
    rmdir(tdir);
}

/* ---- tests: handshake --------------------------------------------------- */

TEST(test_handshake_success) {
    hs_out_t o;
    run_handshake(g_clients_all, 2, NET.pk, NET.sk, ADMIN.pk, NULL, NULL, &o);
    CHECK_ERR(o.cerr, XD_OK);
    CHECK_ERR(o.serr, XD_OK);
    CHECK(o.which == 0, "server identified client index %zu, want 0 (net-vm)", o.which);
    CHECK(strcmp(o.fp, "820da03d") == 0, "fingerprint %s", o.fp); /* net-vm.pk */
    CHECK(memcmp(o.cs.tx_key, o.ss.rx_key, 32) == 0 && memcmp(o.cs.rx_key, o.ss.tx_key, 32) == 0,
          "client and server disagree on the session keys");
    CHECK(memcmp(o.cs.tx_key, o.cs.rx_key, 32) != 0, "both directions share a key");
    CHECK(memcmp(o.ss.peer_pk, NET.pk, 32) == 0, "server's peer is not net-vm");

    /* Records both ways over the real channel. */
    xd_chan_t cc = mkchan(o.cfd), sc = mkchan(o.sfd);
    const char *msg = "hello through the host";
    CHECK_ERR(xd_send_record(&cc, &o.cs, XD_REC_APP, msg, strlen(msg)), XD_OK);
    uint8_t buf[256], type = 0;
    size_t n = 0;
    CHECK_ERR(xd_recv_record(&sc, &o.ss, &type, buf, sizeof(buf), &n, 1000), XD_OK);
    CHECK(type == XD_REC_APP && n == strlen(msg) && memcmp(buf, msg, n) == 0, "c->s payload");
    CHECK_ERR(xd_send_record(&sc, &o.ss, XD_REC_CLOSE, NULL, 0), XD_OK);
    CHECK_ERR(xd_recv_record(&cc, &o.cs, &type, buf, sizeof(buf), &n, 1000), XD_OK);
    CHECK(type == XD_REC_CLOSE && n == 0, "s->c CLOSE");
    close_hs(&o, NULL, 0);

    /* The second pinned client is told apart from the first. */
    run_handshake(g_clients_all, 2, CLI.pk, CLI.sk, ADMIN.pk, NULL, NULL, &o);
    CHECK_ERR(o.cerr, XD_OK);
    CHECK_ERR(o.serr, XD_OK);
    CHECK(o.which == 1, "server identified client index %zu, want 1 (client-vm)", o.which);
    close_hs(&o, NULL, 0);
}

TEST(test_handshake_wrong_server_key) {
    /* The client pins net-vm's key as "the server"; the real server signs
     * with admin-vm's. */
    hs_out_t o;
    run_handshake(g_clients_all, 2, CLI.pk, CLI.sk, NET.pk, NULL, NULL, &o);
    CHECK_ERR(o.cerr, XD_ERR_BAD_SIG);
    CHECK_ERR(o.serr, XD_ERR_PEER_CLOSED);
    CHECK(o.cs.dead && o.ss.dead, "failed handshake left a live session");
    close_hs(&o, NULL, 0);
}

TEST(test_handshake_unknown_client) {
    hs_out_t o;
    run_handshake(g_clients_net, 1, CLI.pk, CLI.sk, ADMIN.pk, NULL, NULL, &o);
    CHECK_ERR(o.serr, XD_ERR_UNKNOWN_CLIENT);
    CHECK(strcmp(o.fp, "094e377f") == 0, "claimed fingerprint %s", o.fp); /* client-vm.pk */
    CHECK_ERR(o.cerr, XD_ERR_PEER_CLOSED);
    close_hs(&o, NULL, 0);
}

TEST(test_handshake_impersonation) {
    /* client-vm claims net-vm's (pinned) public key but can only sign with
     * its own secret key. */
    hs_out_t o;
    run_handshake(g_clients_all, 2, NET.pk, CLI.sk, ADMIN.pk, NULL, NULL, &o);
    CHECK_ERR(o.serr, XD_ERR_BAD_SIG);
    /* The client cannot tell until its first record goes unanswered. */
    CHECK_ERR(o.cerr, XD_OK);
    if (o.cfd >= 0) {
        xd_chan_t cc = mkchan(o.cfd);
        uint8_t buf[64], type;
        size_t n;
        CHECK_ERR(xd_recv_record(&cc, &o.cs, &type, buf, sizeof(buf), &n, 1000), XD_ERR_PEER_CLOSED);
    }
    close_hs(&o, NULL, 0);
}

/* Handshake tampering by the host. */
static int hook_flip_hello_eph(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)len;
    if (dir == 0 && idx == 0) b[2 + 32 + 5] ^= 0x01;
    return 1;
}
static int hook_flip_hello_random(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)len;
    if (dir == 0 && idx == 0) b[XD_HELLO_LEN - 1] ^= 0x80;
    return 1;
}
static int hook_flip_sh_eph(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)len;
    if (dir == 1 && idx == 0) b[1] ^= 0x01;
    return 1;
}
static int hook_flip_sh_random(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)len;
    if (dir == 1 && idx == 0) b[1 + 32 + 7] ^= 0x01;
    return 1;
}
static int hook_flip_sh_sig(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)len;
    if (dir == 1 && idx == 0) b[XD_SERVER_HELLO_LEN - 3] ^= 0x01;
    return 1;
}
static int hook_flip_finish(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)len;
    if (dir == 0 && idx == 1) b[10] ^= 0x01;
    return 1;
}
static int hook_truncate_hello(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)b;
    if (dir == 0 && idx == 0) *len -= 1;
    return 1;
}
static int hook_hello_version(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)len;
    if (dir == 0 && idx == 0) b[1] = 2;
    return 1;
}
static int hook_swap_type(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)len;
    if (dir == 1 && idx == 0) b[0] = XD_MSG_HELLO;
    return 1;
}

TEST(test_handshake_tampering) {
    struct { const char *what; hook_fn hook; xd_err_t cerr, serr; } cases[] = {
        /* Client's HELLO changed in flight: the server signs what it got,
         * the client checks against what it sent. */
        { "HELLO ephemeral",        hook_flip_hello_eph,    XD_ERR_BAD_SIG,   XD_ERR_PEER_CLOSED },
        { "HELLO random",           hook_flip_hello_random, XD_ERR_BAD_SIG,   XD_ERR_PEER_CLOSED },
        { "SERVER_HELLO ephemeral", hook_flip_sh_eph,       XD_ERR_BAD_SIG,   XD_ERR_PEER_CLOSED },
        { "SERVER_HELLO random",    hook_flip_sh_random,    XD_ERR_BAD_SIG,   XD_ERR_PEER_CLOSED },
        { "SERVER_HELLO signature", hook_flip_sh_sig,       XD_ERR_BAD_SIG,   XD_ERR_PEER_CLOSED },
        { "CLIENT_FINISH",          hook_flip_finish,       XD_OK,            XD_ERR_BAD_SIG },
        { "HELLO truncated",        hook_truncate_hello,    XD_ERR_PEER_CLOSED, XD_ERR_MALFORMED },
        { "HELLO version 2",        hook_hello_version,     XD_ERR_PEER_CLOSED, XD_ERR_VERSION },
        { "SERVER_HELLO type",      hook_swap_type,         XD_ERR_MALFORMED, XD_ERR_PEER_CLOSED },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        relay_t relay;
        hs_out_t o;
        run_handshake(g_clients_all, 2, NET.pk, NET.sk, ADMIN.pk, cases[i].hook, &relay, &o);
        CHECK(o.cerr == cases[i].cerr, "%s: client got \"%s\", want \"%s\"", cases[i].what,
              xd_err_str(o.cerr), xd_err_str(cases[i].cerr));
        CHECK(o.serr == cases[i].serr, "%s: server got \"%s\", want \"%s\"", cases[i].what,
              xd_err_str(o.serr), xd_err_str(cases[i].serr));
        close_hs(&o, &relay, 1);
    }
}

/* Capture a full handshake, then replay its client half to a new server and
 * its server half to a new client. */
static uint8_t cap_hello[XD_HELLO_LEN], cap_sh[XD_SERVER_HELLO_LEN], cap_fin[XD_CLIENT_FINISH_LEN];
static int hook_capture(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r;
    if (dir == 0 && idx == 0 && *len == XD_HELLO_LEN) memcpy(cap_hello, b, *len);
    if (dir == 1 && idx == 0 && *len == XD_SERVER_HELLO_LEN) memcpy(cap_sh, b, *len);
    if (dir == 0 && idx == 1 && *len == XD_CLIENT_FINISH_LEN) memcpy(cap_fin, b, *len);
    return 1;
}
static int hook_replay_old_sh(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r;
    if (dir == 1 && idx == 0) { memcpy(b, cap_sh, sizeof(cap_sh)); *len = sizeof(cap_sh); }
    return 1;
}

TEST(test_handshake_replay) {
    relay_t relay;
    hs_out_t o;
    run_handshake(g_clients_all, 2, NET.pk, NET.sk, ADMIN.pk, hook_capture, &relay, &o);
    CHECK_ERR(o.cerr, XD_OK);
    CHECK_ERR(o.serr, XD_OK);
    close_hs(&o, &relay, 1);

    /* Host replays the old HELLO and CLIENT_FINISH to a fresh server: the
     * fresh server ephemeral/random make the old signature worthless. */
    int fds[2];
    sp_pair(fds);
    srv_hs_t h;
    memset(&h, 0, sizeof(h));
    h.chan = mkchan(fds[1]);
    h.sk = ADMIN.sk;
    h.clients = g_clients_all;
    h.n_clients = 2;
    h.timeout_ms = 2000;
    pthread_create(&h.th, NULL, srv_hs_thread, &h);
    send(fds[0], cap_hello, sizeof(cap_hello), MSG_NOSIGNAL);
    uint8_t sh[XD_SERVER_HELLO_LEN + 8];
    ssize_t n = recv(fds[0], sh, sizeof(sh), 0);
    CHECK(n == XD_SERVER_HELLO_LEN, "server answered a replayed HELLO with %zd bytes", n);
    CHECK(memcmp(sh + 1, cap_sh + 1, 64) != 0, "server reused its ephemeral/random");
    send(fds[0], cap_fin, sizeof(cap_fin), MSG_NOSIGNAL);
    pthread_join(h.th, NULL);
    CHECK_ERR(h.err, XD_ERR_BAD_SIG);
    close(fds[0]);

    /* Host answers a fresh client with the old SERVER_HELLO. */
    run_handshake(g_clients_all, 2, NET.pk, NET.sk, ADMIN.pk, hook_replay_old_sh, &relay, &o);
    CHECK_ERR(o.cerr, XD_ERR_BAD_SIG);
    close_hs(&o, &relay, 1);
}

TEST(test_handshake_timeout) {
    int fds[2];
    sp_pair(fds);
    xd_chan_t cc = mkchan(fds[0]);
    xd_session_t s;
    /* Nobody answers. */
    CHECK_ERR(xd_client_handshake(&cc, NET.pk, NET.sk, ADMIN.pk, &s, 200), XD_ERR_TIMEOUT);
    size_t which;
    char fp[9];
    xd_chan_t sc = mkchan(fds[1]);
    /* The server got the HELLO above; now the client never finishes. */
    CHECK_ERR(xd_server_handshake(&sc, ADMIN.sk, g_clients_all, 2, &s, &which, fp, 200),
              XD_ERR_TIMEOUT);
    close(fds[0]);
    close(fds[1]);
}

/* The handshake and record format exactly as the protocol comment in
 * demo_crypto.c specifies, computed here independently of demo_crypto.c's
 * own helpers: a server that signs the wrong transcript, binds the keys
 * differently, or lays out records differently fails this test even though
 * it would still interoperate with a client built from the same (wrong)
 * code. */
static void spec_hash(uint8_t out[32], const uint8_t *hello, const uint8_t *eph,
                      const uint8_t *rnd, const char *suffix) {
    uint8_t in[13 + XD_HELLO_LEN + 32 + 32 + 6];
    size_t o = 0;
    memcpy(in + o, "xchan-demo v1", 13); o += 13;
    memcpy(in + o, hello, XD_HELLO_LEN); o += XD_HELLO_LEN;
    memcpy(in + o, eph, 32); o += 32;
    memcpy(in + o, rnd, 32); o += 32;
    memcpy(in + o, suffix, strlen(suffix)); o += strlen(suffix);
    crypto_generichash(out, 32, in, o, NULL, 0);
}

TEST(test_spec_conformance) {
    int fds[2];
    sp_pair(fds);
    srv_hs_t h;
    memset(&h, 0, sizeof(h));
    h.chan = mkchan(fds[1]);
    h.sk = ADMIN.sk;
    h.clients = g_clients_all;
    h.n_clients = 2;
    h.timeout_ms = 2000;
    pthread_create(&h.th, NULL, srv_hs_thread, &h);

    uint8_t eph_pk[32], eph_sk[32], hello[XD_HELLO_LEN];
    crypto_kx_keypair(eph_pk, eph_sk);
    hello[0] = 0x01;
    hello[1] = 0x01;
    memcpy(hello + 2, NET.pk, 32);
    memcpy(hello + 34, eph_pk, 32);
    randombytes_buf(hello + 66, 32);
    send(fds[0], hello, sizeof(hello), MSG_NOSIGNAL);

    uint8_t sh[XD_SERVER_HELLO_LEN + 8];
    ssize_t n = recv(fds[0], sh, sizeof(sh), 0);
    CHECK(n == 129 && sh[0] == 0x02, "SERVER_HELLO: %zd bytes, type %u", n, sh[0]);
    uint8_t hs[32], hc[32], t[32];
    spec_hash(hs, hello, sh + 1, sh + 33, "server");
    CHECK(crypto_sign_verify_detached(sh + 65, hs, 32, ADMIN.pk) == 0,
          "server did not sign H_s as specified");
    spec_hash(hc, hello, sh + 1, sh + 33, "client");
    uint8_t fin[65];
    fin[0] = 0x03;
    crypto_sign_detached(fin + 1, NULL, hc, 32, NET.sk);
    send(fds[0], fin, sizeof(fin), MSG_NOSIGNAL);
    pthread_join(h.th, NULL);
    CHECK_ERR(h.err, XD_OK);

    uint8_t rx[32], tx[32], krx[32], ktx[32];
    CHECK(crypto_kx_client_session_keys(rx, tx, eph_pk, eph_sk, sh + 1) == 0, "kx");
    spec_hash(t, hello, sh + 1, sh + 33, "keys");
    crypto_generichash(krx, 32, t, 32, rx, 32);
    crypto_generichash(ktx, 32, t, 32, tx, 32);

    /* A record built by hand from demo_crypto.c's protocol comment (counter
     * 0) must open at the server... */
    const char *pt = "spec record";
    uint8_t rec[128], nonce[24] = { 0 }, ad[5];
    size_t ptlen = strlen(pt);
    rec[0] = XD_REC_APP;
    memset(rec + 1, 0, 8);
    rec[9] = (uint8_t)ptlen; rec[10] = 0; rec[11] = 0; rec[12] = 0;
    ad[0] = XD_REC_APP; ad[1] = (uint8_t)ptlen; ad[2] = ad[3] = ad[4] = 0;
    unsigned long long clen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(rec + 13, &clen, (const uint8_t *)pt, ptlen,
                                               ad, 5, NULL, nonce, ktx);
    uint8_t out[128], type;
    size_t olen;
    CHECK_ERR(xd_open(&h.sess, rec, 13 + (size_t)clen, &type, out, sizeof(out), &olen), XD_OK);
    CHECK(olen == ptlen && memcmp(out, pt, ptlen) == 0, "spec record content");

    /* ...and the server's second record (counter 1) must open by hand. */
    uint8_t srec[128];
    size_t slen = 0;
    CHECK_ERR(xd_seal(&h.sess, XD_REC_CLOSE, NULL, 0, srec, sizeof(srec), &slen), XD_OK);
    slen = 0;
    CHECK_ERR(xd_seal(&h.sess, XD_REC_APP, "abc", 3, srec, sizeof(srec), &slen), XD_OK);
    CHECK(slen == 13 + 3 + 16 && srec[0] == XD_REC_APP && srec[1] == 1 && srec[9] == 3,
          "record header layout");
    nonce[0] = 1;
    ad[0] = XD_REC_APP; ad[1] = 3;
    unsigned long long mlen = 0;
    CHECK(slen == 13 + 3 + 16 &&
          crypto_aead_xchacha20poly1305_ietf_decrypt(out, &mlen, NULL, srec + 13, slen - 13,
                                                     ad, 5, nonce, krx) == 0 &&
          mlen == 3 && memcmp(out, "abc", 3) == 0,
          "server record does not decrypt with the spec's nonce/AD/key");
    close(fds[0]);
    if (h.chan.fd >= 0) close(h.chan.fd);
}

/* ---- tests: records ----------------------------------------------------- */

static void fresh_sessions(xd_session_t *cs, xd_session_t *ss) {
    hs_out_t o;
    run_handshake(g_clients_all, 2, NET.pk, NET.sk, ADMIN.pk, NULL, NULL, &o);
    if (o.cerr != XD_OK || o.serr != XD_OK) {
        fprintf(stderr, "fresh_sessions: handshake failed\n");
        exit(2);
    }
    *cs = o.cs;
    *ss = o.ss;
    close_hs(&o, NULL, 0);
}

typedef struct {
    uint8_t b[256];
    size_t n;
} rec_t;

static void seal3(xd_session_t *cs, rec_t r[3]) {
    const char *p[3] = { "first", "second", "third" };
    for (int i = 0; i < 3; i++)
        if (xd_seal(cs, XD_REC_APP, p[i], strlen(p[i]), r[i].b, sizeof(r[i].b), &r[i].n) != XD_OK)
            exit(2);
}

static xd_err_t open1(xd_session_t *s, const rec_t *r) {
    uint8_t out[256], type;
    size_t n;
    return xd_open(s, r->b, r->n, &type, out, sizeof(out), &n);
}

TEST(test_records_in_order) {
    xd_session_t cs, ss;
    rec_t r[3];
    fresh_sessions(&cs, &ss);
    seal3(&cs, r);
    for (int i = 0; i < 3; i++) {
        uint8_t out[256], type;
        size_t n;
        CHECK_ERR(xd_open(&ss, r[i].b, r[i].n, &type, out, sizeof(out), &n), XD_OK);
    }
    CHECK(ss.rx_ctr == 3 && cs.tx_ctr == 3, "counters advanced to 3");
}

TEST(test_records_tampered) {
    xd_session_t cs, ss, s2;
    rec_t r[3], t;
    fresh_sessions(&cs, &ss);
    seal3(&cs, r);

    /* every single byte of ciphertext+tag */
    for (size_t i = XD_REC_HDR; i < r[0].n; i++) {
        s2 = ss;
        t = r[0];
        t.b[i] ^= 0x04;
        CHECK_ERR(open1(&s2, &t), XD_ERR_TAG);
    }
    /* the record type is authenticated (AD): APP -> CLOSE */
    s2 = ss;
    t = r[0];
    t.b[0] = XD_REC_CLOSE;
    CHECK_ERR(open1(&s2, &t), XD_ERR_TAG);
    /* unknown type */
    s2 = ss;
    t = r[0];
    t.b[0] = 0x7f;
    CHECK_ERR(open1(&s2, &t), XD_ERR_MALFORMED);
    /* length field disagrees with the message size */
    s2 = ss;
    t = r[0];
    t.b[9] ^= 0x01;
    CHECK_ERR(open1(&s2, &t), XD_ERR_MALFORMED);
    /* truncated: one byte short, and shorter than a header */
    s2 = ss;
    t = r[0];
    t.n -= 1;
    CHECK_ERR(open1(&s2, &t), XD_ERR_MALFORMED);
    s2 = ss;
    t = r[0];
    t.n = 10;
    CHECK_ERR(open1(&s2, &t), XD_ERR_MALFORMED);
    /* bit flips in the wire counter */
    s2 = ss;
    t = r[0];
    t.b[1] ^= 0x01;
    CHECK_ERR(open1(&s2, &t), XD_ERR_COUNTER);

    /* After any failure the session is dead: even a good record fails. */
    s2 = ss;
    t = r[0];
    t.b[20] ^= 0x01;
    CHECK_ERR(open1(&s2, &t), XD_ERR_TAG);
    CHECK_ERR(open1(&s2, &r[0]), XD_ERR_CLOSED);
    uint8_t buf[64];
    size_t bl;
    CHECK_ERR(xd_seal(&s2, XD_REC_APP, "x", 1, buf, sizeof(buf), &bl), XD_ERR_CLOSED);
    CHECK(sodium_is_zero(s2.rx_key, 32) && sodium_is_zero(s2.tx_key, 32), "keys not wiped");
}

TEST(test_records_replay_reorder) {
    xd_session_t cs, ss, s2;
    rec_t r[3], t;
    fresh_sessions(&cs, &ss);
    seal3(&cs, r);

    /* replay: 0, 0 */
    s2 = ss;
    CHECK_ERR(open1(&s2, &r[0]), XD_OK);
    CHECK_ERR(open1(&s2, &r[0]), XD_ERR_COUNTER);
    /* replay later: 0, 1, 0 */
    s2 = ss;
    CHECK_ERR(open1(&s2, &r[0]), XD_OK);
    CHECK_ERR(open1(&s2, &r[1]), XD_OK);
    CHECK_ERR(open1(&s2, &r[0]), XD_ERR_COUNTER);
    /* reorder: 1 before 0 */
    s2 = ss;
    CHECK_ERR(open1(&s2, &r[1]), XD_ERR_COUNTER);
    /* reorder: 0, 2, 1 */
    s2 = ss;
    CHECK_ERR(open1(&s2, &r[0]), XD_OK);
    CHECK_ERR(open1(&s2, &r[2]), XD_ERR_COUNTER);
    /* drop: 0 is dropped, 1 arrives */
    s2 = ss;
    CHECK_ERR(open1(&s2, &r[1]), XD_ERR_COUNTER);
    /* replay with the wire counter rewritten to the expected value: the
     * nonce comes from the receiver's counter, so the tag fails */
    s2 = ss;
    CHECK_ERR(open1(&s2, &r[0]), XD_OK);
    t = r[0];
    t.b[1] = 1;
    CHECK_ERR(open1(&s2, &t), XD_ERR_TAG);
    /* reorder with rewritten counters: 1 presented as 0 */
    s2 = ss;
    t = r[1];
    t.b[1] = 0;
    CHECK_ERR(open1(&s2, &t), XD_ERR_TAG);
    /* reflection: the client's own record sent back to the client */
    s2 = cs;
    s2.rx_ctr = 0;
    CHECK_ERR(open1(&s2, &r[0]), XD_ERR_TAG);
}

TEST(test_records_cross_channel) {
    /* Two channels between the same two parties, same counters: a record
     * from one must not open on the other. */
    xd_session_t a_c, a_s, b_c, b_s;
    rec_t ra[3], rb[3];
    fresh_sessions(&a_c, &a_s);
    fresh_sessions(&b_c, &b_s);
    seal3(&a_c, ra);
    seal3(&b_c, rb);
    xd_session_t s2 = b_s;
    CHECK_ERR(open1(&s2, &ra[0]), XD_ERR_TAG);
    s2 = a_s;
    CHECK_ERR(open1(&s2, &rb[0]), XD_ERR_TAG);
    /* sanity: each opens on its own channel */
    s2 = a_s;
    CHECK_ERR(open1(&s2, &ra[0]), XD_OK);
    s2 = b_s;
    CHECK_ERR(open1(&s2, &rb[0]), XD_OK);
}

/* ---- tests: the request service ----------------------------------------- */

typedef struct {
    int fail_after;    /* >= 0: return -1 after this many tokens */
    int delay_us;      /* per token */
} fake_model_t;

static int fake_generate(void *gen_ctx, const char *prompt, size_t prompt_len, uint32_t n_predict,
                         int (*on_chunk)(void *ctx, const char *text, size_t len), void *cb_ctx) {
    fake_model_t *m = gen_ctx;
    (void)prompt; (void)prompt_len;
    for (uint32_t i = 0; i < n_predict; i++) {
        if (m && m->fail_after >= 0 && (int)i == m->fail_after) return -1;
        if (m && m->delay_us) {
            struct timespec ts = { 0, (long)m->delay_us * 1000 };
            nanosleep(&ts, NULL);
        }
        char tok[32];
        int n = snprintf(tok, sizeof(tok), "w%u%s", i, i % 4 == 3 ? "\n" : " ");
        if (on_chunk(cb_ctx, tok, (size_t)n) != 0) return -1;
    }
    return 0;
}

typedef struct {
    xd_server_cfg_t cfg;
    xd_chan_t chan;
    unsigned id;
    xd_serve_result_t res;
    pthread_t th;
} serve_job_t;

static void *serve_thread(void *arg) {
    serve_job_t *j = arg;
    xd_serve_channel(&j->cfg, &j->chan, j->id, &j->res);
    close(j->chan.fd);
    return NULL;
}

static void start_server(serve_job_t *j, int sfd, unsigned id, xd_generate_fn gen, void *gen_ctx) {
    memset(j, 0, sizeof(*j));
    j->cfg.sk = ADMIN.sk;
    j->cfg.clients = g_clients_all;
    j->cfg.n_clients = 2;
    j->cfg.generate = gen;
    j->cfg.gen_ctx = gen_ctx;
    j->cfg.handshake_timeout_ms = 2000;
    j->cfg.idle_timeout_ms = 5000;
    j->chan = mkchan(sfd);
    j->id = id;
    pthread_create(&j->th, NULL, serve_thread, j);
}

static const char *expected_reply(unsigned n, char *buf, size_t cap) {
    size_t o = 0;
    buf[0] = '\0';
    for (unsigned i = 0; i < n && o < cap; i++)
        o += (size_t)snprintf(buf + o, cap - o, "w%u%s", i, i % 4 == 3 ? "\n" : " ");
    return buf;
}

TEST(test_service_clean) {
    int fds[2];
    sp_pair(fds);
    fake_model_t m = { .fail_after = -1, .delay_us = 0 };
    serve_job_t j;
    start_server(&j, fds[1], 7, fake_generate, &m);

    xd_chan_t cc = mkchan(fds[0]);
    xd_session_t s;
    CHECK_ERR(xd_client_handshake(&cc, NET.pk, NET.sk, ADMIN.pk, &s, 2000), XD_OK);
    for (uint32_t i = 1; i <= 3; i++) {
        xd_req_result_t r;
        int rc = xd_client_request(&cc, &s, i, "say something", 10, 2000, &r);
        CHECK(rc == 0 && r.ok, "request %u failed: %s", i, r.why);
        CHECK(r.tokens == 10, "request %u: %u tokens", i, r.tokens);
        char want[256];
        expected_reply(10, want, sizeof(want));
        CHECK(r.reply_len == strlen(want) && memcmp(r.reply, want, r.reply_len) == 0,
              "request %u: reply differs", i);
        CHECK(r.tok_s_defined && r.ttft_ms >= 0.0, "request %u: timing", i);
    }
    /* model failure: authenticated MSG_ERROR, channel survives */
    m.fail_after = 2;
    xd_req_result_t r;
    CHECK(xd_client_request(&cc, &s, 4, "fail please", 10, 2000, &r) != 0 && r.err == XD_OK &&
          !s.dead, "model error should fail the request but keep the channel: %s", r.why);
    m.fail_after = -1;
    CHECK(xd_client_request(&cc, &s, 5, "again", 3, 2000, &r) == 0, "after model error: %s", r.why);

    CHECK_ERR(xd_send_record(&cc, &s, XD_REC_CLOSE, NULL, 0), XD_OK);
    pthread_join(j.th, NULL);
    CHECK_ERR(j.res.end, XD_OK);
    CHECK(j.res.authenticated && j.res.client == 0 && j.res.requests == 5,
          "server result: auth=%d client=%zu requests=%u", j.res.authenticated, j.res.client,
          j.res.requests);
    /* The server closed its end: a send now fails as a reset. */
    uint8_t probe[XD_REC_OVERHEAD];
    size_t pn;
    xd_seal(&s, XD_REC_CLOSE, NULL, 0, probe, sizeof(probe), &pn);
    errno = 0;
    CHECK(cc.send(&cc, probe, pn) < 0 && errno == ECONNRESET, "send after server close: errno %d", errno);
    close(fds[0]);
}

/*
 * A channel that sits idle before its client speaks, the normal case once
 * crosvm re-establishes channels ahead of use, must still be served. With
 * hello_wait_ms = 0 the server would time the handshake out after
 * handshake_timeout_ms (200 ms here) and close the channel under the client;
 * on the board that handed every later client a dead channel.
 */
TEST(test_service_waits_for_a_late_hello) {
    int fds[2];
    sp_pair(fds);
    serve_job_t j;
    /* start_server() by hand: the config must be final before the thread runs. */
    memset(&j, 0, sizeof(j));
    j.cfg.sk = ADMIN.sk;
    j.cfg.clients = g_clients_all;
    j.cfg.n_clients = 2;
    j.cfg.generate = fake_generate;
    j.cfg.handshake_timeout_ms = 200;
    j.cfg.idle_timeout_ms = 5000;
    j.cfg.hello_wait_ms = -1; /* as xchan-demo-server runs */
    j.chan = mkchan(fds[1]);
    j.id = 11;
    pthread_create(&j.th, NULL, serve_thread, &j);
    struct timespec idle = { .tv_sec = 0, .tv_nsec = 600 * 1000 * 1000 };
    nanosleep(&idle, NULL); /* idle for three handshake timeouts */
    xd_chan_t cc = mkchan(fds[0]);
    xd_session_t s;
    CHECK_ERR(xd_client_handshake(&cc, NET.pk, NET.sk, ADMIN.pk, &s, 2000), XD_OK);
    xd_req_result_t r;
    CHECK(xd_client_request(&cc, &s, 1, "late", 3, 2000, &r) == 0 && r.ok,
          "request after a late hello failed: %s", r.why);
    CHECK_ERR(xd_send_record(&cc, &s, XD_REC_CLOSE, NULL, 0), XD_OK);
    pthread_join(j.th, NULL);
    CHECK_ERR(j.res.end, XD_OK);
    close(fds[0]);
}

TEST(test_service_peer_close) {
    int fds[2];
    sp_pair(fds);
    serve_job_t j;
    start_server(&j, fds[1], 8, fake_generate, NULL);
    xd_chan_t cc = mkchan(fds[0]);
    xd_session_t s;
    CHECK_ERR(xd_client_handshake(&cc, CLI.pk, CLI.sk, ADMIN.pk, &s, 2000), XD_OK);
    xd_req_result_t r;
    CHECK(xd_client_request(&cc, &s, 1, "x", 2, 2000, &r) == 0, "%s", r.why);
    close(fds[0]);
    pthread_join(j.th, NULL);
    CHECK_ERR(j.res.end, XD_ERR_PEER_CLOSED);
    CHECK(j.res.client == 1 && j.res.requests == 1, "client-vm, 1 request");
}

TEST(test_service_malformed_request) {
    int fds[2];
    sp_pair(fds);
    serve_job_t j;
    start_server(&j, fds[1], 9, fake_generate, NULL);
    xd_chan_t cc = mkchan(fds[0]);
    xd_session_t s;
    CHECK_ERR(xd_client_handshake(&cc, NET.pk, NET.sk, ADMIN.pk, &s, 2000), XD_OK);
    /* authenticated, but prompt_len claims more than was sent */
    bench_request_t req;
    memset(&req, 0, sizeof(req));
    req.magic = BENCH_MAGIC;
    req.type = MSG_REQUEST;
    req.request_id = 1;
    req.max_tokens = 4;
    req.prompt_len = 100;
    CHECK_ERR(xd_send_record(&cc, &s, XD_REC_APP, &req, offsetof(bench_request_t, prompt) + 10), XD_OK);
    pthread_join(j.th, NULL);
    CHECK_ERR(j.res.end, XD_ERR_MALFORMED);
    close(fds[0]);
}

/* An authenticated server that sends an inconsistent stream: the client
 * must not accept it as a reply (defence against a buggy server; the host
 * cannot produce these, every record is authenticated). */
typedef struct {
    int mode;
    srv_hs_t h;
} rogue_t;

static void *rogue_server(void *arg) {
    rogue_t *r = arg;
    srv_hs_thread(&r->h);
    if (r->h.err != XD_OK) return NULL;
    bench_msg_t msg;
    uint8_t type;
    size_t len;
    if (xd_recv_record(&r->h.chan, &r->h.sess, &type, &msg, sizeof(msg), &len, 2000) != XD_OK)
        return NULL;
    uint32_t id = msg.request.request_id;
    bench_chunk_t c;
    memset(&c, 0, sizeof(c));
    c.magic = BENCH_MAGIC;
    c.type = MSG_CHUNK;
    c.request_id = r->mode == 0 ? id + 1 : id;  /* 0: wrong request id */
    c.token_index = r->mode == 1 ? 1 : 0;       /* 1: skips token 0 */
    c.text_len = 2;
    memcpy(c.text, "hi", 2);
    /* 3: a well-formed chunk, but in a CLOSE record */
    xd_send_record(&r->h.chan, &r->h.sess, r->mode == 3 ? XD_REC_CLOSE : XD_REC_APP,
                   &c, bench_chunk_wire_len(&c));
    bench_done_t d;
    memset(&d, 0, sizeof(d));
    d.magic = BENCH_MAGIC;
    d.type = MSG_DONE;
    d.request_id = id;
    d.total_tokens = r->mode == 2 ? 5 : 1;      /* 2: wrong total */
    xd_send_record(&r->h.chan, &r->h.sess, XD_REC_APP, &d, bench_done_wire_len());
    return NULL;
}

TEST(test_client_rejects_bad_stream) {
    for (int mode = 0; mode < 4; mode++) {
        int fds[2];
        sp_pair(fds);
        rogue_t r;
        memset(&r, 0, sizeof(r));
        r.mode = mode;
        r.h.chan = mkchan(fds[1]);
        r.h.sk = ADMIN.sk;
        r.h.clients = g_clients_all;
        r.h.n_clients = 2;
        r.h.timeout_ms = 2000;
        pthread_t th;
        pthread_create(&th, NULL, rogue_server, &r);
        xd_chan_t cc = mkchan(fds[0]);
        xd_session_t s;
        CHECK_ERR(xd_client_handshake(&cc, NET.pk, NET.sk, ADMIN.pk, &s, 2000), XD_OK);
        xd_req_result_t res;
        int rc = xd_client_request(&cc, &s, 1, "x", 4, 2000, &res);
        CHECK(rc != 0 && res.err == XD_ERR_MALFORMED && s.dead,
              "mode %d: rc=%d err=%s", mode, rc, xd_err_str(res.err));
        pthread_join(th, NULL);
        close(fds[0]);
        if (r.h.chan.fd >= 0) close(r.h.chan.fd);
    }
}

/* Host attacks on a running request. Server->client messages: idx 0 is
 * SERVER_HELLO, then one record per token, then DONE. */
static int hook_flip_s2c_rec(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r;
    if (dir == 1 && idx == 3) b[*len - 1] ^= 0x10;
    return 1;
}
static int hook_replay_s2c_rec(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    if (dir == 1 && idx == 2) relay_inject(r, 1, b, *len); /* duplicate it right away */
    return 1;
}
static int hook_drop_s2c_rec(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)b; (void)len;
    return !(dir == 1 && idx == 2);
}
static int hook_reorder_s2c_rec(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    if (dir == 1 && idx == 2) { memcpy(r->held, b, *len); r->held_len = *len; r->held_valid = 1; return 0; }
    if (dir == 1 && idx == 3 && r->held_valid) {
        relay_inject(r, 1, b, *len);
        memcpy(b, r->held, r->held_len);
        *len = r->held_len;
    }
    return 1;
}
static int hook_flip_c2s_req(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    (void)r; (void)len;
    if (dir == 0 && idx == 2) b[XD_REC_HDR + 3] ^= 0x01; /* idx 0 HELLO, 1 FINISH, 2 request */
    return 1;
}
static int hook_replay_c2s_req(relay_t *r, int dir, int idx, uint8_t *b, size_t *len) {
    /* Hold the first request, deliver it again in place of the second. */
    if (dir == 0 && idx == 2) { memcpy(r->held, b, *len); r->held_len = *len; r->held_valid = 1; }
    if (dir == 0 && idx == 3 && r->held_valid) { memcpy(b, r->held, r->held_len); *len = r->held_len; }
    return 1;
}

TEST(test_service_under_attack) {
    struct { const char *what; hook_fn hook; int fail_req; xd_err_t cerr, serr; } cases[] = {
        { "s->c record modified",  hook_flip_s2c_rec,    1, XD_ERR_TAG,         XD_ERR_PEER_CLOSED },
        { "s->c record replayed",  hook_replay_s2c_rec,  1, XD_ERR_COUNTER,     XD_ERR_PEER_CLOSED },
        { "s->c record dropped",   hook_drop_s2c_rec,    1, XD_ERR_COUNTER,     XD_ERR_PEER_CLOSED },
        { "s->c records reordered", hook_reorder_s2c_rec, 1, XD_ERR_COUNTER,    XD_ERR_PEER_CLOSED },
        { "c->s request modified", hook_flip_c2s_req,    1, XD_ERR_PEER_CLOSED, XD_ERR_TAG },
        { "c->s request replayed", hook_replay_c2s_req,  2, XD_ERR_PEER_CLOSED, XD_ERR_COUNTER },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        relay_t relay;
        int cfd, sfd;
        relay_start(&relay, cases[i].hook, &cfd, &sfd);
        serve_job_t j;
        start_server(&j, sfd, 10 + (unsigned)i, fake_generate, NULL);
        xd_chan_t cc = mkchan(cfd);
        xd_session_t s;
        xd_err_t herr = xd_client_handshake(&cc, NET.pk, NET.sk, ADMIN.pk, &s, 2000);
        CHECK(herr == XD_OK, "%s: handshake %s", cases[i].what, xd_err_str(herr));
        xd_req_result_t r;
        int failed_at = 0;
        for (int q = 1; q <= 2 && !failed_at; q++) {
            if (xd_client_request(&cc, &s, (uint32_t)q, "attack me", 5, 2000, &r) != 0) {
                failed_at = q;
                CHECK(r.err == cases[i].cerr, "%s: client got \"%s\", want \"%s\"", cases[i].what,
                      xd_err_str(r.err), xd_err_str(cases[i].cerr));
                CHECK(s.dead, "%s: client session still alive", cases[i].what);
            }
        }
        CHECK(failed_at == cases[i].fail_req, "%s: failed at request %d, want %d",
              cases[i].what, failed_at, cases[i].fail_req);
        close(cfd);
        pthread_join(j.th, NULL);
        CHECK(j.res.end == cases[i].serr, "%s: server ended with \"%s\", want \"%s\"",
              cases[i].what, xd_err_str(j.res.end), xd_err_str(cases[i].serr));
        relay_join(&relay);
    }
}

typedef struct {
    ident_t *id;
    int cfd;
    int ok;
    char why[160];
} conc_client_t;

static void *conc_client(void *arg) {
    conc_client_t *c = arg;
    xd_chan_t cc = mkchan(c->cfd);
    xd_session_t s;
    xd_err_t e = xd_client_handshake(&cc, c->id->pk, c->id->sk, ADMIN.pk, &s, 2000);
    if (e != XD_OK) {
        snprintf(c->why, sizeof(c->why), "handshake: %s", xd_err_str(e));
        return NULL;
    }
    for (uint32_t i = 1; i <= 5; i++) {
        xd_req_result_t r;
        if (xd_client_request(&cc, &s, i, c->id->name, 8, 5000, &r) == 0) c->ok++;
        else snprintf(c->why, sizeof(c->why), "req %u: %s", i, r.why);
    }
    close(c->cfd);
    return NULL;
}

TEST(test_service_two_channels_concurrently) {
    fake_model_t m = { .fail_after = -1, .delay_us = 5000 };
    int a[2], b[2];
    sp_pair(a);
    sp_pair(b);
    serve_job_t ja, jb;
    start_server(&ja, a[1], 21, fake_generate, &m);
    start_server(&jb, b[1], 22, fake_generate, &m);
    conc_client_t ca = { .id = &NET, .cfd = a[0] }, cb = { .id = &CLI, .cfd = b[0] };
    pthread_t ta, tb;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    pthread_create(&ta, NULL, conc_client, &ca);
    pthread_create(&tb, NULL, conc_client, &cb);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    pthread_join(ja.th, NULL);
    pthread_join(jb.th, NULL);
    CHECK(ca.ok == 5, "net-vm: %d/5 ok (%s)", ca.ok, ca.why);
    CHECK(cb.ok == 5, "client-vm: %d/5 ok (%s)", cb.ok, cb.why);
    CHECK(ja.res.client == 0 && jb.res.client == 1, "server named the channels wrongly");
    CHECK(ja.res.requests == 5 && jb.res.requests == 5, "server request counts");
    /* 2 x 5 requests x 8 tokens x 5 ms = 400 ms if serialised; overlapping
     * channels finish in about half that. */
    double ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
    CHECK(ms < 330.0, "two channels took %.1f ms: not served concurrently?", ms);
}

/* ---- tests: llama-server over HTTP --------------------------------------- */

typedef struct {
    int lfd;
    int port;
    char body[8192];
    size_t body_len;
    /* If set: the response body to send, already chunk-encoded, in place of
     * the SSE_TOKENS stream. */
    const char *raw;
    size_t raw_len;
    /* If > 0: stream this many events instead, one chunk each,
     * stream_delay_us apart, until a send fails; sent and aborted (a send
     * failed: the reader hung up) say how it went. */
    unsigned stream_tokens;
    int stream_delay_us;
    unsigned sent;
    int aborted;
    pthread_t th;
} fake_llama_t;

static const char *const SSE_TOKENS[] = {
    "Hello", ",", " world", "\\n", "\\\"quoted\\\"", " caf\xc3\xa9",
};
static const char FAKE_REPLY[] = "Hello, world\n\"quoted\" caf\xc3\xa9";

/* Listens on 127.0.0.1, any port (f->port). Returns 0, or -1 after a
 * failed CHECK. */
static int fake_llama_listen(fake_llama_t *f) {
    f->lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    socklen_t al = sizeof(a);
    if (f->lfd < 0 || bind(f->lfd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(f->lfd, 4) != 0 ||
        getsockname(f->lfd, (struct sockaddr *)&a, &al) != 0) {
        CHECK(0, "cannot listen on 127.0.0.1: %s", strerror(errno));
        return -1;
    }
    f->port = ntohs(a.sin_port);
    return 0;
}

static void send_all(int c, const char *p, size_t n) {
    while (n > 0) {
        ssize_t w = send(c, p, n, MSG_NOSIGNAL);
        if (w <= 0) return;
        p += w;
        n -= (size_t)w;
    }
}

static void *fake_llama_thread(void *arg) {
    fake_llama_t *f = arg;
    int c = accept(f->lfd, NULL, NULL);
    if (c < 0) return NULL;
    char req[16384];
    size_t got = 0;
    char *hdr_end = NULL;
    while (!hdr_end && got < sizeof(req) - 1) {
        ssize_t n = recv(c, req + got, sizeof(req) - 1 - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
        req[got] = '\0';
        hdr_end = strstr(req, "\r\n\r\n");
    }
    if (hdr_end) {
        const char *cl = strstr(req, "Content-Length:");
        size_t want = cl ? (size_t)strtoul(cl + 15, NULL, 10) : 0;
        size_t have = got - (size_t)(hdr_end + 4 - req);
        while (have < want && got < sizeof(req) - 1) {
            ssize_t n = recv(c, req + got, sizeof(req) - 1 - got, 0);
            if (n <= 0) break;
            got += (size_t)n;
            have += (size_t)n;
        }
        if (have > sizeof(f->body) - 1) have = sizeof(f->body) - 1;
        memcpy(f->body, hdr_end + 4, have);
        f->body[have] = '\0';
        f->body_len = have;
    }
    const char *head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                       "Transfer-Encoding: chunked\r\n\r\n";
    send(c, head, strlen(head), MSG_NOSIGNAL);
    if (f->raw) {
        send_all(c, f->raw, f->raw_len);
        close(c);
        return NULL;
    }
    char ev[512], ch[600];
    if (f->stream_tokens > 0) {
        for (unsigned i = 0; i < f->stream_tokens; i++) {
            int n = snprintf(ev, sizeof(ev), "data: {\"content\":\"w%u \",\"stop\":false}\n\n", i);
            int m = snprintf(ch, sizeof(ch), "%x\r\n%s\r\n", n, ev);
            if (send(c, ch, (size_t)m, MSG_NOSIGNAL) != m) {
                f->aborted = 1;
                break;
            }
            f->sent++;
            struct timespec ts = { 0, (long)f->stream_delay_us * 1000 };
            nanosleep(&ts, NULL);
        }
        if (!f->aborted) {
            int n = snprintf(ev, sizeof(ev), "data: {\"content\":\"\",\"stop\":true}\n\n");
            int m = snprintf(ch, sizeof(ch), "%x\r\n%s\r\n0\r\n\r\n", n, ev);
            send(c, ch, (size_t)m, MSG_NOSIGNAL);
        }
        close(c);
        return NULL;
    }
    for (size_t i = 0; i <= sizeof(SSE_TOKENS) / sizeof(SSE_TOKENS[0]); i++) {
        int n;
        if (i < sizeof(SSE_TOKENS) / sizeof(SSE_TOKENS[0]))
            n = snprintf(ev, sizeof(ev), "data: {\"content\":\"%s\",\"stop\":false}\n\n", SSE_TOKENS[i]);
        else
            n = snprintf(ev, sizeof(ev), "data: {\"content\":\"\",\"stop\":true}\n\n");
        int m = snprintf(ch, sizeof(ch), "%x\r\n%s\r\n", n, ev);
        send(c, ch, (size_t)m, MSG_NOSIGNAL);
    }
    send(c, "0\r\n\r\n", 5, MSG_NOSIGNAL);
    close(c);
    return NULL;
}

static int gen_http(void *gen_ctx, const char *prompt, size_t prompt_len, uint32_t n_predict,
                    int (*on_chunk)(void *ctx, const char *text, size_t len), void *cb_ctx) {
    return llama_stream_completion(gen_ctx, prompt, prompt_len, n_predict, on_chunk, cb_ctx);
}

TEST(test_service_llama_http) {
    fake_llama_t f;
    memset(&f, 0, sizeof(f));
    if (fake_llama_listen(&f) != 0) return;
    pthread_create(&f.th, NULL, fake_llama_thread, &f);

    llama_target_t tgt = { .host = "127.0.0.1", .port = f.port, .log_prefix = "test",
                           .io_timeout_sec = 5 };
    int fds[2];
    sp_pair(fds);
    serve_job_t j;
    start_server(&j, fds[1], 30, gen_http, &tgt);
    xd_chan_t cc = mkchan(fds[0]);
    xd_session_t s;
    CHECK_ERR(xd_client_handshake(&cc, NET.pk, NET.sk, ADMIN.pk, &s, 2000), XD_OK);
    xd_req_result_t r;
    const char *prompt = "Tell me \"something\"\nplease";
    int rc = xd_client_request(&cc, &s, 1, prompt, 17, 5000, &r);
    CHECK(rc == 0 && r.ok, "request through fake llama-server: %s", r.why);
    CHECK(r.tokens == 6, "tokens %u", r.tokens);
    CHECK(r.reply_len == strlen(FAKE_REPLY) && memcmp(r.reply, FAKE_REPLY, r.reply_len) == 0,
          "reply \"%.*s\"", (int)r.reply_len, r.reply);
    pthread_join(f.th, NULL);
    CHECK(strstr(f.body, "\"prompt\":\"Tell me \\\"something\\\"\\nplease\"") != NULL,
          "llama-server got body %s", f.body);
    CHECK(strstr(f.body, "\"n_predict\":17") != NULL, "n_predict missing: %s", f.body);
    char disp[4 * 80 + 1];
    xd_display_text(r.reply, r.reply_len, 80, disp);
    CHECK(strcmp(disp, "Hello, world 'quoted' caf\xc3\xa9") == 0, "display \"%s\"", disp);
    close(fds[0]);
    pthread_join(j.th, NULL);
    close(f.lfd);
}

/*
 * A client that goes away mid-reply must stop the generation, not just
 * stop receiving it: llama-server has --parallel slots, one per client, and
 * a request generating on to n_predict for nobody holds one the whole time.
 * The client takes three chunks of a 2000-token reply and hangs up; the
 * fake llama-server (2 ms per token, so 4 s for all of them) must see its
 * connection dropped within a few tokens.
 */
TEST(test_service_client_departs) {
    fake_llama_t f;
    memset(&f, 0, sizeof(f));
    f.stream_tokens = 2000;
    f.stream_delay_us = 2000;
    if (fake_llama_listen(&f) != 0) return;
    pthread_create(&f.th, NULL, fake_llama_thread, &f);
    llama_target_t tgt = { .host = "127.0.0.1", .port = f.port, .log_prefix = "test",
                           .io_timeout_sec = 5 };
    int fds[2];
    sp_pair(fds);
    serve_job_t j;
    start_server(&j, fds[1], 31, gen_http, &tgt);
    xd_chan_t cc = mkchan(fds[0]);
    xd_session_t s;
    CHECK_ERR(xd_client_handshake(&cc, NET.pk, NET.sk, ADMIN.pk, &s, 2000), XD_OK);
    bench_request_t req;
    memset(&req, 0, sizeof(req));
    req.magic = BENCH_MAGIC;
    req.type = MSG_REQUEST;
    req.request_id = 1;
    req.max_tokens = 2000;
    memcpy(req.prompt, "go", 2);
    req.prompt_len = 2;
    CHECK_ERR(xd_send_record(&cc, &s, XD_REC_APP, &req, bench_request_wire_len(&req)), XD_OK);
    for (int i = 0; i < 3; i++) {
        bench_msg_t m;
        uint8_t type = 0;
        size_t len = 0;
        CHECK_ERR(xd_recv_record(&cc, &s, &type, &m, sizeof(m), &len, 2000), XD_OK);
    }
    close(fds[0]); /* the client is gone */
    pthread_join(j.th, NULL);
    pthread_join(f.th, NULL);
    close(f.lfd);
    CHECK_ERR(j.res.end, XD_ERR_PEER_CLOSED);
    CHECK(f.aborted, "llama-server's connection stayed up: it sent all %u tokens", f.sent);
    CHECK(f.sent < 100, "llama-server sent %u of 2000 tokens to a departed client", f.sent);
}

typedef struct {
    char text[8192];
    size_t len;
    unsigned n;
} collect_t;

static int collect_chunk(void *ctx, const char *text, size_t len) {
    collect_t *c = ctx;
    if (c->len + len < sizeof(c->text)) {
        memcpy(c->text + c->len, text, len);
        c->len += len;
    }
    c->n++;
    return 0;
}

/*
 * An HTTP chunk can be larger than the LLAMA_HTTP_READ_CAP bytes llama_http.c
 * decodes per call: llama-server sends each SSE event as one chunk, and its
 * last one repeats the whole prompt, JSON-escaped, which can pass 16 KiB.
 * The decoder must then hand the chunk out over several calls and only
 * afterwards read its CRLF and the next size line; it used to take two
 * bytes of event data as the CRLF and parse the next "size" from inside the
 * JSON. Chunk sizes just below, on, just above and well above the boundary,
 * each chunk carrying many events, at its END (behind an SSE comment line as
 * padding) so the boundary falls among them, and a long padding line in the
 * last case so it spans one boundary on its own.
 */
TEST(test_llama_http_chunk_sizes) {
    enum { EVENTS = 120 };
    const size_t sizes[] = {
        LLAMA_HTTP_READ_CAP - 1, LLAMA_HTTP_READ_CAP, LLAMA_HTTP_READ_CAP + 1,
        LLAMA_HTTP_READ_CAP + 1500, 2 * LLAMA_HTTP_READ_CAP + 7,
    };
    static char raw[3 * LLAMA_HTTP_READ_CAP];
    char events[EVENTS * 64], want[EVENTS * 8];
    size_t ev_len = 0, want_len = 0;
    for (unsigned i = 0; i < EVENTS; i++) {
        ev_len += (size_t)snprintf(events + ev_len, sizeof(events) - ev_len,
                                   "data: {\"content\":\"t%03u \",\"stop\":false}\n\n", i);
        want_len += (size_t)snprintf(want + want_len, sizeof(want) - want_len, "t%03u ", i);
    }
    for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
        size_t sz = sizes[k], o = 0;
        /* chunk 1: ":xxx...x\n" padding, then the events, exactly sz bytes */
        o += (size_t)snprintf(raw + o, sizeof(raw) - o, "%zx\r\n:", sz);
        size_t pad = sz - ev_len - 2;
        memset(raw + o, 'x', pad);
        o += pad;
        raw[o++] = '\n';
        memcpy(raw + o, events, ev_len);
        o += ev_len;
        o += (size_t)snprintf(raw + o, sizeof(raw) - o, "\r\n");
        /* chunk 2: the stop event; then the last chunk */
        const char *stop = "data: {\"content\":\"\",\"stop\":true}\n\n";
        o += (size_t)snprintf(raw + o, sizeof(raw) - o, "%zx\r\n%s\r\n0\r\n\r\n", strlen(stop), stop);

        fake_llama_t f;
        memset(&f, 0, sizeof(f));
        f.raw = raw;
        f.raw_len = o;
        if (fake_llama_listen(&f) != 0) return;
        pthread_create(&f.th, NULL, fake_llama_thread, &f);
        llama_target_t tgt = { .host = "127.0.0.1", .port = f.port, .log_prefix = "test",
                               .io_timeout_sec = 5 };
        collect_t got;
        memset(&got, 0, sizeof(got));
        int rc = llama_stream_completion(&tgt, "p", 1, EVENTS, collect_chunk, &got);
        pthread_join(f.th, NULL);
        close(f.lfd);
        CHECK(rc == 0, "chunk of %zu bytes: rc %d", sz, rc);
        CHECK(got.n == EVENTS, "chunk of %zu bytes: %u events, want %d", sz, got.n, EVENTS);
        CHECK(got.len == want_len && memcmp(got.text, want, want_len) == 0,
              "chunk of %zu bytes: text differs (%zu bytes, want %zu)", sz, got.len, want_len);
    }
}

/* ---- tests: display text ------------------------------------------------- */

TEST(test_display_text) {
    char out[4 * 80 + 1];
    xd_display_text("a\tb\nc\rd\x01" "e\x7f" "f\x1b[31mg", 17, 80, out);
    CHECK(strcmp(out, "a b c def[31mg") == 0, "controls: \"%s\"", out);
    xd_display_text("say \"hi\"", 8, 80, out);
    CHECK(strcmp(out, "say 'hi'") == 0, "quotes: \"%s\"", out);
    /* 100 x 'x' -> 80 */
    char in[200];
    memset(in, 'x', 100);
    xd_display_text(in, 100, 80, out);
    CHECK(strlen(out) == 80, "ascii truncation: %zu", strlen(out));
    /* 100 x U+00E9 (2 bytes) -> 80 characters, 160 bytes, none split */
    char u[200];
    for (int i = 0; i < 100; i++) { u[2 * i] = (char)0xc3; u[2 * i + 1] = (char)0xa9; }
    xd_display_text(u, 200, 80, out);
    CHECK(strlen(out) == 160, "utf-8 truncation: %zu bytes", strlen(out));
    /* C1 control U+009B (CSI) is dropped */
    xd_display_text("a\xc2\x9b" "b", 4, 80, out);
    CHECK(strcmp(out, "ab") == 0, "C1: \"%s\"", out);
    /* invalid UTF-8: endless continuation bytes stay within 4 bytes/char */
    char bad[300];
    bad[0] = (char)0xe2;
    memset(bad + 1, 0x80, sizeof(bad) - 1);
    xd_display_text(bad, sizeof(bad), 80, out);
    CHECK(strlen(out) <= 4, "continuation run: %zu bytes", strlen(out));
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <test-keys dir>\n", argv[0]);
        return 2;
    }
    g_keydir = argv[1];
    signal(SIGPIPE, SIG_IGN);
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 2;
    }
    load_ident(&ADMIN);
    load_ident(&NET);
    load_ident(&CLI);
    snprintf(g_clients_all[0].name, sizeof(g_clients_all[0].name), "net-vm");
    memcpy(g_clients_all[0].pk, NET.pk_file, 32);
    snprintf(g_clients_all[1].name, sizeof(g_clients_all[1].name), "client-vm");
    memcpy(g_clients_all[1].pk, CLI.pk_file, 32);
    g_clients_net[0] = g_clients_all[0];

    RUN(test_seed_to_pk);
    RUN(test_key_file_parsing);
    RUN(test_handshake_success);
    RUN(test_handshake_wrong_server_key);
    RUN(test_handshake_unknown_client);
    RUN(test_handshake_impersonation);
    RUN(test_handshake_tampering);
    RUN(test_handshake_replay);
    RUN(test_handshake_timeout);
    RUN(test_spec_conformance);
    RUN(test_records_in_order);
    RUN(test_records_tampered);
    RUN(test_records_replay_reorder);
    RUN(test_records_cross_channel);
    RUN(test_service_clean);
    RUN(test_service_waits_for_a_late_hello);
    RUN(test_service_peer_close);
    RUN(test_service_malformed_request);
    RUN(test_client_rejects_bad_stream);
    RUN(test_service_under_attack);
    RUN(test_service_two_channels_concurrently);
    RUN(test_service_llama_http);
    RUN(test_service_client_departs);
    RUN(test_llama_http_chunk_sizes);
    RUN(test_display_text);

    fprintf(stderr, "test-demo: %d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
