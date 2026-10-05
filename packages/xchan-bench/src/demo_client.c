/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* demo_client.c, xchan-demo-client: one client guest of the encrypted
 * guest-to-guest LLM demo.
 *
 *   xchan-demo-client -e /dev/xchan0 --name <vm> --key <seed file>
 *                     --server-pk <pk file> -n <N> -p <prompt>
 *                     [--close-reopen] [-t <n_predict>] [--show-text]
 *
 * Opens a channel, runs the demo_crypto.c handshake against the pinned
 * server key, then N encrypted requests, printing for each
 *   DEMO client=<name> req=<i> ttft_ms=<x> tokens=<n> tok_s=<y> reply_len=<b>
 * (or "DEMO client=<name> req=<i> FAILED reason=\"...\"") and finally
 *   DEMO client=<name> ok=<k> failed=<m>
 * ok counts successful requests; failed counts failed steps, failed
 * requests, plus the closed-channel probe of --close-reopen if it did not
 * see ECONNRESET. Exit status 0 iff failed=0 and every request succeeded.
 *
 * Nothing derived from the reply's content is printed by default: this output
 * is collected over ssh by the host-side orchestrator, so whatever is printed
 * here lands in the HOST's journal. That rules out the text and also any
 * digest of it, the host knows the prompt and the model, so it could
 * confirm a guessed reply against an unkeyed hash offline. reply_len tells
 * the host nothing new: it already sees the size of every reply record. The
 * reply text is printed (as text="<...>") only with --show-text, an explicit
 * opt-in for running the client by hand.
 *
 * --close-reopen (N is then ignored; 2 requests): one request; an encrypted CLOSE; wait
 * for the server's close to reach this end; a send on the old channel must
 * now fail with ECONNRESET ("closed-channel-send=ECONNRESET", anything else
 * counts as a failure); close the old channel, wait for a fresh channel, a
 * fresh handshake, one more request.
 *
 * Bounded waits everywhere, because the host can stall any of them: every
 * receive is poll()ed with a timeout, the device fd is O_NONBLOCK and
 * polled for a new channel, and a watchdog thread covers the one wait poll()
 * cannot: a multi-fragment xchan message whose first fragment arrived and
 * whose rest never does blocks in the driver's TASK_KILLABLE committed
 * wait, which only a fatal signal ends. The watchdog then prints the
 * failure and _exit()s, which kills the stuck thread with the process.
 * g2gchan's calls are guarded the same way: g2gc_recv() waits for the rest
 * of a message and g2gc_send() for credit, each for up to G2GC_STALL_MS
 * (g2gchan.h), longer than WATCHDOG_GRACE_MS by default.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "demo_crypto.h"
#include "demo_session.h"
#include "libxchan.h"
#include "g2gchan.h"

/*
 * Time budget. The host orchestrator runs this client under `timeout
 * <clientTimeoutSeconds>` (300 s by default, xchan-demo.nix), which on
 * expiry SIGTERMs the whole process group: the client and the
 * xchan-demo-run wrapper that relays its output alike. A run still going
 * by then loses its "ok= failed=" line with it, so every wait here is
 * bounded for the run to end on its own well inside that:
 *   CONNECT_TIMEOUT_MS, RECONNECT_TIMEOUT_MS: ONE deadline per connect,
 *     covering the channel wait, the handshake and every stale-channel
 *     retry (a fresh wait per retry let four attempts take 4 x (60 + 15) s);
 *   RECORD_TIMEOUT_MS: the longest silence inside a request, after which
 *     the channel is dead and every later request fails at once;
 *   CLOSE_SETTLE_TIMEOUT_MS: --close-reopen's wait for the server's close
 *     (always the whole of it over g2g, see close_and_probe()).
 * Waiting adds up to at most 60 + 60 = 120 s with -n N, and 60 + 60 + 10 +
 * 30 + 60 = 220 s with --close-reopen, plus whatever time the server
 * spends actually streaming replies. (WATCHDOG_GRACE_MS is no extra wait:
 * a channel call stuck that long ends the run, summary line included.) The
 * two connect budgets can be overridden at build time, for tests.
 */
#ifndef CONNECT_TIMEOUT_MS
#define CONNECT_TIMEOUT_MS        60000 /* the channel may still be coming up */
#endif
#ifndef RECONNECT_TIMEOUT_MS
#define RECONNECT_TIMEOUT_MS      30000
#endif
#define CLOSE_SETTLE_TIMEOUT_MS   10000 /* server close -> our end sees DETACHED */
#define RECORD_TIMEOUT_MS         60000 /* longest silence inside a request */
#define WATCHDOG_GRACE_MS         10000 /* a started send/recv must finish by then */
#define DISPLAY_CHARS             80

static const char *g_name = "?";
static int g_show_text; /* --show-text; see the header comment */

/* ---- watchdog ---------------------------------------------------------- */

static pthread_mutex_t wd_lock = PTHREAD_MUTEX_INITIALIZER;
static long long wd_deadline_ms; /* 0 = disarmed */
static const char *wd_what = "";
static int wd_ok, wd_failed;     /* tallies, for the line the watchdog prints */

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void wd_arm(const char *what, int ms) {
    pthread_mutex_lock(&wd_lock);
    wd_deadline_ms = mono_ms() + ms;
    wd_what = what;
    pthread_mutex_unlock(&wd_lock);
}
static void wd_disarm(void) {
    pthread_mutex_lock(&wd_lock);
    wd_deadline_ms = 0;
    pthread_mutex_unlock(&wd_lock);
}
static void wd_tally(int ok, int failed) {
    pthread_mutex_lock(&wd_lock);
    wd_ok = ok;
    wd_failed = failed;
    pthread_mutex_unlock(&wd_lock);
}

static void *watchdog(void *arg) {
    (void)arg;
    for (;;) {
        struct timespec ts = { 0, 250 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        pthread_mutex_lock(&wd_lock);
        long long dl = wd_deadline_ms;
        const char *what = wd_what;
        int ok = wd_ok, failed = wd_failed;
        pthread_mutex_unlock(&wd_lock);
        if (dl != 0 && mono_ms() > dl) {
            /* dprintf, not stdio: the stuck thread might hold stdout's lock. */
            dprintf(STDOUT_FILENO,
                    "DEMO client=%s watchdog: %s stuck for over %d ms\n"
                    "DEMO client=%s ok=%d failed=%d\n",
                    g_name, what, WATCHDOG_GRACE_MS, g_name, ok, failed + 1);
            _exit(1);
        }
    }
    return NULL;
}

/* ---- xchan channel ops, watchdog-guarded ------------------------------- */

static ssize_t chan_send(xd_chan_t *c, const void *buf, size_t len) {
    wd_arm("xchan_send", WATCHDOG_GRACE_MS);
    ssize_t n = xchan_send(c->fd, buf, len);
    int e = errno;
    wd_disarm();
    errno = e;
    return n;
}
static ssize_t chan_recv(xd_chan_t *c, void *buf, size_t cap) {
    wd_arm("xchan_recv", WATCHDOG_GRACE_MS);
    ssize_t n = xchan_recv(c->fd, buf, cap);
    int e = errno;
    wd_disarm();
    errno = e;
    return n;
}

/* g2gchan's channel ops, watchdog-guarded like xchan's. */
static ssize_t g2g_chan_send(xd_chan_t *c, const void *buf, size_t len) {
    wd_arm("g2gc_send", WATCHDOG_GRACE_MS);
    ssize_t n = g2gc_send(c->user, buf, len);
    int e = errno;
    wd_disarm();
    errno = e;
    return n;
}
static ssize_t g2g_chan_recv(xd_chan_t *c, void *buf, size_t cap) {
    wd_arm("g2gc_recv", WATCHDOG_GRACE_MS);
    ssize_t n = g2gc_recv(c->user, buf, cap);
    int e = errno;
    wd_disarm();
    errno = e;
    return n;
}

/* devfd is O_NONBLOCK: poll for a ready channel, then claim it; EAGAIN means
 * it went elsewhere, so poll again until the deadline. */
static int wait_channel(int devfd, int timeout_ms, unsigned *channel_id) {
    long long deadline = mono_ms() + timeout_ms;
    for (;;) {
        struct xchan_channel_info info;
        int fd = xchan_wait_channel(devfd, &info);
        if (fd >= 0) {
            *channel_id = info.channel_id;
            return fd;
        }
        if (errno != EAGAIN && errno != EINTR) return -1;
        long long left = deadline - mono_ms();
        if (left <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct pollfd p = { .fd = devfd, .events = POLLIN, .revents = 0 };
        if (poll(&p, 1, (int)left) < 0 && errno != EINTR) return -1;
    }
}

static const char *errno_name(int e) {
    switch (e) {
        case ECONNRESET: return "ECONNRESET";
        case EAGAIN:     return "EAGAIN";
        case EPIPE:      return "EPIPE";
        case ENODEV:     return "ENODEV";
        case EINTR:      return "EINTR";
        case ECANCELED:  return "ECANCELED";
        case EMSGSIZE:   return "EMSGSIZE";
        case EBADF:      return "EBADF";
        case EINVAL:     return "EINVAL";
        case EIO:        return "EIO";
        case ETIMEDOUT:  return "ETIMEDOUT";
        default:         return NULL;
    }
}

/* ---- the run ----------------------------------------------------------- */

typedef struct {
    int devfd;
    int use_g2g;         /* -e g2g:<id-hi>[:<id-lo>]: g2gchan instead of xchan */
    uint64_t g2g_hi, g2g_lo;
    g2gc_t *g;           /* the g2g channel, or NULL */
    xd_chan_t chan;      /* chan.fd < 0: no channel */
    xd_session_t sess;   /* sess.dead: no usable session */
    uint8_t pk[XD_PK_BYTES], sk[XD_SK_BYTES], server_pk[XD_PK_BYTES];
    const char *prompt;
    uint32_t n_predict;
    int ok, failed;
} run_t;

static void count(run_t *r, int good) {
    if (good) r->ok++; else r->failed++;
    wd_tally(r->ok, r->failed);
}
static void count_failed_step(run_t *r) {
    r->failed++;
    wd_tally(r->ok, r->failed);
}

/*
 * A channel handed out by WAIT_CHANNEL may already be dead: crosvm opens a
 * client's next channel as soon as its previous one closes (or as soon as
 * the VM boots), so it can have been sitting unclaimed long enough for the
 * peer to have dropped it. Such a channel fails the handshake with
 * XD_ERR_PEER_CLOSED before the server has said anything; closing it is what
 * lets crosvm open a fresh one, so take the next channel instead, a
 * bounded number of times, and all within the one connect deadline, since a
 * host that keeps killing channels must still end in a failure, not a loop.
 */
#define STALE_CHANNEL_RETRIES 3

/* Gets a channel and runs the handshake on it, retries included, within
 * budget_ms (see the time budget at the top). Prints one line either way.
 * On failure the run continues: the requests that follow fail and say so. */
static void connect_channel(run_t *r, int budget_ms) {
    char fp[9];
    xd_fingerprint(r->server_pk, fp);
    long long deadline = mono_ms() + budget_ms;
    if (r->use_g2g) {
        r->sess.dead = 1;
        r->g = g2gc_connect(r->g2g_hi, r->g2g_lo, budget_ms);
        if (!r->g) {
            printf("DEMO client=%s channel=none reason=\"g2g connect: %s\"\n", g_name, strerror(errno));
            return;
        }
        r->chan.fd = g2gc_fd(r->g);
        r->chan.send = g2g_chan_send;
        r->chan.recv = g2g_chan_recv;
        r->chan.user = r->g;
        long long left = deadline - mono_ms();
        int hs_ms = left >= XD_HANDSHAKE_TIMEOUT_MS ? XD_HANDSHAKE_TIMEOUT_MS : left > 0 ? (int)left : 0;
        xd_err_t err = xd_client_handshake(&r->chan, r->pk, r->sk, r->server_pk, &r->sess, hs_ms);
        if (err == XD_OK) {
            printf("DEMO client=%s channel=g2g handshake=ok server_fp=%s\n", g_name, fp);
            return;
        }
        printf("DEMO client=%s channel=g2g handshake=fail reason=\"%s\" server_fp=%s\n",
               g_name, xd_err_str(err), fp);
        g2gc_close(r->g);
        r->g = NULL;
        r->chan.fd = -1;
        return;
    }
    for (int attempt = 0;; attempt++) {
        unsigned id = 0;
        r->sess.dead = 1;
        long long left = deadline - mono_ms();
        r->chan.fd = wait_channel(r->devfd, left > 0 ? (int)left : 0, &id);
        if (r->chan.fd < 0) {
            printf("DEMO client=%s channel=none reason=\"%s\"\n", g_name,
                   errno == ETIMEDOUT ? "no channel within the timeout" : strerror(errno));
            return;
        }
        /* The handshake gets what is left of the budget, at most its usual
         * per-step bound. */
        left = deadline - mono_ms();
        int hs_ms = left >= XD_HANDSHAKE_TIMEOUT_MS ? XD_HANDSHAKE_TIMEOUT_MS
                  : left > 0                         ? (int)left
                                                     : 0;
        xd_err_t err = xd_client_handshake(&r->chan, r->pk, r->sk, r->server_pk, &r->sess,
                                           hs_ms);
        if (err == XD_OK) {
            printf("DEMO client=%s channel=%u handshake=ok server_fp=%s\n", g_name, id, fp);
            return;
        }
        close(r->chan.fd);
        r->chan.fd = -1;
        if (err == XD_ERR_PEER_CLOSED && attempt < STALE_CHANNEL_RETRIES) {
            printf("DEMO client=%s channel=%u stale (closed before the handshake), "
                   "taking the next one\n", g_name, id);
            continue;
        }
        printf("DEMO client=%s channel=%u handshake=fail reason=\"%s\" server_fp=%s\n",
               g_name, id, xd_err_str(err), fp);
        return;
    }
}

static void drop_channel(run_t *r) {
    xd_session_kill(&r->sess);
    if (r->g) {
        g2gc_close(r->g);
        r->g = NULL;
        r->chan.fd = -1;
        return;
    }
    if (r->chan.fd >= 0) close(r->chan.fd);
    r->chan.fd = -1;
}

static void one_request(run_t *r, uint32_t i) {
    xd_req_result_t res;
    if (r->chan.fd < 0 || r->sess.dead) {
        printf("DEMO client=%s req=%u FAILED reason=\"no secure channel\"\n", g_name, i);
        count(r, 0);
        return;
    }
    if (xd_client_request(&r->chan, &r->sess, i, r->prompt, r->n_predict,
                          RECORD_TIMEOUT_MS, &res) != 0) {
        printf("DEMO client=%s req=%u FAILED reason=\"%s\"\n", g_name, i, res.why);
        count(r, 0);
        /* Any channel-level failure: the session is dead, close the channel. */
        if (r->sess.dead) drop_channel(r);
        return;
    }
    char tps[32];
    if (res.tok_s_defined) snprintf(tps, sizeof(tps), "%.2f", res.tok_s);
    else snprintf(tps, sizeof(tps), "n/a");
    printf("DEMO client=%s req=%u ttft_ms=%.2f tokens=%u tok_s=%s reply_len=%zu",
           g_name, i, res.ttft_ms, res.tokens, tps, (size_t)res.reply_len);
    if (g_show_text) {
        char text[4 * DISPLAY_CHARS + 1];
        xd_display_text(res.reply, res.reply_len, DISPLAY_CHARS, text);
        printf(" text=\"%s\"", text);
    }
    printf("\n");
    count(r, 1);
}

/* The CLOSE step of --close-reopen. Counts as a failed step unless the
 * send on the closed channel fails with exactly ECONNRESET. */
static void close_and_probe(run_t *r) {
    if (r->chan.fd < 0 || r->sess.dead) {
        printf("DEMO client=%s closed-channel-send=SKIPPED reason=\"no secure channel\"\n", g_name);
        count_failed_step(r);
        return;
    }
    xd_err_t err = xd_send_record(&r->chan, &r->sess, XD_REC_CLOSE, NULL, 0);
    if (err != XD_OK) {
        printf("DEMO client=%s closed-channel-send=SKIPPED reason=\"sending CLOSE failed: %s\"\n",
               g_name, xd_err_str(err));
        count_failed_step(r);
        drop_channel(r);
        return;
    }

    /* Wait (bounded) for the server's close to arrive here as a hang-up.
     * POLLHUP/POLLERR are always reported, so no events are requested,
     * the xchan fd is always writable and would otherwise wake us at once.
     * Over g2g, chan.fd is g2gchan's eventfd, which never reports POLLHUP or
     * POLLERR: the wait then always runs the full CLOSE_SETTLE_TIMEOUT_MS
     * and ends with hup = 0. The probe below does not depend on it. */
    long long deadline = mono_ms() + CLOSE_SETTLE_TIMEOUT_MS;
    int hup = 0;
    for (;;) {
        long long left = deadline - mono_ms();
        if (left <= 0) break;
        struct pollfd p = { .fd = r->chan.fd, .events = 0, .revents = 0 };
        int pr = poll(&p, 1, (int)left);
        if (pr < 0 && errno == EINTR) continue;
        if (pr > 0 && (p.revents & (POLLHUP | POLLERR))) hup = 1;
        break;
    }

    /* The probe is a sealed record like any other, so even if the send
     * wrongly succeeds the host only ever sees ciphertext. */
    uint8_t rec[XD_REC_OVERHEAD];
    size_t n = 0;
    err = xd_seal(&r->sess, XD_REC_CLOSE, NULL, 0, rec, sizeof(rec), &n);
    if (err != XD_OK) {
        printf("DEMO client=%s closed-channel-send=SKIPPED reason=\"%s\"\n", g_name, xd_err_str(err));
        count_failed_step(r);
        drop_channel(r);
        return;
    }
    ssize_t s = r->chan.send(&r->chan, rec, n);
    int e = errno;
    if (s < 0 && e == ECONNRESET) {
        printf("DEMO client=%s closed-channel-send=ECONNRESET\n", g_name);
    } else if (s >= 0) {
        printf("DEMO client=%s closed-channel-send=SUCCEEDED hangup_seen=%d (expected ECONNRESET)\n",
               g_name, hup);
        count_failed_step(r);
    } else {
        const char *nm = errno_name(e);
        if (nm) printf("DEMO client=%s closed-channel-send=%s (expected ECONNRESET)\n", g_name, nm);
        else printf("DEMO client=%s closed-channel-send=errno%d (expected ECONNRESET)\n", g_name, e);
        count_failed_step(r);
    }
    drop_channel(r);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s -e <xchan device | g2g:<id-hi>[:<id-lo>]> --name <vm> --key <seed file> --server-pk <pk file>\n"
        "          -n <requests> -p <prompt> [--close-reopen] [-t <n_predict, default 32>]\n"
        "          [--show-text: also print the decrypted reply, it then reaches whoever\n"
        "           reads this output, which for the demo orchestrator is the host]\n",
        argv0);
}

int main(int argc, char **argv) {
    const char *dev = NULL, *key = NULL, *server_pk = NULL, *prompt = NULL;
    long n_req = -1, n_predict = 32;
    int close_reopen = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) dev = argv[++i];
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) g_name = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key = argv[++i];
        else if (strcmp(argv[i], "--server-pk") == 0 && i + 1 < argc) server_pk = argv[++i];
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) n_req = strtol(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) prompt = argv[++i];
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) n_predict = strtol(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--close-reopen") == 0) close_reopen = 1;
        else if (strcmp(argv[i], "--show-text") == 0) g_show_text = 1;
        else { usage(argv[0]); return 2; }
    }
    if (!dev || !key || !server_pk || !prompt || n_req < 1 || n_req > 100000 ||
        n_predict < 1 || n_predict > (long)XD_MAX_PREDICT || strcmp(g_name, "?") == 0) {
        usage(argv[0]);
        return 2;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);

    static run_t r; /* static: holds key material, kept off the stack */
    r.prompt = prompt;
    r.n_predict = (uint32_t)n_predict;
    r.chan.fd = -1;
    r.chan.send = chan_send;
    r.chan.recv = chan_recv;
    r.sess.dead = 1;
    int total = close_reopen ? 2 : (int)n_req; /* requests */

    if (sodium_init() < 0) {
        printf("DEMO client=%s error=\"sodium_init failed\"\nDEMO client=%s ok=0 failed=%d\n",
               g_name, g_name, total);
        return 1;
    }
    const char *why = NULL;
    if (xd_load_identity(key, r.pk, r.sk, &why) != 0 ||
        xd_read_hex32(server_pk, r.server_pk, &why) != 0) {
        printf("DEMO client=%s error=\"key files: %s\"\nDEMO client=%s ok=0 failed=%d\n",
               g_name, why, g_name, total);
        return 1;
    }

    pthread_t wd;
    if (pthread_create(&wd, NULL, watchdog, NULL) != 0) {
        printf("DEMO client=%s error=\"cannot start watchdog\"\nDEMO client=%s ok=0 failed=%d\n",
               g_name, g_name, total);
        return 1;
    }

    r.devfd = -1;
    if (strncmp(dev, "g2g:", 4) == 0) {
        char *end = NULL;
        r.use_g2g = 1;
        r.g2g_lo = G2GC_PROBE_ID_LO;
        r.g2g_hi = strtoull(dev + 4, &end, 0);
        if (*end == ':') r.g2g_lo = strtoull(end + 1, &end, 0);
        if (*end != '\0' || r.g2g_hi == 0) {
            printf("DEMO client=%s error=\"bad endpoint %s\"\nDEMO client=%s ok=0 failed=%d\n",
                   g_name, dev, g_name, total);
            return 1;
        }
    } else if ((r.devfd = xchan_open(dev)) < 0 ||
               fcntl(r.devfd, F_SETFL, fcntl(r.devfd, F_GETFL) | O_NONBLOCK) != 0) {
        printf("DEMO client=%s error=\"open %s: %s\"\nDEMO client=%s ok=0 failed=%d\n",
               g_name, dev, strerror(errno), g_name, total);
        return 1;
    }

    connect_channel(&r, CONNECT_TIMEOUT_MS);
    if (!close_reopen) {
        for (long i = 1; i <= n_req; i++) one_request(&r, (uint32_t)i);
    } else {
        one_request(&r, 1);
        close_and_probe(&r);
        connect_channel(&r, RECONNECT_TIMEOUT_MS);
        one_request(&r, 2);
    }
    drop_channel(&r);
    if (r.devfd >= 0) close(r.devfd);
    sodium_memzero(r.sk, sizeof(r.sk));

    printf("DEMO client=%s ok=%d failed=%d\n", g_name, r.ok, r.failed);
    return r.failed == 0 && r.ok == total ? 0 : 1;
}
