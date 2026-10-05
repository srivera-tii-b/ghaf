/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* demo_crypto.c, secure channel for the encrypted xchan LLM demo.
 *
 * =====================================================================
 * THREAT MODEL
 *   The host is untrusted: crosvm on the host relays every byte between the
 *   guests and can read, drop, reorder, replay, delay, inject and rewrite
 *   anything on an xchan channel. Client guests mutually distrust (net-vm
 *   must not be able to pass for client-vm). Availability is out of scope:
 *   the host can always stop forwarding.
 *
 * PROTOCOL (version 1). All primitives are libsodium's; nothing hand-rolled.
 *
 *   Identities. Every guest has an Ed25519 key pair, from a 32-byte seed
 *   via crypto_sign_seed_keypair(). The server (admin-vm) pins the client
 *   public keys (one <name>.pk file each); each client pins the server's.
 *
 *   Handshake, one per channel (signed ephemeral X25519, SIGMA-style).
 *   Every message is one transport message of a fixed size.
 *
 *     C -> S  HELLO (98 B)
 *               0x01 | version (0x01) | client static Ed25519 pk (32)
 *                    | client ephemeral X25519 pk (32, crypto_kx_keypair)
 *                    | client random (32)
 *     S       rejects unless the static pk equals one of its pinned client
 *             keys (sodium_memcmp); the matching file's basename names the
 *             client in the logs.
 *     S -> C  SERVER_HELLO (129 B)
 *               0x02 | server ephemeral pk (32) | server random (32)
 *                    | Ed25519 signature by the server's static key over
 *                      H_s = BLAKE2b-256("xchan-demo v1" || HELLO
 *                                        || server eph pk || server random
 *                                        || "server")
 *     C       verifies the signature with the pinned server pk.
 *     C -> S  CLIENT_FINISH (65 B)
 *               0x03 | Ed25519 signature by the client's static key over
 *                      H_c = BLAKE2b-256(same inputs || "client")
 *     S       verifies it with the pk of the client named in HELLO.
 *
 *     HELLO above means the exact 98 bytes on the wire. The labels are ASCII
 *     with no terminator.
 *
 *     Session keys: crypto_kx_client_session_keys() /
 *     crypto_kx_server_session_keys() on the two ephemeral key pairs give
 *     one key per direction; each is then re-derived as
 *       key' = crypto_generichash(out 32, in = T, key = key)
 *       T    = BLAKE2b-256("xchan-demo v1" || HELLO || server eph pk
 *                          || server random || "keys")
 *     so the record keys are bound to this handshake's transcript, not
 *     just to the ephemeral DH result. Ephemeral secrets, the raw kx keys
 *     and the transcript hashes are wiped once the keys exist.
 *
 *   Records, after the handshake, both directions:
 *       type (1) | counter (8, LE) | plaintext length (4, LE)
 *                | crypto_aead_xchacha20poly1305_ietf ciphertext + tag (16)
 *     nonce = the direction's 64-bit counter, little endian, zero-padded
 *             to 24 bytes; starts at 0, +1 per record.
 *     AD    = type (1) || plaintext length (4, LE).
 *     Types: 0x10 APP (one proto.h bench message), 0x11 CLOSE (empty: ask
 *     the server to close the channel).
 *     The receiver accepts only counter == the next one it expects, and
 *     decrypts with the nonce built from ITS OWN expected counter, not the
 *     wire field, so even without the explicit check a replayed or reordered
 *     record could only fail. The counter travels in the clear only so
 *     that a mismatch is reported as such ("counter mismatch") rather than
 *     as an anonymous tag failure.
 *
 *   Any failure, bad signature, unknown client, bad tag, counter
 *   mismatch, malformed message, timeout, kills the session (keys wiped,
 *   every later call fails) and the caller logs one line with the reason
 *   (at most a key fingerprint: the first 8 hex digits of a PUBLIC key) and
 *   closes the channel. There is no error message to the peer and no retry
 *   within a session.
 *
 * PROPERTIES PROVIDED
 *   - Mutual authentication against pinned keys. The client proceeds only if
 *     the pinned server key signed a transcript containing the client's own
 *     fresh HELLO (its ephemeral and random); the server proceeds only for a
 *     pinned client key that signed a transcript containing the server's
 *     fresh ephemeral and random. A replayed signature from another
 *     handshake does not verify. The "server"/"client" labels stop one
 *     side's signature being reflected as the other's.
 *   - Confidentiality and integrity of every record against the host: it
 *     sees only ciphertext, and any modification fails the tag.
 *   - Forward secrecy. Record keys depend only on the ephemeral X25519 keys
 *     (plus public transcript data), which are wiped after the handshake. A
 *     later theft of a guest's Ed25519 seed lets the thief impersonate that
 *     guest from then on; it does not decrypt recorded past traffic.
 *   - No replay, reordering or dropping within a session (strict counters:
 *     a dropped record makes the next one a counter mismatch), and no
 *     truncation passed off as success: a response is complete only when its
 *     authenticated DONE record arrives.
 *   - No cross-channel replay. Each session's keys come from fresh
 *     ephemerals and randoms on both sides, so a record or handshake message
 *     lifted from another channel (or an earlier session on this one) fails
 *     the tag or the signature check. Since a handshake message re-routed
 *     between channels by the host simply completes the same session
 *     between the same two authenticated parties, the host gains nothing by
 *     doing so.
 *
 * NOT PROVIDED (by design for this demo, or out of scope)
 *   - Identity hiding: HELLO carries the client's static pk in the clear, so
 *     the host learns which client is talking.
 *   - Traffic-analysis resistance: record sizes and timing are visible.
 *     There is one record per generated token, so the host sees the prompt
 *     length, the byte length of every token and the token timing.
 *   - Key provisioning: the committed test keys in ../test-keys are public
 *     and land world-readable in the nix store, which every guest mounts;
 *     real keys need per-device provisioning.
 *   - Availability, and protection from a compromised endpoint (admin-vm sees
 *     every plaintext prompt and reply by construction).
 *   - Binding of the server's static key into the transcript. Each client
 *     pins exactly one server key here, so the unknown-key-share pattern
 *     this would prevent cannot arise; add the server pk to H_s/H_c/T before
 *     ever letting a client accept more than one server identity.
 * =====================================================================
 */
#include "demo_crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char XD_LABEL[] = "xchan-demo v1";

const char *xd_err_str(xd_err_t e) {
    switch (e) {
        case XD_OK:                 return "ok";
        case XD_ERR_IO:             return "transport error";
        case XD_ERR_TIMEOUT:        return "timed out waiting for peer";
        case XD_ERR_PEER_CLOSED:    return "peer closed the channel";
        case XD_ERR_MALFORMED:      return "malformed message";
        case XD_ERR_VERSION:        return "unsupported protocol version";
        case XD_ERR_UNKNOWN_CLIENT: return "unknown client key";
        case XD_ERR_BAD_SIG:        return "bad signature";
        case XD_ERR_KX:             return "key exchange rejected peer ephemeral";
        case XD_ERR_COUNTER:        return "record counter mismatch";
        case XD_ERR_TAG:            return "record authentication failed";
        case XD_ERR_TOO_BIG:        return "message too large";
        case XD_ERR_CLOSED:         return "session closed";
        case XD_ERR_INTERNAL:       return "internal error";
    }
    return "unknown error";
}

/* ---- channel I/O with bounded waits ----------------------------------- */

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

xd_err_t xd_chan_recv_timeout(xd_chan_t *c, void *buf, size_t cap,
                              size_t *out_len, int timeout_ms) {
    long long deadline = timeout_ms < 0 ? -1 : now_ms() + timeout_ms;
    for (;;) {
        int wait = -1;
        if (deadline >= 0) {
            long long left = deadline - now_ms();
            if (left < 0) left = 0;
            wait = (int)left;
        }
        struct pollfd p = { .fd = c->fd, .events = POLLIN, .revents = 0 };
        int r = poll(&p, 1, wait);
        if (r < 0) {
            if (errno == EINTR) continue;
            return XD_ERR_IO;
        }
        if (r == 0) return XD_ERR_TIMEOUT;
        /* Readable, or hung up (xchan: EPOLLHUP|EPOLLERR once the peer
         * detached). Either way recv() says which: a queued message, or
         * ECONNRESET once none is left. */
        ssize_t n = c->recv(c, buf, cap);
        if (n >= 0) {
            *out_len = (size_t)n;
            return XD_OK;
        }
        switch (errno) {
            case EINTR:
            case EAGAIN:
                continue;
            case ECONNRESET:
            case EPIPE:
                return XD_ERR_PEER_CLOSED;
            case EMSGSIZE:
                return XD_ERR_TOO_BIG;
            default:
                return XD_ERR_IO;
        }
    }
}

xd_err_t xd_chan_send(xd_chan_t *c, const void *buf, size_t len) {
    ssize_t n = c->send(c, buf, len);
    if (n < 0) {
        if (errno == ECONNRESET || errno == EPIPE) return XD_ERR_PEER_CLOSED;
        return XD_ERR_IO;
    }
    if ((size_t)n != len) return XD_ERR_IO;
    return XD_OK;
}

/* ---- identities ------------------------------------------------------- */

int xd_read_hex32(const char *path, uint8_t out[32], const char **why) {
    /* 64 hex digits plus a newline; anything much longer is not a key file. */
    char buf[160];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { *why = "cannot open"; return -1; }
    size_t got = 0;
    for (;;) {
        ssize_t n = read(fd, buf + got, sizeof(buf) - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            sodium_memzero(buf, sizeof(buf));
            *why = "read error";
            return -1;
        }
        if (n == 0) break;
        got += (size_t)n;
        if (got == sizeof(buf)) break;
    }
    close(fd);

    int rc = -1;
    size_t bin_len = 0;
    const char *end = NULL;
    if (got == sizeof(buf)) {
        *why = "file too long";
    } else if (sodium_hex2bin(out, 32, buf, got, NULL, &bin_len, &end) != 0 ||
               bin_len != 32) {
        *why = "not 64 hex digits";
    } else {
        rc = 0;
        for (const char *p = end; p < buf + got; p++) {
            if (*p != '\n' && *p != '\r' && *p != ' ' && *p != '\t') {
                *why = "trailing garbage after 64 hex digits";
                rc = -1;
                break;
            }
        }
    }
    if (rc != 0) sodium_memzero(out, 32);
    sodium_memzero(buf, sizeof(buf));
    return rc;
}

int xd_load_identity(const char *seed_path, uint8_t pk[XD_PK_BYTES],
                     uint8_t sk[XD_SK_BYTES], const char **why) {
    uint8_t seed[XD_SEED_BYTES];
    if (xd_read_hex32(seed_path, seed, why) != 0) return -1;
    int rc = crypto_sign_seed_keypair(pk, sk, seed);
    sodium_memzero(seed, sizeof(seed));
    if (rc != 0) { *why = "crypto_sign_seed_keypair failed"; return -1; }
    return 0;
}

void xd_fingerprint(const uint8_t pk[XD_PK_BYTES], char out[9]) {
    sodium_bin2hex(out, 9, pk, 4);
}

/* ---- handshake -------------------------------------------------------- */

/* Offsets inside HELLO / SERVER_HELLO. */
#define HELLO_STATIC  2
#define HELLO_EPH     (HELLO_STATIC + XD_PK_BYTES)
#define HELLO_RANDOM  (HELLO_EPH + crypto_kx_PUBLICKEYBYTES)
#define SH_EPH        1
#define SH_RANDOM     (SH_EPH + crypto_kx_PUBLICKEYBYTES)
#define SH_SIG        (SH_RANDOM + XD_RANDOM_BYTES)
#define CF_SIG        1

_Static_assert(HELLO_RANDOM + XD_RANDOM_BYTES == XD_HELLO_LEN, "HELLO layout");
_Static_assert(SH_SIG + crypto_sign_BYTES == XD_SERVER_HELLO_LEN, "SERVER_HELLO layout");
_Static_assert(crypto_kx_SESSIONKEYBYTES ==
               crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "kx key size");

/* BLAKE2b-256("xchan-demo v1" || hello || s_eph || s_rand || suffix) */
static void transcript_hash(uint8_t out[32], const uint8_t hello[XD_HELLO_LEN],
                            const uint8_t s_eph[crypto_kx_PUBLICKEYBYTES],
                            const uint8_t s_rand[XD_RANDOM_BYTES],
                            const char *suffix) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const uint8_t *)XD_LABEL, sizeof(XD_LABEL) - 1);
    crypto_generichash_update(&st, hello, XD_HELLO_LEN);
    crypto_generichash_update(&st, s_eph, crypto_kx_PUBLICKEYBYTES);
    crypto_generichash_update(&st, s_rand, XD_RANDOM_BYTES);
    crypto_generichash_update(&st, (const uint8_t *)suffix, strlen(suffix));
    crypto_generichash_final(&st, out, 32);
    sodium_memzero(&st, sizeof(st));
}

/* key' = BLAKE2b-256(in = T, key = raw kx key), per direction. */
static void bind_keys(xd_session_t *s, const uint8_t rx[crypto_kx_SESSIONKEYBYTES],
                      const uint8_t tx[crypto_kx_SESSIONKEYBYTES],
                      const uint8_t hello[XD_HELLO_LEN],
                      const uint8_t s_eph[crypto_kx_PUBLICKEYBYTES],
                      const uint8_t s_rand[XD_RANDOM_BYTES]) {
    uint8_t t[32];
    transcript_hash(t, hello, s_eph, s_rand, "keys");
    crypto_generichash(s->rx_key, sizeof(s->rx_key), t, sizeof(t), rx, crypto_kx_SESSIONKEYBYTES);
    crypto_generichash(s->tx_key, sizeof(s->tx_key), t, sizeof(t), tx, crypto_kx_SESSIONKEYBYTES);
    sodium_memzero(t, sizeof(t));
    s->tx_ctr = 0;
    s->rx_ctr = 0;
    s->dead = 0;
}

void xd_session_kill(xd_session_t *s) {
    sodium_memzero(s->tx_key, sizeof(s->tx_key));
    sodium_memzero(s->rx_key, sizeof(s->rx_key));
    s->dead = 1;
}

xd_err_t xd_client_handshake(xd_chan_t *c, const uint8_t my_pk[XD_PK_BYTES],
                             const uint8_t my_sk[XD_SK_BYTES],
                             const uint8_t server_pk[XD_PK_BYTES],
                             xd_session_t *s, int timeout_ms) {
    xd_err_t err;
    uint8_t eph_pk[crypto_kx_PUBLICKEYBYTES], eph_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t hello[XD_HELLO_LEN];
    uint8_t sh[XD_SERVER_HELLO_LEN + 1]; /* +1: an oversized reply is malformed, not truncated */
    uint8_t fin[XD_CLIENT_FINISH_LEN];
    uint8_t h[32];
    uint8_t rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES];
    size_t n = 0;

    memset(s, 0, sizeof(*s));
    s->dead = 1;

    crypto_kx_keypair(eph_pk, eph_sk);
    hello[0] = XD_MSG_HELLO;
    hello[1] = XD_PROTO_VERSION;
    memcpy(hello + HELLO_STATIC, my_pk, XD_PK_BYTES);
    memcpy(hello + HELLO_EPH, eph_pk, sizeof(eph_pk));
    randombytes_buf(hello + HELLO_RANDOM, XD_RANDOM_BYTES);

    err = xd_chan_send(c, hello, sizeof(hello));
    if (err != XD_OK) goto out;

    err = xd_chan_recv_timeout(c, sh, sizeof(sh), &n, timeout_ms);
    if (err != XD_OK) goto out;
    if (n != XD_SERVER_HELLO_LEN || sh[0] != XD_MSG_SERVER_HELLO) {
        err = XD_ERR_MALFORMED;
        goto out;
    }

    transcript_hash(h, hello, sh + SH_EPH, sh + SH_RANDOM, "server");
    if (crypto_sign_verify_detached(sh + SH_SIG, h, sizeof(h), server_pk) != 0) {
        err = XD_ERR_BAD_SIG;
        goto out;
    }

    if (crypto_kx_client_session_keys(rx, tx, eph_pk, eph_sk, sh + SH_EPH) != 0) {
        err = XD_ERR_KX;
        goto out;
    }

    transcript_hash(h, hello, sh + SH_EPH, sh + SH_RANDOM, "client");
    fin[0] = XD_MSG_CLIENT_FINISH;
    crypto_sign_detached(fin + CF_SIG, NULL, h, sizeof(h), my_sk);
    err = xd_chan_send(c, fin, sizeof(fin));
    if (err != XD_OK) goto out;

    bind_keys(s, rx, tx, hello, sh + SH_EPH, sh + SH_RANDOM);
    memcpy(s->peer_pk, server_pk, XD_PK_BYTES);
    err = XD_OK;

out:
    sodium_memzero(eph_sk, sizeof(eph_sk));
    sodium_memzero(rx, sizeof(rx));
    sodium_memzero(tx, sizeof(tx));
    sodium_memzero(h, sizeof(h));
    if (err != XD_OK) xd_session_kill(s);
    return err;
}

xd_err_t xd_server_handshake(xd_chan_t *c, const uint8_t my_sk[XD_SK_BYTES],
                             const xd_client_key_t *clients, size_t n_clients,
                             xd_session_t *s, size_t *which, char fp[9],
                             int timeout_ms) {
    xd_err_t err;
    uint8_t hello[XD_HELLO_LEN + 1];
    uint8_t eph_pk[crypto_kx_PUBLICKEYBYTES], eph_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t sh[XD_SERVER_HELLO_LEN];
    uint8_t fin[XD_CLIENT_FINISH_LEN + 1];
    uint8_t h[32];
    uint8_t rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES];
    size_t n = 0, idx = 0;
    int found = 0;

    memset(s, 0, sizeof(*s));
    s->dead = 1;
    if (fp) strcpy(fp, "?");
    /* Generated up front so the cleanup path always wipes initialised data. */
    crypto_kx_keypair(eph_pk, eph_sk);

    err = xd_chan_recv_timeout(c, hello, sizeof(hello), &n, timeout_ms);
    if (err != XD_OK) goto out;
    if (n != XD_HELLO_LEN || hello[0] != XD_MSG_HELLO) {
        err = XD_ERR_MALFORMED;
        goto out;
    }
    if (hello[1] != XD_PROTO_VERSION) {
        err = XD_ERR_VERSION;
        goto out;
    }
    if (fp) xd_fingerprint(hello + HELLO_STATIC, fp);

    /* Exact match against the pinned keys. Public data, but there is no
     * reason to make the comparison time key-dependent either. */
    for (size_t i = 0; i < n_clients; i++) {
        if (sodium_memcmp(clients[i].pk, hello + HELLO_STATIC, XD_PK_BYTES) == 0) {
            idx = i;
            found = 1;
            break;
        }
    }
    if (!found) {
        err = XD_ERR_UNKNOWN_CLIENT;
        goto out;
    }

    sh[0] = XD_MSG_SERVER_HELLO;
    memcpy(sh + SH_EPH, eph_pk, sizeof(eph_pk));
    randombytes_buf(sh + SH_RANDOM, XD_RANDOM_BYTES);

    if (crypto_kx_server_session_keys(rx, tx, eph_pk, eph_sk, hello + HELLO_EPH) != 0) {
        err = XD_ERR_KX;
        goto out;
    }

    transcript_hash(h, hello, sh + SH_EPH, sh + SH_RANDOM, "server");
    crypto_sign_detached(sh + SH_SIG, NULL, h, sizeof(h), my_sk);
    err = xd_chan_send(c, sh, sizeof(sh));
    if (err != XD_OK) goto out;

    err = xd_chan_recv_timeout(c, fin, sizeof(fin), &n, timeout_ms);
    if (err != XD_OK) goto out;
    if (n != XD_CLIENT_FINISH_LEN || fin[0] != XD_MSG_CLIENT_FINISH) {
        err = XD_ERR_MALFORMED;
        goto out;
    }
    transcript_hash(h, hello, sh + SH_EPH, sh + SH_RANDOM, "client");
    if (crypto_sign_verify_detached(fin + CF_SIG, h, sizeof(h), clients[idx].pk) != 0) {
        err = XD_ERR_BAD_SIG;
        goto out;
    }

    bind_keys(s, rx, tx, hello, sh + SH_EPH, sh + SH_RANDOM);
    memcpy(s->peer_pk, clients[idx].pk, XD_PK_BYTES);
    *which = idx;
    err = XD_OK;

out:
    sodium_memzero(eph_sk, sizeof(eph_sk));
    sodium_memzero(rx, sizeof(rx));
    sodium_memzero(tx, sizeof(tx));
    sodium_memzero(h, sizeof(h));
    if (err != XD_OK) xd_session_kill(s);
    return err;
}

/* ---- records ----------------------------------------------------------- */

static void store_le64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t load_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
static void store_le32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t load_le32(const uint8_t *p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static void make_nonce(uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
                       uint64_t ctr) {
    memset(nonce, 0, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    store_le64(nonce, ctr);
}

static int known_record_type(uint8_t t) {
    return t == XD_REC_APP || t == XD_REC_CLOSE;
}

xd_err_t xd_seal(xd_session_t *s, uint8_t type, const void *pt, size_t ptlen,
                 uint8_t *out, size_t cap, size_t *out_len) {
    if (s->dead) return XD_ERR_CLOSED;
    if (!known_record_type(type) || ptlen > XD_REC_MAX_PT) {
        xd_session_kill(s);
        return XD_ERR_INTERNAL;
    }
    if (cap < ptlen + XD_REC_OVERHEAD) {
        xd_session_kill(s);
        return XD_ERR_TOO_BIG;
    }
    if (s->tx_ctr == UINT64_MAX) { /* never reuse a nonce */
        xd_session_kill(s);
        return XD_ERR_INTERNAL;
    }

    uint8_t ad[5];
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    out[0] = type;
    store_le64(out + 1, s->tx_ctr);
    store_le32(out + 9, (uint32_t)ptlen);
    ad[0] = type;
    store_le32(ad + 1, (uint32_t)ptlen);
    make_nonce(nonce, s->tx_ctr);

    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(out + XD_REC_HDR, &clen,
                                               pt, ptlen, ad, sizeof(ad),
                                               NULL, nonce, s->tx_key);
    s->tx_ctr++;
    *out_len = XD_REC_HDR + (size_t)clen;
    return XD_OK;
}

xd_err_t xd_open(xd_session_t *s, const uint8_t *in, size_t in_len,
                 uint8_t *type, void *pt, size_t cap, size_t *pt_len) {
    xd_err_t err;
    uint8_t t;
    uint64_t ctr;
    uint32_t len;
    uint8_t ad[5];
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned long long mlen = 0;

    if (s->dead) return XD_ERR_CLOSED;

    if (in_len < XD_REC_OVERHEAD) { err = XD_ERR_MALFORMED; goto fail; }
    t = in[0];
    ctr = load_le64(in + 1);
    len = load_le32(in + 9);
    if (!known_record_type(t)) { err = XD_ERR_MALFORMED; goto fail; }
    if ((size_t)len != in_len - XD_REC_OVERHEAD) { err = XD_ERR_MALFORMED; goto fail; }
    if ((size_t)len > cap) { err = XD_ERR_TOO_BIG; goto fail; }
    if (ctr != s->rx_ctr) { err = XD_ERR_COUNTER; goto fail; }
    if (s->rx_ctr == UINT64_MAX) { err = XD_ERR_INTERNAL; goto fail; }

    ad[0] = t;
    store_le32(ad + 1, len);
    make_nonce(nonce, s->rx_ctr); /* our counter, not the wire's */

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &mlen, NULL,
                                                   in + XD_REC_HDR, in_len - XD_REC_HDR,
                                                   ad, sizeof(ad), nonce, s->rx_key) != 0) {
        err = XD_ERR_TAG;
        goto fail;
    }
    s->rx_ctr++;
    *type = t;
    *pt_len = (size_t)mlen;
    return XD_OK;

fail:
    xd_session_kill(s);
    return err;
}

xd_err_t xd_send_record(xd_chan_t *c, xd_session_t *s, uint8_t type,
                        const void *pt, size_t ptlen) {
    uint8_t rec[XD_REC_MAX];
    size_t n = 0;
    xd_err_t err = xd_seal(s, type, pt, ptlen, rec, sizeof(rec), &n);
    if (err == XD_OK) {
        err = xd_chan_send(c, rec, n);
        if (err != XD_OK) xd_session_kill(s);
    }
    return err;
}

xd_err_t xd_recv_record(xd_chan_t *c, xd_session_t *s, uint8_t *type,
                        void *pt, size_t cap, size_t *pt_len, int timeout_ms) {
    uint8_t rec[XD_REC_MAX];
    size_t n = 0;
    if (s->dead) return XD_ERR_CLOSED;
    xd_err_t err = xd_chan_recv_timeout(c, rec, sizeof(rec), &n, timeout_ms);
    if (err != XD_OK) {
        xd_session_kill(s);
        return err;
    }
    return xd_open(s, rec, n, type, pt, cap, pt_len);
}
