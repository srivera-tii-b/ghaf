/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* demo_crypto.h, the secure channel used by xchan-demo-server and
 * xchan-demo-client: pinned Ed25519 identities, a signed ephemeral X25519
 * handshake (SIGMA-style) and XChaCha20-Poly1305 records. libsodium only.
 *
 * The full protocol description, what it guarantees and what it does not,
 * is the comment block at the top of demo_crypto.c. Read it before changing
 * anything here.
 *
 * Everything below talks to the peer through an xd_chan_t: a message-
 * oriented pipe (one send = one message at the far end, exactly libxchan's
 * contract) whose fd can be poll()ed. xchan channels are the real thing; the
 * tests use an AF_UNIX SOCK_SEQPACKET socketpair, which has the same shape.
 */
#ifndef DEMO_CRYPTO_H
#define DEMO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <sodium.h>

/* ---- result codes ------------------------------------------------------ */

/* Every failure is one of these, so callers log a reason and tests can
 * assert WHICH check rejected an input, a test that only asserted "it
 * failed" could not tell the counter check apart from the tag check. */
typedef enum {
    XD_OK = 0,
    XD_ERR_IO,             /* transport send/recv failed (errno has detail) */
    XD_ERR_TIMEOUT,        /* bounded wait for the peer expired */
    XD_ERR_PEER_CLOSED,    /* peer detached / closed its end (ECONNRESET) */
    XD_ERR_MALFORMED,      /* wrong size, wrong type, inconsistent length */
    XD_ERR_VERSION,        /* HELLO carried a protocol version we don't speak */
    XD_ERR_UNKNOWN_CLIENT, /* server: client static key not in --clients */
    XD_ERR_BAD_SIG,        /* Ed25519 signature did not verify */
    XD_ERR_KX,             /* X25519 rejected the peer's ephemeral key */
    XD_ERR_COUNTER,        /* record counter is not the next expected one */
    XD_ERR_TAG,            /* AEAD authentication failed */
    XD_ERR_TOO_BIG,        /* record larger than the caller's buffer */
    XD_ERR_CLOSED,         /* session already failed or was closed */
    XD_ERR_INTERNAL,       /* local failure (allocation, counter exhausted) */
} xd_err_t;

const char *xd_err_str(xd_err_t e);

/* ---- channel abstraction ---------------------------------------------- */

typedef struct xd_chan {
    int fd; /* poll()able for POLLIN; xchan channel fd or a seqpacket socket */
    /* Send one whole message. Returns len or -1/errno (ECONNRESET = peer
     * gone). */
    ssize_t (*send)(struct xd_chan *c, const void *buf, size_t len);
    /* Receive one whole message. Returns its length or -1/errno; must
     * report a peer that went away as ECONNRESET and an oversized message
     * as EMSGSIZE. Only ever called after poll() reported fd readable. */
    ssize_t (*recv)(struct xd_chan *c, void *buf, size_t cap);
    void *user; /* free for the owner (the client hangs its watchdog here) */
} xd_chan_t;

/* Waits at most timeout_ms for a message, then receives it. Maps a timeout
 * to XD_ERR_TIMEOUT, ECONNRESET to XD_ERR_PEER_CLOSED, EMSGSIZE to
 * XD_ERR_TOO_BIG and anything else to XD_ERR_IO. *out_len gets the size. */
xd_err_t xd_chan_recv_timeout(xd_chan_t *c, void *buf, size_t cap,
                              size_t *out_len, int timeout_ms);
xd_err_t xd_chan_send(xd_chan_t *c, const void *buf, size_t len);

/* ---- identities ------------------------------------------------------- */

#define XD_PK_BYTES   crypto_sign_PUBLICKEYBYTES   /* 32 */
#define XD_SEED_BYTES crypto_sign_SEEDBYTES        /* 32 */
#define XD_SK_BYTES   crypto_sign_SECRETKEYBYTES   /* 64 */

/* Reads a key file: exactly 64 hex digits, optionally followed by
 * whitespace (one trailing newline is the normal case), nothing else.
 * Returns 0, or -1 with a short reason in *why (never the file contents). */
int xd_read_hex32(const char *path, uint8_t out[32], const char **why);

/* <vm>.seed -> Ed25519 keypair via crypto_sign_seed_keypair(). The seed is
 * wiped before returning. Returns 0 or -1 (reason in *why). */
int xd_load_identity(const char *seed_path, uint8_t pk[XD_PK_BYTES],
                     uint8_t sk[XD_SK_BYTES], const char **why);

/* First 8 hex characters of a public key, for logs. Never pass a secret. */
void xd_fingerprint(const uint8_t pk[XD_PK_BYTES], char out[9]);

/* ---- handshake -------------------------------------------------------- */

#define XD_PROTO_VERSION 1

/* Wire message types. Handshake and record types share one byte space so a
 * handshake message can never be parsed as a record or vice versa. */
#define XD_MSG_HELLO         0x01
#define XD_MSG_SERVER_HELLO  0x02
#define XD_MSG_CLIENT_FINISH 0x03
#define XD_REC_APP           0x10 /* payload: one proto.h bench message */
#define XD_REC_CLOSE         0x11 /* payload: empty; "please close this channel" */

#define XD_RANDOM_BYTES 32
#define XD_HELLO_LEN         (1 + 1 + XD_PK_BYTES + crypto_kx_PUBLICKEYBYTES + XD_RANDOM_BYTES)
#define XD_SERVER_HELLO_LEN  (1 + crypto_kx_PUBLICKEYBYTES + XD_RANDOM_BYTES + crypto_sign_BYTES)
#define XD_CLIENT_FINISH_LEN (1 + crypto_sign_BYTES)

/* How long each handshake step waits for the peer. */
#define XD_HANDSHAKE_TIMEOUT_MS 15000

/* An established session: one key and one counter per direction. Not
 * thread-safe; one session belongs to one thread. */
typedef struct {
    uint8_t  tx_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t  rx_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint64_t tx_ctr;
    uint64_t rx_ctr;
    int      dead;   /* set by the first failure; every later call fails */
    uint8_t  peer_pk[XD_PK_BYTES]; /* the authenticated peer identity */
} xd_session_t;

/* Pinned client keys the server accepts. */
typedef struct {
    char    name[64];   /* basename of <name>.pk */
    uint8_t pk[XD_PK_BYTES];
} xd_client_key_t;

/* Client side. On XD_OK *s is ready to use. On failure *s is dead and
 * wiped. */
xd_err_t xd_client_handshake(xd_chan_t *c, const uint8_t my_pk[XD_PK_BYTES],
                             const uint8_t my_sk[XD_SK_BYTES],
                             const uint8_t server_pk[XD_PK_BYTES],
                             xd_session_t *s, int timeout_ms);

/* Server side. On XD_OK, *which is the index into `clients` of the
 * authenticated peer. On XD_ERR_UNKNOWN_CLIENT / XD_ERR_BAD_SIG, `fp` (if
 * non-NULL) gets the fingerprint of the static key the client CLAIMED, for
 * the log line. */
xd_err_t xd_server_handshake(xd_chan_t *c, const uint8_t my_sk[XD_SK_BYTES],
                             const xd_client_key_t *clients, size_t n_clients,
                             xd_session_t *s, size_t *which, char fp[9],
                             int timeout_ms);

/* Wipes keys and marks the session dead. Idempotent. */
void xd_session_kill(xd_session_t *s);

/* ---- records ----------------------------------------------------------- */

/* type(1) | counter(8, LE) | plaintext length(4, LE) | ciphertext+tag */
#define XD_REC_HDR      13
#define XD_REC_OVERHEAD (XD_REC_HDR + crypto_aead_xchacha20poly1305_ietf_ABYTES)
#define XD_REC_MAX_PT   8192u  /* comfortably above BENCH_MSG_MAX_SIZE */
#define XD_REC_MAX      (XD_REC_OVERHEAD + XD_REC_MAX_PT)

/* Encrypts pt into out (cap >= ptlen + XD_REC_OVERHEAD) and advances the
 * send counter. */
xd_err_t xd_seal(xd_session_t *s, uint8_t type, const void *pt, size_t ptlen,
                 uint8_t *out, size_t cap, size_t *out_len);

/* Authenticates and decrypts one record. Rejects anything but the next
 * expected counter. On any failure the session is killed. */
xd_err_t xd_open(xd_session_t *s, const uint8_t *in, size_t in_len,
                 uint8_t *type, void *pt, size_t cap, size_t *pt_len);

/* Seal + send / receive + open, with the session killed on any failure. */
xd_err_t xd_send_record(xd_chan_t *c, xd_session_t *s, uint8_t type,
                        const void *pt, size_t ptlen);
xd_err_t xd_recv_record(xd_chan_t *c, xd_session_t *s, uint8_t *type,
                        void *pt, size_t cap, size_t *pt_len, int timeout_ms);

#endif /* DEMO_CRYPTO_H */
