/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* llama_http.c, streaming client for llama.cpp's llama-server
 * `/completion` endpoint, shared by bench-llama-shim and xchan-demo-server.
 *
 * Moved verbatim out of llama_shim.c (where it was proven against a real
 * llama-server, see that file's header) so the encrypted demo server can
 * reuse it rather than carry a second copy. The only changes on the way:
 * llama_stream_completion() is no longer static, its one log line takes its
 * prefix from llama_target_t (llama_shim passes "llama_shim", so its output
 * is unchanged), and llama_target_t gained an optional socket timeout that
 * llama_shim leaves at 0 (= fully blocking, as before).
 *
 * Thread-safe: no globals; every call keeps its state on its own stack/heap.
 */
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "llama_http.h"
#include "proto.h"

/* sodium_memzero() for a file that bench-llama-shim also links, without
 * libsodium: memset through a volatile function pointer, which the compiler
 * cannot drop as a dead store (OpenSSL's OPENSSL_cleanse and mbed TLS's
 * mbedtls_platform_zeroize do the same). */
static void *(*const volatile wipe_memset)(void *, int, size_t) = memset;

static void wipe(void *p, size_t n) {
    wipe_memset(p, 0, n);
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

/* ---------------------------------------------------------------------
 * Minimal HTTP client to a single known server (host/port fixed at
 * startup). Streams the response body out via a callback, one decoded
 * fragment at a time, so the caller can react before the body ends.
 * ------------------------------------------------------------------- */

#define RAWBUF_CAP (64 * 1024)

typedef struct {
    int fd;
    unsigned char raw[RAWBUF_CAP];
    size_t raw_len; /* bytes currently held */
    size_t raw_pos; /* consumed offset */
} http_stream_t;

/* Ensure there is at least one more byte available past raw_pos, or
 * report EOF/error. Compacts the buffer first. */
static ssize_t hs_fill(http_stream_t *hs) {
    if (hs->raw_pos > 0) {
        size_t remain = hs->raw_len - hs->raw_pos;
        memmove(hs->raw, hs->raw + hs->raw_pos, remain);
        hs->raw_len = remain;
        hs->raw_pos = 0;
    }
    if (hs->raw_len >= sizeof(hs->raw)) {
        errno = EMSGSIZE; /* a header or chunk-size line far too long */
        return -1;
    }
    for (;;) {
        ssize_t n = recv(hs->fd, hs->raw + hs->raw_len, sizeof(hs->raw) - hs->raw_len, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        hs->raw_len += (size_t)n;
        return n; /* may be 0 == EOF */
    }
}

/* Ensure at least `n` unread bytes are buffered (n must be <= RAWBUF_CAP).
 * Returns 0 on success, -1 on error, -2 on premature EOF. */
static int hs_need(http_stream_t *hs, size_t n) {
    while (hs->raw_len - hs->raw_pos < n) {
        ssize_t got = hs_fill(hs);
        if (got < 0) return -1;
        if (got == 0) return -2;
    }
    return 0;
}

/* Read one line (up to and including '\n') from the stream, stripping a
 * trailing \r\n or \n, into out (NUL-terminated). Returns line length
 * (excluding terminator), -1 on error, -2 on EOF before any '\n'. */
static int hs_read_line(http_stream_t *hs, char *out, size_t outcap) {
    size_t used = 0;
    for (;;) {
        /* scan currently buffered unread bytes for '\n' */
        for (size_t i = hs->raw_pos; i < hs->raw_len; i++) {
            if (hs->raw[i] == '\n') {
                size_t linelen = i - hs->raw_pos; /* excludes '\n' */
                size_t copy = linelen;
                if (copy > 0 && hs->raw[hs->raw_pos + copy - 1] == '\r') copy--;
                if (copy >= outcap) copy = outcap - 1;
                memcpy(out, hs->raw + hs->raw_pos, copy);
                out[copy] = '\0';
                hs->raw_pos = i + 1;
                return (int)copy;
            }
        }
        /* not found yet, need more bytes; but also allow one partial
         * copy pass so we never fail on lines that arrive split across
         * recv() calls */
        (void)used;
        ssize_t got = hs_fill(hs);
        if (got < 0) return -1;
        if (got == 0) return -2; /* EOF mid-line */
    }
}

typedef enum { BODY_CHUNKED, BODY_LENGTH, BODY_UNTIL_EOF } body_mode_t;

typedef struct {
    body_mode_t mode;
    long content_length_remaining; /* BODY_LENGTH only */
    /* BODY_CHUNKED only: data bytes of the current chunk not yet handed
     * out. A chunk larger than the caller's buffer is drained over several
     * calls; its CRLF and the next size line are read only once it is
     * empty. */
    size_t chunk_remaining;
    int done;
} body_state_t;

/* Copy up to `cap` (> 0) decoded body bytes into out. Returns bytes written
 * (0 means end of body reached cleanly), -1 on error. */
static ssize_t hs_next_body(http_stream_t *hs, body_state_t *bs, char *out, size_t cap) {
    if (bs->done) return 0;

    if (bs->mode == BODY_UNTIL_EOF) {
        if (hs->raw_len == hs->raw_pos) {
            ssize_t got = hs_fill(hs);
            if (got < 0) return -1;
            if (got == 0) { bs->done = 1; return 0; }
        }
        size_t avail = hs->raw_len - hs->raw_pos;
        size_t n = avail < cap ? avail : cap;
        memcpy(out, hs->raw + hs->raw_pos, n);
        hs->raw_pos += n;
        return (ssize_t)n;
    }

    if (bs->mode == BODY_LENGTH) {
        if (bs->content_length_remaining <= 0) { bs->done = 1; return 0; }
        if (hs->raw_len == hs->raw_pos) {
            ssize_t got = hs_fill(hs);
            if (got < 0) return -1;
            if (got == 0) { bs->done = 1; return 0; } /* short body, treat as end */
        }
        size_t avail = hs->raw_len - hs->raw_pos;
        size_t want = (size_t)bs->content_length_remaining;
        size_t n = avail < cap ? avail : cap;
        if (n > want) n = want;
        memcpy(out, hs->raw + hs->raw_pos, n);
        hs->raw_pos += n;
        bs->content_length_remaining -= (long)n;
        return (ssize_t)n;
    }

    /* BODY_CHUNKED. One call returns data from one chunk only: all of it
     * when it fits in `cap` (its CRLF consumed too), else the first `cap`
     * bytes, the rest coming from the next call(s) before any new size
     * line is read. A chunk can be any size: llama-server sends each SSE
     * event as one chunk, and its last event repeats the whole prompt,
     * JSON-escaped (six bytes per control character), which can pass
     * 16 KiB. */
    if (bs->chunk_remaining == 0) {
        char line[64];
        int ll = hs_read_line(hs, line, sizeof(line));
        if (ll < 0) return -1;
        /* chunk size in hex, optionally followed by ";extension". Anything
         * else means we have lost the framing: fail rather than read the
         * body as sizes. */
        char *end = line;
        unsigned long sz = isxdigit((unsigned char)line[0]) ? strtoul(line, &end, 16) : 0;
        if (end == line || (*end != '\0' && *end != ';' && *end != ' ' && *end != '\t')) {
            errno = EPROTO;
            return -1;
        }
        if (sz == 0) {
            /* trailers, terminated by an empty line */
            for (;;) {
                char trailer[256];
                int tl = hs_read_line(hs, trailer, sizeof(trailer));
                if (tl < 0) return -1;
                if (tl == 0) break;
            }
            bs->done = 1;
            return 0;
        }
        bs->chunk_remaining = sz;
    }
    size_t total_copied = 0;
    while (bs->chunk_remaining > 0 && total_copied < cap) {
        if (hs_need(hs, 1) < 0) return -1; /* at least 1 byte, then take what's there */
        size_t avail = hs->raw_len - hs->raw_pos;
        size_t n = bs->chunk_remaining < avail ? bs->chunk_remaining : avail;
        if (n > cap - total_copied) n = cap - total_copied;
        memcpy(out + total_copied, hs->raw + hs->raw_pos, n);
        hs->raw_pos += n;
        bs->chunk_remaining -= n;
        total_copied += n;
    }
    if (bs->chunk_remaining == 0) {
        /* the chunk's data ends with CRLF */
        if (hs_need(hs, 2) < 0) return -1;
        if (hs->raw[hs->raw_pos] != '\r' || hs->raw[hs->raw_pos + 1] != '\n') {
            errno = EPROTO;
            return -1;
        }
        hs->raw_pos += 2;
    }
    return (ssize_t)total_copied;
}

/* ---------------------------------------------------------------------
 * Tiny flat-JSON helpers, only handle exactly what llama-server's
 * per-token stream objects contain: {"content":"...","stop":bool,...}.
 * ------------------------------------------------------------------- */

/* strcasestr is a GNU/BSD extension, not POSIX; hand-roll it rather than
 * pull in _GNU_SOURCE. */
static const char *ci_strstr(const char *hay, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0) return hay;
    for (const char *p = hay; *p; p++) {
        if (strncasecmp(p, needle, nlen) == 0) return p;
    }
    return NULL;
}

/* Find `"key":` in s and return pointer just past the colon, or NULL. */
static const char *json_find_key(const char *s, const char *key) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(s, pat);
    if (!p) return NULL;
    return p + strlen(pat);
}

static int json_get_bool(const char *s, const char *key, int *out) {
    const char *p = json_find_key(s, key);
    if (!p) return -1;
    while (isspace((unsigned char)*p)) p++;
    if (strncmp(p, "true", 4) == 0) { *out = 1; return 0; }
    if (strncmp(p, "false", 5) == 0) { *out = 0; return 0; }
    return -1;
}

/* Extract and unescape a JSON string value for `key` from `s` into `out`
 * (capacity outcap, always NUL-terminated). Returns byte length written,
 * or -1 if the key/string isn't found. */
static int json_get_string(const char *s, const char *key, char *out, size_t outcap) {
    const char *p = json_find_key(s, key);
    if (!p) return -1;
    while (isspace((unsigned char)*p)) p++;
    if (*p != '"') return -1;
    p++;
    size_t o = 0;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p;
        if (c == '\\') {
            p++;
            if (!*p) break;
            char e = *p;
            char decoded = 0;
            int have = 1;
            switch (e) {
                case '"': decoded = '"'; break;
                case '\\': decoded = '\\'; break;
                case '/': decoded = '/'; break;
                case 'n': decoded = '\n'; break;
                case 't': decoded = '\t'; break;
                case 'r': decoded = '\r'; break;
                case 'b': decoded = '\b'; break;
                case 'f': decoded = '\f'; break;
                case 'u': {
                    /* Minimal \uXXXX -> UTF-8 (BMP only, no surrogate
                     * pairs, adequate for the control-char escapes
                     * JSON encoders actually emit; real non-ASCII text
                     * from the model comes through as raw UTF-8 bytes,
                     * not \u escapes, in nlohmann::json's default dump). */
                    if (strlen(p) >= 5) {
                        char hex[5] = { p[1], p[2], p[3], p[4], 0 };
                        unsigned int cp = (unsigned int)strtoul(hex, NULL, 16);
                        p += 4;
                        if (cp < 0x80) {
                            if (o < outcap - 1) out[o++] = (char)cp;
                        } else if (cp < 0x800) {
                            if (o + 1 < outcap - 1) {
                                out[o++] = (char)(0xC0 | (cp >> 6));
                                out[o++] = (char)(0x80 | (cp & 0x3F));
                            }
                        } else {
                            if (o + 2 < outcap - 1) {
                                out[o++] = (char)(0xE0 | (cp >> 12));
                                out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                                out[o++] = (char)(0x80 | (cp & 0x3F));
                            }
                        }
                    }
                    have = 0;
                    break;
                }
                default: decoded = e; break;
            }
            if (have && o < outcap - 1) out[o++] = decoded;
            p++;
        } else {
            if (o < outcap - 1) out[o++] = (char)c;
            p++;
        }
    }
    out[o] = '\0';
    return (int)o;
}

/* ---------------------------------------------------------------------
 * The actual llama-server call.
 * ------------------------------------------------------------------- */


static int tcp_connect(const char *host, int port) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        errno = ECONNREFUSED;
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* JSON-escape src into a heap buffer suitable for embedding as a JSON
 * string value (caller frees). Only needs to handle text a benchmark
 * prompt can plausibly contain. */
static char *json_escape(const char *src, size_t len) {
    char *out = malloc(len * 6 + 1); /* worst case \u00XX per byte */
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
            case '"': out[o++] = '\\'; out[o++] = '"'; break;
            case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
            case '\n': out[o++] = '\\'; out[o++] = 'n'; break;
            case '\r': out[o++] = '\\'; out[o++] = 'r'; break;
            case '\t': out[o++] = '\\'; out[o++] = 't'; break;
            default:
                if (c < 0x20) {
                    o += (size_t)snprintf(out + o, 7, "\\u%04x", c);
                } else {
                    out[o++] = (char)c;
                }
        }
    }
    out[o] = '\0';
    return out;
}

/* See llama_http.h.
 *
 * The prompt (escaped, then in the JSON body) and the reply (raw stream,
 * decoded body, SSE lines, content text) pass through several buffers here.
 * Every one is wiped before it is freed or goes out of scope, on every
 * path, so no plaintext lingers in freed heap or dead stack for a later
 * allocation, or a core dump, to turn up. */
int llama_stream_completion(const llama_target_t *tgt,
                             const char *prompt, size_t prompt_len,
                             uint32_t n_predict,
                             int (*on_chunk)(void *ctx, const char *text, size_t len),
                             void *ctx) {
    int rc = -1;
    int fd = -1;
    char *body = NULL;
    size_t body_cap = 0;
    char *sse_buf = NULL; /* SSE line accumulator, see below */
    size_t sse_cap = 0;
    http_stream_t hs;
    char chunk[LLAMA_HTTP_READ_CAP];
    memset(&hs, 0, sizeof(hs));

    char *esc_prompt = json_escape(prompt, prompt_len);
    if (!esc_prompt) goto out;
    size_t esc_len = strlen(esc_prompt);
    body_cap = esc_len + 256;
    body = malloc(body_cap);
    int body_len = -1;
    if (body)
        body_len = snprintf(body, body_cap,
            "{\"prompt\":\"%s\",\"n_predict\":%u,\"stream\":true}",
            esc_prompt, n_predict);
    wipe(esc_prompt, esc_len + 1);
    free(esc_prompt);
    if (body_len < 0) goto out;

    fd = tcp_connect(tgt->host, tgt->port);
    if (fd < 0) goto out;
    if (tgt->io_timeout_sec > 0) {
        /* Bounds every send()/recv() on this connection: a stalled
         * llama-server then fails the request instead of wedging the
         * caller. 0 (llama_shim) leaves the socket fully blocking, exactly
         * as before this code was shared. */
        struct timeval tv = { .tv_sec = tgt->io_timeout_sec, .tv_usec = 0 };
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
            goto out;
    }

    char req[512];
    int req_len = snprintf(req, sizeof(req),
        "POST /completion HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        tgt->host, tgt->port, body_len);
    if (req_len < 0 || write_full(fd, req, (size_t)req_len) != 0 ||
        write_full(fd, body, (size_t)body_len) != 0)
        goto out;
    wipe(body, body_cap);
    free(body);
    body = NULL;

    hs.fd = fd;

    char line[4096];
    int ll = hs_read_line(&hs, line, sizeof(line));
    if (ll < 0) goto out;
    int status_code = 0;
    sscanf(line, "HTTP/%*d.%*d %d", &status_code);

    body_state_t bs;
    memset(&bs, 0, sizeof(bs));
    bs.mode = BODY_UNTIL_EOF;

    for (;;) {
        int hl = hs_read_line(&hs, line, sizeof(line));
        if (hl < 0) goto out;
        if (hl == 0) break; /* end of headers */
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *val = colon + 1;
        while (*val == ' ') val++;
        if (strcasecmp(line, "Transfer-Encoding") == 0 && ci_strstr(val, "chunked")) {
            bs.mode = BODY_CHUNKED;
        } else if (strcasecmp(line, "Content-Length") == 0 && bs.mode != BODY_CHUNKED) {
            bs.mode = BODY_LENGTH;
            bs.content_length_remaining = atol(val);
        }
    }

    if (status_code != 200) {
        fprintf(stderr, "%s: llama-server returned HTTP %d\n",
                tgt->log_prefix ? tgt->log_prefix : "llama", status_code);
        goto out;
    }

    /* SSE line accumulator: decoded body bytes go in here until we see a
     * '\n', at which point we process one line and shift the rest down. */
    sse_cap = 16384;
    sse_buf = malloc(sse_cap);
    size_t sse_len = 0;
    if (!sse_buf) goto out;

    int stopped = 0;
    for (;;) {
        ssize_t n = hs_next_body(&hs, &bs, chunk, sizeof(chunk));
        if (n < 0) goto out;
        if (n == 0) break; /* body ended */

        /* Append to SSE accumulator, growing if needed, by hand rather
         * than realloc(), which may move the block and free the old copy
         * unwiped. */
        if (sse_len + (size_t)n + 1 > sse_cap) {
            size_t newcap = (sse_len + (size_t)n + 1) * 2;
            char *grown = malloc(newcap);
            if (!grown) goto out;
            memcpy(grown, sse_buf, sse_len);
            wipe(sse_buf, sse_cap);
            free(sse_buf);
            sse_buf = grown;
            sse_cap = newcap;
        }
        memcpy(sse_buf + sse_len, chunk, (size_t)n);
        sse_len += (size_t)n;

        /* Extract and process every complete line currently buffered. */
        size_t start = 0;
        for (size_t i = 0; i < sse_len; i++) {
            if (sse_buf[i] != '\n') continue;
            size_t linelen = i - start;
            if (linelen > 0 && sse_buf[start + linelen - 1] == '\r') linelen--;
            if (linelen > 6 && strncmp(sse_buf + start, "data: ", 6) == 0) {
                char *json = sse_buf + start + 6;
                char saved = sse_buf[start + linelen];
                sse_buf[start + linelen] = '\0';

                char text[BENCH_MAX_CHUNK];
                int tlen = json_get_string(json, "content", text, sizeof(text));
                int abort_req = tlen > 0 && on_chunk(ctx, text, (size_t)tlen) != 0;
                wipe(text, sizeof(text));
                /* The caller wants no more (its reader is gone): hang up
                 * now, so llama-server stops generating. */
                if (abort_req) goto out;

                int stop_flag = 0;
                if (json_get_bool(json, "stop", &stop_flag) == 0 && stop_flag) stopped = 1;

                sse_buf[start + linelen] = saved;
            }
            start = i + 1;
        }
        if (start > 0) {
            memmove(sse_buf, sse_buf + start, sse_len - start);
            sse_len -= start;
        }
        if (stopped) break;
    }
    rc = 0;

out:
    if (body) {
        wipe(body, body_cap);
        free(body);
    }
    if (sse_buf) {
        wipe(sse_buf, sse_cap);
        free(sse_buf);
    }
    wipe(chunk, sizeof(chunk));
    wipe(hs.raw, sizeof(hs.raw));
    if (fd >= 0) close(fd);
    return rc;
}
