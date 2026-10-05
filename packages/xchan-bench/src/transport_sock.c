/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* transport_sock.c, unix SOCK_STREAM backend for transport.h.
 *
 * A stream socket has no message boundaries, so we invent framing: every
 * message is sent as a 4-byte big-endian length prefix followed by exactly
 * that many payload bytes. transport_recv() loops on read() until it has
 * the whole prefix and the whole payload, so callers always get one
 * complete message, exactly like xchan, this file is the only place that
 * framing exists; everything above transport.h is unaware of it.
 *
 * Compiled when USE_XCHAN is NOT defined (see Makefile).
 */
#include "transport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct transport {
    int fd;
};

struct transport_listener {
    int fd;
    char path[108]; /* sizeof(struct sockaddr_un.sun_path) */
};

const char *transport_backend_name(void) { return "sock"; }

transport_t *transport_connect(const char *endpoint) {
    if (!endpoint) { errno = EINVAL; return NULL; }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(endpoint) >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return NULL;
    }
    strncpy(addr.sun_path, endpoint, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return NULL;
    }

    transport_t *t = malloc(sizeof(*t));
    if (!t) {
        int e = errno;
        close(fd);
        errno = e;
        return NULL;
    }
    t->fd = fd;
    return t;
}

/* Loop until exactly `len` bytes are read/written or a hard error occurs.
 * Returns 0 on success, -1/errno on failure (including EOF, mapped to
 * ECONNRESET since that's what it means for our peer to vanish mid-message,
 * matching xchan's convention for a detached peer). */
static int read_full(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1; /* EAGAIN propagates as-is for O_NONBLOCK sockets */
        }
        if (n == 0) { /* peer closed mid-message */
            errno = ECONNRESET;
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EPIPE) errno = ECONNRESET;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

ssize_t transport_send(transport_t *t, const void *buf, size_t len) {
    if (len > UINT32_MAX) { errno = EMSGSIZE; return -1; }
    uint32_t be_len = htonl((uint32_t)len);
    if (write_full(t->fd, &be_len, sizeof(be_len)) != 0) return -1;
    if (len > 0 && write_full(t->fd, buf, len) != 0) return -1;
    return (ssize_t)len;
}

ssize_t transport_recv(transport_t *t, void *buf, size_t cap) {
    uint32_t be_len;
    if (read_full(t->fd, &be_len, sizeof(be_len)) != 0) return -1;
    uint32_t len = ntohl(be_len);

    if ((size_t)len > cap) {
        /* Drain the oversized message so the stream stays in sync for the
         * next call, then report it the way xchan does: EMSGSIZE, nothing
         * accepted into buf. */
        uint8_t scratch[4096];
        uint32_t remaining = len;
        while (remaining > 0) {
            size_t chunk = remaining < sizeof(scratch) ? remaining : sizeof(scratch);
            if (read_full(t->fd, scratch, chunk) != 0) break;
            remaining -= (uint32_t)chunk;
        }
        errno = EMSGSIZE;
        return -1;
    }

    if (len > 0 && read_full(t->fd, buf, len) != 0) return -1;
    return (ssize_t)len;
}

void transport_close(transport_t *t) {
    if (!t) return;
    close(t->fd);
    free(t);
}

transport_listener_t *transport_listen(const char *endpoint) {
    if (!endpoint) { errno = EINVAL; return NULL; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(endpoint) >= sizeof(addr.sun_path)) { errno = ENAMETOOLONG; return NULL; }
    strncpy(addr.sun_path, endpoint, sizeof(addr.sun_path) - 1);

    /* Stale socket files outlive a killed server and make bind() fail with
     * EADDRINUSE, which reads like "already running" when it is not. */
    unlink(endpoint);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return NULL;
    }

    transport_listener_t *l = malloc(sizeof(*l));
    if (!l) { int e = errno; close(fd); errno = e; return NULL; }
    l->fd = fd;
    memcpy(l->path, addr.sun_path, sizeof(l->path));
    return l;
}

transport_t *transport_accept(transport_listener_t *l) {
    int cfd;
    do { cfd = accept(l->fd, NULL, NULL); } while (cfd < 0 && errno == EINTR);
    if (cfd < 0) return NULL;

    transport_t *t = malloc(sizeof(*t));
    if (!t) { int e = errno; close(cfd); errno = e; return NULL; }
    t->fd = cfd;
    return t;
}

void transport_listener_close(transport_listener_t *l) {
    if (!l) return;
    close(l->fd);
    unlink(l->path);
    free(l);
}
