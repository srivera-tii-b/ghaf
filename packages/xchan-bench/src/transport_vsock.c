/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* transport_vsock.c, AF_VSOCK backend for transport.h.
 *
 * Third arm of the transport comparison. Under pKVM, xchan's zero-copy
 * shared window kills the listener's vCPU, so every xchan payload crosses
 * host memory as inline fragments, the same way a vsock payload does. That
 * makes vsock, the team's original default transport, a live
 * alternative again rather than a fallback, and the only honest way to
 * settle it is to measure the same client code over both.
 *
 * Wire-identical to transport_sock.c: 4-byte big-endian length prefix, then
 * that many payload bytes. The framing helpers are duplicated here rather
 * than shared, matching the choice already made in mock_server.c, these
 * backends are meant to be readable in isolation, and the shared thing that
 * actually matters (the message contract) lives in transport.h.
 *
 * Topology note, because it changes what a number means: vsock is
 * guest-to-HOST. With the model on the host a client guest reaches it
 * directly and this backend measures one hop. With the model in another
 * guest (a GPU-owning one) there is no guest-to-guest vsock, so a host-side
 * relay is required and its cost belongs in the measurement. A vsock number
 * to a model on the host is NOT comparable to a guest-to-guest xchan number.
 *
 * Endpoint syntax: "CID:PORT", e.g. "2:9000" (CID 2 is the host).
 *
 * Compiled only when USE_VSOCK is defined (see Makefile).
 */
#include "transport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/vm_sockets.h>

struct transport {
    int fd;
};

struct transport_listener {
    int fd;
};

const char *transport_backend_name(void) { return "vsock"; }

/* Parse "CID:PORT". Both must be present and fit in a u32; anything else is
 * EINVAL rather than a silently-defaulted address, because connecting to the
 * wrong CID produces a confusing timeout rather than an obvious failure. */
static int parse_endpoint(const char *endpoint, unsigned int *cid, unsigned int *port) {
    const char *colon = strchr(endpoint, ':');
    if (!colon || colon == endpoint || colon[1] == '\0') return -1;

    char *end = NULL;
    unsigned long c = strtoul(endpoint, &end, 10);
    if (end != colon || c > 0xffffffffUL) return -1;

    unsigned long p = strtoul(colon + 1, &end, 10);
    if (*end != '\0' || p > 0xffffffffUL) return -1;

    *cid = (unsigned int)c;
    *port = (unsigned int)p;
    return 0;
}

transport_t *transport_connect(const char *endpoint) {
    if (!endpoint) { errno = EINVAL; return NULL; }

    unsigned int cid, port;
    if (parse_endpoint(endpoint, &cid, &port) != 0) {
        fprintf(stderr, "transport_vsock: endpoint must be CID:PORT (e.g. 2:9000), got \"%s\"\n",
                endpoint);
        errno = EINVAL;
        return NULL;
    }

    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = cid;
    addr.svm_port = port;

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

/* Loop until exactly `len` bytes move or a hard error occurs. EOF maps to
 * ECONNRESET, matching xchan's convention for a peer that detached. */
static int read_full(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
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
        /* Drain so the stream stays in sync for the next call, then report
         * the way xchan does: EMSGSIZE, nothing accepted into buf. */
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

    /* Accept either "PORT" or "CID:PORT" so the same string that addresses a
     * server can also start one. The CID half is ignored: a listener binds
     * VMADDR_CID_ANY and therefore needs no knowledge of its own address,
     * which is what lets the same command line work in any guest. */
    const char *port_str = strchr(endpoint, ':');
    port_str = port_str ? port_str + 1 : endpoint;

    char *end = NULL;
    unsigned long port = strtoul(port_str, &end, 10);
    if (end == port_str || *end != '\0' || port > 0xffffffffUL) {
        fprintf(stderr, "transport_vsock: listen endpoint must be PORT or CID:PORT, got \"%s\"\n",
                endpoint);
        errno = EINVAL;
        return NULL;
    }

    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = (unsigned int)port;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return NULL;
    }

    transport_listener_t *l = malloc(sizeof(*l));
    if (!l) { int e = errno; close(fd); errno = e; return NULL; }
    l->fd = fd;
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
    free(l);
}
