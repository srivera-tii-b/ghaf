/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* transport_xchan.c, xchan backend for transport.h.
 *
 * xchan already delivers whole messages in both directions (libxchan's
 * xchan_send/xchan_recv contract, see libxchan.h), so this backend adds
 * no framing at all: it is a thin, almost transparent wrapper. All the
 * "make a stream look like messages" work lives in the stream-socket
 * backends (transport_sock.c, transport_vsock.c) instead; this file exists
 * mainly to translate xchan's connection setup (open device -> wait for
 * channel) into transport_connect(), and to map its documented errno set
 * onto the same conventions the socket backends use, so callers never need
 * to know which backend they're on.
 *
 * Only compiled when USE_XCHAN is defined (see Makefile). It needs libxchan
 * to link and a /dev/xchan* device to run; package.nix builds it against
 * pkgs.libxchan, natively and for aarch64. By hand:
 *
 *   make xchan LIBXCHAN_DIR=/path/to/xchan/src LIBXCHAN_LIB=/path/to/libxchan.a
 */
#include "transport.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "libxchan.h"
#include "xchan_uapi.h"

struct transport {
    int devfd;
    int chanfd;
};

/* The device fd only. Which end of the link this process is on was decided
 * by crosvm's --vendor-device role=, so there is nothing role-specific to
 * store here, the listener side simply waits for channels rather than
 * causing one. */
struct transport_listener {
    int devfd;
};

const char *transport_backend_name(void) { return "xchan"; }

transport_t *transport_connect(const char *endpoint) {
    /* endpoint == NULL lets libxchan use its default device ("/dev/xchan0") */
    int devfd = xchan_open(endpoint);
    if (devfd < 0) return NULL;

    struct xchan_channel_info info;
    int chanfd = xchan_wait_channel(devfd, &info);
    if (chanfd < 0) {
        int e = errno;
        close(devfd);
        errno = e;
        return NULL;
    }

    transport_t *t = malloc(sizeof(*t));
    if (!t) {
        int e = errno;
        close(chanfd);
        close(devfd);
        errno = e;
        return NULL;
    }
    t->devfd = devfd;
    t->chanfd = chanfd;
    return t;
}

ssize_t transport_send(transport_t *t, const void *buf, size_t len) {
    /* xchan_send already returns -1/errno with exactly the semantics we
     * want to expose (EAGAIN, ECONNRESET, EMSGSIZE), nothing to
     * translate. */
    return xchan_send(t->chanfd, buf, len);
}

ssize_t transport_recv(transport_t *t, void *buf, size_t cap) {
    /* Likewise: EAGAIN, ECONNRESET, EMSGSIZE, ECANCELED all pass through
     * unchanged. Measurement code above transport.h treats ECANCELED (peer
     * aborted mid-send) as a hard failure for that request, same as it
     * would treat a socket EOF, see client.c's run_one_request(). */
    return xchan_recv(t->chanfd, buf, cap);
}

void transport_close(transport_t *t) {
    if (!t) return;
    close(t->chanfd);
    if (t->devfd >= 0) close(t->devfd); /* -1 when accepted: listener owns it */
    free(t);
}

transport_listener_t *transport_listen(const char *endpoint) {
    int devfd = xchan_open(endpoint);
    if (devfd < 0) return NULL;

    transport_listener_t *l = malloc(sizeof(*l));
    if (!l) { int e = errno; close(devfd); errno = e; return NULL; }
    l->devfd = devfd;
    return l;
}

/* Each accepted transport borrows the listener's device fd rather than
 * owning it, so transport_close() must not close devfd on this path.
 * devfd == -1 is the marker for that. */
transport_t *transport_accept(transport_listener_t *l) {
    struct xchan_channel_info info;
    int chanfd;
    do { chanfd = xchan_wait_channel(l->devfd, &info); } while (chanfd < 0 && errno == EINTR);
    if (chanfd < 0) return NULL;

    transport_t *t = malloc(sizeof(*t));
    if (!t) { int e = errno; close(chanfd); errno = e; return NULL; }
    t->devfd = -1;
    t->chanfd = chanfd;
    return t;
}

void transport_listener_close(transport_listener_t *l) {
    if (!l) return;
    close(l->devfd);
    free(l);
}
