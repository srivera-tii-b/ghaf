/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* transport.h, backend-agnostic message transport used by the benchmark
 * client.
 *
 * Every backend (unix socket, vsock, xchan, g2g) implements the SAME
 * contract:
 *
 *   - transport_send(t, buf, len): send exactly `len` bytes as ONE message.
 *     Returns `len` on success, -1/errno on failure.
 *   - transport_recv(t, buf, cap): receive the next complete message into
 *     `buf` (capacity `cap`). Returns the number of bytes written (the
 *     sender's `len`), -1/errno on failure. Never returns a partial message
 *     and never blends two messages together.
 *
 * xchan and g2gchan satisfy this natively. A stream socket (unix or vsock)
 * does not (it's a byte pipe with no message boundaries), so
 * transport_sock.c and transport_vsock.c each invent a 4-byte big-endian
 * length prefix per message and loop send()/recv() until that many bytes
 * have moved. That framing is entirely private to those two files,
 * nothing above transport.h, including all measurement code, ever sees it.
 * This is the one place the backends' underlying shapes actually differ;
 * everything else in this codebase treats a transport_t* as "a thing you
 * hand whole messages to and get whole messages back from," which is what
 * makes the same client/measurement code valid evidence for all of them.
 *
 * Error mapping: the socket backends map their failures onto errno the way
 * xchan already does (EAGAIN = would block, ECONNRESET = peer gone,
 * EMSGSIZE = message too big for the buffer, ECANCELED = peer aborted
 * mid-send), synthesizing these from EOF/short-read/oversized-length-prefix
 * conditions so callers can handle every backend with the same errno
 * switch. g2gchan reports a peer that is gone as ECONNRESET and an
 * oversized message as EMSGSIZE too (g2gchan.h).
 */
#ifndef BENCH_TRANSPORT_H
#define BENCH_TRANSPORT_H

#include <stddef.h>
#include <sys/types.h>

typedef struct transport transport_t;

/* Server side. Split into listener-open and accept because that is the
 * shape all four backends already have: sock/vsock are bind+listen then
 * accept(), xchan is xchan_open() on the device then xchan_wait_channel()
 * for each channel, and g2g is g2gc_listen() then g2gc_accept(). Collapsing
 * them into one call would force the socket backends to re-bind per
 * connection.
 *
 * The server being backend-agnostic is what makes the transport comparison
 * trustworthy: both ends run identical code on every arm, so a measured
 * difference is the transport rather than two different server
 * implementations. */
typedef struct transport_listener transport_listener_t;

/* Connect as a CLIENT to `endpoint`:
 *   - sock backend: `endpoint` is a filesystem path to a unix socket that
 *     a server is listening on (created with socket(AF_UNIX,SOCK_STREAM)
 *     + connect()).
 *   - vsock backend: `endpoint` is "CID:PORT", e.g. "2:9000".
 *   - xchan backend: `endpoint` is the xchan device node (e.g.
 *     "/dev/xchan0", or NULL for the libxchan default). The connect call
 *     opens the device and blocks in xchan_wait_channel() for a channel.
 *   - g2g backend: `endpoint` is "g2g:<id-hi>[:<id-lo>]", the server VM's
 *     guest-to-guest identity (see transport_g2g.c).
 *
 * Returns a transport handle, or NULL with errno set.
 */
transport_t *transport_connect(const char *endpoint);

/* Open a listening endpoint:
 *   - sock backend:  `endpoint` is a filesystem path, unlinked then bound.
 *   - vsock backend: `endpoint` is "PORT" or "CID:PORT"; the CID is ignored
 *     and VMADDR_CID_ANY is bound, so the server needs no knowledge of its
 *     own address.
 *   - xchan backend: `endpoint` is the device node (or NULL for the
 *     libxchan default). No role is chosen here, listener vs connector is
 *     fixed by crosvm's --vendor-device, not by this process.
 *   - g2g backend: `endpoint` is ignored; the listener is the VM itself.
 *
 * Returns a listener handle, or NULL with errno set. */
transport_listener_t *transport_listen(const char *endpoint);

/* Block until one peer arrives, and return a transport for it. Returns NULL
 * with errno set on failure; EINTR is retried internally. Call repeatedly to
 * serve connections sequentially. */
transport_t *transport_accept(transport_listener_t *l);

/* Close the listening endpoint (and, for the sock backend, unlink its
 * path). Does not affect transports already accepted from it. */
void transport_listener_close(transport_listener_t *l);

/* Send exactly `len` bytes as one message. Returns len, or -1/errno. */
ssize_t transport_send(transport_t *t, const void *buf, size_t len);

/* Receive the next whole message into buf (capacity cap). Returns the
 * number of bytes received, or -1/errno. */
ssize_t transport_recv(transport_t *t, void *buf, size_t cap);

/* Release all resources associated with the transport. */
void transport_close(transport_t *t);

/* Human-readable name of the backend compiled into this binary ("sock",
 * "vsock", "xchan" or "g2g"), for logging/reporting. */
const char *transport_backend_name(void);

#endif /* BENCH_TRANSPORT_H */
