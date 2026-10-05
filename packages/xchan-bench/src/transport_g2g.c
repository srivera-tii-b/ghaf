/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* transport_g2g.c, g2gchan backend for transport.h.
 *
 * endpoint: client "g2g:<id-hi>[:<id-lo>]" (id-lo defaults to "probe-id");
 * server: anything (the listener is the VM itself). One process per VM. */
#include "transport.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "g2gchan.h"

#define CONNECT_MS 10000

struct transport { g2gc_t *c; };
struct transport_listener { g2gc_listener_t *l; };

const char *transport_backend_name(void) { return "g2g"; }

transport_t *transport_connect(const char *endpoint) {
    uint64_t hi, lo = G2GC_PROBE_ID_LO;
    char *end;
    if (!endpoint || strncmp(endpoint, "g2g:", 4) != 0) { errno = EINVAL; return NULL; }
    hi = strtoull(endpoint + 4, &end, 0);
    if (*end == ':') lo = strtoull(end + 1, &end, 0);
    if (*end != '\0' || hi == 0) { errno = EINVAL; return NULL; }
    transport_t *t = malloc(sizeof(*t));
    if (!t) return NULL;
    t->c = g2gc_connect(hi, lo, CONNECT_MS);
    if (!t->c) { int e = errno; free(t); errno = e; return NULL; }
    return t;
}

ssize_t transport_send(transport_t *t, const void *buf, size_t len) { return g2gc_send(t->c, buf, len); }
ssize_t transport_recv(transport_t *t, void *buf, size_t cap) { return g2gc_recv(t->c, buf, cap); }

void transport_close(transport_t *t) {
    if (!t) return;
    g2gc_close(t->c);
    free(t);
}

transport_listener_t *transport_listen(const char *endpoint) {
    (void)endpoint;
    transport_listener_t *l = malloc(sizeof(*l));
    if (!l) return NULL;
    l->l = g2gc_listen();
    if (!l->l) { int e = errno; free(l); errno = e; return NULL; }
    return l;
}

transport_t *transport_accept(transport_listener_t *l) {
    transport_t *t = malloc(sizeof(*t));
    if (!t) return NULL;
    t->c = g2gc_accept(l->l, -1);
    if (!t->c) { int e = errno; free(t); errno = e; return NULL; }
    return t;
}

void transport_listener_close(transport_listener_t *l) {
    if (!l) return;
    g2gc_listener_close(l->l);
    free(l);
}
