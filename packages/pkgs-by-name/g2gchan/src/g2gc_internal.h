/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* struct g2gc and the library's counters, for g2gchan.c, its tests and
 * g2gc-echo; not installed for applications. */
#ifndef G2GC_INTERNAL_H
#define G2GC_INTERNAL_H

#include <pthread.h>
#include <linux/pkvm_g2g.h>
#include "g2gc_proto.h"

struct g2gc {
	int fd;				/* device file: this channel's two shares live on it */
	int efd;			/* eventfd, see g2gc_fd() */
	struct pkvm_g2g_ident peer;
	uint64_t my_handle, peer_handle;
	int have_mine, have_peer;
	struct g2gc_hdr *me;		/* our share, read-write */
	const struct g2gc_hdr *them;	/* the peer's share, read-only */
	unsigned char *my_bufs;
	const unsigned char *peer_bufs;
	pthread_mutex_t tx, rx, st;
	uint64_t tx_prod, last_peer_cons;	/* under tx */
	uint64_t rx_cons, last_peer_prod;	/* under rx */
	int broken;			/* atomic: the errno every later call gets, 0 while healthy */
	int peer_closed;		/* under st: saw the peer's closed; peer_final is its last prod */
	int peer_gone;			/* under st: its share faulted; it is never read again */
	int acked;			/* under st: we set our closed_ack */
	uint64_t peer_final;
	int signaled;			/* under st: the eventfd is readable */
	struct g2gc *next;		/* the poller's list */
};

/* Guarded accesses that faulted (EL2 had taken the share), process-wide. */
extern unsigned long g2gc_fault_count;
/* Nonzero while the poller thread runs (it exits when no channel is open). */
extern int g2gc_poller_running;

#endif
