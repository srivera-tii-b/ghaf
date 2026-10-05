// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0
/*
 * g2gchan: message channels between two protected pKVM guests over pages EL2
 * shares between them. The API and its rules: g2gchan.h; wire format and its
 * checks: g2gc_proto.[ch]. Setup goes through EL2's mailbox (CONNECT, then
 * ACCEPTED or REFUSED); data never does.
 *
 * Everything read from the peer's share is copied out once and only the copy
 * is used. The peer can rewrite its share at any moment, and EL2 takes it
 * away the moment the peer revokes or dies: that read then faults, which
 * peer_copy()/peer_load() turn into ECONNRESET.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "g2gchan.h"
#include "g2gc_dev.h"
#include "g2gc_internal.h"

/* Time limits: first guesses, overridable at build time (-D; the ghaf
 * package takes them as arguments). What each bounds: g2gchan.h. */
#ifndef G2GC_STALL_MS
#define G2GC_STALL_MS		30000
#endif
#ifndef G2GC_CLOSE_DRAIN_MS
#define G2GC_CLOSE_DRAIN_MS	2000
#endif
#define G2GC_REPLY_MS		2000	/* server: bound on sending ACCEPTED or REFUSED */

struct g2gc_listener {
	int fd;
};

static long long mono_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int past(long long deadline)
{
	return deadline >= 0 && mono_ms() >= deadline;
}

/* Spin, then yield, then sleep 50 us, then 1 ms. */
static void backoff(unsigned *n)
{
	struct timespec ts = { 0, 0 };

	if (++*n <= 100)
		return;
	if (*n <= 200) {
		sched_yield();
		return;
	}
	ts.tv_nsec = *n <= 400 ? 50000 : 1000000;
	nanosleep(&ts, NULL);
}

/* ---- reading the peer's share ----------------------------------------- */

/*
 * A guarded access: the jump buffer and the bytes it covers. Only a fault in
 * those bytes is ours; anything else goes to the handler that was there
 * before (the application's, or the default).
 *
 * fault_g is volatile, and the accesses are fenced: nothing in C says a
 * memcpy() reads it, so a plain variable lets the compiler drop the store
 * that arms the guard (it did, at -O1 and -O2) and a fault then kills the
 * process instead of returning -1.
 *
 * sigsetjmp(.., 0) and SA_NODEFER: the handler runs with the mask unchanged,
 * so the jump out needs no sigprocmask() call to restore it.
 */
struct fault_guard {
	sigjmp_buf jb;
	uintptr_t lo, hi;	/* the guarded bytes, [lo, hi) */
};

static __thread struct fault_guard *volatile fault_g;
unsigned long g2gc_fault_count;
static pthread_once_t fault_once = PTHREAD_ONCE_INIT;
static struct sigaction fault_prev[2];	/* SIGBUS, and the simulator's SIGSEGV */

/* Not ours: what the handler installed before ours would have done. */
static void fault_chain(int sig, siginfo_t *si, void *uc)
{
	struct sigaction *p = &fault_prev[sig == SIGBUS ? 0 : 1];
	struct sigaction dfl;

	if ((p->sa_flags & SA_SIGINFO) && p->sa_sigaction) {
		p->sa_sigaction(sig, si, uc);
		return;
	}
	if (!(p->sa_flags & SA_SIGINFO) && p->sa_handler != SIG_DFL && p->sa_handler != SIG_IGN) {
		p->sa_handler(sig);
		return;
	}
	/* Default, or ignored (which would only fault again): die as we would have. */
	memset(&dfl, 0, sizeof(dfl));
	dfl.sa_handler = SIG_DFL;
	sigemptyset(&dfl.sa_mask);
	sigaction(sig, &dfl, NULL);
	raise(sig);
}

static void on_fault(int sig, siginfo_t *si, void *uc)
{
	struct fault_guard *g = fault_g;
	uintptr_t a = (uintptr_t)si->si_addr;

	/* An address of 0: the abort did not report one; inside a guarded
	 * access that is still the share being read. */
	if (g && (!a || (a >= g->lo && a < g->hi))) {
		__atomic_fetch_add(&g2gc_fault_count, 1, __ATOMIC_RELAXED);
		siglongjmp(g->jb, 1);
	}
	fault_g = NULL;		/* a handler that jumps away must not leave a guard armed */
	fault_chain(sig, si, uc);
	fault_g = g;		/* it returned: the access is retried, still guarded */
}

static void fault_install(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = on_fault;
	sa.sa_flags = SA_SIGINFO | SA_NODEFER;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGBUS, &sa, &fault_prev[0]);
#ifdef G2GC_FAULT_SIGNAL_2
	sigaction(G2GC_FAULT_SIGNAL_2, &sa, &fault_prev[1]);
#endif
}

/* Copy n bytes out of a peer mapping. -1: EL2 took the mapping away. */
static int peer_copy(void *dst, const void *src, size_t n)
{
	struct fault_guard g;
	struct fault_guard *volatile saved = fault_g;

	if (sigsetjmp(g.jb, 0)) {
		fault_g = saved;
		return -1;
	}
	g.lo = (uintptr_t)src;
	g.hi = (uintptr_t)src + n;
	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	fault_g = &g;
	__atomic_signal_fence(__ATOMIC_SEQ_CST);	/* armed before the access */
	memcpy(dst, src, n);
	__atomic_signal_fence(__ATOMIC_SEQ_CST);	/* and until it is done */
	fault_g = saved;
	return 0;
}

/* An acquire load of a peer's counter. -1: EL2 took the mapping away. */
static int peer_load(const uint64_t *p, uint64_t *v)
{
	struct fault_guard g;
	struct fault_guard *volatile saved = fault_g;

	if (sigsetjmp(g.jb, 0)) {
		fault_g = saved;
		return -1;
	}
	g.lo = (uintptr_t)p;
	g.hi = (uintptr_t)(p + 1);
	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	fault_g = &g;
	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	*v = __atomic_load_n(p, __ATOMIC_ACQUIRE);
	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	fault_g = saved;
	return 0;
}

/* A release store to our own share, guarded like the loads: in the
 * simulator a dead guest's channel stays on the poller's list after its own
 * share went with its device file. -1: the page is gone. */
static int own_store(uint64_t *p, uint64_t v)
{
	struct fault_guard g;
	struct fault_guard *volatile saved = fault_g;

	if (sigsetjmp(g.jb, 0)) {
		fault_g = saved;
		return -1;
	}
	g.lo = (uintptr_t)p;
	g.hi = (uintptr_t)(p + 1);
	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	fault_g = &g;
	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	fault_g = saved;
	return 0;
}

/* ---- readiness, breaking, the poller ---------------------------------- */

static int broken(struct g2gc *c)
{
	return __atomic_load_n(&c->broken, __ATOMIC_ACQUIRE);
}

/*
 * Under c->st: the peer's prod, and whether it has closed, read from its share
 * only while that is still safe. Once it has closed and we hold everything it
 * sent, we ack (closed_ack) and never read its share again, so the REVOKE it
 * does next cannot land under one of our reads. -1: the share is gone (EL2
 * took it); the channel is then broken and its share never read again.
 */
static int peer_state(struct g2gc *c, uint64_t *pp, int *closed)
{
	uint64_t cl, p;

	if (c->peer_gone)
		return -1;
	if (!c->peer_closed) {
		/* closed first: a prod read after it includes the peer's last frame */
		if (peer_load(&c->them->closed, &cl) || peer_load(&c->them->prod, &p)) {
			c->peer_gone = 1;
			if (!broken(c))
				__atomic_store_n(&c->broken, ECONNRESET, __ATOMIC_RELEASE);
			return -1;
		}
		if (!cl) {
			*pp = p;
			*closed = 0;
			return 0;
		}
		c->peer_closed = 1;
		c->peer_final = p;
	}
	if (!c->acked) {
		uint64_t mine;

		if (!peer_load(&c->me->cons, &mine) && mine == c->peer_final &&
		    !own_store(&c->me->closed_ack, 1))
			c->acked = 1;
	}
	*pp = c->peer_final;
	*closed = 1;
	return 0;
}

/* Under c->st: would g2gc_recv() return without waiting? */
static int chan_readable(struct g2gc *c)
{
	uint64_t pp, mine;
	int closed;

	if (broken(c))
		return 1;
	if (peer_state(c, &pp, &closed))
		return 1;
	/* Our own page, but guarded too: in the simulator a dead guest's
	 * channel stays on this list with its memory gone. */
	if (peer_load(&c->me->cons, &mine) || pp != mine)
		return 1;
	return closed;
}

/* Under c->st: make the eventfd say what chan_readable() says. Returns 1
 * when it has just become readable. Keeps errno. */
static int chan_signal(struct g2gc *c)
{
	int e = errno, r = chan_readable(c), rose = 0;
	uint64_t v = 1;

	if (r && !c->signaled) {
		if (write(c->efd, &v, sizeof(v)) == sizeof(v)) {
			c->signaled = 1;
			rose = 1;
		}
	} else if (!r && c->signaled) {
		if (read(c->efd, &v, sizeof(v)) == sizeof(v) || errno == EAGAIN)
			c->signaled = 0;
	}
	errno = e;
	return rose;
}

/* Tear the channel down with errno e (the first reason wins). Returns -1. */
static int chan_break(struct g2gc *c, int e)
{
	pthread_mutex_lock(&c->st);
	if (!broken(c))
		__atomic_store_n(&c->broken, e, __ATOMIC_RELEASE);
	e = broken(c);
	chan_signal(c);
	pthread_mutex_unlock(&c->st);
	errno = e;
	return -1;
}

static pthread_mutex_t plock = PTHREAD_MUTEX_INITIALIZER;
static struct g2gc *plist;
int g2gc_poller_running;	/* under plock; read atomically by tests */

/*
 * One per process while any channel is open: keeps every channel's eventfd
 * level-true. It exits when the last channel closes (under plock, so
 * chan_start() knows to start a new one). It must not block SIGBUS: its reads
 * of a share that vanished are guarded like any other.
 */
static void *poller(void *arg)
{
	unsigned n = 200;	/* never spins: 50 us sleeps, then 1 ms */

	(void)arg;
	for (;;) {
		struct g2gc *c;
		int rose = 0;

		pthread_mutex_lock(&plock);
		if (!plist) {
			__atomic_store_n(&g2gc_poller_running, 0, __ATOMIC_RELEASE);
			pthread_mutex_unlock(&plock);
			return NULL;
		}
		for (c = plist; c; c = c->next) {
			pthread_mutex_lock(&c->st);
			rose |= chan_signal(c);
			pthread_mutex_unlock(&c->st);
		}
		pthread_mutex_unlock(&plock);
		if (rose)
			n = 200;
		backoff(&n);
	}
	return NULL;
}

static int chan_start(struct g2gc *c)
{
	pthread_t t;
	pthread_attr_t a;
	int rc = 0;

	pthread_mutex_lock(&plock);
	if (!g2gc_poller_running) {
		pthread_attr_init(&a);
		pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
		rc = pthread_create(&t, &a, poller, NULL);
		pthread_attr_destroy(&a);
		__atomic_store_n(&g2gc_poller_running, !rc, __ATOMIC_RELEASE);
	}
	if (!rc) {
		c->next = plist;
		plist = c;
	}
	pthread_mutex_unlock(&plock);
	if (rc) {
		errno = rc;
		return -1;
	}
	pthread_mutex_lock(&c->st);
	chan_signal(c);
	pthread_mutex_unlock(&c->st);
	return 0;
}

static void chan_stop(struct g2gc *c)
{
	struct g2gc **pp;

	pthread_mutex_lock(&plock);
	for (pp = &plist; *pp; pp = &(*pp)->next)
		if (*pp == c) {
			*pp = c->next;
			break;
		}
	pthread_mutex_unlock(&plock);
}

/* ---- channel setup and teardown ---------------------------------------- */

/* Unmaps and ends both shares, closes the files. Keeps errno. */
static void chan_destroy(struct g2gc *c)
{
	struct pkvm_g2g_end end;
	int e = errno;

	if (!c)
		return;
	memset(&end, 0, sizeof(end));
	if (c->them)
		dev_munmap((void *)c->them, G2GC_SHARE_BYTES);
	if (c->have_peer) {
		end.handle = c->peer_handle;
		dev_ioctl(c->fd, PKVM_G2G_IOC_RELEASE, &end);
	}
	if (c->me)
		dev_munmap(c->me, G2GC_SHARE_BYTES);
	if (c->have_mine) {
		end.handle = c->my_handle;
		dev_ioctl(c->fd, PKVM_G2G_IOC_REVOKE, &end);
	}
	if (c->fd >= 0)
		dev_close(c->fd);
	if (c->efd >= 0)
		close(c->efd);
	pthread_mutex_destroy(&c->tx);
	pthread_mutex_destroy(&c->rx);
	pthread_mutex_destroy(&c->st);
	free(c);
	errno = e;
}

static struct g2gc *chan_new(void)
{
	struct g2gc *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	pthread_once(&fault_once, fault_install);
	pthread_mutex_init(&c->tx, NULL);
	pthread_mutex_init(&c->rx, NULL);
	pthread_mutex_init(&c->st, NULL);
	c->fd = -1;
	c->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (c->efd >= 0)
		c->fd = dev_open();
	if (c->fd < 0) {
		chan_destroy(c);
		return NULL;
	}
	return c;
}

/* Offer our share to c->peer, read-only, map it and write its header. */
static int share_offer(struct g2gc *c)
{
	struct pkvm_g2g_offer o;
	void *p;

	memset(&o, 0, sizeof(o));
	o.peer = c->peer;
	o.nr_pages = G2GC_SHARE_PAGES;
	o.flags = PKVM_G2G_SHARE_RO;
	if (dev_ioctl(c->fd, PKVM_G2G_IOC_OFFER, &o))
		return -1;
	c->my_handle = o.handle;
	c->have_mine = 1;
	p = dev_mmap(c->fd, G2GC_SHARE_BYTES, PROT_READ | PROT_WRITE, o.mmap_offset);
	if (p == MAP_FAILED)
		return -1;
	c->me = p;
	c->my_bufs = (unsigned char *)p + G2GC_PAGE;
	/* The driver's pages are zeroed: prod, cons and closed start at 0. */
	c->me->version = G2GC_VERSION;
	c->me->bufs = G2GC_BUFS;
	c->me->buf_size = G2GC_BUF_SIZE;
	__atomic_store_n(&c->me->magic, G2GC_MAGIC, __ATOMIC_RELEASE);
	return 0;
}

/* Accept the peer's share (it must be read-only to us), map it, check it. */
static int share_accept(struct g2gc *c, uint64_t handle)
{
	struct pkvm_g2g_accept a;
	struct g2gc_hdr h;
	void *p;

	memset(&a, 0, sizeof(a));
	a.owner = c->peer;
	a.handle = handle;
	a.nr_pages = G2GC_SHARE_PAGES;
	if (dev_ioctl(c->fd, PKVM_G2G_IOC_ACCEPT, &a))
		return -1;
	c->peer_handle = handle;
	c->have_peer = 1;
	if (!(a.flags & PKVM_G2G_SHARE_RO)) {
		errno = EPROTO;
		return -1;
	}
	p = dev_mmap(c->fd, G2GC_SHARE_BYTES, PROT_READ, a.mmap_offset);
	if (p == MAP_FAILED)
		return -1;
	c->them = p;
	c->peer_bufs = (const unsigned char *)p + G2GC_PAGE;
	if (peer_copy(&h, c->them, sizeof(h))) {
		errno = ECONNRESET;
		return -1;
	}
	if (g2gc_check_hdr(&h)) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static int same_peer(const struct pkvm_g2g_ident *a, const struct pkvm_g2g_ident *b)
{
	return a->id_lo == b->id_lo && a->id_hi == b->id_hi && a->incarnation == b->incarnation;
}

/* One mailbox message; a full slot at the peer (EAGAIN) is retried. */
static int mbox_send(int fd, const struct pkvm_g2g_ident *to, uint64_t type,
		     uint64_t handle, uint64_t nonce, long long deadline)
{
	struct pkvm_g2g_msg m;
	unsigned n = 0;

	memset(&m, 0, sizeof(m));
	m.peer = *to;
	m.payload[0] = G2GC_W0(type);
	m.payload[1] = handle;
	m.payload[2] = G2GC_SHARE_PAGES;
	m.payload[3] = nonce;
	for (;;) {
		if (!dev_ioctl(fd, PKVM_G2G_IOC_MSG_SEND, &m))
			return 0;
		if (errno != EAGAIN)
			return -1;
		if (past(deadline)) {
			errno = ETIMEDOUT;
			return -1;
		}
		backoff(&n);
	}
}

/* Client: the server's answer to our CONNECT. Other messages are dropped:
 * this process is its VM's only mailbox reader, and this call its only
 * reader thread (a concurrent connect or accept would drop our answer). */
static int await_accepted(struct g2gc *c, uint64_t nonce, long long deadline)
{
	unsigned n = 0;

	for (;;) {
		struct pkvm_g2g_msg m;

		if (past(deadline)) {
			errno = ETIMEDOUT;
			return -1;
		}
		memset(&m, 0, sizeof(m));
		if (dev_ioctl(c->fd, PKVM_G2G_IOC_MSG_RECV, &m)) {
			if (errno != EAGAIN)
				return -1;
			backoff(&n);
			continue;
		}
		if (!same_peer(&m.peer, &c->peer) || m.payload[3] != nonce)
			continue;
		if (m.payload[0] == G2GC_W0(G2GC_MSG_ACCEPTED) && m.payload[2] == G2GC_SHARE_PAGES)
			return share_accept(c, m.payload[1]);
		if (m.payload[0] == G2GC_W0(G2GC_MSG_REFUSED)) {
			errno = ECONNREFUSED;
			return -1;
		}
	}
}

g2gc_t *g2gc_connect(uint64_t id_hi, uint64_t id_lo, int timeout_ms)
{
	long long deadline = timeout_ms < 0 ? -1 : mono_ms() + timeout_ms;
	struct g2gc *c = chan_new();
	uint64_t nonce;

	if (!c)
		return NULL;
	c->peer.id_lo = id_lo;
	c->peer.id_hi = id_hi;
	if (dev_ioctl(c->fd, PKVM_G2G_IOC_LOOKUP, &c->peer))
		goto fail;
	if (!c->peer.incarnation) {
		errno = ECONNREFUSED;
		goto fail;
	}
	if (getrandom(&nonce, sizeof(nonce), 0) != sizeof(nonce))
		goto fail;
	if (share_offer(c))
		goto fail;
	if (mbox_send(c->fd, &c->peer, G2GC_MSG_CONNECT, c->my_handle, nonce, deadline))
		goto fail;
	if (await_accepted(c, nonce, deadline))
		goto fail;
	if (chan_start(c))
		goto fail;
	return c;
fail:
	chan_destroy(c);
	return NULL;
}

g2gc_listener_t *g2gc_listen(void)
{
	g2gc_listener_t *l = calloc(1, sizeof(*l));
	int e;

	if (!l)
		return NULL;
	l->fd = dev_open();
	if (l->fd < 0) {
		e = errno;
		free(l);
		errno = e;
		return NULL;
	}
	return l;
}

void g2gc_listener_close(g2gc_listener_t *l)
{
	if (!l)
		return;
	dev_close(l->fd);
	free(l);
}

/* A CONNECT: take the client's share, offer ours, answer. NULL: refused. */
static struct g2gc *accept_one(int lfd, const struct pkvm_g2g_msg *m)
{
	long long deadline = mono_ms() + G2GC_REPLY_MS;
	struct g2gc *c = chan_new();
	int e;

	if (!c)
		goto refuse;
	c->peer = m->peer;
	if (share_accept(c, m->payload[1]) || share_offer(c) ||
	    mbox_send(c->fd, &c->peer, G2GC_MSG_ACCEPTED, c->my_handle, m->payload[3], deadline) ||
	    chan_start(c))
		goto refuse;
	return c;
refuse:
	e = errno;
	mbox_send(lfd, &m->peer, G2GC_MSG_REFUSED, 0, m->payload[3], deadline);
	chan_destroy(c);
	errno = e;
	return NULL;
}

g2gc_t *g2gc_accept(g2gc_listener_t *l, int timeout_ms)
{
	long long deadline = timeout_ms < 0 ? -1 : mono_ms() + timeout_ms;
	unsigned n = 0;

	for (;;) {
		struct pkvm_g2g_msg m;

		memset(&m, 0, sizeof(m));
		if (!dev_ioctl(l->fd, PKVM_G2G_IOC_MSG_RECV, &m)) {
			n = 0;
			if (m.payload[0] == G2GC_W0(G2GC_MSG_CONNECT) &&
			    m.payload[2] == G2GC_SHARE_PAGES) {
				struct g2gc *c = accept_one(l->fd, &m);

				if (c)
					return c;
			}
		} else if (errno != EAGAIN) {
			return NULL;
		}
		if (past(deadline)) {
			errno = ETIMEDOUT;
			return NULL;
		}
		backoff(&n);
	}
}

int g2gc_fd(g2gc_t *c)
{
	return c->efd;
}

/* ---- data ---------------------------------------------------------------- */

/* Wait for credit for one more frame. A stall past G2GC_STALL_MS tears the
 * channel down (ETIMEDOUT), between messages as well as inside one. mid:
 * inside a message, where a peer that has closed also tears it down; between
 * messages that send just fails (ECONNRESET), and what the peer sent before
 * closing stays readable. */
static int tx_wait(struct g2gc *c, int mid)
{
	long long stall = mono_ms() + G2GC_STALL_MS;
	unsigned n = 0;

	for (;;) {
		uint64_t pc = 0, cl = 0;
		int gone, closed;

		if (broken(c)) {
			errno = broken(c);
			return -1;
		}
		/* Under st, like every read of the peer's counters and flags: see
		 * peer_state(). */
		pthread_mutex_lock(&c->st);
		closed = c->peer_closed;
		gone = c->peer_gone;
		if (!closed && !gone) {
			gone = peer_load(&c->them->closed, &cl) || peer_load(&c->them->cons, &pc);
			c->peer_gone = gone;
			closed = cl != 0;
		}
		pthread_mutex_unlock(&c->st);
		if (gone)
			return chan_break(c, ECONNRESET);
		if (closed) {	/* it reads nothing more */
			if (mid)
				return chan_break(c, ECONNRESET);
			errno = ECONNRESET;
			return -1;
		}
		if (g2gc_check_cons(pc, c->last_peer_cons, c->tx_prod))
			return chan_break(c, EPROTO);
		c->last_peer_cons = pc;
		if (c->tx_prod - pc < G2GC_BUFS)
			return 0;
		if (mono_ms() >= stall)
			return chan_break(c, ETIMEDOUT);
		backoff(&n);
	}
}

ssize_t g2gc_send(g2gc_t *c, const void *buf, size_t len)
{
	const unsigned char *s = buf;
	size_t off = 0;
	int mid = 0;

	if (len > G2GC_MAX_MSG) {
		errno = EMSGSIZE;
		return -1;
	}
	pthread_mutex_lock(&c->tx);
	do {
		size_t n = len - off > G2GC_BUF_SIZE ? G2GC_BUF_SIZE : len - off;
		unsigned w = (unsigned)(c->tx_prod % G2GC_BUFS);
		struct g2gc_frame *f = &c->me->frame[w];

		if (tx_wait(c, mid)) {
			pthread_mutex_unlock(&c->tx);
			return -1;
		}
		if (n)
			memcpy(c->my_bufs + (size_t)w * G2GC_BUF_SIZE, s + off, n);
		f->seq = c->tx_prod;
		f->len = (uint32_t)n;
		f->msg_len = (uint32_t)len;
		f->flags = (uint16_t)(G2GC_F_WINDOW_REF | (off + n < len ? G2GC_F_MORE : 0));
		f->window_id = (uint16_t)w;
		f->pad = 0;
		c->tx_prod++;
		__atomic_store_n(&c->me->prod, c->tx_prod, __ATOMIC_RELEASE);
		off += n;
		mid = 1;
	} while (off < len);
	pthread_mutex_unlock(&c->tx);
	return (ssize_t)len;
}

/* Wait for the next frame. mid: inside a message, where a stall past
 * G2GC_STALL_MS tears the channel down; between messages it waits for ever. */
static int rx_wait(struct g2gc *c, int mid)
{
	long long stall = mid ? mono_ms() + G2GC_STALL_MS : -1;
	unsigned n = 0;

	for (;;) {
		uint64_t pp;
		int closed, r;

		if (broken(c)) {
			errno = broken(c);
			return -1;
		}
		pthread_mutex_lock(&c->st);
		r = peer_state(c, &pp, &closed);
		pthread_mutex_unlock(&c->st);
		if (r)
			return chan_break(c, ECONNRESET);
		if (g2gc_check_prod(pp, c->last_peer_prod, c->rx_cons))
			return chan_break(c, EPROTO);
		c->last_peer_prod = pp;
		if (pp > c->rx_cons)
			return 0;
		if (closed) {
			if (mid)
				return chan_break(c, EPROTO);	/* closed inside a message */
			errno = ECONNRESET;
			return -1;
		}
		if (past(stall))
			return chan_break(c, ETIMEDOUT);
		backoff(&n);
	}
}

ssize_t g2gc_recv(g2gc_t *c, void *buf, size_t cap)
{
	unsigned char *d = buf;
	struct g2gc_frame f;
	uint32_t got = 0, msg_len = 0;
	ssize_t ret = -1;
	int first = 1, e;

	pthread_mutex_lock(&c->rx);
	for (;;) {
		unsigned w;

		if (rx_wait(c, !first))
			goto out;
		w = (unsigned)(c->rx_cons % G2GC_BUFS);
		if (peer_copy(&f, &c->them->frame[w], sizeof(f))) {
			chan_break(c, ECONNRESET);
			goto out;
		}
		if (g2gc_check_frame(&f, c->rx_cons, got, msg_len)) {
			chan_break(c, EPROTO);
			goto out;
		}
		if (first) {
			msg_len = f.msg_len;
			if (msg_len > cap) {	/* nothing consumed: retry with room */
				errno = EMSGSIZE;
				goto out;
			}
			first = 0;
		}
		if (f.len && peer_copy(d + got, c->peer_bufs + (size_t)w * G2GC_BUF_SIZE, f.len)) {
			chan_break(c, ECONNRESET);
			goto out;
		}
		got += f.len;
		c->rx_cons++;
		/* This store is the RELEASE: the peer may now reuse that buffer. */
		__atomic_store_n(&c->me->cons, c->rx_cons, __ATOMIC_RELEASE);
		if (got == msg_len)
			break;
	}
	ret = (ssize_t)msg_len;
out:
	e = errno;
	pthread_mutex_lock(&c->st);
	chan_signal(c);
	pthread_mutex_unlock(&c->st);
	pthread_mutex_unlock(&c->rx);
	errno = e;
	return ret;
}

void g2gc_close(g2gc_t *c)
{
	long long deadline;
	unsigned n = 0;

	if (!c)
		return;
	chan_stop(c);
	pthread_mutex_lock(&c->tx);
	__atomic_store_n(&c->me->closed, 1, __ATOMIC_RELEASE);
	deadline = mono_ms() + G2GC_CLOSE_DRAIN_MS;
	/* Wait (bounded) for the peer's ack: it holds everything we sent and
	 * reads our share no more, so our REVOKE cannot land under its read. */
	for (;;) {
		uint64_t pp, ack = 0;
		int closed, done;

		pthread_mutex_lock(&c->st);
		if (broken(c) || peer_state(c, &pp, &closed)) {
			done = 1;
		} else if (closed) {
			/* It closed too: ack it so it stops waiting. Both shares then go
			 * at once; a read of ours it still had in flight is its handled
			 * fault. */
			if (!c->acked && !own_store(&c->me->closed_ack, 1))
				c->acked = 1;
			done = 1;
		} else {
			done = peer_load(&c->them->closed_ack, &ack) || ack;
		}
		pthread_mutex_unlock(&c->st);
		if (done || mono_ms() >= deadline)
			break;
		backoff(&n);
	}
	pthread_mutex_unlock(&c->tx);
	chan_destroy(c);
}
