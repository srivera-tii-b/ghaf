// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: GPL-2.0-only
/*
 * pkvm-g2g-test: guest-to-guest shared memory end to end, from userspace, through
 * /dev/pkvm-g2g. Run it in two protected guests: one as owner, one as
 * borrower.
 *
 *   owner                                    borrower
 *   OFFER n zeroed pages to the peer
 *   mmap, check zero, write magic, nonce,
 *   ~nonce, and nonce^salt at the end
 *   MSG_SEND OFFERED(handle, n)       --->   MSG_RECV (EL2 names the sender)
 *                                            ACCEPT, mmap, check the nonce
 *                                            write reply, echo, ~reply, and
 *                                            reply^salt at the end
 *   MSG_RECV                          <---   MSG_SEND ACCEPTED(handle, verified)
 *   check the reply, in our own pages
 *   MSG_SEND CHECKED(handle, ok)      --->   MSG_RECV
 *                                            munmap, RELEASE, RELEASE again
 *   MSG_RECV                          <---   MSG_SEND RELEASED(handle, ok)
 *   munmap, REVOKE, REVOKE again
 *
 * Only the handle, a page count and verdicts travel in messages; the nonces
 * travel only through the shared pages. They are printed only with -v.
 *
 * Exit status: 0 PASS, 1 FAIL, 2 cannot run (no device, no identity, no
 * peer), 64 usage.
 *
 * Peers are named with the predictable boot-probe identity the guest kernel
 * registers ("probe-id", incarnation); see arm-pkvm-guest.c for why that is a
 * demonstration convenience and not a model.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include <linux/pkvm_g2g.h>

#define DEV_PATH	"/dev/pkvm-g2g"
#define PROBE_ID_LO	0x70726f62652d6964ULL	/* "probe-id" */
#define PAGE		4096UL
#define PEER_SWEEP	64

/* Payload word 0 of a message; word 1 is the handle, word 2 an argument. */
#define MSG_OFFERED	0x52464f2d55673267ULL	/* "g2gU-OFR" */
#define MSG_ACCEPTED	0x5043412d55673267ULL	/* "g2gU-ACP" */
#define MSG_CHECKED	0x4b48432d55673267ULL	/* "g2gU-CHK" */
#define MSG_RELEASED	0x444c522d55673267ULL	/* "g2gU-RLD" */
#define MSG_TAG		0x2174736574726573ULL	/* "sertest!": word 3 */

/* Page 0 of a share; the last 16 bytes of the share carry the salted copies. */
#define PAGE_MAGIC	0x5245535553673267ULL	/* "g2gSUSER" */
#define PAGE_REPLY	0x594c504555673267ULL	/* "g2gUEPLY" */
#define PAGE_SALT	0x5a5a5a5a5a5a5a5aULL
struct test_page {
	uint64_t magic, nonce, check;			/* written by the owner */
	uint64_t reply_magic, echo, reply, reply_check;	/* written by the borrower */
};

#ifdef PKVM_G2G_TEST_SIM
#include "sim_ops.h"
#define main test_main
#else
static int dev_open(void)
{
	return open(DEV_PATH, O_RDWR | O_CLOEXEC);
}

static int dev_ioctl(int fd, unsigned long cmd, void *arg)
{
	return ioctl(fd, cmd, arg);
}

static void *dev_mmap(int fd, size_t len, int prot, uint64_t off)
{
	return mmap(NULL, len, prot, MAP_SHARED, fd, (off_t)off);
}

static int dev_munmap(void *p, size_t len)
{
	return munmap(p, len);
}

static void dev_close(int fd)
{
	close(fd);
}
#endif

struct ctx {
	const char *role;
	int fd;
	int verbose;
	unsigned int timeout_s;
	struct pkvm_g2g_ident self;
	unsigned int failed, foreign;
};

static void say(struct ctx *c, const char *fmt, ...)
{
	char line[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	printf("pkvm-g2g-test: %s: %s\n", c->role, line);
	fflush(stdout);
}

static void fail(struct ctx *c, const char *fmt, ...)
{
	char line[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	printf("pkvm-g2g-test: %s: FAIL: %s\n", c->role, line);
	fflush(stdout);
	c->failed++;
}

#define CHECK(c, cond, ...) do { if (!(cond)) fail(c, __VA_ARGS__); } while (0)

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static void nap(void)
{
	struct timespec t = { 0, 20 * 1000 * 1000 };

	nanosleep(&t, NULL);
}

static uint64_t rnd64(void)
{
	uint64_t v = 0;

	if (getrandom(&v, sizeof(v), 0) != sizeof(v)) {
		perror("getrandom");
		exit(2);
	}
	return v;
}

static const char *msg_name(uint64_t type)
{
	switch (type) {
	case MSG_OFFERED:	return "OFFERED";
	case MSG_ACCEPTED:	return "ACCEPTED";
	case MSG_CHECKED:	return "CHECKED";
	case MSG_RELEASED:	return "RELEASED";
	default:		return "an unknown message";
	}
}

static int same_name(const struct pkvm_g2g_ident *a, const struct pkvm_g2g_ident *b)
{
	return a->id_lo == b->id_lo && a->id_hi == b->id_hi;
}

static int send_msg(struct ctx *c, const struct pkvm_g2g_ident *to, uint64_t type,
		    uint64_t handle, uint64_t arg)
{
	struct pkvm_g2g_msg m = { .peer = *to, .payload = { type, handle, arg, MSG_TAG } };
	double end = now() + c->timeout_s;

	for (;;) {
		if (!dev_ioctl(c->fd, PKVM_G2G_IOC_MSG_SEND, &m))
			return 0;
		if (errno != EAGAIN || now() > end) {	/* EAGAIN: the peer's mailbox is full */
			fail(c, "MSG_SEND %s to incarnation %llu: %s", msg_name(type),
			     (unsigned long long)to->incarnation, strerror(errno));
			return -1;
		}
		nap();
	}
}

/*
 * Wait for a @type message about @handle (0: any) from a VM called @from
 * (NULL: anyone). Anything else is dropped - but note that it is gone from the
 * mailbox, which has one slot and one reader.
 */
static int recv_msg(struct ctx *c, const struct pkvm_g2g_ident *from, uint64_t type,
		    uint64_t handle, struct pkvm_g2g_msg *out)
{
	double end = now() + c->timeout_s;
	struct pkvm_g2g_msg m;

	for (;;) {
		if (now() > end) {
			fail(c, "no %s within %u s", msg_name(type), c->timeout_s);
			return -1;
		}
		memset(&m, 0, sizeof(m));
		if (dev_ioctl(c->fd, PKVM_G2G_IOC_MSG_RECV, &m)) {
			if (errno != EAGAIN) {	/* EAGAIN: the mailbox is empty */
				fail(c, "MSG_RECV: %s", strerror(errno));
				return -1;
			}
			nap();
			continue;
		}
		if (m.payload[3] != MSG_TAG || (from && !same_name(&m.peer, from))) {
			if (!c->foreign++)
				say(c, "dropped a message from incarnation %llu that is not this test's (is the in-kernel ping/share test still running? wait for 'pkvm-g2g: share: finished' in dmesg)",
				    (unsigned long long)m.peer.incarnation);
			continue;
		}
		if (m.payload[0] != type || (handle && m.payload[1] != handle)) {
			c->foreign++;
			say(c, "dropped %s for handle %#llx while waiting for %s", msg_name(m.payload[0]),
			    (unsigned long long)m.payload[1], msg_name(type));
			continue;
		}
		*out = m;
		return 0;
	}
}

static int resolve_peer(struct ctx *c, int argc, char **argv, struct pkvm_g2g_ident *peer)
{
	struct pkvm_g2g_ident id;
	unsigned int i, n = 0;

	if (!strcmp(argv[0], "auto")) {
		for (i = 1; i <= PEER_SWEEP; i++) {
			if (c->self.id_lo == PROBE_ID_LO && c->self.id_hi == i)
				continue;
			id = (struct pkvm_g2g_ident){ .id_lo = PROBE_ID_LO, .id_hi = i };
			if (dev_ioctl(c->fd, PKVM_G2G_IOC_LOOKUP, &id) || !id.incarnation)
				continue;
			say(c, "live peer: identity %#llx:%#llx, incarnation %llu",
			    (unsigned long long)id.id_hi, (unsigned long long)id.id_lo,
			    (unsigned long long)id.incarnation);
			if (!n++)
				*peer = id;
		}
		if (n != 1) {
			say(c, "found %u live peer(s) named probe-id:1..%u; name the one to use", n, PEER_SWEEP);
			return -1;
		}
		return 0;
	}

	id = (struct pkvm_g2g_ident){
		.id_hi = strtoull(argv[0], NULL, 0),
		.id_lo = argc > 1 ? strtoull(argv[1], NULL, 0) : PROBE_ID_LO,
	};
	if (dev_ioctl(c->fd, PKVM_G2G_IOC_LOOKUP, &id)) {
		say(c, "LOOKUP %#llx:%#llx: %s", (unsigned long long)id.id_hi,
		    (unsigned long long)id.id_lo, strerror(errno));
		return -1;
	}
	if (!id.incarnation) {
		say(c, "no live protected VM is called %#llx:%#llx", (unsigned long long)id.id_hi,
		    (unsigned long long)id.id_lo);
		return -1;
	}
	*peer = id;
	return 0;
}

static int run_owner(struct ctx *c, int argc, char **argv, unsigned long nr)
{
	struct pkvm_g2g_ident peer;
	struct pkvm_g2g_offer o;
	struct pkvm_g2g_end e;
	struct pkvm_g2g_msg m;
	volatile struct test_page *pg;
	volatile uint64_t *tail, *w;
	size_t len = nr * PAGE, i;
	uint64_t nonce, reply;
	int ok = 0;
	void *p;

	if (resolve_peer(c, argc, argv, &peer))
		return 2;

	o = (struct pkvm_g2g_offer){ .peer = peer, .nr_pages = nr };
	if (dev_ioctl(c->fd, PKVM_G2G_IOC_OFFER, &o)) {
		fail(c, "OFFER of %lu page(s) to incarnation %llu: %s", nr,
		     (unsigned long long)peer.incarnation, strerror(errno));
		return 1;
	}
	say(c, "offered %lu page(s) to incarnation %llu: handle %#llx, mmap offset %#llx", nr,
	    (unsigned long long)peer.incarnation, (unsigned long long)o.handle,
	    (unsigned long long)o.mmap_offset);

	p = dev_mmap(c->fd, PAGE, PROT_READ, o.mmap_offset + len);
	CHECK(c, p == MAP_FAILED && errno == EINVAL, "mapping a page past the share's end: %s",
	      p == MAP_FAILED ? strerror(errno) : "it worked");
	if (p != MAP_FAILED)
		dev_munmap(p, PAGE);

	p = dev_mmap(c->fd, len, PROT_READ | PROT_WRITE, o.mmap_offset);
	if (p == MAP_FAILED) {
		fail(c, "mmap of our offer: %s", strerror(errno));
		goto revoke;
	}
	w = p;
	for (i = 0; i < len / 8; i++)
		if (w[i]) {
			fail(c, "the offered pages are not zeroed (word %zu)", i);
			break;
		}

	pg = p;
	tail = (volatile uint64_t *)((char *)p + len - 16);
	nonce = rnd64();
	pg->magic = PAGE_MAGIC;
	pg->nonce = nonce;
	pg->check = ~nonce;
	tail[0] = nonce ^ PAGE_SALT;
	__sync_synchronize();
	if (c->verbose)
		say(c, "wrote nonce %016llx", (unsigned long long)nonce);

	if (send_msg(c, &peer, MSG_OFFERED, o.handle, nr) ||
	    recv_msg(c, &peer, MSG_ACCEPTED, o.handle, &m))
		goto unmap;
	CHECK(c, m.payload[2] == 1, "the borrower did not find our nonce in its window");

	__sync_synchronize();
	reply = pg->reply;
	ok = m.payload[2] == 1 && pg->reply_magic == PAGE_REPLY && pg->echo == nonce &&
	     pg->reply_check == ~reply && tail[1] == (reply ^ PAGE_SALT);
	CHECK(c, ok, "no valid reply from the borrower in our pages");
	if (ok) {
		if (c->verbose)
			say(c, "read reply %016llx", (unsigned long long)reply);
		say(c, "the borrower read our nonce through its window and wrote a reply we read in our own pages: data crossed both ways");
	}

	if (send_msg(c, &peer, MSG_CHECKED, o.handle, ok) ||
	    recv_msg(c, &peer, MSG_RELEASED, o.handle, &m))
		goto unmap;
	CHECK(c, m.payload[2] == 1, "the borrower's RELEASE failed");
	CHECK(c, pg->magic == PAGE_MAGIC, "our pages changed after the borrower released them");

unmap:
	dev_munmap(p, len);
revoke:
	e = (struct pkvm_g2g_end){ .handle = o.handle };
	if (dev_ioctl(c->fd, PKVM_G2G_IOC_REVOKE, &e))
		fail(c, "REVOKE: %s", strerror(errno));
	else
		say(c, "REVOKE: the pages are ours alone again, and freed");
	CHECK(c, dev_ioctl(c->fd, PKVM_G2G_IOC_REVOKE, &e) && errno == EINVAL,
	      "a second REVOKE of the same handle did not fail with EINVAL");

	return c->failed ? 1 : 0;
}

static int run_borrower(struct ctx *c, int argc, char **argv)
{
	struct pkvm_g2g_ident want, owner;
	struct pkvm_g2g_accept a;
	struct pkvm_g2g_end e;
	struct pkvm_g2g_msg m;
	volatile struct test_page *pg;
	volatile uint64_t *tail;
	uint64_t handle, nr, nonce, reply;
	int verified = 0, released = 0;
	size_t len;
	void *p;

	if (argc > 0)
		want = (struct pkvm_g2g_ident){
			.id_hi = strtoull(argv[0], NULL, 0),
			.id_lo = argc > 1 ? strtoull(argv[1], NULL, 0) : PROBE_ID_LO,
		};
	if (recv_msg(c, argc > 0 ? &want : NULL, MSG_OFFERED, 0, &m))
		return 1;
	owner = m.peer;
	handle = m.payload[1];
	nr = m.payload[2];
	len = nr * PAGE;
	say(c, "incarnation %llu (identity %#llx:%#llx) offers %llu page(s), handle %#llx",
	    (unsigned long long)owner.incarnation, (unsigned long long)owner.id_hi,
	    (unsigned long long)owner.id_lo, (unsigned long long)nr, (unsigned long long)handle);

	a = (struct pkvm_g2g_accept){ .owner = owner, .handle = handle, .nr_pages = nr };
	if (dev_ioctl(c->fd, PKVM_G2G_IOC_ACCEPT, &a)) {
		fail(c, "ACCEPT: %s", strerror(errno));
		goto tell;
	}
	say(c, "accepted into a window: flags %#llx, mmap offset %#llx",
	    (unsigned long long)a.flags, (unsigned long long)a.mmap_offset);

	p = dev_mmap(c->fd, PAGE, PROT_READ | PROT_EXEC, a.mmap_offset);
	CHECK(c, p == MAP_FAILED && errno == EACCES, "an executable mapping of a borrowed share: %s",
	      p == MAP_FAILED ? strerror(errno) : "it worked");
	if (p != MAP_FAILED)
		dev_munmap(p, PAGE);

	p = dev_mmap(c->fd, len, PROT_READ | PROT_WRITE, a.mmap_offset);
	if (p == MAP_FAILED) {
		fail(c, "mmap of the window: %s", strerror(errno));
		goto release;
	}
	pg = p;
	tail = (volatile uint64_t *)((char *)p + len - 16);
	__sync_synchronize();
	nonce = pg->nonce;
	verified = pg->magic == PAGE_MAGIC && pg->check == ~nonce && tail[0] == (nonce ^ PAGE_SALT);
	CHECK(c, verified, "no valid nonce in the owner's pages");
	if (verified) {
		reply = rnd64();
		pg->reply_magic = PAGE_REPLY;
		pg->echo = nonce;
		pg->reply = reply;
		pg->reply_check = ~reply;
		tail[1] = reply ^ PAGE_SALT;
		__sync_synchronize();
		if (c->verbose)
			say(c, "read nonce %016llx, wrote reply %016llx", (unsigned long long)nonce,
			    (unsigned long long)reply);
		say(c, "read the owner's nonce in its pages and wrote a reply beside it");
	}
	if (!send_msg(c, &owner, MSG_ACCEPTED, handle, verified) &&
	    !recv_msg(c, &owner, MSG_CHECKED, handle, &m))
		CHECK(c, m.payload[2] == 1, "the owner did not find our reply in its pages");
	/* Never touch the window again. */
	dev_munmap(p, len);

release:
	e = (struct pkvm_g2g_end){ .handle = handle };
	released = !dev_ioctl(c->fd, PKVM_G2G_IOC_RELEASE, &e);
	if (released)
		say(c, "RELEASE: the pages left our address space");
	else
		fail(c, "RELEASE: %s", strerror(errno));
	CHECK(c, dev_ioctl(c->fd, PKVM_G2G_IOC_RELEASE, &e) && errno == EINVAL,
	      "a second RELEASE of the same handle did not fail with EINVAL");
	send_msg(c, &owner, MSG_RELEASED, handle, released);
	return c->failed ? 1 : 0;

tell:
	/* Let the owner finish: say we could not, then wait for its verdict. */
	if (!send_msg(c, &owner, MSG_ACCEPTED, handle, 0))
		recv_msg(c, &owner, MSG_CHECKED, handle, &m);
	send_msg(c, &owner, MSG_RELEASED, handle, 0);
	return 1;
}

static int usage(void)
{
	fprintf(stderr,
		"usage: pkvm-g2g-test self\n"
		"       pkvm-g2g-test owner [-v] [-n pages] [-t seconds] auto | <peer-id-hi> [<peer-id-lo>]\n"
		"       pkvm-g2g-test borrower [-v] [-t seconds] [<owner-id-hi> [<owner-id-lo>]]\n"
		"pages: 1..%d (default 2); seconds: per wait (default 300); id-lo defaults to \"probe-id\"\n",
		PKVM_G2G_MAX_PAGES);
	return 64;
}

int main(int argc, char **argv)
{
	struct ctx c = { .timeout_s = 300 };
	unsigned long nr = 2;
	int i = 2, ret;

	if (argc < 2)
		return usage();
	c.role = argv[1];
	if (strcmp(c.role, "self") && strcmp(c.role, "owner") && strcmp(c.role, "borrower"))
		return usage();
	for (; i < argc && argv[i][0] == '-'; i++) {
		if (!strcmp(argv[i], "-v"))
			c.verbose = 1;
		else if (!strcmp(argv[i], "-n") && i + 1 < argc)
			nr = strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "-t") && i + 1 < argc)
			c.timeout_s = strtoul(argv[++i], NULL, 0);
		else
			return usage();
	}
	if (nr < 1 || nr > PKVM_G2G_MAX_PAGES || (!strcmp(c.role, "owner") && i == argc))
		return usage();

	c.fd = dev_open();
	if (c.fd < 0) {
		fprintf(stderr, "pkvm-g2g-test: cannot open %s: %s\n"
			"  (it needs a guest kernel with CONFIG_PKVM_GUEST_TO_GUEST on a hypervisor that advertises the guest-to-guest calls, and root)\n",
			DEV_PATH, strerror(errno));
		return 2;
	}
	if (dev_ioctl(c.fd, PKVM_G2G_IOC_SELF, &c.self)) {
		fprintf(stderr, "pkvm-g2g-test: SELF: %s\n", strerror(errno));
		dev_close(c.fd);
		return 2;
	}
	say(&c, "this VM: identity %#llx:%#llx, incarnation %llu", (unsigned long long)c.self.id_hi,
	    (unsigned long long)c.self.id_lo, (unsigned long long)c.self.incarnation);
	if (!c.self.id_lo && !c.self.id_hi) {
		say(&c, "this VM has no identity (a guest kernel with CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST registers one at boot)");
		dev_close(c.fd);
		return 2;
	}
	if (!strcmp(c.role, "self")) {
		dev_close(c.fd);
		return 0;
	}

	if (!strcmp(c.role, "owner"))
		ret = run_owner(&c, argc - i, argv + i, nr);
	else
		ret = run_borrower(&c, argc - i, argv + i);
	dev_close(c.fd);

	if (ret == 2)
		say(&c, "cannot run");
	else
		say(&c, "%s (%u failed check(s), %u foreign message(s) dropped)",
		    ret ? "FAIL" : "PASS", c.failed, c.foreign);
	return ret;
}
