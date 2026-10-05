// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0
/*
 * g2gc-echo: byte-exact streaming over g2gchan between two guests, for the
 * board: what the simulator cannot show is whether two guests' mappings of
 * the same pages stay coherent under load.
 *
 *   g2gc-echo server                      echo every message back, until the client closes
 *   g2gc-echo client <id-hi> [rounds]     send 0 B .. 1 MiB+3 (fragmented), compare every byte
 *   g2gc-echo vanish <id-hi>              send 1 MiB+3, then exit at once without closing: the
 *                                         server's reads of the vanished share then fault (on the
 *                                         board, an abort the host injects), and it must end cleanly
 *
 * One g2gchan process per VM: stop any other program using g2gchan first.
 * Exit: 0 every byte matched (the server: the client went away), 1 a mismatch
 * or a channel error, 2 usage/setup.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "g2gchan.h"
#include "g2gc_internal.h"	/* g2gc_fault_count */
#ifdef G2GC_ECHO_NO_MAIN
#include "g2gc_dev.h"		/* the simulator's dev_close() */
#endif

#define CAP	((2u << 20) + 64)

static const size_t sizes[] = { 0, 1, 100, 4095, 65535, 65536, 65537, 3 * 65536 + 7,
				(1u << 20) - 1, (1u << 20), (1u << 20) + 3 };

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void fill(unsigned char *p, size_t n, uint32_t seed)
{
	uint32_t x = seed * 2654435761u + 1;
	size_t i;

	for (i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		p[i] = (unsigned char)x;
	}
}

#define NSIZES	(sizeof(sizes) / sizeof(sizes[0]))

static int cmp_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return x < y ? -1 : x > y;
}

/* This process's CPU so far: what polling instead of a doorbell costs. */
static void report_cpu(const char *who, double wall)
{
	struct rusage ru;

	if (getrusage(RUSAGE_SELF, &ru))
		return;
	printf("g2gc-echo: %s: cpu user %.2f s, sys %.2f s over %.2f s\n", who,
	       ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6,
	       ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6, wall);
}

static int server(void)
{
	g2gc_listener_t *l = g2gc_listen();
	unsigned char *buf = malloc(CAP);
	unsigned long msgs = 0;
	double t0 = now_s();
	g2gc_t *c;

	if (!l || !buf) {
		printf("g2gc-echo: server: %s\n", strerror(errno));
		return 2;
	}
	printf("g2gc-echo: server: waiting for a client\n");
	fflush(stdout);
	c = g2gc_accept(l, -1);
	if (!c) {
		printf("g2gc-echo: server: accept: %s\n", strerror(errno));
		return 2;
	}
	for (;;) {
		ssize_t n = g2gc_recv(c, buf, CAP);

		/* The client going away ends a recv or the echo's send alike. */
		if (n >= 0 && g2gc_send(c, buf, (size_t)n) != n)
			n = -1;
		if (n < 0) {
			int e = errno;

			printf("g2gc-echo: server: %lu message(s) echoed, then %s (%lu faulted read(s))\n",
			       msgs, e == ECONNRESET ? "the client went away" : strerror(e),
			       __atomic_load_n(&g2gc_fault_count, __ATOMIC_RELAXED));
			report_cpu("server", now_s() - t0);
			g2gc_close(c);
			g2gc_listener_close(l);
			free(buf);
			return e == ECONNRESET ? 0 : 1;
		}
		msgs++;
	}
}

static int client(uint64_t hi, int rounds)
{
	unsigned char *out = malloc(CAP), *in = malloc(CAP);
	double *rtt = calloc(NSIZES * (size_t)rounds, sizeof(*rtt));
	unsigned long bytes = 0, msgs = 0, bad = 0;
	double t0, wall;
	g2gc_t *c;
	int r;
	size_t i;

	if (!out || !in || !rtt)
		return 2;
	c = g2gc_connect(hi, G2GC_PROBE_ID_LO, 10000);
	if (!c) {
		printf("g2gc-echo: client: connect to 0x%llx: %s\n", (unsigned long long)hi, strerror(errno));
		return 2;
	}
	t0 = now_s();
	for (r = 0; r < rounds; r++) {
		for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
			size_t len = sizes[i];
			ssize_t n;
			double ts;

			fill(out, len, (uint32_t)(r * 64 + i));
			ts = now_s();
			if (g2gc_send(c, out, len) != (ssize_t)len) {
				printf("g2gc-echo: client: send %zu B: %s\n", len, strerror(errno));
				g2gc_close(c);
				return 1;
			}
			n = g2gc_recv(c, in, CAP);
			rtt[i * (size_t)rounds + r] = (now_s() - ts) * 1e6;
			if (n != (ssize_t)len) {
				printf("g2gc-echo: client: echo of %zu B came back as %zd (%s)\n", len, n,
				       n < 0 ? strerror(errno) : "wrong length");
				g2gc_close(c);
				return 1;
			}
			if (memcmp(in, out, len)) {
				size_t k = 0;

				while (in[k] == out[k])
					k++;
				printf("g2gc-echo: client: MISMATCH in round %d, %zu B message, first at byte %zu\n",
				       r, len, k);
				bad++;
			}
			bytes += 2 * len;
			msgs += 2;
		}
	}
	wall = now_s() - t0;
	/* Round trip = send + the echo back, per message size, in microseconds. */
	for (i = 0; i < NSIZES; i++) {
		double *v = rtt + i * (size_t)rounds;

		qsort(v, (size_t)rounds, sizeof(*v), cmp_double);
		printf("g2gc-echo: client: rtt %zu B: median %.0f us, min %.0f us, max %.0f us\n",
		       sizes[i], v[rounds / 2], v[0], v[rounds - 1]);
	}
	printf("g2gc-echo: client: %.1f MB/s both ways\n", wall > 0 ? bytes / wall / 1e6 : 0.0);
	report_cpu("client", wall);
	printf("g2gc-echo: client: %s (%lu message(s), %lu byte(s) both ways in %.2f s, %lu mismatch(es))\n",
	       bad ? "FAIL" : "PASS", msgs, bytes, wall, bad);
	g2gc_close(c);
	free(out);
	free(in);
	free(rtt);
	return bad ? 1 : 0;
}

/* Send 1 MiB+3, then die without g2gc_close(). */
static int vanish(uint64_t hi)
{
	size_t len = (1u << 20) + 3;
	unsigned char *out = malloc(len);
	g2gc_t *c = g2gc_connect(hi, G2GC_PROBE_ID_LO, 10000);

	if (!out || !c) {
		printf("g2gc-echo: vanish: connect to 0x%llx: %s\n", (unsigned long long)hi, strerror(errno));
		return 2;
	}
	fill(out, len, 7);
	if (g2gc_send(c, out, len) != (ssize_t)len) {
		printf("g2gc-echo: vanish: send: %s\n", strerror(errno));
		return 1;
	}
	printf("g2gc-echo: vanish: 1 MiB+3 sent, exiting without closing\n");
	fflush(stdout);
#ifdef G2GC_ECHO_NO_MAIN
	/* The simulator is one process: dying is the device file closing, as the
	 * kernel closes it at exit, which ends both shares at once. */
	dev_close(((struct g2gc *)c)->fd);
	free(out);
	return 0;
#else
	_exit(0);
#endif
}

#ifdef G2GC_ECHO_NO_MAIN
int echo_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc == 2 && !strcmp(argv[1], "server"))
		return server();
	if ((argc == 3 || argc == 4) && !strcmp(argv[1], "client")) {
		char *end;
		uint64_t hi = strtoull(argv[2], &end, 0);
		int rounds = argc == 4 ? atoi(argv[3]) : 20;

		if (*end || !hi || rounds < 1) {
			printf("g2gc-echo: bad arguments\n");
			return 2;
		}
		return client(hi, rounds);
	}
	if (argc == 3 && !strcmp(argv[1], "vanish")) {
		char *end;
		uint64_t hi = strtoull(argv[2], &end, 0);

		if (*end || !hi) {
			printf("g2gc-echo: bad arguments\n");
			return 2;
		}
		return vanish(hi);
	}
	printf("usage: %s server | client <server id-hi> [rounds, default 20] | vanish <server id-hi>\n",
	       argv[0]);
	return 2;
}
