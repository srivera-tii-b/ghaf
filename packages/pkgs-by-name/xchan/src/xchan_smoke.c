// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0
//
// First-light smoke test for the virtio-xchan transport.
//
// Runs in both guests as a systemd service and reports to stdout, which the
// guest console carries into the host journal, deliberately no interactive
// login, no credentials, no network. Results land where they can be read
// without a shell in either VM.
//
//   listener  waits for a message, echoes it back
//   connector sends a ping, waits for the echo, reports the round trip
//
// Every step prints what it attempted before attempting it, so a hang is
// attributable to a specific call rather than to "it didn't work".
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "libxchan.h"
#include "xchan_uapi.h"

#define TAG "xchan-smoke: "

/* Largest single message this test asks for. No longer a property of the
 * transport: there is no window any more (it cannot be mapped into a second
 * protected guest under pKVM), so a message is a chain of 4 KiB inline
 * fragments and has no mechanism-imposed ceiling. Kept at 8 MiB because that
 * is what the previous sweep topped out at, so a regression in throughput at
 * the old ceiling is still visible. */
#define MAX_PAYLOAD (8u * 1024u * 1024u)

/* XCHAN_INLINE_MAX. Not included from the driver's private header (it is not
 * exported through the UAPI), so stated here and pinned by the 4096/4097 pair
 * below, if the driver's value ever changes, those two sizes stop
 * straddling anything and this comment is the thing to fix. */
#define INLINE_MAX 4096u

/* Straddles the one boundary that still exists, a single frame versus a
 * fragmented chain, rather than sampling evenly. 4096 is the largest
 * message that fits in one frame; 4097 is the smallest that does not, so it
 * is the first size that exercises XCHAN_F_MORE, reassembly, and the
 * byte-identity check below across a fragment seam. The old 512 KiB
 * "exactly one window buffer" point is gone with the window; 1 MiB replaces
 * it as the size that is exactly one full tx ring of fragments (256 frames
 * at 4 KiB), which is where a driver that failed to wait for ring room would
 * break. */
static const size_t sweep_sizes[] = {
	64u,
	1024u,
	INLINE_MAX,           /* largest single-frame message */
	INLINE_MAX + 1u,      /* smallest fragmented message: 2 frames */
	16u * 1024u,          /* 4 frames, the size that died on hardware */
	1024u * 1024u,        /* 256 frames: one full tx ring */
	MAX_PAYLOAD,          /* 2048 frames */
};
#define SWEEP_N (sizeof(sweep_sizes) / sizeof(sweep_sizes[0]))

/*
 * Deterministic payload pattern. Period 251 (prime, and not a divisor of
 * either 4096 or any sweep size), so a fragment delivered out of order,
 * duplicated, dropped, or reassembled at the wrong offset changes the bytes,
 * which is exactly the failure mode inline fragmentation introduces and
 * which a memset() of one repeated byte cannot see. The previous version of
 * this test filled the buffer with 'x' and compared only the LENGTH of the
 * echo, so every one of those faults would have been reported as a pass.
 */
static void fill_pattern(unsigned char *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (unsigned char)(i % 251u);
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static uint64_t now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

int main(int argc, char **argv)
{
	const char *role = (argc > 1) ? argv[1] : "";
	int is_listener = (strcmp(role, "listener") == 0);
	int iterations = (argc > 2) ? atoi(argv[2]) : 10;
	/* 0 would spin the sweep continuously and swamp the journal. */
	unsigned repeat_s = (argc > 3) ? (unsigned)atoi(argv[3]) : 60u;
	struct xchan_channel_info info;
	char *buf;
	/* Separate from `buf` on purpose: the echo is received INTO buf, so a
	 * reference the send came from is the only thing left to compare it
	 * against. Sending straight out of ref also means a send that reads
	 * past its length would be reading known bytes, not the previous
	 * reply's. */
	unsigned char *ref;
	size_t bufcap = MAX_PAYLOAD;
	int devfd, chanfd;
	ssize_t n;

	setvbuf(stdout, NULL, _IOLBF, 0);

	if (!is_listener && strcmp(role, "connector") != 0) {
		fprintf(stderr, TAG "usage: xchan-smoke listener|connector [iterations] [repeat_seconds]\n");
		return 2;
	}
	if (iterations < 1)
		iterations = 1;
	if (repeat_s < 1)
		repeat_s = 1;
	buf = malloc(bufcap);
	ref = malloc(bufcap);
	if (!buf || !ref) {
		printf(TAG "FAIL alloc %zu bytes\n", bufcap);
		return 1;
	}
	memset(buf, 0, bufcap);
	fill_pattern(ref, bufcap);

	printf(TAG "role=%s starting\n", role);

	printf(TAG "opening device...\n");
	devfd = xchan_open(NULL);
	if (devfd < 0) {
		printf(TAG "FAIL open: %s\n", strerror(errno));
		return 1;
	}
	printf(TAG "OK device opened (fd=%d)\n", devfd);

	printf(TAG "waiting for a channel (blocks until the peer attaches)...\n");
	memset(&info, 0, sizeof(info));
	chanfd = xchan_wait_channel(devfd, &info);
	if (chanfd < 0) {
		printf(TAG "FAIL wait_channel: %s\n", strerror(errno));
		return 1;
	}
	printf(TAG "OK channel: id=%u flags=0x%x window_slice_size=%llu\n",
	       info.channel_id, info.flags,
	       (unsigned long long)info.window_slice_size);

	if (is_listener) {
		unsigned long served = 0;

		// Serve indefinitely rather than echoing once and exiting. A
		// connector that runs later, a manual invocation, a repeat
		// measurement, needs a peer still holding the channel: once
		// this process closes its fd the channel closes and the next
		// client has nothing to talk to.
		printf(TAG "serving echoes (one line per 100)...\n");
		for (;;) {
			n = xchan_recv(chanfd, buf, bufcap);
			if (n < 0) {
				printf(TAG "FAIL recv after %lu: %s\n",
				       served, strerror(errno));
				return 1;
			}
			if (xchan_send(chanfd, buf, (size_t)n) < 0) {
				printf(TAG "FAIL echo send after %lu: %s\n",
				       served, strerror(errno));
				return 1;
			}
			if (served == 0)
				printf(TAG "RESULT listener: PASS (first echo, %zd bytes)\n", n);
			served++;
			if (served % 100 == 0)
				printf(TAG "served %lu echoes\n", served);
		}
	} else {
		unsigned long pass = 0;

		// Long-lived on purpose. A one-shot connector closes its channel
		// fd on exit, and a slot is only freed once the guest has closed
		// AND the peer has detached, so with a long-lived listener the
		// slot is trapped and no later connector can ever attach. Holding
		// the channel and looping sidesteps that entirely, and makes the
		// boot run and an on-demand run the same code path.
		for (;;) {
			size_t si;

			pass++;
			for (si = 0; si < SWEEP_N; si++) {
				size_t len = sweep_sizes[si];
				uint64_t *rt = calloc((size_t)iterations, sizeof(*rt));
				uint64_t bytes_total = 0, span_us;
				int i, failed = 0;

				if (!rt) {
					printf(TAG "FAIL alloc stats\n");
					return 1;
				}

				// Unmeasured warm-up at each size: the first message of a
				// new size pays first-touch costs the steady state does
				// not, and folding that in is how a 102ms "latency" gets
				// reported for a path that is not slow.
				if (xchan_send(chanfd, ref, len) < 0 ||
				    xchan_recv(chanfd, buf, bufcap) < 0) {
					printf(TAG "FAIL warm-up at %zu bytes: %s\n",
					       len, strerror(errno));
					free(rt);
					return 1;
				}

				span_us = now_us();
				for (i = 0; i < iterations; i++) {
					uint64_t t0 = now_us();

					memset(buf, 0, len);
					if (xchan_send(chanfd, ref, len) < 0) {
						printf(TAG "FAIL send %zu bytes at %d: %s\n",
						       len, i, strerror(errno));
						failed = 1;
						break;
					}
					n = xchan_recv(chanfd, buf, bufcap);
					rt[i] = now_us() - t0;
					if (n < 0) {
						printf(TAG "FAIL recv %zu bytes at %d: %s\n",
						       len, i, strerror(errno));
						failed = 1;
						break;
					}
					if ((size_t)n != len) {
						printf(TAG "FAIL echo size %zu != %zu at %d\n",
						       (size_t)n, len, i);
						failed = 1;
						break;
					}
					// The check the length comparison above cannot make:
					// every message over 4096 bytes is now a chain of
					// fragments reassembled by the peer's driver, so a
					// fragment lost, duplicated, reordered or written at the
					// wrong offset produces an echo of exactly the right
					// LENGTH and the wrong CONTENT. Report the first
					// differing byte, which localises the fault to a
					// fragment index (offset / 4096) instead of just
					// asserting "corrupt".
					if (memcmp(buf, ref, len) != 0) {
						size_t off = 0;

						while (off < len &&
						       (unsigned char)buf[off] == ref[off])
							off++;
						printf(TAG "FAIL echo content at %zu bytes, iter %d: "
						       "first mismatch at offset %zu "
						       "(fragment %zu): got 0x%02x want 0x%02x\n",
						       len, i, off, off / INLINE_MAX,
						       (unsigned char)buf[off], ref[off]);
						failed = 1;
						break;
					}
					bytes_total += (uint64_t)len * 2; // there and back
				}
				span_us = now_us() - span_us;

				if (failed) {
					free(rt);
					return 1;
				}

				qsort(rt, (size_t)iterations, sizeof(*rt), cmp_u64);
				// Throughput counts bytes moved in BOTH directions over the
				// whole measured span, so it is the round-trip figure, not a
				// one-way send rate. Stated here because the two differ by 2x
				// and an unlabelled number invites the wrong reading.
				printf(TAG "STATS pass=%lu bytes=%zu n=%d "
				       "min=%llu us median=%llu us max=%llu us "
				       "rtt_MBps=%.1f\n",
				       pass, len, iterations,
				       (unsigned long long)rt[0],
				       (unsigned long long)rt[iterations / 2],
				       (unsigned long long)rt[iterations - 1],
				       span_us ? (double)bytes_total / (double)span_us : 0.0);
				free(rt);
			}

			if (pass == 1)
				printf(TAG "RESULT connector: PASS (swept %zu sizes)\n",
				       (size_t)SWEEP_N);
			sleep(repeat_s);
		}
	}

	close(chanfd);
	close(devfd);
	return 0;
}
