/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Standalone deterministic fuzz driver for xchan_frame_validate.
 *
 * clang is not available on every build host, so the libFuzzer target in
 * fuzz_frame.c cannot always be compiled there. This driver gives the
 * validator equivalent randomised-input coverage using nothing but a
 * seeded PRNG and plain gcc, built with -fsanitize=address,undefined so
 * memory-safety and undefined-behaviour bugs still abort loudly.
 *
 * The oracle is identical to fuzz_frame.c: xchan_frame_validate() must
 * only ever return 0, -EINVAL or -EMSGSIZE. Anything else is a bug and
 * aborts the process immediately, printing the offending input first.
 *
 * Usage: fuzz_frame_standalone [iterations] [seed]
 *   iterations - number of random frames to try (default 1000000)
 *   seed       - PRNG seed, for reproducing a run (default: time-based)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/xchan_frame.h"

/* xorshift64* - small, fast, deterministic given a seed. */
static uint64_t rng_state;

static uint64_t next_rand(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return rng_state * 0x2545F4914F6CDD1DULL;
}

/*
 * Generate a flags value with heavy weight on the 8 low-bit combinations (0..7
 * spans every combination of WINDOW_REF, RELEASE and MORE), so every
 * combination, including the ones the validator specifically rejects
 * (RELEASE|WINDOW_REF together, RELEASE with a payload), gets frequent,
 * roughly-uniform coverage. XCHAN_F_ABORT (bit 3) is only reached through the
 * raw-noise draws. flags must NOT be generated with the window_id-tuned
 * biased_u32() helper below: each of that helper's boundary constants (15, 16,
 * 17) is rejected by one of the validator's first checks, 15 sets RELEASE
 * and WINDOW_REF together, 16 and 17 set an unknown bit, so reusing it for
 * flags starves the later, most security-relevant branches in the validator.
 * A separate draw occasionally substitutes raw 16-bit noise so the
 * "reject unknown bits" fail-closed path still gets exercised too.
 */
static __u16 gen_flags(void)
{
	uint64_t pick = next_rand();

	/* ~1/8 of draws: raw noise, almost always sets some bit >= 4,
	 * exercising the fail-closed "unknown flags" rejection path. */
	if ((pick & 0x7) == 0)
		return (__u16)(next_rand() & 0xFFFFu);

	/* Otherwise: uniform pick across all 8 combinations of the three low
	 * flag bits, valid and invalid alike. */
	return (__u16)(next_rand() % 8);
}

/*
 * Return a random value with a bit-width of max_bits, but skew the
 * distribution toward the boundary values the validator actually branches
 * on (0, 1, the field's max, one below max, and values around
 * XCHAN_WINDOW_BUFS) so a run spends real time at the edges instead of
 * almost always landing in the uninteresting middle of the range.
 *
 * NOTE: this helper is tuned for window_id-shaped fields. Do not reuse it
 * for flags, see gen_flags() above for why that starves the flag checks.
 */
static uint32_t biased_u32(unsigned max_bits)
{
	uint64_t r = next_rand();
	uint64_t mask = (max_bits >= 64) ? ~0ULL : ((1ULL << max_bits) - 1);
	uint64_t v = r & mask;

	switch (r % 16) {
	case 0:
		return 0;
	case 1:
		return 1;
	case 2:
		return (uint32_t)mask;
	case 3:
		return (uint32_t)(mask - 1);
	case 4:
		return XCHAN_WINDOW_BUFS;
	case 5:
		return XCHAN_WINDOW_BUFS - 1;
	case 6:
		return XCHAN_WINDOW_BUFS + 1;
	default:
		return (uint32_t)v;
	}
}

int main(int argc, char **argv)
{
	unsigned long iterations = 1000000;
	unsigned long seed;
	unsigned long i;
	unsigned long count_ok = 0, count_einval = 0, count_emsgsize = 0;
	/* Coverage evidence: histogram of (flags & 0x7), plus a bucket for
	 * draws that set any bit >= 3 ("other": the raw-noise draws, ABORT
	 * included). */
	unsigned long flags_hist[8] = { 0 };
	unsigned long flags_other = 0;

	if (argc > 1)
		iterations = strtoul(argv[1], NULL, 0);

	if (argc > 2)
		seed = strtoul(argv[2], NULL, 0);
	else
		seed = (unsigned long)time(NULL);

	rng_state = seed ? (uint64_t)seed : 0xdeadbeefULL;

	for (i = 0; i < iterations; i++) {
		struct xchan_frame f;
		__u32 slice_size;
		__u32 dst_cap;
		int rc;

		memset(&f, 0, sizeof(f));
		f.seq = ((uint64_t)next_rand() << 32) | next_rand();
		f.len = biased_u32(32);
		f.flags = gen_flags();
		f.window_id = (__u16)biased_u32(16);

		slice_size = biased_u32(32);
		dst_cap = biased_u32(32);

		if (f.flags & ~0x7u)
			flags_other++;
		else
			flags_hist[f.flags & 0x7]++;

		rc = xchan_frame_validate(&f, slice_size, dst_cap);
		if (rc != 0 && rc != -EINVAL && rc != -EMSGSIZE) {
			fprintf(stderr,
				"FAIL iter=%lu seed=%lu rc=%d seq=%llu len=%u "
				"flags=0x%x window_id=%u slice_size=%u dst_cap=%u\n",
				i, seed, rc, (unsigned long long)f.seq, f.len,
				f.flags, f.window_id, slice_size, dst_cap);
			abort();
		}

		switch (rc) {
		case 0:
			count_ok++;
			break;
		case -EINVAL:
			count_einval++;
			break;
		default:
			count_emsgsize++;
			break;
		}
	}

	printf("fuzz_frame_standalone: iterations=%lu seed=%lu ok=%lu einval=%lu emsgsize=%lu no_oracle_violation=1 "
	       "flags_hist[0]=%lu [1]=%lu [2]=%lu [3]=%lu [4]=%lu [5]=%lu [6]=%lu [7]=%lu other=%lu\n",
	       iterations, seed, count_ok, count_einval, count_emsgsize,
	       flags_hist[0], flags_hist[1], flags_hist[2], flags_hist[3],
	       flags_hist[4], flags_hist[5], flags_hist[6], flags_hist[7],
	       flags_other);

	return 0;
}
