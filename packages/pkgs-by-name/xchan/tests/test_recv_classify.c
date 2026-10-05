/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * *** LIMITATION, STATED UP FRONT SO IT CANNOT BE MISTAKEN FOR DRIVER
 * COVERAGE: ***
 *
 * classify_is_fatal() below is a MANUALLY-MAINTAINED MIRROR of one small
 * piece of xchan_do_recv()'s branch logic (xchan_chardev.c), not a call into
 * that function. xchan_do_recv() is kernel-only, spinlocks, virtqueues,
 * wait queues, copy_to_user(), and cannot be linked or run here. If a
 * future edit to xchan_do_recv() changes or reverts its EMSGSIZE-vs-EINVAL
 * branch, classify_is_fatal() will NOT notice and this file will keep
 * passing. It is documentation-as-assertion for the *predicate*
 * xchan_do_recv() uses, not a regression test for xchan_do_recv() itself.
 *
 * What IS genuine, real-code coverage in this file (every assertion calls the
 * actual xchan_frame_validate() from xchan_frame.c, unmodified): the
 * CHECK-ORDER assumptions xchan_do_recv()'s mid-message drain logic depends
 * on. Those assumptions are about xchan_frame_validate()'s internal behaviour,
 * not xchan_do_recv()'s, so they genuinely regress-test the thing this file
 * can actually link against:
 *
 *   1. `len > dst_cap` is checked BEFORE the window_id bounds check, so a
 *      frame can fail with -EMSGSIZE while carrying an out-of-range
 *      window_id validate() never got to reject. This is exactly why
 *      xchan_do_recv() must bounds-check window_id itself before trusting
 *      it for a RELEASE on the -EMSGSIZE path.
 *      See emsgsize_can_mask_bad_window_id below.
 *
 *   2. Given a generous dst_cap (U32_MAX, what xchan_recv_drain() and the
 *      rx_vq ISR both use), validate() DOES reach and enforce the
 *      window_id bounds check, which is exactly why those two call sites
 *      can trust window_id afterward without a second manual check. See
 *      generous_dst_cap_still_bounds_window_id below.
 *
 * If xchan_frame.c's check order ever changes, these two tests, not
 * classify_is_fatal(), are what would catch it.
 */
#include <assert.h>
#include <stdio.h>
#include "../src/xchan_frame.h"

#define SLICE 4096
#define DSTCAP 8192

static struct xchan_frame mk(__u64 seq, __u32 len, __u16 flags, __u16 wid)
{
	struct xchan_frame f = { .seq = seq, .len = len, .flags = flags, .window_id = wid };
	return f;
}

/* SHADOW, not coverage, see the file header. Mirrors xchan_do_recv()'s
 * classification: only -EMSGSIZE is non-fatal. Every other non-zero return,
 * including -EINVAL, tears the channel down. Kept because it is useful as
 * executable documentation of the predicate, not as a safety net.
 */
static int classify_is_fatal(int ret)
{
	return ret != 0 && ret != -EMSGSIZE;
}

int main(void)
{
	int ret;

	/* A well-formed inline frame that simply does not fit the caller's
	 * destination buffer, the case an earlier revision got wrong by
	 * tearing the channel down. Must be -EMSGSIZE, and the classifier
	 * must call it non-fatal.
	 */
	struct xchan_frame too_big_for_caller = mk(0, DSTCAP + 1, 0, 0);
	ret = xchan_frame_validate(&too_big_for_caller, SLICE, DSTCAP);
	assert(ret == -EMSGSIZE);
	assert(!classify_is_fatal(ret));

	/* A second, independent EMSGSIZE-producing shape: a window-path
	 * frame whose declared len fits the window slice but not what is
	 * left of the caller's buffer, the "remaining capacity" case
	 * xchan_do_recv() actually passes as dst_cap on every fragment-loop
	 * iteration (cap - offset), not just on the first call. Still
	 * non-fatal, and this is the shape the mid-message drain exists
	 * for: a non-first fragment can fail on capacity just as
	 * easily as the first one.
	 */
	struct xchan_frame too_big_for_remaining = mk(0, 100, XCHAN_F_WINDOW_REF, 0);
	ret = xchan_frame_validate(&too_big_for_remaining, SLICE, 50);
	assert(ret == -EMSGSIZE);
	assert(!classify_is_fatal(ret));

	/* A well-formed frame within capacity: no error, not fatal. */
	struct xchan_frame ok = mk(0, 64, 0, 0);
	ret = xchan_frame_validate(&ok, SLICE, DSTCAP);
	assert(ret == 0);
	assert(!classify_is_fatal(ret));

	/* Every genuine protocol violation must classify as fatal, and must
	 * NOT be -EMSGSIZE.
	 */
	struct xchan_frame bad_flags = mk(0, 64, 0x8000, 0);
	ret = xchan_frame_validate(&bad_flags, SLICE, DSTCAP);
	assert(ret == -EINVAL);
	assert(classify_is_fatal(ret));

	struct xchan_frame bad_window_id = mk(0, 64, XCHAN_F_WINDOW_REF, 0xFFFF);
	ret = xchan_frame_validate(&bad_window_id, SLICE, DSTCAP);
	assert(ret == -EINVAL);
	assert(classify_is_fatal(ret));

	struct xchan_frame release_with_window_ref =
		mk(0, 0, XCHAN_F_RELEASE | XCHAN_F_WINDOW_REF, 0);
	ret = xchan_frame_validate(&release_with_window_ref, SLICE, DSTCAP);
	assert(ret == -EINVAL);
	assert(classify_is_fatal(ret));

	/*
	 * NOT a protocol violation any more, and listed here because it used
	 * to be one: MORE without WINDOW_REF is an ordinary inline fragment
	 * (the window cannot be mapped into a second protected guest under
	 * pKVM, so every message above XCHAN_INLINE_MAX is a chain of these).
	 * It must validate clean, and therefore must NOT classify as fatal,
	 * if it did, xchan_do_recv() would tear the channel down on the first
	 * non-final fragment of every large message.
	 */
	struct xchan_frame more_without_window_ref = mk(0, 64, XCHAN_F_MORE, 0);
	ret = xchan_frame_validate(&more_without_window_ref, SLICE, DSTCAP);
	assert(ret == 0);
	assert(!classify_is_fatal(ret));

	/*
	 * A mid-message inline fragment that overruns what is LEFT of the
	 * caller's buffer is the -EMSGSIZE-with-MORE shape xchan_do_recv()'s
	 * drain exists for, and it must stay non-fatal now that inline
	 * fragments are the normal case rather than an impossible one.
	 */
	struct xchan_frame inline_fragment_over_remaining =
		mk(0, 4096, XCHAN_F_MORE, 0);
	ret = xchan_frame_validate(&inline_fragment_over_remaining, SLICE, 100);
	assert(ret == -EMSGSIZE);
	assert(!classify_is_fatal(ret));

	/*
	 * REAL coverage (not a shadow) of the check-order assumption
	 * xchan_do_recv()'s -EMSGSIZE branch depends on for its own window_id
	 * bounds check. A frame that is simultaneously too big for dst_cap AND
	 * carries an out-of-range window_id must report -EMSGSIZE, not -EINVAL,
	 * proving xchan_frame_validate() really does check capacity first
	 * and never reaches the window_id check in this case. If this
	 * assertion ever fails, xchan_do_recv()'s manual window_id bounds
	 * check before issuing RELEASE on the -EMSGSIZE path is protecting
	 * against exactly the wrong assumption and must be revisited.
	 */
	struct xchan_frame emsgsize_can_mask_bad_window_id =
		mk(0, DSTCAP + 1, XCHAN_F_WINDOW_REF, 0xFFFF);
	ret = xchan_frame_validate(&emsgsize_can_mask_bad_window_id, SLICE, DSTCAP);
	assert(ret == -EMSGSIZE);

	/*
	 * REAL coverage of the complementary assumption xchan_recv_drain() and
	 * the rx_vq ISR both depend on, given a generous dst_cap (U32_MAX,
	 * so the capacity check can never fire), xchan_frame_validate() DOES
	 * still reach and enforce the window_id bounds check. This is what
	 * lets both of those call sites trust window_id afterward without a
	 * second manual check.
	 */
	struct xchan_frame generous_dst_cap_still_bounds_window_id =
		mk(0, 64, XCHAN_F_WINDOW_REF, 0xFFFF);
	ret = xchan_frame_validate(&generous_dst_cap_still_bounds_window_id,
				   SLICE, 0xFFFFFFFFU);
	assert(ret == -EINVAL);

	printf("all recv-classification tests passed\n");
	return 0;
}
