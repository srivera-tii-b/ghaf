/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/xchan_frame.h"

#define SLICE 4096
#define DSTCAP 8192

static struct xchan_frame mk(__u64 seq, __u32 len, __u16 flags, __u16 wid) {
	struct xchan_frame f = { .seq = seq, .len = len, .flags = flags, .window_id = wid };
	return f;
}

int main(void) {
	/* A well-formed inline frame is accepted. */
	struct xchan_frame ok = mk(0, 64, 0, 0);
	assert(xchan_frame_validate(&ok, SLICE, DSTCAP) == 0);

	/* len beyond the window slice is rejected, not clamped. */
	struct xchan_frame big = mk(0, SLICE + 1, XCHAN_F_WINDOW_REF, 0);
	assert(xchan_frame_validate(&big, SLICE, DSTCAP) == -EINVAL);

	/* len beyond the caller's destination buffer is rejected. */
	struct xchan_frame over = mk(0, DSTCAP + 1, 0, 0);
	assert(xchan_frame_validate(&over, SLICE, DSTCAP) == -EMSGSIZE);

	/* A window_id outside the slot's buffer count is rejected. */
	struct xchan_frame badid = mk(0, 64, XCHAN_F_WINDOW_REF, 0xFFFF);
	assert(xchan_frame_validate(&badid, SLICE, DSTCAP) == -EINVAL);

	/* Unknown flag bits are rejected, fail closed, never ignore. */
	struct xchan_frame weird = mk(0, 64, 0x8000, 0);
	assert(xchan_frame_validate(&weird, SLICE, DSTCAP) == -EINVAL);

	/* len == 0 with WINDOW_REF is meaningless and rejected. */
	struct xchan_frame empty = mk(0, 0, XCHAN_F_WINDOW_REF, 0);
	assert(xchan_frame_validate(&empty, SLICE, DSTCAP) == -EINVAL);

	/* A zero slice size means no window: WINDOW_REF must be refused. */
	struct xchan_frame nowin = mk(0, 64, XCHAN_F_WINDOW_REF, 0);
	assert(xchan_frame_validate(&nowin, 0, DSTCAP) == -EINVAL);

	/* A RELEASE frame's window_id names the buffer being freed and must
	 * be bounds-checked exactly like a WINDOW_REF one, never index the
	 * window-tracking array with an unchecked value. */
	struct xchan_frame release_badid = mk(0, 0, XCHAN_F_RELEASE, 0xFFFF);
	assert(xchan_frame_validate(&release_badid, SLICE, DSTCAP) == -EINVAL);

	/* A well-formed RELEASE frame (in-range window_id, no payload) is
	 * still accepted, the bounds check must not overreject. */
	struct xchan_frame release_ok = mk(0, 0, XCHAN_F_RELEASE, 5);
	assert(xchan_frame_validate(&release_ok, SLICE, DSTCAP) == 0);

	/* RELEASE and WINDOW_REF are mutually exclusive: RELEASE is its own
	 * signal, never a payload-bearing data frame. */
	struct xchan_frame release_and_ref = mk(0, 0, XCHAN_F_RELEASE | XCHAN_F_WINDOW_REF, 0);
	assert(xchan_frame_validate(&release_and_ref, SLICE, DSTCAP) == -EINVAL);

	/* RELEASE carries no payload: non-zero len is rejected. */
	struct xchan_frame release_with_len = mk(0, 64, XCHAN_F_RELEASE, 0);
	assert(xchan_frame_validate(&release_with_len, SLICE, DSTCAP) == -EINVAL);

	/* INLINE FRAGMENTATION: MORE without WINDOW_REF is the normal case
	 * now, not -EINVAL. The window cannot be mapped into a second
	 * protected guest under pKVM, so every message above XCHAN_INLINE_MAX
	 * travels as a chain of inline MORE fragments. If the repealed rule is
	 * ever restored, no payload over 4096 bytes can cross this transport
	 * at all, which is the whole reason it was repealed. */
	struct xchan_frame more_inline = mk(0, 64, XCHAN_F_MORE, 0);
	assert(xchan_frame_validate(&more_inline, SLICE, DSTCAP) == 0);

	/* A full-size inline fragment, what every non-final fragment of a
	 * large message actually looks like on the wire: len == the 4096 the
	 * send path chunks at, MORE set, no WINDOW_REF, window_id unused and
	 * therefore not bounds-checked. */
	struct xchan_frame more_inline_full = mk(0, 4096, XCHAN_F_MORE, 0);
	assert(xchan_frame_validate(&more_inline_full, SLICE, DSTCAP) == 0);

	/* The repeal is narrow: it removed the MORE-implies-WINDOW_REF
	 * coupling and nothing else. MORE *with* WINDOW_REF stays legal (the
	 * window path is unused, not illegal)... */
	struct xchan_frame more_window = mk(0, 64, XCHAN_F_MORE | XCHAN_F_WINDOW_REF, 3);
	assert(xchan_frame_validate(&more_window, SLICE, DSTCAP) == 0);

	/* ...and an inline MORE fragment is still bounded by the caller's
	 * remaining capacity, so reassembly can never overrun the destination
	 * buffer one fragment at a time. */
	struct xchan_frame more_inline_over = mk(0, DSTCAP + 1, XCHAN_F_MORE, 0);
	assert(xchan_frame_validate(&more_inline_over, SLICE, DSTCAP) == -EMSGSIZE);

	/* An inline MORE fragment on a channel with no window at all
	 * (slice_size == 0) is accepted: fragmentation no longer depends on
	 * the window existing. This is the shape a pKVM guest, where the
	 * window mapping is what kills the vCPU, actually sends. */
	struct xchan_frame more_inline_nowin = mk(0, 4096, XCHAN_F_MORE, 0);
	assert(xchan_frame_validate(&more_inline_nowin, 0, DSTCAP) == 0);

	/* Boundary: window_id == XCHAN_WINDOW_BUFS (16) is out of range. */
	struct xchan_frame wid_at_limit = mk(0, 64, XCHAN_F_WINDOW_REF, 16);
	assert(xchan_frame_validate(&wid_at_limit, SLICE, DSTCAP) == -EINVAL);

	/* Boundary: window_id == 15 is the last valid buffer index. */
	struct xchan_frame wid_last_valid = mk(0, 64, XCHAN_F_WINDOW_REF, 15);
	assert(xchan_frame_validate(&wid_last_valid, SLICE, DSTCAP) == 0);

	/* Boundary: len == dst_cap exactly is accepted, not rejected. */
	struct xchan_frame len_at_dstcap = mk(0, DSTCAP, 0, 0);
	assert(xchan_frame_validate(&len_at_dstcap, SLICE, DSTCAP) == 0);

	/* Boundary: len == slice_size exactly on a WINDOW_REF frame is
	 * accepted, not rejected. */
	struct xchan_frame len_at_slice = mk(0, SLICE, XCHAN_F_WINDOW_REF, 0);
	assert(xchan_frame_validate(&len_at_slice, SLICE, DSTCAP) == 0);

	/* --- XCHAN_F_ABORT: a well-formed ABORT frame, no other
	 * flags, no payload, is accepted. This is the one shape
	 * xchan_do_send() ever actually emits. */
	struct xchan_frame abort_ok = mk(0, 0, XCHAN_F_ABORT, 0);
	assert(xchan_frame_validate(&abort_ok, SLICE, DSTCAP) == 0);

	/* A well-formed ABORT frame is accepted even with a nonzero window_id:
	 * ABORT never sets WINDOW_REF or RELEASE, so window_id is not
	 * meaningful on it and must not be bounds-checked as though it were. */
	struct xchan_frame abort_ok_wid = mk(0, 0, XCHAN_F_ABORT, 0xFFFF);
	assert(xchan_frame_validate(&abort_ok_wid, SLICE, DSTCAP) == 0);

	/* ABORT + MORE is a contradiction, ABORT already says "the message
	 * ends here", MORE says "there is more to come", and must be
	 * rejected rather than accepted with one flag silently winning. */
	struct xchan_frame abort_and_more = mk(0, 0, XCHAN_F_ABORT | XCHAN_F_MORE, 0);
	assert(xchan_frame_validate(&abort_and_more, SLICE, DSTCAP) == -EINVAL);

	/* ABORT carries no payload: a nonzero length is rejected, exactly
	 * like RELEASE's identical rule above. */
	struct xchan_frame abort_with_len = mk(0, 64, XCHAN_F_ABORT, 0);
	assert(xchan_frame_validate(&abort_with_len, SLICE, DSTCAP) == -EINVAL);

	/* ABORT is not a payload-bearing data frame: it must never ride along
	 * with WINDOW_REF, whether or not that combination would otherwise
	 * validate (a small, in-range, well-formed WINDOW_REF frame here, to
	 * isolate that ABORT alone is what triggers the rejection). */
	struct xchan_frame abort_and_ref =
		mk(0, 64, XCHAN_F_ABORT | XCHAN_F_WINDOW_REF, 0);
	assert(xchan_frame_validate(&abort_and_ref, SLICE, DSTCAP) == -EINVAL);

	/* ABORT and RELEASE are two distinct control signals and must not be
	 * combined into a third, unspecified one. */
	struct xchan_frame abort_and_release =
		mk(0, 0, XCHAN_F_ABORT | XCHAN_F_RELEASE, 0);
	assert(xchan_frame_validate(&abort_and_release, SLICE, DSTCAP) == -EINVAL);

	printf("all frame validation tests passed\n");
	return 0;
}
