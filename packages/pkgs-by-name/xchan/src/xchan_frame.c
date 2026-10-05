/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: GPL-2.0-only */
#include "xchan_frame.h"

int xchan_frame_validate(const struct xchan_frame *f, __u32 slice_size,
			 __u32 dst_cap)
{
	__u16 flags;
	__u32 len;
	__u16 window_id;

	if (!f)
		return -EINVAL;

	flags = f->flags;
	len = f->len;
	window_id = f->window_id;

	/* Fail closed on anything we do not recognise. */
	if (flags & ~XCHAN_FLAGS_KNOWN)
		return -EINVAL;

	/*
	 * RELEASE is its own signal returning a buffer, not a payload-bearing
	 * data frame: it never carries WINDOW_REF and never carries a
	 * payload.
	 */
	if ((flags & XCHAN_F_RELEASE) && (flags & XCHAN_F_WINDOW_REF))
		return -EINVAL;

	if ((flags & XCHAN_F_RELEASE) && len != 0)
		return -EINVAL;

	/*
	 * MORE without WINDOW_REF used to be -EINVAL here, on the reasoning
	 * that fragmentation only ever occurred on the window path and inline
	 * payloads were capped and never split. That rule is repealed: under
	 * pKVM the shared window cannot be mapped into a second protected
	 * guest at all (mapping it kills the guest's vCPU with -EREMOTEIO), so
	 * every payload now travels inline and an INLINE MORE fragment is the
	 * normal case for any message above XCHAN_INLINE_MAX. The send path
	 * (xchan_do_send()) splits at XCHAN_INLINE_MAX and the receive path
	 * (xchan_do_recv()) reassembles from each fragment's inline payload;
	 * the window-path variant (MORE together with WINDOW_REF) stays legal
	 * so nothing about the still-present window code becomes invalid
	 * on the wire.
	 *
	 * Deliberately no rule added here bounding an inline fragment's `len`
	 * by XCHAN_INLINE_MAX: this function validates a frame against the
	 * CALLER's capacity (dst_cap) and the window geometry (slice_size).
	 * The bound on how many payload bytes actually arrived is the
	 * transport's delivered byte count, which xchan_do_recv() checks as
	 * `sizeof(hdr) + len > rb->len` at the point it has that number, and
	 * which this function is never given. That count is itself the host's
	 * claim; the rx_vq ISR rejects one larger than the inbuf before it is
	 * stored in rb->len, and that is what makes it a bound.
	 */

	/*
	 * ABORT ends an in-progress message in place of its final fragment: it
	 * is its own control signal, not a payload-bearing data frame, so it
	 * is mutually exclusive with every other data-path flag and carries no
	 * payload, exactly RELEASE's treatment above, for the same reason (a
	 * second semantic path piggybacked on one frame buys nothing and only
	 * multiplies the states a reader has to hold in their head). MORE is
	 * explicitly included in the exclusion: ABORT already means "the
	 * message ends here", so MORE alongside it would simultaneously claim
	 * the message is ending and that more is coming.
	 */
	if ((flags & XCHAN_F_ABORT) &&
	    (flags & (XCHAN_F_WINDOW_REF | XCHAN_F_RELEASE | XCHAN_F_MORE)))
		return -EINVAL;

	if ((flags & XCHAN_F_ABORT) && len != 0)
		return -EINVAL;

	if (len > dst_cap)
		return -EMSGSIZE;

	if (flags & XCHAN_F_WINDOW_REF) {
		if (slice_size == 0)
			return -EINVAL;
		if (len == 0)
			return -EINVAL;
		if (len > slice_size)
			return -EINVAL;
	}

	/*
	 * window_id names a real buffer for WINDOW_REF (the buffer being
	 * referenced) and for RELEASE (the buffer being freed) alike. The
	 * driver indexes its window-tracking bitmap (tx_win_inuse) with this
	 * value, so it must never reach that code unchecked.
	 */
	if (flags & (XCHAN_F_WINDOW_REF | XCHAN_F_RELEASE)) {
		if (window_id >= XCHAN_WINDOW_BUFS)
			return -EINVAL;
	}

	return 0;
}
