// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0
/* g2gchan's wire checks. Pure: everything they read is a copy. */
#include <errno.h>
#include "g2gc_proto.h"

int g2gc_check_hdr(const struct g2gc_hdr *h)
{
	if (h->magic != G2GC_MAGIC)
		return -EPROTO;
	if (h->version != G2GC_VERSION)
		return -EPROTO;
	if (h->bufs != G2GC_BUFS)
		return -EPROTO;
	if (h->buf_size != G2GC_BUF_SIZE)
		return -EPROTO;
	return 0;
}

int g2gc_check_prod(uint64_t peer_prod, uint64_t last_peer_prod, uint64_t my_cons)
{
	if (peer_prod < last_peer_prod)
		return -EPROTO;
	if (peer_prod < my_cons)
		return -EPROTO;
	if (peer_prod - my_cons > G2GC_BUFS)	/* more in flight than it has credit for */
		return -EPROTO;
	return 0;
}

int g2gc_check_cons(uint64_t peer_cons, uint64_t last_peer_cons, uint64_t my_prod)
{
	if (peer_cons < last_peer_cons)
		return -EPROTO;
	if (peer_cons > my_prod)
		return -EPROTO;
	return 0;
}

int g2gc_check_frame(const struct g2gc_frame *f, uint64_t expect_seq,
		     uint32_t got, uint32_t first_msg_len)
{
	uint32_t left;

	if (f->seq != expect_seq)
		return -EPROTO;
	if (f->window_id != expect_seq % G2GC_BUFS)
		return -EPROTO;
	if (!(f->flags & G2GC_F_WINDOW_REF))
		return -EPROTO;
	if (f->flags & ~(G2GC_F_WINDOW_REF | G2GC_F_MORE))
		return -EPROTO;
	if (f->pad)
		return -EPROTO;
	if (f->len > G2GC_BUF_SIZE)
		return -EPROTO;
	if (f->msg_len > G2GC_MAX_MSG)
		return -EPROTO;
	if (got && f->msg_len != first_msg_len)
		return -EPROTO;
	if (got && got >= f->msg_len)
		return -EPROTO;
	left = f->msg_len - got;
	if (left > G2GC_BUF_SIZE) {
		/* Not the last fragment: a full buffer, marked MORE. */
		if (!(f->flags & G2GC_F_MORE))
			return -EPROTO;
		if (f->len != G2GC_BUF_SIZE)
			return -EPROTO;
		return 0;
	}
	/* The last (or only) fragment: exactly what is left. */
	if (f->flags & G2GC_F_MORE)
		return -EPROTO;
	if (f->len != left)
		return -EPROTO;
	return 0;
}
