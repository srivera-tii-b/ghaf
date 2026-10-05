/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * g2gchan wire format: one share per direction, owned by its sender and
 * lent read-only to the receiver, so neither side can write the other's
 * memory and no field is written by both. Frames and flow control are
 * virtio-xchan's: strict sequence numbers, 16 window buffers per direction,
 * and a release of each buffer, here the receiver's in-order "consumed"
 * counter (cons) instead of a RELEASE frame per buffer.
 */
#ifndef G2GC_PROTO_H
#define G2GC_PROTO_H

#include <stddef.h>
#include <stdint.h>

#define G2GC_PAGE		4096u
#define G2GC_BUFS		16u
#define G2GC_BUF_SIZE		(64u * 1024u)
#define G2GC_SHARE_PAGES	(1u + G2GC_BUFS * G2GC_BUF_SIZE / G2GC_PAGE)	/* 257 */
#define G2GC_SHARE_BYTES	((size_t)G2GC_SHARE_PAGES * G2GC_PAGE)
#define G2GC_MAX_MSG		(16u * 1024u * 1024u)
#define G2GC_MAGIC		0x316e616863673267ULL	/* "g2gchan1" */
#define G2GC_VERSION		1u

#define G2GC_F_WINDOW_REF	0x1u	/* XCHAN_F_WINDOW_REF: on every frame */
#define G2GC_F_MORE		0x4u	/* XCHAN_F_MORE: a full, non-final fragment */

/* Mailbox word 0: a tag in the high half, the message type in the low. */
#define G2GC_TAG		0x67326763ULL	/* "g2gc" */
#define G2GC_W0(type)		((G2GC_TAG << 32) | (uint64_t)(type))
enum { G2GC_MSG_CONNECT = 1, G2GC_MSG_ACCEPTED = 2, G2GC_MSG_REFUSED = 3 };

struct g2gc_frame {
	uint64_t seq;		/* this frame's number in its direction, from 0 */
	uint32_t len;		/* this fragment's bytes */
	uint32_t msg_len;	/* the whole message's bytes, on every fragment */
	uint16_t flags;
	uint16_t window_id;	/* seq % G2GC_BUFS */
	uint32_t pad;		/* zero */
};

/* The first page of a share. Written only by the share's owner. */
struct g2gc_hdr {
	uint64_t magic;
	uint32_t version, bufs, buf_size, pad0;
	uint64_t prod;		/* frames this side has published */
	uint64_t cons;		/* frames of the peer's ring this side has consumed */
	uint64_t closed;	/* nonzero: this side sends nothing more */
	uint64_t closed_ack;	/* nonzero: this side saw the peer's closed, holds all it
				 * sent (or is closing too), and never reads the
				 * peer's share again */
	struct g2gc_frame frame[G2GC_BUFS];
};

_Static_assert(sizeof(struct g2gc_frame) == 24, "frame layout is wire format");
_Static_assert(sizeof(struct g2gc_hdr) <= G2GC_PAGE, "header fits its page");

/* Each returns 0, or -EPROTO for a peer that broke the protocol. */
int g2gc_check_hdr(const struct g2gc_hdr *h);
/* The peer's prod, against the last one we saw and what we consumed. */
int g2gc_check_prod(uint64_t peer_prod, uint64_t last_peer_prod, uint64_t my_cons);
/* The peer's cons, against the last one we saw and what we published. */
int g2gc_check_cons(uint64_t peer_cons, uint64_t last_peer_cons, uint64_t my_prod);
/*
 * A frame header the receiver has already copied out of the peer's share.
 * expect_seq: the next frame's number. got: bytes of this message received so
 * far (0: f is the first fragment). first_msg_len: the first fragment's
 * msg_len (ignored when got == 0).
 */
int g2gc_check_frame(const struct g2gc_frame *f, uint64_t expect_seq,
		     uint32_t got, uint32_t first_msg_len);

#endif
