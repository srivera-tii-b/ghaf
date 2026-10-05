/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
 * SPDX-License-Identifier: (GPL-2.0-only WITH Linux-syscall-note) OR Apache-2.0
 *
 * virtio-xchan UAPI. CANONICAL, crosvm's uapi.rs mirrors this file.
 */
#ifndef _XCHAN_UAPI_H
#define _XCHAN_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define XCHAN_DEVICE_ID 61

#define VIRTIO_XCHAN_F_WINDOW      0
/*
 * Reserved for a future data-plane resume operation; must not be offered by
 * the device or negotiated by the driver. This bit used to mean that
 * xchan_event and xchan_channel_info carried a session token. Both are
 * control-plane structures, which the host always sees, so a session identity
 * carried in them could never become host-invisible; the token was removed
 * from both. Defined only so nothing reuses the bit.
 */
#define VIRTIO_XCHAN_F_SESSION     1
#define VIRTIO_XCHAN_F_ATTESTED_ID 2

struct virtio_xchan_config {
	__le32 max_channels;
	__le32 window_slice_size;
	/* 0 = endpoint A, 1 = endpoint B: fixes which half of each slot's
	 * window this side sends on. NOT inferable from max_channels: that
	 * is a capacity, and a hub serving one client is indistinguishable
	 * from a client by channel count.
	 */
	__le32 endpoint;
	__le32 reserved;
};

struct xchan_channel_info {
	__u32 channel_id;
	__u32 flags;
	__u64 window_slice_size;
	__u8  peer_identity[32];
};

#define XCHAN_F_WINDOW_REF (1u << 0)
#define XCHAN_F_RELEASE    (1u << 1)
#define XCHAN_F_MORE       (1u << 2)
/*
 * Ends an in-progress fragmented message in place of what would have been its
 * final fragment: the sender failed mid-message, after already posting at
 * least one XCHAN_F_MORE fragment, committing the peer's XCHAN_RECV to a
 * TASK_KILLABLE wait for the rest, and has no other way to tell that
 * receiver to give up rather than block until the process is killed. A control
 * signal like RELEASE, not a payload-bearing data frame: mutually exclusive
 * with WINDOW_REF, RELEASE and MORE, and carries no payload (len must be 0).
 * See xchan_frame.c for the validator rules and xchan_chardev.c's
 * xchan_do_send()/xchan_do_recv() for how it is emitted and consumed.
 */
#define XCHAN_F_ABORT      (1u << 3)

struct xchan_msg {
	__u64 seq;
	__u32 flags;
	__u32 len;
	union {
		__u64 addr;
		__u64 offset;
	};
};

#define XCHAN_WAIT_CHANNEL _IOR('x', 1, struct xchan_channel_info)
#define XCHAN_SEND         _IOW('x', 2, struct xchan_msg)
#define XCHAN_RECV        _IOWR('x', 3, struct xchan_msg)

#define XCHAN_EV_ATTACHED 1
#define XCHAN_EV_DETACHED 2

/*
 * xchan_event.reason on XCHAN_EV_DETACHED; always 0 on XCHAN_EV_ATTACHED.
 *   PEER_CLOSED  the peer ended the channel in band (a CLOSE): its guest
 *                closed the fd, or its crosvm tore the channel down.
 *   TORN_DOWN    this guest's own crosvm closed the channel for a protocol
 *                violation: a sequence gap or replay, an undeliverable
 *                frame, or a peer record it could not parse.
 *   PEER_LOST    the peer's connection ended with no CLOSE: its crosvm, or
 *                its whole VM, is gone.
 * Like every field of the event it comes from the device, which is
 * untrusted: the driver only logs it.
 */
#define XCHAN_DETACH_PEER_CLOSED 0
#define XCHAN_DETACH_TORN_DOWN   1
#define XCHAN_DETACH_PEER_LOST   2

/*
 * Control plane: the device (crosvm) writes every byte of this, so it must
 * never carry anything meant to be hidden from the host.
 */
struct xchan_event {
	__le32 type;
	__le32 slot;
	__le32 channel_id;
	__le32 reason;
	__u8   peer_identity[32];
};

struct xchan_frame {
	__le64 seq;
	__le32 len;
	__le16 flags;
	__le16 window_id;
};

/*
 * Driver -> device commandq (queue 1). This is the wire message an earlier
 * revision of the ABI was missing entirely: without it the guest has no way
 * to tell crosvm it has closed a channel fd, and the "close" half of the
 * slot-reuse rule (a slot is reused only once the peer has detached AND the
 * guest has closed its fd) can never be observed by the side that owns slot
 * allocation.
 */
#define XCHAN_CMD_CHANNEL_CLOSED 1

struct xchan_command {
	__le32 type;
	__le32 slot;
	__le32 channel_id;
	__le32 reserved;
};

/*
 * Layout assertions. xchan_uapi.h is the canonical ABI definition; the Rust
 * mirror in crosvm (uapi.rs) asserts the same sizes and offsets, field for
 * field, at compile time and again in its tests. Any edit that changes a size
 * or moves a field must fail the build here, in the canonical file, rather
 * than silently diverging from the other repository.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define XCHAN_ASSERT_OFF(s, f, off) \
	_Static_assert(__builtin_offsetof(struct s, f) == (off), \
		       #s "." #f " must be at offset " #off)
_Static_assert(sizeof(struct virtio_xchan_config) == 16,
	       "virtio_xchan_config must be 16 bytes");
XCHAN_ASSERT_OFF(virtio_xchan_config, max_channels, 0);
XCHAN_ASSERT_OFF(virtio_xchan_config, window_slice_size, 4);
XCHAN_ASSERT_OFF(virtio_xchan_config, endpoint, 8);
XCHAN_ASSERT_OFF(virtio_xchan_config, reserved, 12);

_Static_assert(sizeof(struct xchan_frame) == 16,
	       "xchan_frame must be 16 bytes");
XCHAN_ASSERT_OFF(xchan_frame, seq, 0);
XCHAN_ASSERT_OFF(xchan_frame, len, 8);
XCHAN_ASSERT_OFF(xchan_frame, flags, 12);
XCHAN_ASSERT_OFF(xchan_frame, window_id, 14);

_Static_assert(sizeof(struct xchan_event) == 48,
	       "xchan_event must be 48 bytes");
XCHAN_ASSERT_OFF(xchan_event, type, 0);
XCHAN_ASSERT_OFF(xchan_event, slot, 4);
XCHAN_ASSERT_OFF(xchan_event, channel_id, 8);
XCHAN_ASSERT_OFF(xchan_event, reason, 12);
XCHAN_ASSERT_OFF(xchan_event, peer_identity, 16);

_Static_assert(sizeof(struct xchan_channel_info) == 48,
	       "xchan_channel_info must be 48 bytes");
XCHAN_ASSERT_OFF(xchan_channel_info, channel_id, 0);
XCHAN_ASSERT_OFF(xchan_channel_info, flags, 4);
XCHAN_ASSERT_OFF(xchan_channel_info, window_slice_size, 8);
XCHAN_ASSERT_OFF(xchan_channel_info, peer_identity, 16);

_Static_assert(sizeof(struct xchan_command) == 16,
	       "xchan_command must be 16 bytes");
XCHAN_ASSERT_OFF(xchan_command, type, 0);
XCHAN_ASSERT_OFF(xchan_command, slot, 4);
XCHAN_ASSERT_OFF(xchan_command, channel_id, 8);
XCHAN_ASSERT_OFF(xchan_command, reserved, 12);
#undef XCHAN_ASSERT_OFF
#endif

#endif /* _XCHAN_UAPI_H */
