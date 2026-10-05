/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * virtio-xchan guest driver: private (non-UAPI) state shared between the
 * virtio probe (xchan_drv.c) and the character device / channel-acquisition
 * layer (xchan_chardev.c).
 *
 * Nothing in this file is part of the guest<->host ABI. xchan_uapi.h remains
 * the sole canonical ABI surface (ioctl numbers, wire structs, layout
 * assertions) and is untouched by anything here; this header only lets two
 * translation units agree on the driver's own internal struct xchan_dev /
 * struct xchan_channel layout, which used to be private to xchan_drv.c
 * before the character device needed to reach into it.
 */
#ifndef _XCHAN_PRIV_H
#define _XCHAN_PRIV_H

#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/virtio.h>
#include <linux/wait.h>

#include "xchan_frame.h"
#include "xchan_uapi.h"

/*
 * One driver-private receive descriptor, posted as an inbuf on a channel's
 * rx_vq. `data` is a fixed XCHAN_FRAME_BUF_SIZE allocation (see
 * xchan_chardev.c) holding a struct xchan_frame header followed by room for
 * the largest inline payload; `len` is the byte count virtqueue_get_buf()
 * reported for the completion currently occupying it, valid only while the
 * buffer is linked on xchan_channel.rx_ready. `link` is used for exactly one
 * list at a time: never linked while posted as a live inbuf on the device,
 * linked on rx_ready from the moment the rx_vq ISR pops it until XCHAN_RECV
 * has consumed and reposted it.
 */
struct xchan_rxbuf {
	void *data;
	unsigned int len;
	struct list_head link;
};

/*
 * Per-slot lifecycle. Mirrors, field for field, the state machine crosvm's own
 * channel table keeps on the device side: a slot becomes reusable only once
 * BOTH the peer has detached and the guest has closed its fd, in either order.
 * Recycling on peer-detach alone would let a new client land in a slot whose
 * window still held the previous tenant's data, and a stale fd in a
 * slow-to-clean-up server could then touch a channel that now belongs to
 * someone else.
 */
enum xchan_slot_state {
	XCHAN_SLOT_FREE = 0,	/* no channel; slot may receive XCHAN_EV_ATTACHED */
	XCHAN_SLOT_ACTIVE,	/* peer attached; fd may or may not exist yet */
	XCHAN_SLOT_DETACHED,	/* peer gone, fd still open: ops -> ECONNRESET */
	XCHAN_SLOT_CLOSED,	/* fd closed, peer still attached */
};

/* Per-channel-slot virtqueue pair (queues 2+2k / 3+2k). */
struct xchan_channel {
	struct virtqueue *rx_vq;
	struct virtqueue *tx_vq;

	/* --- fields below are owned by the chardev layer --- */

	struct xchan_dev *xdev;	/* back-pointer */
	u32 slot;		/* index into xdev->channels[]; == this slot number */

	enum xchan_slot_state state;

	/*
	 * peer_gone / fd_closed mirror crosvm's ChannelTable::Slot exactly
	 * (vendor/tegra234/devices/src/xchan/channel.rs), so the two sides
	 * of one slot's lifecycle can be reasoned about identically even
	 * though nothing here talks to that code directly.
	 */
	bool peer_gone;
	bool fd_closed;

	/*
	 * crosvm-assigned identity of the current occupant; 0 when FREE.
	 * Monotonic and never reused for the device's lifetime, used to
	 * reject a delayed or duplicated DETACHED naming a slot's *former*
	 * occupant (an ABA: slots are reused, channel ids are not).
	 */
	u32 channel_id;
	u32 flags;
	u8  peer_identity[32];

	/* True while linked into xdev->ready_list: attached but not yet
	 * claimed by XCHAN_WAIT_CHANNEL.
	 */
	bool waiting;
	struct list_head ready_link;

	/* Woken on state transitions a poll()ing or blocked caller on this
	 * channel's fd needs to see: peer detach, a frame landing on
	 * rx_ready, a RELEASE freeing TX window credit, and torn_down below.
	 */
	wait_queue_head_t poll_wq;

	/* --- fields below are owned by the frame data path --- */

	/*
	 * Kernel mappings of this slot's two shared-memory halves, established
	 * once at xchan_chardev_init() time (process context, no concurrency,
	 * see the loop there) via memremap(..., MEMREMAP_WB) of the
	 * physical range the window layout assigns this slot, and torn down
	 * in xchan_teardown() after the device has been reset. NULL if the
	 * device did not negotiate VIRTIO_XCHAN_F_WINDOW, advertises
	 * window_slice_size == 0, or the mapping failed, callers must treat
	 * a NULL window as "this channel has no window support". (Every send
	 * is inline now whether or not a window is mapped, see
	 * xchan_do_send().)
	 *
	 * tx_window is the SAME physical range xchan_chan_mmap() exposes to
	 * userspace. It was mapped here for XCHAN_SEND's window path, which no
	 * longer exists (see TODO(inline) in xchan_chardev.c). rx_window
	 * backs the direction never mapped into userspace at all; the
	 * driver's copy-out of it is what XCHAN_RECV's window path reads from.
	 */
	void *tx_window;
	void *rx_window;

	/*
	 * Per-buffer capacity within this slot's window: window_slice_size
	 * divided into XCHAN_WINDOW_BUFS equal buffers, so `window_id` in a
	 * frame header selects one. This subdivision is part of the wire
	 * contract, not an implementation choice this driver is free to pick,
	 * if the two ends disagreed on the buffer count, window_id would
	 * resolve to different byte offsets at each end and payload would be
	 * silently misdirected rather than failing loudly, which is why
	 * XCHAN_WINDOW_BUFS is defined once, in xchan_frame.h, shared with
	 * xchan_frame_validate()'s own window_id bounds check rather than
	 * re-derived here. 0 if windows are unavailable (see
	 * tx_window/rx_window above), in which case xchan_frame_validate()
	 * already rejects any WINDOW_REF frame, this driver never has to
	 * special-case "no window" beyond passing 0 through.
	 */
	u32 slice_size;

	/*
	 * TX-side window buffer allocator: bit k set means buffer k of this
	 * channel's OWN window (the half we send on) is currently lent to
	 * the peer, a WINDOW_REF frame referencing it went out and no
	 * RELEASE has come back yet. A bit is set before posting a
	 * WINDOW_REF frame, which nothing does now that every send is
	 * inline (see TODO(inline) in xchan_chardev.c), and the rx_vq ISR
	 * clears it the moment a matching RELEASE is validated (release
	 * fires on the peer's copy, not on anything this side does),
	 * independent of whether anyone is calling XCHAN_RECV, see the
	 * ISR's own comment for why that independence is load-bearing.
	 * Protected by xdev->lock.
	 */
	DECLARE_BITMAP(tx_win_inuse, XCHAN_WINDOW_BUFS);

	/* Next sequence number this side assigns on send;
	 * covers both data frames and this side's own RELEASE frames, which
	 * are just another frame in the TX stream. Protected by xdev->lock.
	 */
	u64 tx_seq;

	/*
	 * Next sequence number this side will ACCEPT on receive: strict
	 * monotonic, starting at 0 to match a fresh peer's tx_seq (both reset
	 * together on slot reuse, see xchan_slot_wipe()). Covers every frame
	 * arriving in this direction, RELEASE included, RELEASE is just
	 * another frame in the peer's TX stream, so a gap or replay hidden
	 * inside a dropped/replayed RELEASE would go undetected if only data
	 * frames were checked. Checked and advanced in exactly one place,
	 * xchan_rx_vq_isr(), in the ring's actual arrival order, under
	 * xdev->lock, NOT re-derived or re-checked in XCHAN_RECV, which only
	 * ever sees frames the ISR has already accepted.
	 *
	 * This check is this side's own, independent of anything crosvm does:
	 * crosvm constructs the frame headers this driver reads, so a sequence
	 * check performed in crosvm bounds a malicious client but is the
	 * adversary checking itself against a malicious host. Only this
	 * counter gives the design's asserted replay/reorder-detection
	 * property any teeth against the host.
	 */
	u64 rx_seq;

	/*
	 * Serialise whole XCHAN_SEND / XCHAN_RECV calls on this channel
	 * against each other (one of each direction at a time). This is NOT
	 * about xdev->lock's job of protecting shared state from the ISR, it
	 * is what keeps two threads racing XCHAN_SEND on the same fd from
	 * interleaving: without it, thread A could be assigned seq N, drop the
	 * lock for its copy_from_user(), and thread B could assign seq N+1 and
	 * post to tx_vq first, delivering seq N+1 before seq N and handing the
	 * peer's strict sequence check a self-inflicted gap. Held across the
	 * sleeping copy_from_user()/copy_to_user() portions of a call, which
	 * xdev->lock (a spinlock) cannot be; never held by the rx_vq ISR, so
	 * there is no lock-order hazard against xdev->lock (mutex held, then
	 * spinlock taken and dropped inside, same as any normal
	 * process-context caller).
	 */
	struct mutex send_lock;
	struct mutex recv_lock;

	/*
	 * Fixed pool of driver-owned receive descriptors, allocated once and
	 * kept posted as inbufs on rx_vq for the device's lifetime (mirrors
	 * xdev->event_bufs). rx_depth is the number actually posted (may be
	 * less than XCHAN_RX_QUEUE_DEPTH if the ring is smaller or a post
	 * failed partway through setup).
	 */
	struct xchan_rxbuf *rx_bufs;
	unsigned int rx_depth;

	/*
	 * Completed rx_vq buffers the rx_vq ISR has classified as real data
	 * frames (RELEASE frames are fully handled in the ISR itself and never
	 * appear here) and is handing off to process context, in arrival order
	 * (fragments of one message must be consumed in the order they
	 * arrived). XCHAN_RECV pops from the head, processes, and reposts the
	 * buffer. Protected by xdev->lock.
	 */
	struct list_head rx_ready;

	/*
	 * Set on a local protocol violation (a malformed frame, an
	 * out-of-range window reference, a length the transport did not
	 * actually deliver) discovered on this channel's data path. Distinct
	 * from `state`/XCHAN_SLOT_DETACHED, which is reserved for the real
	 * peer-lifecycle state machine driven by XCHAN_EV_DETACHED and fd
	 * close, torn_down never feeds back into that machine, it only makes
	 * XCHAN_SEND/XCHAN_RECV fail closed with -ECONNRESET from here on, the
	 * same externally-visible failure mode as a real detach. Protected by
	 * xdev->lock; sticky once set.
	 */
	bool torn_down;
};

struct xchan_dev {
	struct virtio_device *vdev;

	u32 max_channels;
	u32 window_slice_size;
	u32 endpoint;		/* 0 = A, 1 = B; from config space */

	unsigned int nvqs;
	struct virtqueue **vqs;	/* nvqs entries; vqs[0] is the eventq, vqs[1]
				 * is the commandq
				 */
	struct virtqueue *event_vq;	/* device -> driver lifecycle events;
					 * == vqs[0]
					 */
	struct virtqueue *cmd_vq;	/* driver -> device notifications
					 * (currently just CHANNEL_CLOSED);
					 * == vqs[1]
					 */

	struct xchan_channel *channels;	/* max_channels entries */

	const char **vq_names;	/* nvqs kasprintf()'d strings, kept for the
				 * virtqueues' lifetime and freed at remove()
				 */

	/* --- chardev / channel-acquisition state --- */

	spinlock_t lock;		/* protects all channel state + ready_list */
	wait_queue_head_t wait_q;	/* XCHAN_WAIT_CHANNEL blocks here */
	struct list_head ready_list;	/* channels with an unclaimed ATTACHED */

	struct xchan_event *event_bufs;	/* event_depth entries, kept posted
						 * on event_vq as inbufs for the
						 * device to fill with lifecycle
						 * events
						 */
	unsigned int event_depth;

	struct miscdevice miscdev;	/* /dev/xchan0 */
	bool chardev_ready;		/* miscdev successfully registered */

	/*
	 * true once xchan_remove()/a failed probe has started tearing the
	 * virtio side down: xdev->vdev and everything reachable only through
	 * it (virtqueues, config space) must not be touched once this is
	 * set. Does NOT mean xdev/xdev->channels have been freed, refcnt
	 * below keeps those alive for as long as any channel fd is open.
	 */
	bool removed;

	/*
	 * Reference count on the xdev/xdev->channels allocation itself,
	 * independent of virtio device lifetime. One reference is held by
	 * the driver for as long as the virtio device exists (dropped in
	 * xchan_teardown()); one more is held per currently-open channel fd
	 * (taken when XCHAN_WAIT_CHANNEL hands one out, dropped in its
	 * .release()). This exists because a channel fd legitimately
	 * outlives XCHAN_WAIT_CHANNEL and must not be left pointing at freed
	 * memory if the module is unloaded (or the device removed) while
	 * that fd is still open.
	 */
	refcount_t refcnt;
};

/* xchan_chardev.c, called from xchan_drv.c's probe()/remove(). */
int xchan_chardev_init(struct xchan_dev *xdev);
void xchan_chardev_exit(struct xchan_dev *xdev);

/* The eventq's interrupt callback, installed by xchan_drv.c's probe() at
 * virtio_find_vqs() time (index 0). Defined in xchan_chardev.c because
 * processing XCHAN_EV_ATTACHED/DETACHED is channel-acquisition logic, not
 * probe-scope config handling.
 */
void xchan_event_vq_isr(struct virtqueue *vq);

/* The commandq's interrupt callback (index 1), also installed by probe().
 * The commandq is driver -> device, so there is nothing to process on this
 * side, this only reclaims (frees) the struct xchan_command buffers that
 * xchan_chardev.c's close-notification path posts as outbufs, once the
 * device has consumed them.
 */
void xchan_cmd_vq_isr(struct virtqueue *vq);

/*
 * Per-channel-slot RX queue callback, installed by xchan_drv.c's probe() on
 * every even index >= 2 (2+2k is slot k's RX). Drains completed inbufs, fully
 * handles RELEASE frames inline (credit bookkeeping only, no sleeping, safe
 * in this context), and hands real data frames off to xchan_channel.rx_ready
 * for XCHAN_RECV to validate against the caller's actual buffer and copy out
 * in process context, where copy_to_user() is legal. Never installed on a TX
 * queue.
 */
void xchan_rx_vq_isr(struct virtqueue *vq);

/*
 * Reference counting on the struct xchan_dev allocation itself (see the
 * refcnt field comment above). Small enough, and needed identically from
 * both translation units, to keep as header-inline rather than exporting
 * two more functions from xchan_chardev.c.
 *
 * xchan_get() takes a reference and reports whether that succeeded: it can
 * fail once the driver's own base reference has already been dropped
 * (xchan_teardown() underway), which only happens after xdev->removed is
 * set, so callers who already checked that under xdev->lock will not see
 * this fail in practice, the _not_zero form is still the correct
 * primitive to use here rather than plain refcount_inc().
 */
static inline bool xchan_get(struct xchan_dev *xdev)
{
	return refcount_inc_not_zero(&xdev->refcnt);
}

/*
 * Drops a reference; frees xdev->channels and xdev itself the moment the
 * last one goes away, whether that is the driver's own base reference
 * (xchan_teardown(), device gone) or the last open channel fd's (.release(),
 * possibly long after the device is gone). By this point xdev->vdev may
 * already be a dangling pointer (see xdev->removed), freeing xdev itself
 * never touches it.
 */
static inline void xchan_put(struct xchan_dev *xdev)
{
	if (refcount_dec_and_test(&xdev->refcnt)) {
		kfree(xdev->channels);
		kfree(xdev);
	}
}

#endif /* _XCHAN_PRIV_H */
