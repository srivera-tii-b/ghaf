/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * virtio-xchan guest driver: character device and channel acquisition.
 *
 * This file turns the virtio plumbing xchan_drv.c establishes into what
 * userspace actually talks to:
 *
 *   - a misc device, /dev/xchan0, whose only operation is XCHAN_WAIT_CHANNEL;
 *   - the per-channel-slot state machine driven by
 *     XCHAN_EV_ATTACHED / XCHAN_EV_DETACHED arriving on the eventq (queue 0,
 *     device -> driver), and, in the other direction, the
 *     XCHAN_CMD_CHANNEL_CLOSED notification this file posts on the commandq
 *     (queue 1, driver -> device) when a channel fd closes, without that,
 *     crosvm has no way to observe the "guest closed its fd" half of the
 *     slot-reuse rule (a slot is reused only once the peer has detached AND
 *     the guest has closed its fd);
 *   - per-channel file_operations, each fd bound to exactly one channel for
 *     the lifetime of that fd, there is no ioctl or syscall path here that
 *     lets one fd name a different channel's slot index;
 *   - the frame data path: XCHAN_SEND/XCHAN_RECV, window-buffer credit
 *     tracking and RELEASE, and fragment reassembly directly into the
 *     caller's destination buffer.
 *
 * The device is hostile, crosvm runs in the host, which this transport does
 * not trust. Every field this file reads out of an eventq event, a
 * control-queue command, or a data-path frame header is attacker-controlled
 * and is validated before it is used to index anything or change state,
 * bounds on `slot`, exact-size checks against what the transport actually
 * delivered, channel_id equality on detach, and, on the data path,
 * xchan_frame_validate() plus this file's own length/window_id checks (see
 * xchan_rx_vq_isr() and xchan_do_recv() below).
 */

#include <linux/anon_inodes.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/scatterlist.h>
/* schedule_timeout_killable() and fatal_signal_pending(): xchan_do_send()'s
 * bounded poll for room on a momentarily full chan->tx_vq.
 */
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/wait.h>

#include "xchan_frame.h"
#include "xchan_priv.h"
#include "xchan_uapi.h"

/*
 * Frame data path constants.
 *
 * XCHAN_INLINE_MAX: the most payload one frame carries in the virtqueue
 * descriptor itself. This is now the FRAGMENT size for every message, not a
 * cap above which a different mechanism takes over: the shared-memory window
 * cannot be mapped into a second protected guest under pKVM (see
 * xchan_do_send()), so a message longer than this is split into
 * XCHAN_F_MORE fragments of this size rather than copied through a window
 * buffer.
 *
 * Not raised as part of that change, deliberately: 4096 is what the
 * receiving side's rx inbufs are sized for (XCHAN_FRAME_BUF_SIZE below) and
 * what crosvm's relay bounds an inline payload by, so raising it is a
 * three-repository ABI change with a real cost, XCHAN_FRAME_BUF_SIZE x
 * queue depth x channels of pinned kernel memory per guest, to trade
 * against the ~2048 round trips fragmenting 8 MiB at 4096 costs. Worth
 * measuring, separately.
 *
 * XCHAN_FRAME_BUF_SIZE: size of every rx_vq inbuf. Header first
 * (sizeof(struct xchan_frame)), then room for the largest possible inline
 * payload, which is now every payload. (A WINDOW_REF frame uses only the
 * header portion, since its payload would live in the window instead; that
 * remains legal on the wire but nothing this driver sends produces one.)
 *
 * XCHAN_RX_QUEUE_DEPTH: how many such inbufs are kept posted per channel,
 * mirroring XCHAN_EVENT_QUEUE_DEPTH's reasoning, a fixed pool, clamped to
 * the queue's actual ring size in xchan_chardev_init().
 *
 * Raised from 8 to 32 while the driver still sent through the window: this
 * rx_vq then carried both the peer's data frames AND the RELEASE frames
 * returning credit for OUR OWN window sends, so the two independent
 * XCHAN_WINDOW_BUFS (16) credit limits, the peer's own outstanding
 * WINDOW_REF frames, and RELEASEs owed back to us, could both be near-full
 * on this one queue at once. 32 covers that combined worst case with
 * headroom, at a modest, bounded cost: XCHAN_FRAME_BUF_SIZE bytes per entry
 * (~4 KiB) times 32 is ~128 KiB of kernel memory per channel, ~2 MiB total
 * at the default max_channels=16, affordable on this platform.
 *
 * NOT load-bearing for correctness (unlike the old value of 8, which
 * effectively was): the actual fix for the relay dropping frames under
 * burst is crosvm-side backpressure, the relay stalls consumption from its
 * socket once this side has no inbuf posted, rather than acking and
 * silently dropping a frame with nowhere to put it, which is what turned an
 * 8-deep pool into a correctness bug in the first place (every such drop is
 * a permanent sequence gap, and a gap is fatal to the channel, ordinary
 * burst load was tearing down healthy channels). With that backpressure in
 * crosvm, this number only trades kernel memory against how deep a burst can
 * run before the relay has to stall; it is not a bound this driver's
 * correctness depends on.
 */
#define XCHAN_INLINE_MAX	4096U
#define XCHAN_FRAME_BUF_SIZE	(sizeof(struct xchan_frame) + XCHAN_INLINE_MAX)
#define XCHAN_RX_QUEUE_DEPTH	32U

/*
 * Depth of the pool of struct xchan_event buffers kept posted on the
 * eventq as inbufs. Lifecycle events are low frequency (one pair per
 * attaching/detaching peer, not per frame), so a small fixed pool refilled
 * immediately on each callback is enough headroom without scaling with
 * max_channels; clamped further to the queue's actual ring size in
 * xchan_chardev_init() in case a device advertises a smaller queue.
 */
#define XCHAN_EVENT_QUEUE_DEPTH 8U

/* ------------------------------------------------------------------ *
 * Shared window memory: one shared-memory region for the whole device;
 * slot k owns a contiguous TX/RX pair within it, addressed by direction of
 * travel rather than local role. This is the same layout xchan_chan_mmap()
 * maps into userspace (TX half only), xchan_slot_phys_offsets() below is
 * the arithmetic that function and xchan_setup_windows() both need,
 * extracted so the two can never drift out of sync with each other.
 * ------------------------------------------------------------------
 */

/*
 * Pure arithmetic: derives slot `slot`'s TX/RX physical base addresses
 * within an already-fetched shm `region`. Does not touch xdev->vdev, so it
 * needs no locking of its own, callers that fetched `region` via
 * virtio_get_shm_region() under xdev->lock may use the result after
 * unlocking, exactly as xchan_chan_mmap() already relies on for its own
 * post-unlock arithmetic.
 *
 * Returns 0 and fills *tx_phys and *rx_phys on success, or a negative errno if
 * the region does not fit this slot's pair or an address computation would
 * overflow, region.addr/region.len are device-supplied, so untrusted, and
 * every step is overflow-checked rather than ever computing a wrapped
 * address.
 */
static int xchan_slot_phys_offsets(const struct virtio_shm_region *region,
				   u32 window_slice_size, u32 endpoint,
				   u32 slot, phys_addr_t *tx_phys,
				   phys_addr_t *rx_phys)
{
	u64 pair_bytes, pair_offset, pair_end, tx_offset, rx_offset;
	u64 tx_phys_u64, rx_phys_u64;
	bool is_endpoint_a;

	pair_bytes = 2ULL * window_slice_size;
	pair_offset = (u64)slot * pair_bytes;

	if (check_add_overflow(pair_offset, pair_bytes, &pair_end))
		return -ENODEV;
	if (region->len < pair_end)
		return -ENODEV;

	is_endpoint_a = endpoint == 0;
	tx_offset = pair_offset + (is_endpoint_a ? window_slice_size : 0);
	rx_offset = pair_offset + (is_endpoint_a ? 0 : window_slice_size);

	if (check_add_overflow(region->addr, tx_offset, &tx_phys_u64))
		return -ENODEV;
	if (check_add_overflow(region->addr, rx_offset, &rx_phys_u64))
		return -ENODEV;

	*tx_phys = (phys_addr_t)tx_phys_u64;
	*rx_phys = (phys_addr_t)rx_phys_u64;
	return 0;
}

/*
 * Establishes every channel's kernel-side window mappings and slice_size,
 * once, at xchan_chardev_init() time (process context, before
 * misc_register(), no fd exists yet, so nothing else can be touching
 * xdev->channels concurrently, exactly the reasoning xchan_chardev_init()'s
 * eventq buffer posting already relies on for running lock-free).
 *
 * Best-effort per channel: a channel whose window cannot be mapped (feature
 * not negotiated, no window configured, region absent or malformed, or the
 * memremap() itself failing) is left with slice_size == 0 and NULL
 * tx_window/rx_window. Every data-path check downstream treats slice_size
 * == 0 the same way xchan_frame_validate() already does for a WINDOW_REF
 * frame, reject it, so an unmapped window degrades a channel to
 * inline-only rather than failing channel setup as a whole.
 *
 * TODO(inline): every channel is inline-only now regardless of what this
 * establishes, xchan_do_send() never touches chan->tx_window and
 * xchan_do_recv() only reads chan->rx_window for a WINDOW_REF frame no peer
 * running this driver emits. Left in place because retiring the window is
 * its own change; note that under pKVM the memremap() below is the last
 * thing that still touches the region at all, and that the "best-effort,
 * degrade to inline-only" posture it was given is exactly what makes a
 * failure here harmless now.
 */
static void xchan_setup_windows(struct xchan_dev *xdev)
{
	struct virtio_shm_region region;
	bool have_region;
	u32 i;

	have_region = virtio_has_feature(xdev->vdev, VIRTIO_XCHAN_F_WINDOW) &&
		      xdev->window_slice_size > 0 &&
		      virtio_get_shm_region(xdev->vdev, &region, 0);

	for (i = 0; i < xdev->max_channels; i++) {
		struct xchan_channel *chan = &xdev->channels[i];
		phys_addr_t tx_phys, rx_phys;

		if (!have_region)
			continue;

		if (xchan_slot_phys_offsets(&region, xdev->window_slice_size,
					    xdev->endpoint, i, &tx_phys,
					    &rx_phys))
			continue;

		chan->tx_window = memremap(tx_phys, xdev->window_slice_size,
					   MEMREMAP_WB);
		chan->rx_window = memremap(rx_phys, xdev->window_slice_size,
					   MEMREMAP_WB);
		if (!chan->tx_window || !chan->rx_window) {
			dev_warn(&xdev->vdev->dev,
				"xchan: slot %u window memremap failed, window sends disabled on this channel\n",
				i);
			if (chan->tx_window) {
				memunmap(chan->tx_window);
				chan->tx_window = NULL;
			}
			if (chan->rx_window) {
				memunmap(chan->rx_window);
				chan->rx_window = NULL;
			}
			continue;
		}

		/*
		 * window_slice_size / XCHAN_WINDOW_BUFS is not a locally
		 * chosen implementation detail: the subdivision of each half
		 * into XCHAN_WINDOW_BUFS (16) equally sized buffers is part
		 * of the WIRE CONTRACT with crosvm, exactly because a
		 * mismatch here would not fail loudly, it would make
		 * window_id resolve to a different byte offset at each end
		 * and silently misdirect payload. XCHAN_WINDOW_BUFS lives in
		 * xchan_frame.h (shared with xchan_frame_validate()'s own
		 * window_id bounds check) precisely so there is one
		 * definition of it in this repository, not a second one
		 * here that could drift from crosvm's.
		 *
		 * Only recorded once both halves are actually mapped: this
		 * is what every WINDOW_REF check downstream (both send and
		 * xchan_frame_validate() on receive) gates on, so a channel
		 * with a half-failed mapping must present as "no window",
		 * not as a mismatched capacity with nothing to back it.
		 */
		chan->slice_size = xdev->window_slice_size / XCHAN_WINDOW_BUFS;
	}
}

/* ------------------------------------------------------------------ *
 * RX buffer pool: the fixed set of driver-owned inbufs kept
 * posted on each channel's rx_vq for the device's lifetime.
 * ------------------------------------------------------------------
 */

/*
 * Reposts `rb` as a fresh inbuf on chan->rx_vq. Called with xdev->lock held
 * (touches chan->rx_vq, which is only guaranteed live while xdev->removed is
 * false, same rule as every other rx_vq/tx_vq access in this file) and
 * never sleeps (GFP_ATOMIC, and virtqueue_add_inbuf()/kick() do not sleep),
 * so it is safe from both the rx_vq ISR and process-context callers that
 * already hold the lock.
 *
 * A failure here (allocation-free, add_inbuf itself can only fail on a
 * full or torn-down ring) just leaves `rb` off the ring: the pool shrinks by
 * one for this channel's remaining lifetime rather than crashing or leaking
 * `rb` itself, which is still reachable through chan->rx_bufs and freed in
 * xchan_teardown(). Not reported to the caller, callers that need to know
 * degrade gracefully either way, and a channel that has lost every buffer in
 * its pool will simply stop delivering frames, which is visible.
 */
static void xchan_repost_rxbuf(struct xchan_dev *xdev,
			       struct xchan_channel *chan,
			       struct xchan_rxbuf *rb)
{
	struct scatterlist sg;

	if (xdev->removed)
		return;

	sg_init_one(&sg, rb->data, XCHAN_FRAME_BUF_SIZE);
	if (virtqueue_add_inbuf(chan->rx_vq, &sg, 1, rb, GFP_ATOMIC))
		return;

	virtqueue_kick(chan->rx_vq);
}

/*
 * Wraps xchan_repost_rxbuf() for callers that do NOT already hold
 * xdev->lock, xchan_do_recv() below, which pops an entry from
 * chan->rx_ready and then does a sleeping copy_to_user()/copy_from_user()
 * with no lock held at all (spin_lock_irqsave() must never wrap those) and
 * therefore cannot simply extend an existing critical section out to the
 * repost the way the ISR and xchan_slot_wipe() do. Takes the lock, reposts,
 * drops it: nothing else runs between those two steps, so this is exactly as
 * safe as any other in-lock repost, just packaged for a caller that is
 * unlocked at the call site.
 */
static void xchan_repost_rxbuf_locked(struct xchan_dev *xdev,
				      struct xchan_channel *chan,
				      struct xchan_rxbuf *rb)
{
	unsigned long flags;

	spin_lock_irqsave(&xdev->lock, flags);
	xchan_repost_rxbuf(xdev, chan, rb);
	spin_unlock_irqrestore(&xdev->lock, flags);
}

/*
 * Allocates and posts up to XCHAN_RX_QUEUE_DEPTH inbufs on one channel's
 * rx_vq. Called from xchan_chardev_init(), same lock-free process-context
 * reasoning as xchan_setup_windows() above, and additionally safe to call
 * xchan_repost_rxbuf() without xdev->lock specifically here because
 * xdev->removed is still false and cannot become true until this function's
 * caller (xchan_chardev_init()) returns and probe() proceeds, so the "safe
 * only while not removed" contract that function documents already holds by
 * construction.
 */
static void xchan_setup_rx_pool(struct xchan_dev *xdev,
				struct xchan_channel *chan)
{
	unsigned int depth, i;

	depth = min_t(unsigned int, XCHAN_RX_QUEUE_DEPTH,
		     virtqueue_get_vring_size(chan->rx_vq));
	if (depth == 0)
		return;

	chan->rx_bufs = kcalloc(depth, sizeof(*chan->rx_bufs), GFP_KERNEL);
	if (!chan->rx_bufs)
		return;

	for (i = 0; i < depth; i++) {
		chan->rx_bufs[i].data = kmalloc(XCHAN_FRAME_BUF_SIZE, GFP_KERNEL);
		if (!chan->rx_bufs[i].data)
			break;
		xchan_repost_rxbuf(xdev, chan, &chan->rx_bufs[i]);
	}
	chan->rx_depth = i;
}

/* ------------------------------------------------------------------ *
 * Per-slot state machine. Mirrors crosvm's own
 * ChannelTable::attach()/detach()/close()
 * (vendor/tegra234/devices/src/xchan/channel.rs) field for field, so both
 * sides of one slot's lifecycle reason about it identically even though this
 * driver never talks to that code directly.
 *
 * All four helpers below must be called with xdev->lock held.
 * ------------------------------------------------------------------
 */

static void xchan_slot_attach(struct xchan_channel *chan, u32 channel_id,
			      const struct xchan_event *evt)
{
	chan->state = XCHAN_SLOT_ACTIVE;
	chan->channel_id = channel_id;
	chan->peer_gone = false;
	chan->fd_closed = false;
	chan->flags = 0;
	memcpy(chan->peer_identity, evt->peer_identity,
	       sizeof(chan->peer_identity));
}

/*
 * Returns false if the signal was stale, duplicated, or names a slot that
 * was never attached, the ABA guard (slots are reused, channel ids never
 * are): a delayed or duplicated DETACHED naming a slot's *former* occupant
 * must never touch its current one. Callers must not act on a false return
 * beyond dropping the event.
 */
static bool xchan_slot_detach(struct xchan_channel *chan, u32 channel_id)
{
	if (chan->state == XCHAN_SLOT_FREE || chan->channel_id != channel_id)
		return false;

	chan->peer_gone = true;
	chan->state = chan->fd_closed ? XCHAN_SLOT_FREE : XCHAN_SLOT_DETACHED;
	return true;
}

/*
 * The guest's own half of the close signal: no channel_id to validate
 * against, because unlike detach() this is never driven by untrusted
 * device input, it only ever runs against the slot a live fd (or a
 * not-yet-issued one still on the ready list) was already holding.
 */
static void xchan_slot_close(struct xchan_channel *chan)
{
	chan->fd_closed = true;
	chan->state = chan->peer_gone ? XCHAN_SLOT_FREE : XCHAN_SLOT_CLOSED;
}

/*
 * Clears residual per-tenant data once a slot has reached XCHAN_SLOT_FREE,
 * so nothing leaks into whatever ATTACHED reuses it next. Safe to call
 * whether or not the channel was still on xdev->ready_list.
 *
 * Also resets the frame-data-path state a fresh occupant must not inherit: a
 * stale torn_down latch would fail every send/recv on a channel that has done
 * nothing wrong yet; stale tx_win_inuse bits would make this side believe
 * window buffers are lent out that no current peer holds, eventually starving
 * sends on a channel that has never hit real credit pressure; a stale rx_seq
 * would make this side reject the new tenant's very first, correctly-numbered
 * frame as a bogus gap (each channel's sequence counters start at 0, so a
 * fresh peer's tx_seq also restarts at 0, see tx_seq's own reset here); and
 * any frames left on rx_ready belonged to the previous tenant's stream and
 * must never be delivered to the next one. rx_vq/tx_vq, the window mappings
 * and the rx_bufs pool itself are NOT reset here: they are plumbing tied to
 * the slot for the device's whole lifetime, established once in
 * xchan_chardev_init(), not to any one occupant.
 */
static void xchan_slot_wipe(struct xchan_channel *chan)
{
	struct xchan_rxbuf *rb, *tmp;

	if (chan->waiting) {
		list_del(&chan->ready_link);
		chan->waiting = false;
	}
	chan->channel_id = 0;
	chan->flags = 0;
	memset(chan->peer_identity, 0, sizeof(chan->peer_identity));

	chan->torn_down = false;
	chan->tx_seq = 0;
	chan->rx_seq = 0;
	bitmap_zero(chan->tx_win_inuse, XCHAN_WINDOW_BUFS);

	list_for_each_entry_safe(rb, tmp, &chan->rx_ready, link) {
		list_del(&rb->link);
		xchan_repost_rxbuf(chan->xdev, chan, rb);
	}
}

/* ------------------------------------------------------------------ *
 * Eventq (queue 0, device -> driver): XCHAN_EV_ATTACHED / XCHAN_EV_DETACHED
 * processing.
 * ------------------------------------------------------------------
 */

/* Called with xdev->lock held. */
static void xchan_handle_attached(struct xchan_dev *xdev, u32 slot,
				  u32 channel_id, const struct xchan_event *evt)
{
	struct xchan_channel *chan = &xdev->channels[slot];

	if (chan->state != XCHAN_SLOT_FREE) {
		/*
		 * The device is hostile: a well-behaved backend never
		 * re-attaches an occupied slot, but a malicious or buggy one
		 * might. Accepting it would clobber live channel state
		 * (including a fd's peer_identity) out from under whatever
		 * holds the current fd. Drop it.
		 */
		dev_warn(&xdev->vdev->dev,
			"xchan: ATTACHED for occupied slot %u (state %d), dropping\n",
			slot, chan->state);
		return;
	}

	xchan_slot_attach(chan, channel_id, evt);

	chan->waiting = true;
	list_add_tail(&chan->ready_link, &xdev->ready_list);

	dev_info(&xdev->vdev->dev, "xchan: slot %u channel %u attached\n",
		slot, channel_id);

	wake_up_interruptible(&xdev->wait_q);
}

/*
 * Names an XCHAN_EV_DETACHED reason for the log. The value comes from the
 * untrusted device, so it is only ever printed, never acted on, and an
 * unrecognised one is reported as such.
 */
static const char *xchan_detach_reason_name(u32 reason)
{
	switch (reason) {
	case XCHAN_DETACH_PEER_CLOSED:
		return "peer closed";
	case XCHAN_DETACH_TORN_DOWN:
		return "closed by crosvm (protocol violation)";
	case XCHAN_DETACH_PEER_LOST:
		return "peer lost";
	default:
		return "unknown reason";
	}
}

/* Called with xdev->lock held. */
static void xchan_handle_detached(struct xchan_dev *xdev, u32 slot,
				  u32 channel_id, u32 reason)
{
	struct xchan_channel *chan = &xdev->channels[slot];

	if (!xchan_slot_detach(chan, channel_id)) {
		/*
		 * Stale/duplicated/spurious (the channel_id ABA guard) or a
		 * never-attached slot. Not logged: a hostile or merely buggy
		 * device could otherwise spam dmesg by replaying old
		 * DETACHED events, and there is nothing actionable to report
		 * beyond what was already safely ignored.
		 */
		return;
	}

	if (chan->state == XCHAN_SLOT_FREE) {
		/* fd_closed was already true: never claimed via
		 * XCHAN_WAIT_CHANNEL, or claimed and already released. Both
		 * halves of the reuse gate (peer detached, fd closed) are now
		 * satisfied.
		 */
		xchan_slot_wipe(chan);
		dev_info(&xdev->vdev->dev,
			"xchan: slot %u channel %u detached: %s (reason %u), slot released\n",
			slot, channel_id, xchan_detach_reason_name(reason),
			reason);
	} else {
		dev_info(&xdev->vdev->dev,
			"xchan: slot %u channel %u detached: %s (reason %u)\n",
			slot, channel_id, xchan_detach_reason_name(reason),
			reason);
		/* wake_up_all(), not wake_up_interruptible(): chan->poll_wq
		 * can host TASK_KILLABLE sleepers (xchan_rx_pop_ready()'s
		 * committed mode) that wake_up_interruptible() would not
		 * match.
		 */
		wake_up_all(&chan->poll_wq);
	}
}

/* Called with xdev->lock held. */
static void xchan_process_ctrl_event(struct xchan_dev *xdev,
				     const struct xchan_event *evt,
				     unsigned int len)
{
	u32 type, slot, channel_id, reason;

	/*
	 * The device is hostile: never assume len matches what was actually
	 * delivered. A short or long buffer means the fields below cannot be
	 * trusted at all; drop the whole event rather than read a
	 * partially-written struct.
	 */
	if (len != sizeof(*evt)) {
		dev_warn(&xdev->vdev->dev,
			"xchan: control event has bad length %u (want %zu), dropping\n",
			len, sizeof(*evt));
		return;
	}

	type = le32_to_cpu(evt->type);
	slot = le32_to_cpu(evt->slot);
	channel_id = le32_to_cpu(evt->channel_id);
	reason = le32_to_cpu(evt->reason);

	/*
	 * Bounds-check the device-supplied slot before it is ever used to
	 * index xdev->channels[]: never index an array by a device-supplied
	 * value unchecked.
	 */
	if (slot >= xdev->max_channels) {
		dev_warn(&xdev->vdev->dev,
			"xchan: control event names out-of-range slot %u (max %u), dropping\n",
			slot, xdev->max_channels);
		return;
	}

	switch (type) {
	case XCHAN_EV_ATTACHED:
		xchan_handle_attached(xdev, slot, channel_id, evt);
		break;
	case XCHAN_EV_DETACHED:
		xchan_handle_detached(xdev, slot, channel_id, reason);
		break;
	default:
		/* Fail closed on anything unrecognised. */
		dev_warn(&xdev->vdev->dev,
			"xchan: unknown control event type %u on slot %u, dropping\n",
			type, slot);
		break;
	}
}

/* Posts one buffer as an inbuf on the eventq for the device to fill
 * with a future lifecycle event. Called both at initial setup (process
 * context) and to re-arm from the callback (may run in softirq context on
 * some transports), GFP_ATOMIC is correct and safe in both.
 */
static int xchan_post_event_buf(struct xchan_dev *xdev, struct xchan_event *evt)
{
	struct scatterlist sg;

	sg_init_one(&sg, evt, sizeof(*evt));
	return virtqueue_add_inbuf(xdev->event_vq, &sg, 1, evt, GFP_ATOMIC);
}

void xchan_event_vq_isr(struct virtqueue *vq)
{
	struct xchan_dev *xdev = vq->vdev->priv;
	struct xchan_event *evt;
	unsigned int len;
	unsigned long flags;

	if (!xdev)
		return;

	spin_lock_irqsave(&xdev->lock, flags);

	if (xdev->removed) {
		/* Torn down concurrently; the queue is about to be (or has
		 * been) destroyed by xchan_teardown(). Nothing left to do.
		 */
		spin_unlock_irqrestore(&xdev->lock, flags);
		return;
	}

	while ((evt = virtqueue_get_buf(vq, &len)) != NULL) {
		xchan_process_ctrl_event(xdev, evt, len);

		/*
		 * Re-arm immediately: the buffer is ours again the instant
		 * get_buf() returns it, and leaving it off the queue would
		 * shrink the eventq's effective depth on every event
		 * processed. A repost failure here is logged and simply
		 * drops that one buffer's future capacity rather than
		 * crashing, the remaining posted buffers keep the queue
		 * usable.
		 */
		if (xchan_post_event_buf(xdev, evt))
			dev_warn(&xdev->vdev->dev,
				"xchan: failed to repost event buffer\n");
	}

	spin_unlock_irqrestore(&xdev->lock, flags);

	virtqueue_kick(vq);
}

/* ------------------------------------------------------------------ *
 * Commandq (queue 1, driver -> device): posting XCHAN_CMD_CHANNEL_CLOSED
 * and reclaiming the buffers once the device has consumed them.
 * ------------------------------------------------------------------
 */

/*
 * Posts an XCHAN_CMD_CHANNEL_CLOSED command on the commandq: the driver's half
 * of the close-notification path. Without this, crosvm, which owns slot
 * allocation, has no way to learn the guest has closed a channel fd, and the
 * "close" half of the slot-reuse rule can never be satisfied no matter what
 * the peer does. channel_id is included for the same reason
 * xchan_slot_detach() above validates it: a delayed or duplicated close must
 * not be attributed to whatever tenant occupies this slot by the time the
 * device gets around to processing it.
 *
 * Called with xdev->lock held (spin_lock_irqsave), and every step below is
 * safe in that context: the allocation is GFP_ATOMIC (never sleeps) and
 * virtqueue_add_outbuf()/virtqueue_kick() never sleep either. Holding the lock
 * for all of it, rather than dropping it partway through, is what keeps this
 * safe against a concurrent xchan_remove(): xdev->cmd_vq is only guaranteed to
 * still exist for as long as xdev->removed is false, by the same reasoning
 * documented at length in xchan_chan_mmap() and xchan_chan_release() below
 * (xchan_chardev_exit() sets xdev->removed under this same lock, and
 * xchan_teardown() cannot reach del_vqs() until xchan_chardev_exit(), which
 * needs this lock too, has returned). Failure to post (allocation failure or
 * a full ring) is logged and dropped: a guest that never gets its close heard
 * simply never gets that slot reused, which is self-inflicted and not a
 * security issue, so there is nothing more aggressive to do here (no retry
 * queue).
 */
static void xchan_post_channel_closed(struct xchan_dev *xdev, u32 slot,
				  u32 channel_id)
{
	struct xchan_command *cmd;
	struct scatterlist sg;

	if (xdev->removed)
		return;

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd) {
		dev_warn(&xdev->vdev->dev,
			"xchan: failed to allocate CHANNEL_CLOSED for slot %u channel %u, not sent\n",
			slot, channel_id);
		return;
	}

	cmd->type = cpu_to_le32(XCHAN_CMD_CHANNEL_CLOSED);
	cmd->slot = cpu_to_le32(slot);
	cmd->channel_id = cpu_to_le32(channel_id);
	cmd->reserved = 0;

	sg_init_one(&sg, cmd, sizeof(*cmd));

	if (virtqueue_add_outbuf(xdev->cmd_vq, &sg, 1, cmd, GFP_ATOMIC)) {
		dev_warn(&xdev->vdev->dev,
			"xchan: failed to post CHANNEL_CLOSED for slot %u channel %u, not sent\n",
			slot, channel_id);
		kfree(cmd);
		return;
	}

	virtqueue_kick(xdev->cmd_vq);
}

/*
 * Reclaims struct xchan_command buffers posted by
 * xchan_post_channel_closed() once the device has consumed them. The
 * commandq is driver -> device, so there is no payload to process here the
 * way xchan_event_vq_isr() processes incoming events, this only frees the
 * outbuf's backing memory, which xchan_post_channel_closed() allocated with
 * kmalloc() per command rather than from a fixed pool (close is rare enough
 * that pooling would be needless complexity).
 */
void xchan_cmd_vq_isr(struct virtqueue *vq)
{
	struct xchan_dev *xdev = vq->vdev->priv;
	struct xchan_command *cmd;
	unsigned int len;
	unsigned long flags;

	if (!xdev)
		return;

	spin_lock_irqsave(&xdev->lock, flags);

	if (xdev->removed) {
		/* Torn down concurrently; the queue is about to be (or has
		 * been) destroyed by xchan_teardown(). Nothing left to
		 * reclaim through.
		 */
		spin_unlock_irqrestore(&xdev->lock, flags);
		return;
	}

	while ((cmd = virtqueue_get_buf(vq, &len)) != NULL)
		kfree(cmd);

	spin_unlock_irqrestore(&xdev->lock, flags);
}

/* ------------------------------------------------------------------ *
 * Frame data path: per-channel RX/TX queues.
 *
 * rx_vq (device -> driver) carries both real data frames from the peer and
 * RELEASE frames returning credit for THIS side's earlier window sends, both
 * travel on the same queue; there is no separate control path for RELEASE.
 * xchan_rx_vq_isr() below classifies every completion: RELEASE is fully
 * handled right there (pure bookkeeping, safe in interrupt context, and
 * deliberately NOT deferred to XCHAN_RECV, a single-threaded requester
 * blocked inside XCHAN_SEND waiting on window credit would otherwise deadlock
 * waiting for a RELEASE that only a RECV call would ever drain). A real data
 * frame is queued on chan->rx_ready for XCHAN_RECV to validate against the
 * caller's actual destination capacity and copy out in process context, where
 * copy_to_user() is legal and sleeping is fine.
 *
 * tx_vq (driver -> device) has no installed callback (xchan_drv.c leaves it
 * NULL): XCHAN_SEND reclaims completed outbufs opportunistically on its own
 * next call (xchan_tx_reap()) instead, which keeps the TX side out of
 * interrupt context entirely.
 * ------------------------------------------------------------------
 */

void xchan_rx_vq_isr(struct virtqueue *vq)
{
	struct xchan_dev *xdev = vq->vdev->priv;
	struct xchan_channel *chan;
	struct xchan_rxbuf *rb;
	struct xchan_frame hdr;
	unsigned long flags;
	unsigned int slot, len;
	bool wake = false;

	if (!xdev)
		return;

	/*
	 * vq->index is 2 + 2*slot for every RX queue, xchan_drv.c's probe()
	 * only ever installs this callback on those indices, so the arithmetic
	 * is exact rather than a guess. Still bounds-checked before it indexes
	 * xdev->channels[]: failing closed here costs nothing even though
	 * vq->index itself comes from this driver's own virtio_find_vqs()
	 * call, not from the device.
	 */
	slot = (vq->index - 2) / 2;
	if (slot >= xdev->max_channels)
		return;
	chan = &xdev->channels[slot];

	spin_lock_irqsave(&xdev->lock, flags);

	if (xdev->removed) {
		/* Torn down concurrently; the queue is about to be (or has
		 * been) destroyed by xchan_teardown(). Nothing left to do.
		 */
		spin_unlock_irqrestore(&xdev->lock, flags);
		return;
	}

	while ((rb = virtqueue_get_buf(chan->rx_vq, &len)) != NULL) {
		/*
		 * No occupant currently holds this slot (the window between a
		 * prior tenant's slot going FREE and a future ATTACHED). Data
		 * frames carry no channel_id, only the control plane's
		 * ATTACHED/DETACHED events do, so a stray completion
		 * arriving here cannot be attributed to anyone. A well-behaved
		 * crosvm should not be relaying anything for an unattached
		 * slot in the first place (this is exactly what the
		 * detach+close gate exists to ensure before a slot is reused),
		 * but this does not rely on that: discard rather than risk it
		 * landing on chan->rx_ready for whichever tenant attaches
		 * next.
		 */
		if (chan->state == XCHAN_SLOT_FREE) {
			xchan_repost_rxbuf(xdev, chan, rb);
			continue;
		}

		/*
		 * Never trust the transport's own length before trusting
		 * anything it delivered: a completion shorter than one header
		 * cannot even be read as a struct xchan_frame. This is itself
		 * a protocol violation, fail closed rather than silently
		 * drop it: a silent drop here would also desynchronise the
		 * rx_seq check below, since the frame that was supposed to
		 * occupy this sequence slot would never be accounted for,
		 * surfacing as a confusing "gap" on whatever arrives next
		 * instead of at its actual cause.
		 *
		 * The upper bound matters more. `len` is the used length the
		 * DEVICE wrote, i.e. the host's claim, and the virtio core
		 * does not check it against the buffer. It becomes rb->len,
		 * which xchan_do_recv() treats as the bound on how many bytes
		 * it may copy out of rb->data. A host that reports more than
		 * the XCHAN_FRAME_BUF_SIZE bytes this inbuf holds would turn
		 * that check into a copy_to_user() past the end of the
		 * allocation: guest heap, possibly other channels' frames,
		 * handed to userspace, which may then send it on.
		 */
		if (len < sizeof(hdr) || len > XCHAN_FRAME_BUF_SIZE) {
			chan->torn_down = true;
			wake = true;
			xchan_repost_rxbuf(xdev, chan, rb);
			continue;
		}

		/*
		 * Copy the header out of the driver-owned inbuf before
		 * inspecting it, and validate only the copy, the rule for
		 * anything read out of peer-writable memory, applied
		 * uniformly here even though this buffer is not the
		 * peer-writable shared window: one code shape everywhere a
		 * frame header is read, and defence in depth.
		 *
		 * dst_cap is U32_MAX here deliberately. This call exists only
		 * to safely classify RELEASE vs. data and bounds-check
		 * window_id before it can index tx_win_inuse, it is not
		 * enforcing the caller's real destination capacity, which this
		 * ISR has no way to know. XCHAN_RECV (xchan_do_recv() below)
		 * re-validates every data frame against the real capacity,
		 * from its OWN independently copied header, before copying
		 * anything to userspace, that second validation is the
		 * load-bearing one, not this one.
		 */
		memcpy(&hdr, rb->data, sizeof(hdr));

		if (xchan_frame_validate(&hdr, chan->slice_size, U32_MAX)) {
			/* Protocol violation: fail closed.
			 * torn_down makes every subsequent XCHAN_SEND/RECV on
			 * this channel return -ECONNRESET from here on.
			 */
			chan->torn_down = true;
			wake = true;
			xchan_repost_rxbuf(xdev, chan, rb);
			continue;
		}

		/*
		 * Sequencing: this direction's frames, data AND RELEASE
		 * alike, since RELEASE is just another frame in the peer's TX
		 * stream, carry one strict monotonic counter. Checked HERE,
		 * uniformly, in the ring's actual arrival order, rather than
		 * deferred to XCHAN_RECV: a RELEASE is fully consumed in this
		 * ISR and never reaches XCHAN_RECV, so a check placed there
		 * could never see a gap or replay hidden inside a
		 * dropped/replayed RELEASE, and could also misidentify
		 * ordinary interleaving of data and RELEASE frames as a gap if
		 * the two were checked against the counter at different times.
		 * This check is this side's own and does not trust crosvm's
		 * bookkeeping to have done it already: crosvm constructs the
		 * headers this driver reads, so a check performed there is the
		 * adversary checking itself against a malicious host,
		 * accepting last_seen + 1 and nothing else here is what makes
		 * the design's asserted replay/reorder-detection property
		 * actually true.
		 */
		if (le64_to_cpu(hdr.seq) != chan->rx_seq) {
			chan->torn_down = true;
			wake = true;
			xchan_repost_rxbuf(xdev, chan, rb);
			continue;
		}
		chan->rx_seq++;

		if (le16_to_cpu(hdr.flags) & XCHAN_F_RELEASE) {
			/*
			 * window_id was already bounds-checked by
			 * xchan_frame_validate() above (a RELEASE frame's
			 * window_id must be checked precisely because it
			 * indexes this array), safe to use directly.
			 */
			clear_bit(le16_to_cpu(hdr.window_id), chan->tx_win_inuse);
			wake = true;
			xchan_repost_rxbuf(xdev, chan, rb);
			continue;
		}

		/*
		 * A real data frame: record the byte count virtqueue_get_buf()
		 * actually reported, not hdr.len (still adversary-controlled
		 * at this point), XCHAN_RECV re-validates hdr.len against
		 * this same figure before trusting it to bound an inline
		 * payload copy (never assume len matches what was actually
		 * delivered).
		 */
		rb->len = len;
		list_add_tail(&rb->link, &chan->rx_ready);
		wake = true;
	}

	/* wake_up_all(), not wake_up_interruptible(): chan->poll_wq can
	 * host TASK_KILLABLE sleepers (xchan_rx_pop_ready()'s committed
	 * mode) that wake_up_interruptible() would not match, silently
	 * never waking a committed drain/receive.
	 */
	if (wake)
		wake_up_all(&chan->poll_wq);

	spin_unlock_irqrestore(&xdev->lock, flags);
}

/*
 * Reclaims completed outbufs on chan->tx_vq, freeing the kmalloc()'d
 * buffers XCHAN_SEND posted for them (there is no TX interrupt callback,
 * see the section comment above, so this happens opportunistically
 * instead). Called with xdev->lock already held; never sleeps.
 */
static void xchan_tx_reap(struct xchan_channel *chan)
{
	void *buf;
	unsigned int len;

	while ((buf = virtqueue_get_buf(chan->tx_vq, &len)) != NULL)
		kfree(buf);
}

/*
 * Posts one already-filled TX buffer (a header, or a header immediately
 * followed by an inline payload) as a single outbuf on chan->tx_vq,
 * assigning it the next sequence number ITSELF, in the same critical
 * section as the post, rather than trusting a value the caller computed
 * earlier.
 *
 * This ordering is load-bearing, not a style choice: a caller that assigned
 * `hdr->seq = chan->tx_seq++` before reaching here would have already consumed
 * that sequence number even if the post below then fails with -EAGAIN (ring
 * full). That number would never reach the wire, permanently opening a gap in
 * this direction's sequence stream for a purely local reason, and the peer's
 * strict monotonic check cannot tell that apart from a real dropped frame.
 * Assigning and committing chan->tx_seq++ only once virtqueue_add_outbuf() has
 * actually succeeded makes that impossible: a failed post leaves the counter
 * untouched, so the next successful post anywhere (this call retried, or the
 * next one) reuses the same number rather than skipping it.
 *
 * `buf` must begin with a struct xchan_frame whose every field except `seq`
 * is already filled in by the caller. Takes xdev->lock itself (mirrors
 * xchan_post_channel_closed()'s reasoning: the allocation is GFP_ATOMIC,
 * add_outbuf()/kick() never sleep, and touching chan->tx_vq requires both
 * the lock and a fresh xdev->removed/torn_down check regardless of what the
 * caller verified earlier, since callers here always drop the lock for a
 * copy_from_user() first).
 *
 * On success, ownership of `buf` passes to the virtqueue (reclaimed later by
 * xchan_tx_reap()) and this returns 0. On failure `buf` is freed here and a
 * negative errno is returned: -ENODEV if the device is gone, -ECONNRESET if
 * this channel already failed closed, -EAGAIN if the ring has no room
 * (XCHAN_SEND returns EAGAIN when out of credit; a full local ring is this
 * driver's own form of that).
 */
static int xchan_tx_post(struct xchan_dev *xdev, struct xchan_channel *chan,
			 void *buf, size_t len)
{
	struct xchan_frame *hdr = buf;
	struct scatterlist sg;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&xdev->lock, flags);

	if (xdev->removed) {
		ret = -ENODEV;
		goto out_unlock;
	}
	if (chan->torn_down || chan->state == XCHAN_SLOT_DETACHED) {
		ret = -ECONNRESET;
		goto out_unlock;
	}

	xchan_tx_reap(chan);

	hdr->seq = cpu_to_le64(chan->tx_seq);

	sg_init_one(&sg, buf, len);
	if (virtqueue_add_outbuf(chan->tx_vq, &sg, 1, buf, GFP_ATOMIC)) {
		ret = -EAGAIN;
		goto out_unlock;
	}

	chan->tx_seq++;
	virtqueue_kick(chan->tx_vq);
	spin_unlock_irqrestore(&xdev->lock, flags);
	return 0;

out_unlock:
	spin_unlock_irqrestore(&xdev->lock, flags);
	kfree(buf);
	return ret;
}

/*
 * Undoes a tentative tx_win_inuse reservation that never made it onto the
 * wire (a copy_from_user() fault or an allocation failure after the bit was
 * set, below in xchan_do_send()). Purely local bookkeeping, the peer was
 * never told about this window_id, unlike xchan_send_release() below, which
 * sends an actual RELEASE frame for a buffer the peer DOES know it lent out.
 *
 * TODO(inline): dead. Its only caller was xchan_do_send()'s window-
 * fragmentation loop, which now fragments inline instead (see that
 * function's comment for why the window cannot be used under pKVM at all).
 * __maybe_unused rather than deleted because retiring the window is a change
 * of its own, deleting this alone would mean also removing tx_win_inuse,
 * the readiness gate and the RELEASE protocol.
 */
static void __maybe_unused xchan_tx_win_free(struct xchan_dev *xdev,
			      struct xchan_channel *chan, unsigned int wid)
{
	unsigned long flags;

	spin_lock_irqsave(&xdev->lock, flags);
	clear_bit(wid, chan->tx_win_inuse);
	spin_unlock_irqrestore(&xdev->lock, flags);
	/* wake_up_all(): see xchan_rx_vq_isr()'s identical comment,
	 * chan->poll_wq can host TASK_KILLABLE sleepers now.
	 */
	wake_up_all(&chan->poll_wq);
}

/*
 * Posts a RELEASE frame on chan->tx_vq naming `window_id`, returning that
 * window buffer to the peer that lent it. Sent by xchan_do_recv() as soon as
 * its copy of a WINDOW_REF frame's payload completes, not when userspace is
 * done with the data, which is the property that keeps buffer-lifetime
 * tracking out of libxchan entirely. Best-effort: a failure here (allocation,
 * or a full ring) is dropped, the peer's window buffer simply stays lent out
 * longer than necessary rather than the receive itself failing, the same
 * bounded, self-recovering posture xchan_post_channel_closed() documents for
 * its own failure path.
 */
static void xchan_send_release(struct xchan_dev *xdev,
			       struct xchan_channel *chan, u16 window_id)
{
	struct xchan_frame *rel;

	rel = kmalloc(sizeof(*rel), GFP_KERNEL);
	if (!rel)
		return;

	/* seq is assigned by xchan_tx_post() itself, only once the post
	 * actually succeeds, see its comment for why that ordering matters.
	 */
	rel->len = cpu_to_le32(0);
	rel->flags = cpu_to_le16(XCHAN_F_RELEASE);
	rel->window_id = cpu_to_le16(window_id);

	/* xchan_tx_post() takes xdev->lock itself, checks xdev->removed/
	 * chan->torn_down/detached, and frees rel on any failure path;
	 * nothing further to do with the return value here, a dropped
	 * RELEASE is a bounded, self-recovering leak of one window buffer,
	 * not a correctness issue for this call.
	 */
	xchan_tx_post(xdev, chan, rel, sizeof(*rel));
}

/*
 * Posts an XCHAN_F_ABORT frame ending an in-progress fragmented message that
 * xchan_do_send() below cannot finish. Needed only once at least one fragment
 * of THIS message has already gone out with XCHAN_F_MORE set, see the
 * `committed` local in xchan_do_send(), because only then has the peer's
 * XCHAN_RECV committed to a TASK_KILLABLE wait (xchan_rx_pop_ready()'s
 * "committed" mode) for a continuation that, without this, would never arrive:
 * nothing short of killing the receiving process would ever free it. A message
 * that never got as far as a MORE fragment needs no abort, the peer was
 * never told this message existed at all, so there is nothing for it to be
 * waiting on.
 *
 * Deliberately a header-only control frame like XCHAN_F_RELEASE, not a
 * window-path data frame: xchan_frame.c rejects XCHAN_F_ABORT combined with
 * XCHAN_F_WINDOW_REF, so an abort never needs window credit. Like every frame
 * it does need room on chan->tx_vq, and it is posted once, without the retry
 * data fragments get: if the ring is still full the abort is dropped (see
 * "Best-effort" below).
 *
 * Called from xchan_do_send()'s `out` label, still under chan->send_lock:
 * that serialises it against any other XCHAN_SEND on this channel, so this
 * is guaranteed to be the very next frame after the last successfully
 * posted fragment, no other call's fragment can land between them and be
 * mistaken for part of the aborted message.
 *
 * Best-effort, same posture as xchan_send_release(): xchan_tx_post() frees the
 * frame and returns a negative errno on any failure (device gone, channel
 * already independently torn down, allocation failure, full ring), and that
 * outcome is discarded here. There is no second failure mode this introduces,
 * if the abort itself cannot be sent, the peer is in exactly the state it
 * would have been in without the abort frame, never worse; this is a
 * best-effort attempt to avoid that, not a guarantee, and xchan_do_send()
 * always returns the ORIGINAL error regardless of whether this succeeded.
 */
static void xchan_send_abort(struct xchan_dev *xdev, struct xchan_channel *chan)
{
	struct xchan_frame *hdr;

	hdr = kmalloc(sizeof(*hdr), GFP_KERNEL);
	if (!hdr)
		return;

	/* seq is assigned by xchan_tx_post() itself, only once the post
	 * actually succeeds, see that function's comment.
	 */
	hdr->len = cpu_to_le32(0);
	hdr->flags = cpu_to_le16(XCHAN_F_ABORT);
	hdr->window_id = cpu_to_le16(0);

	xchan_tx_post(xdev, chan, hdr, sizeof(*hdr));
}

/*
 * How many times one fragment's post is retried after -EAGAIN (chan->tx_vq
 * momentarily full) before XCHAN_SEND gives up, and how long each retry
 * waits.
 *
 * This bound exists because inline fragmentation multiplies the frame count
 * of a large message by ~128 relative to the window path it replaces (4 KiB
 * per frame instead of one 512 KiB window buffer), and chan->tx_vq is 256
 * entries deep: a 1 MiB message is 256 frames, exactly the whole ring, so
 * "the ring is momentarily full while crosvm catches up" moved from
 * essentially unreachable to routine. Without a retry, that transient
 * returns -EAGAIN mid-message, which (correctly, see xchan_do_send())
 * aborts the message at the peer, a hard failure on an entirely healthy
 * channel.
 *
 * A poll rather than a wait, deliberately: tx_vq has no completion callback
 * (see the tx_vq section comment above), so there is nothing to be woken BY.
 * Each iteration re-enters xchan_tx_post(), which reaps completed outbufs
 * under xdev->lock before trying again, so the retry is what makes room
 * visible. TASK_KILLABLE so a stuck channel cannot make a process
 * unkillable, and bounded so it cannot spin forever against a dead relay:
 * ~2s at HZ=1000 per fragment, after which the original -EAGAIN is returned
 * and the mid-message abort path runs exactly as before.
 */
#define XCHAN_TX_POST_RETRIES	2000U

/*
 * Builds and posts one inline fragment of a message: allocates a
 * header-plus-payload buffer, copies `chunk` bytes from the caller's buffer
 * at `user_off` into it, and hands it to xchan_tx_post().
 *
 * The frame carries its payload inline, immediately after its own header,
 * no XCHAN_F_WINDOW_REF, no window_id, and XCHAN_F_MORE exactly when
 * `more` says another fragment follows.
 *
 * Does the allocation and the copy_from_user() itself rather than taking a
 * pre-built buffer specifically so xchan_do_send()'s retry loop can call it
 * again after a full-ring -EAGAIN: xchan_tx_post() takes ownership of the
 * buffer it is given and frees it on every failure path (see its comment),
 * so a retry cannot reuse the previous attempt's buffer and must rebuild it.
 * Repeating a 4 KiB copy_from_user() on the rare full-ring retry is the
 * cheaper of the two options, the alternative is changing
 * xchan_tx_post()'s ownership-on-failure contract for all four of its call
 * sites, where a single missed free is a leak.
 *
 * Returns 0 once the fragment is on the ring, or a negative errno
 * (-ENOMEM/-EFAULT locally, or whatever xchan_tx_post() returned).
 */
static int xchan_send_fragment(struct xchan_dev *xdev,
			       struct xchan_channel *chan,
			       const struct xchan_msg *msg, u64 user_off,
			       u32 chunk, bool more)
{
	struct xchan_frame *hdr;
	void *buf;

	buf = kmalloc(sizeof(*hdr) + chunk, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	hdr = buf;

	if (chunk &&
	    copy_from_user((u8 *)buf + sizeof(*hdr),
			   (const u8 __user *)(unsigned long)msg->addr + user_off,
			   chunk)) {
		kfree(buf);
		return -EFAULT;
	}

	/* seq is assigned by xchan_tx_post() itself; everything else this
	 * frame needs is filled in here.
	 */
	hdr->len = cpu_to_le32(chunk);
	hdr->flags = cpu_to_le16(more ? XCHAN_F_MORE : 0);
	hdr->window_id = cpu_to_le16(0);

	return xchan_tx_post(xdev, chan, buf, sizeof(*hdr) + chunk);
}

/*
 * XCHAN_SEND. Every payload travels inline, in the virtqueue descriptor
 * itself: a message longer than XCHAN_INLINE_MAX is split into XCHAN_F_MORE
 * fragments of at most XCHAN_INLINE_MAX bytes, the final fragment unmarked,
 * and xchan_do_recv() on the far side reassembles them.
 *
 * WHY NOT THE WINDOW (the change this function's shape exists for): the
 * shared-memory window cannot be used under pKVM at all. Mapping a window
 * into a second protected guest kills that guest's vCPU with -EREMOTEIO,
 * established by analysis and then reproduced on an Orin AGX, where the
 * first-light smoke test passed at 4096 bytes and died at 16384, which is
 * exactly the old inline/window boundary. So the choice this function used
 * to make by size is gone: there is one path, and it is inline.
 *
 * The fragmentation and reassembly machinery itself is not new, it was
 * built for the window path and is simply no longer wired to it. What
 * changed here is that a fragment's bytes are copied into the frame's own
 * inline payload instead of into chan->tx_window, and the header goes out
 * with XCHAN_F_MORE alone instead of XCHAN_F_WINDOW_REF | XCHAN_F_MORE.
 *
 * TODO(inline): chan->tx_window, chan->slice_size, chan->tx_win_inuse,
 * xchan_tx_win_free() and xchan_send_release() are no longer reachable from
 * this function. They are left in place deliberately: retiring the window
 * is a change of its own, and the window's read-only/read-write split
 * between the two guests, RELEASE frames, the crosvm-side WindowPool and
 * readiness gate all go with it.
 *
 * Serialised against any other XCHAN_SEND on this same channel by
 * chan->send_lock (see its field comment) so a multi-fragment message's
 * pieces are never interleaved with another call's, and so sequence numbers
 * are assigned in the same order frames actually reach the wire.
 *
 * Returns 0 having sent the caller's entire msg->len bytes, or a negative
 * errno. Never a partial byte count: libxchan's xchan_send() maps 0 straight
 * onto msg->len for its own ssize_t return.
 *
 * A MID-MESSAGE SEND FAILURE MUST NOT WEDGE THE PEER. Without the abort below,
 * any error return here after at least one fragment had already gone out with
 * XCHAN_F_MORE set would leave the peer's XCHAN_RECV committed to the rest of
 * the message and blocked in a TASK_KILLABLE wait with nothing to wake it but
 * killing that process, -EFAULT from a bad user pointer, -ENOMEM from an
 * allocation failure, -EAGAIN from a local ring that stayed full for
 * XCHAN_TX_POST_RETRIES, and -EINTR from a fatal signal while polling for ring
 * room could all strand a perfectly healthy peer this way. This matters MORE
 * now than it did on the window path, not less: a 1 MiB message is 256 inline
 * fragments rather than 2 window ones, so there are two orders of magnitude
 * more places for a mid-message failure to land. `committed` below tracks
 * whether the peer's receive is in that state; if it is, the shared `out`
 * label posts an explicit XCHAN_F_ABORT frame (xchan_send_abort() above)
 * before returning the original error, so the peer's XCHAN_RECV fails cleanly
 * with -ECANCELED (xchan_do_recv() below) instead of hanging. This is
 * deliberately NOT channel teardown: every failure above is local and
 * transient, and tearing the whole channel down for a transient,
 * non-adversarial failure would trade one self-inflicted denial-of-service for
 * another.
 */
static int xchan_do_send(struct xchan_dev *xdev, struct xchan_channel *chan,
			 bool nonblock, const struct xchan_msg *msg)
{
	int ret;
	u32 remaining = msg->len;
	u64 user_off = 0;
	/*
	 * True once at least one fragment of THIS message has gone out with
	 * XCHAN_F_MORE set, i.e. the peer's XCHAN_RECV is now committed to
	 * receiving the rest. Stays false for any message that fits in a
	 * single frame (msg->len <= XCHAN_INLINE_MAX, zero-length included),
	 * so the abort check at `out` below is a no-op for those. See
	 * xchan_send_abort()'s and this function's own comments for why this
	 * is the condition that matters, not merely "did the fragmentation
	 * loop run at all".
	 */
	bool committed = false;

	mutex_lock(&chan->send_lock);

	/*
	 * One loop for every size, entered unconditionally rather than
	 * guarded by `while (remaining > 0)`: a zero-length message is a legal
	 * send and must still put exactly one frame (len 0, no MORE) on the
	 * wire, which a pre-tested loop would skip entirely. `more` is
	 * computed from whether anything is left AFTER this chunk, so the
	 * final fragment, and a single-fragment message's only frame, is
	 * correctly unmarked.
	 */
	for (;;) {
		u32 chunk = min_t(u32, remaining, XCHAN_INLINE_MAX);
		bool more = remaining > chunk;
		unsigned int attempts = 0;

		for (;;) {
			ret = xchan_send_fragment(xdev, chan, msg, user_off,
						  chunk, more);
			if (ret != -EAGAIN)
				break;

			/*
			 * chan->tx_vq is momentarily full. O_NONBLOCK means
			 * exactly "do not wait", so it still fails fast
			 * (XCHAN_SEND returns EAGAIN when out of credit, and a
			 * full local ring is this driver's own form of that).
			 */
			if (nonblock)
				break;

			if (++attempts > XCHAN_TX_POST_RETRIES)
				break;

			/*
			 * Bounded poll, not a wait: there is no TX completion
			 * callback to be woken by (see the tx_vq section
			 * comment), and it is the next xchan_send_fragment()
			 * call re-entering xchan_tx_post(), which reaps
			 * completed outbufs under xdev->lock, that makes
			 * room visible. TASK_KILLABLE so this can never make
			 * the calling process unkillable; a fatal signal ends
			 * the send with -EINTR and the mid-message abort below
			 * tells the peer.
			 */
			if (schedule_timeout_killable(1) ||
			    fatal_signal_pending(current)) {
				ret = -EINTR;
				break;
			}
		}
		if (ret)
			goto out;

		/*
		 * This fragment reached the wire. If it carried MORE, the
		 * peer's XCHAN_RECV is now committed to waiting for a
		 * continuation, any failure on a later fragment of this same
		 * call from here on must tell that receiver so, via the `out`
		 * label below, rather than silently walking away from it.
		 */
		if (more)
			committed = true;

		remaining -= chunk;
		user_off += chunk;

		if (!remaining)
			break;
	}

	ret = 0;
out:
	/*
	 * A peer committed by an earlier MORE fragment of this same message
	 * must be told this call is abandoning it, rather than left to
	 * discover that only by having its process killed. Skipped on the
	 * success path (ret == 0) and for any message that never got as far as
	 * a MORE fragment (committed == false, which covers every message that
	 * fit in a single frame).
	 *
	 * Still under chan->send_lock here (see xchan_send_abort()'s comment
	 * for why that ordering matters) and xdev->lock is never held at this
	 * point: the loop above takes no spinlock at all, xchan_tx_post()
	 * acquires and releases xdev->lock entirely within itself.
	 */
	if (ret && committed)
		xchan_send_abort(xdev, chan);
	mutex_unlock(&chan->send_lock);
	return ret;
}

/*
 * Pops one entry off chan->rx_ready. Called with chan->recv_lock held (so
 * this and the caller's subsequent use of *rb form one atomic step per
 * fragment from the point of view of any concurrent XCHAN_RECV on this fd)
 * but xdev->lock NOT held, takes it itself. Returns 0 with *rb set, or a
 * negative errno (-EAGAIN/-EINTR/-ENODEV/-ECONNRESET) with *rb untouched.
 *
 * `committed` selects which of two very different waits this call is
 * allowed to do once nothing is immediately ready:
 *
 *   - committed == false: this is the FIRST fragment of a message that has
 *     not started yet (xchan_do_recv() has consumed no fragment). Ordinary,
 *     interruptible wait, honours `nonblock` (-EAGAIN) and any signal
 *     (-EINTR), exactly the behaviour a plain blocking read() is expected to
 *     have when nothing is pending yet. Nothing has been delivered to the
 *     caller for this call, so abandoning it here is free of consequence.
 *
 *   - committed == true: a message has already begun, either this is a
 *     continuation fragment of one already in progress, or this is
 *     xchan_recv_drain() consuming the abandoned remainder of one after a
 *     mid-message -EMSGSIZE/-EFAULT. Earlier fragments have already been
 *     delivered or accounted for, so abandoning the wait here over an
 *     ordinary signal or O_NONBLOCK would leave the stream desynchronised:
 *     the next XCHAN_RECV() would have no memory of being mid-message and
 *     would misread the next continuation fragment as a new one. `nonblock`
 *     is therefore ignored entirely, and the wait uses wait_event_killable()
 *     (TASK_KILLABLE) instead of wait_event_interruptible() (TASK_INTERRUPTIBLE),
 *     immune to ordinary signals, woken only by the real condition below
 *     or a FATAL one (the owning process being killed, whose fd then closes
 *     on its own and resets this channel's state via xchan_slot_wipe() once
 *     both peer-detach and fd-close land, so there is never a partially
 *     drained message left for a future call to misinterpret: either this
 *     call finishes the job, or the fd that was mid-job stops existing).
 *     Every wake_up_interruptible(&chan->poll_wq) call in this file was
 *     changed to wake_up_all() for exactly this reason: TASK_INTERRUPTIBLE
 *     wakes do not match a TASK_KILLABLE sleeper, so this mode would
 *     otherwise never be woken by a legitimate event.
 */
static int xchan_rx_pop_ready(struct xchan_dev *xdev, struct xchan_channel *chan,
			      bool nonblock, bool committed, struct xchan_rxbuf **rb)
{
	unsigned long flags;
	int ret;

	for (;;) {
		spin_lock_irqsave(&xdev->lock, flags);

		if (xdev->removed) {
			spin_unlock_irqrestore(&xdev->lock, flags);
			return -ENODEV;
		}
		if (chan->torn_down) {
			spin_unlock_irqrestore(&xdev->lock, flags);
			return -ECONNRESET;
		}

		if (!list_empty(&chan->rx_ready)) {
			*rb = list_first_entry(&chan->rx_ready,
					       struct xchan_rxbuf, link);
			list_del(&(*rb)->link);
			spin_unlock_irqrestore(&xdev->lock, flags);
			return 0;
		}

		/*
		 * A detached peer is reported only once the frames already
		 * queued here have been handed over. They arrived before this
		 * call saw DETACHED, and a sender that sends and then closes
		 * must not lose its last message to that ordering. torn_down,
		 * above, is the opposite case: the stream itself failed a
		 * check, so nothing still queued on it is delivered.
		 */
		if (chan->state == XCHAN_SLOT_DETACHED) {
			spin_unlock_irqrestore(&xdev->lock, flags);
			return -ECONNRESET;
		}

		spin_unlock_irqrestore(&xdev->lock, flags);

		if (committed) {
			ret = wait_event_killable(chan->poll_wq,
				!list_empty(&chan->rx_ready) || xdev->removed ||
				chan->torn_down || chan->state == XCHAN_SLOT_DETACHED);
			if (ret)
				return -EINTR;
			continue;
		}

		if (nonblock)
			return -EAGAIN;

		ret = wait_event_interruptible(chan->poll_wq,
			!list_empty(&chan->rx_ready) || xdev->removed ||
			chan->torn_down || chan->state == XCHAN_SLOT_DETACHED);
		if (ret)
			return -EINTR;
	}
}

/*
 * Drains the remainder of a message abandoned mid-stream: consumes and
 * discards every further fragment, issuing RELEASE for each WINDOW_REF one,
 * until the fragment without XCHAN_F_MORE. Called by xchan_do_recv() after a
 * mid-message -EMSGSIZE or -EFAULT: earlier fragments of the message have
 * already been delivered or accounted for by that point, so silently
 * abandoning the rest here would leave the next XCHAN_RECV() call with no
 * memory of being mid-message, it would read the next continuation fragment
 * as the start of a brand new one, which is silent cross-message corruption
 * with no error raised anywhere. (An earlier revision tore the channel down on
 * ANY xchan_frame_validate() failure, EMSGSIZE included, crude, but safe:
 * destroying the channel also destroyed the desync. Making -EMSGSIZE non-fatal
 * without adding this drain reintroduced the desync that crude guard happened
 * to prevent.)
 *
 * `more` is whether the fragment that triggered the abandonment itself had
 * XCHAN_F_MORE set, if not, there is nothing to drain and this returns 0
 * immediately without touching the ring at all.
 *
 * Every fragment fetch here goes through xchan_rx_pop_ready() in its
 * "committed" mode (TASK_KILLABLE, ignores O_NONBLOCK and ordinary signals,
 * see that function's own comment): once a message has begun, this
 * function does not abandon it again over anything short of the channel
 * dying or the owning process being killed. That means there is never a
 * need to remember "partially drained" state across separate XCHAN_RECV()
 * calls, either this call finishes the drain, or the fd that started it
 * will not be used again (channel torn down here or independently, or the
 * killed process's fd closing resets this channel's state via
 * xchan_slot_wipe() once both peer-detach and fd-close land, see that
 * function's own comment for why draining chan->rx_ready there is exactly
 * this same concern, at the slot-reuse boundary instead of mid-call).
 *
 * Uses a generous dst_cap (U32_MAX) for every drained fragment's
 * xchan_frame_validate() call: capacity is moot here (everything is being
 * discarded), so this lets validate() run its FULL check chain, including the
 * window_id bounds check, which is exactly what lets the WINDOW_REF branch
 * below trust window_id for a RELEASE without a second manual bounds check.
 * Contrast the fragment that triggered the drain in the first place, whose
 * window_id xchan_do_recv() must bounds-check itself before this function is
 * ever called, see the comment at that call site.
 *
 * Returns 0 once the drain reaches the non-MORE fragment (or `more` was
 * already false), or a negative errno if the channel died mid-drain
 * (-ENODEV/-ECONNRESET) or a fatal signal arrived (-EINTR). xchan_do_recv()
 * returns whichever of these happens INSTEAD OF the original triggering
 * error: a dead channel makes "what error to report about the abandoned
 * message" moot (nothing further will succeed on it either way), and a
 * fatal signal means this call, and the process it belongs to, is
 * ending regardless of what it returns.
 */
static int xchan_recv_drain(struct xchan_dev *xdev, struct xchan_channel *chan,
			    bool more)
{
	while (more) {
		struct xchan_rxbuf *rb;
		struct xchan_frame hdr;
		int ret;

		ret = xchan_rx_pop_ready(xdev, chan, false, true, &rb);
		if (ret)
			return ret;

		/* Copy-then-validate, same rule as everywhere else a frame
		 * header is read, draining is still reading frames from a
		 * peer that is always treated as hostile, not a context where
		 * that rule relaxes.
		 */
		memcpy(&hdr, rb->data, sizeof(hdr));

		if (xchan_frame_validate(&hdr, chan->slice_size, U32_MAX)) {
			unsigned long flags;

			spin_lock_irqsave(&xdev->lock, flags);
			chan->torn_down = true;
			xchan_repost_rxbuf(xdev, chan, rb);
			spin_unlock_irqrestore(&xdev->lock, flags);
			return -ECONNRESET;
		}

		if (le16_to_cpu(hdr.flags) & XCHAN_F_WINDOW_REF) {
			/* window_id is safe to use directly here: the
			 * xchan_frame_validate() call just above was given
			 * dst_cap == U32_MAX, so it ran its full check chain
			 * (the window_id bounds check included) rather than
			 * bailing early on a capacity comparison the way the
			 * ORIGINAL failing fragment's validation did.
			 */
			u16 wid = le16_to_cpu(hdr.window_id);

			xchan_repost_rxbuf_locked(xdev, chan, rb);
			xchan_send_release(xdev, chan, wid);
		} else {
			xchan_repost_rxbuf_locked(xdev, chan, rb);
		}

		more = le16_to_cpu(hdr.flags) & XCHAN_F_MORE;
	}

	return 0;
}

/*
 * XCHAN_RECV. Fills the caller's destination buffer (msg->addr, capacity
 * msg->len on input) and reports the total bytes written back through msg->len
 * on output. Loops while XCHAN_F_MORE is set, advancing the write offset by
 * each fragment's length; xchan_frame_validate() is given the REMAINING
 * capacity (cap - offset) as dst_cap on every iteration, so its existing
 * `len > dst_cap` check both bounds each individual fragment AND enforces the
 * rule that a message's running total must not exceed the caller's capacity,
 * without this function re-implementing it, on the very first fragment as
 * on every later one.
 *
 * Fragments now arrive INLINE (the `else` branch of the WINDOW_REF split
 * below), each carrying at most XCHAN_INLINE_MAX bytes immediately after its
 * own header in the same driver-owned rx buffer, because the shared window
 * cannot be mapped into a second protected guest under pKVM at all, see
 * xchan_do_send()'s comment for that finding and what it forced on the send
 * side. This loop did not have to change to accommodate that: it already
 * appended each fragment's payload at `offset` regardless of which branch
 * produced it. What changed is only which branch a large message's fragments
 * now take.
 *
 * TODO(inline): the XCHAN_F_WINDOW_REF branch below, and every
 * xchan_send_release() call in this function and in xchan_recv_drain(), are no
 * longer reachable from anything this driver's own send path emits. They are
 * kept because a peer may still legally send WINDOW_REF frames (the flag is
 * still part of the wire format) and because deleting them belongs with
 * retiring the window as a whole.
 *
 * Serialised against any other XCHAN_RECV on this channel by
 * chan->recv_lock, so one call's fragment-reassembly loop can never be
 * interleaved with another's (see recv_lock's field comment).
 *
 * THE load-bearing rule (every check runs on memory only this guest can
 * write): for every popped rx_ready entry, the header is memcpy()'d out of the
 * driver-owned buffer into a local `hdr` and xchan_frame_validate() runs on
 * that copy; then, and only then, is the payload copied, straight to the
 * caller's buffer, from either the inline buffer (same driver-owned rb->data)
 * or chan->rx_window (the actual shared, peer-writable memory). Nothing
 * downstream of validate() ever re-reads a field from rb->data or
 * chan->rx_window, every check that decides what happens next reads local
 * variables (`hdr`, `remaining`, `offset`) computed once, here. Sequence
 * validation is NOT repeated here: the rx_vq ISR (xchan_rx_vq_isr()) already
 * accepted or rejected this frame's seq, in arrival order, before it could
 * ever reach chan->rx_ready, see that function's own comment for why the
 * check has to live there rather than here.
 *
 * Two distinct failure classes out of xchan_frame_validate(), handled
 * differently on purpose: `-EMSGSIZE` (the caller's own buffer is too small)
 * is an ordinary, non-adversarial local condition, returned to the caller
 * with the channel left fully usable, exactly like an -EFAULT from a bad
 * copy_to_user() below. Anything else (`-EINVAL`) is a protocol violation and
 * tears the channel down. Conflating the two would turn a routine short-buffer
 * call into permanent channel death, a self-inflicted denial of service on
 * entirely correct use.
 *
 * A THIRD class, `XCHAN_F_ABORT`, sits outside that split: it is neither a
 * protocol violation (the frame is well-formed and xchan_frame_validate()
 * accepts it) nor a local capacity problem, it is the PEER telling us it
 * failed on its own send path after already committing us to this message.
 * Handled just below the two branches above, once validate() has returned
 * success: repost the buffer and return `-ECANCELED`, channel left fully
 * usable, exactly like `-EMSGSIZE`, but under its own errno so a caller can
 * tell "my buffer was too small" apart from "the sender gave up", see that
 * branch's own comment for the full reasoning, and xchan_do_send()'s for the
 * send side that emits this frame.
 *
 * MID-MESSAGE -EMSGSIZE/-EFAULT: a short buffer or a bad user pointer
 * discovered on a NON-FIRST fragment is not simply "return the error",
 * earlier fragments have already been delivered, so the rest of the message
 * must be drained (xchan_recv_drain(), above) before returning, or the next
 * call desyncs (see that function's own comment for the full failure mode this
 * closes). The two `remaining` / `offset` variables below make this reachable
 * on ANY fragment, not just the first: xchan_frame_validate() is given
 * cap - offset as dst_cap on every loop iteration, so capacity can fail on
 * fragment 2, 3, ... of an otherwise well-formed message just as easily as on
 * fragment 1.
 *
 * A related corollary this function alone must handle: xchan_frame_validate()
 * checks `len > dst_cap` BEFORE its window_id bounds check (xchan_frame.c), so
 * a fragment that fails validation with -EMSGSIZE has NOT had window_id
 * bounds-checked yet. Before this function can safely issue a RELEASE for such
 * a fragment (needed so the peer's window buffer is not lent forever), it
 * bounds-checks window_id itself, against the same XCHAN_WINDOW_BUFS
 * xchan_frame_validate() uses internally (visible via xchan_frame.h, not
 * redefined here), xchan_frame.c/.h themselves are not modified for this.
 *
 * Once this call has consumed at least one fragment of a message still in
 * progress (have_first_seq; not offset > 0, which a zero-length fragment
 * leaves false), every further xchan_rx_pop_ready() call,
 * both in the main loop below and inside xchan_recv_drain(), runs in
 * "committed" mode: it ignores O_NONBLOCK and ordinary signals rather than
 * risking the exact same desync via an early return with data already
 * delivered. See xchan_rx_pop_ready()'s own comment for the full reasoning
 * and why this needed wake_up_interruptible(&chan->poll_wq) call sites in
 * this file changed to wake_up_all().
 *
 * Every xchan_repost_rxbuf() call below runs under xdev->lock (that
 * function's own contract: it touches chan->rx_vq, which xchan_rx_vq_isr()
 * mutates concurrently from IRQ context under the same lock), but never
 * while a copy_from_user()/copy_to_user() is in flight, since those must not
 * run under spin_lock_irqsave(). The two torn-down branches below fold the
 * flag set and the repost into one critical section; the plain-repost cases
 * (EMSGSIZE, EFAULT, and the two success paths) go through
 * xchan_repost_rxbuf_locked(), a thin wrapper that takes the lock, reposts,
 * and drops it, for exactly the call sites here that do not already hold it.
 */
static int xchan_do_recv(struct xchan_dev *xdev, struct xchan_channel *chan,
			 bool nonblock, struct xchan_msg *msg)
{
	u32 cap = msg->len;
	u32 offset = 0;
	u64 first_seq = 0;
	bool have_first_seq = false;
	int ret;

	mutex_lock(&chan->recv_lock);

	for (;;) {
		struct xchan_rxbuf *rb;
		struct xchan_frame hdr;
		u32 remaining = cap - offset;
		bool more;

		/*
		 * have_first_seq, not offset > 0: a zero-length fragment
		 * carrying XCHAN_F_MORE is valid and leaves offset at 0, and
		 * the message is in progress all the same.
		 */
		ret = xchan_rx_pop_ready(xdev, chan, nonblock, have_first_seq, &rb);
		if (ret)
			goto out;

		/*
		 * Copy the header out of shared/driver memory FIRST, then
		 * validate the copy. Re-reading any field from rb->data or
		 * the window after this point would reintroduce the TOCTOU
		 * this design exists to remove.
		 */
		memcpy(&hdr, rb->data, sizeof(hdr));

		ret = xchan_frame_validate(&hdr, chan->slice_size, remaining);
		if (ret == -EMSGSIZE) {
			u16 hflags = le16_to_cpu(hdr.flags);
			u16 wid = le16_to_cpu(hdr.window_id);
			int drain_ret;

			/*
			 * validate() bailed on the capacity check before
			 * reaching its window_id bounds check, so window_id
			 * is not yet known safe. A WINDOW_REF frame whose
			 * window_id is ALSO out-of-range is independently a
			 * protocol violation validate() simply had not gotten
			 * to yet, tear down rather than trust it for a
			 * RELEASE (never use a device-supplied value to name
			 * anything without checking it first).
			 */
			if ((hflags & XCHAN_F_WINDOW_REF) &&
			    wid >= XCHAN_WINDOW_BUFS) {
				unsigned long lockflags;

				spin_lock_irqsave(&xdev->lock, lockflags);
				chan->torn_down = true;
				xchan_repost_rxbuf(xdev, chan, rb);
				spin_unlock_irqrestore(&xdev->lock, lockflags);
				ret = -ECONNRESET;
				goto out;
			}

			xchan_repost_rxbuf_locked(xdev, chan, rb);
			if (hflags & XCHAN_F_WINDOW_REF)
				xchan_send_release(xdev, chan, wid);

			/*
			 * Local condition: the caller's destination buffer is
			 * too small for this frame. Not adversarial and says
			 * nothing about the peer, but if this fragment had
			 * XCHAN_F_MORE set, earlier fragments of this message
			 * (if any) are already delivered and later ones are
			 * still coming, so the remainder must be drained
			 * before the channel is left usable for the next call
			 * (xchan_recv_drain(), see its own comment for why).
			 */
			drain_ret = (hflags & XCHAN_F_MORE) ?
				xchan_recv_drain(xdev, chan, true) : 0;
			ret = drain_ret ? drain_ret : -EMSGSIZE;
			goto out;
		}
		if (ret) {
			/* Protocol violation (every xchan_frame_validate()
			 * failure other than -EMSGSIZE): fail closed and tear
			 * the channel down for every future call, not just
			 * this one. No drain
			 * needed: torn_down makes every future call on this
			 * channel fail immediately, so there is no "next
			 * call" left to desync.
			 */
			unsigned long flags;

			spin_lock_irqsave(&xdev->lock, flags);
			chan->torn_down = true;
			xchan_repost_rxbuf(xdev, chan, rb);
			spin_unlock_irqrestore(&xdev->lock, flags);
			goto out;
		}

		if (le16_to_cpu(hdr.flags) & XCHAN_F_ABORT) {
			/*
			 * The peer failed on ITS OWN send path after already
			 * committing us to this message (an earlier fragment
			 * of it carried XCHAN_F_MORE) and is telling us to
			 * give up rather than sit in xchan_rx_pop_ready()'s
			 * TASK_KILLABLE "committed" wait for a continuation
			 * that is never coming, see xchan_send_abort() in
			 * this file for the send side that emits this frame.
			 *
			 * Deliberately -ECANCELED, not -EMSGSIZE and not
			 * -ECONNRESET/-EINVAL:
			 *
			 *   - Not -EMSGSIZE: that errno means OUR destination
			 *     buffer was too small, an ordinary local condition
			 *     a bigger buffer would fix. This message was never
			 *     going to complete regardless of `cap`, the
			 *     PEER gave up on it, not us, so reusing EMSGSIZE
			 *     here would send the caller looking for a sizing
			 *     bug that does not exist.
			 *   - Not a protocol violation: XCHAN_F_ABORT is a
			 *     legal, expected frame (xchan_frame_validate()
			 *     already accepted it above), not something the
			 *     peer was forbidden to send. Returning -ECONNRESET
			 *     and setting chan->torn_down here would tear the
			 *     channel down for correct use of a mechanism that
			 *     exists precisely to avoid teardown on a transient
			 *     failure (see xchan_do_send()'s comment on why
			 *     that self-DoS is exactly what the abort frame
			 *     avoids).
			 *   -ECANCELED says what actually happened: this
			 *     specific receive did not complete because the
			 *     operation it was part of was cancelled by the
			 *     peer, and nothing about the channel itself is
			 *     broken, the very next XCHAN_RECV on this fd is
			 *     expected to work normally.
			 *
			 * No drain needed: xchan_frame_validate() rejects
			 * XCHAN_F_ABORT combined with XCHAN_F_MORE, so this is
			 * always itself the terminal frame of the abandoned
			 * message (exactly like a normal final fragment),
			 * there is nothing further to consume before the
			 * stream is back in sync for the next call. `msg->len`/
			 * `msg->seq` are left untouched on this error path,
			 * consistent with every other error return here (their
			 * contents on error are not part of the API contract,
			 * see libxchan.h).
			 */
			xchan_repost_rxbuf_locked(xdev, chan, rb);
			ret = -ECANCELED;
			goto out;
		}

		if (le16_to_cpu(hdr.flags) & XCHAN_F_WINDOW_REF) {
			u16 wid = le16_to_cpu(hdr.window_id);

			if (!chan->rx_window) {
				/* Validated as WINDOW_REF against a nonzero
				 * chan->slice_size, yet this side has no
				 * window mapped, can only happen if the
				 * mapping failed at probe time while the peer
				 * still believes windows work. Fail closed
				 * rather than dereference a NULL rx_window.
				 * No drain: this tears the channel down too.
				 */
				unsigned long flags;

				spin_lock_irqsave(&xdev->lock, flags);
				chan->torn_down = true;
				xchan_repost_rxbuf(xdev, chan, rb);
				spin_unlock_irqrestore(&xdev->lock, flags);
				ret = -ECONNRESET;
				goto out;
			}

			if (copy_to_user((u8 __user *)(unsigned long)msg->addr + offset,
					 (u8 *)chan->rx_window +
					 (size_t)wid * chan->slice_size,
					 le32_to_cpu(hdr.len))) {
				int drain_ret;

				xchan_repost_rxbuf_locked(xdev, chan, rb);
				/*
				 * Same mid-message reasoning as -EMSGSIZE
				 * above: a bad user pointer discovered after
				 * earlier fragments were already delivered is
				 * just as capable of desyncing the stream as
				 * a short buffer is. window_id here IS already
				 * known safe (this frame passed the FULL
				 * xchan_frame_validate() chain, real dst_cap
				 * included, to reach this copy at all), so no
				 * separate bounds check is needed before the
				 * drain below issues RELEASE for it, only
				 * xchan_send_release() for THIS wid, since the
				 * copy_to_user() failure means this specific
				 * buffer was never actually delivered either.
				 */
				xchan_send_release(xdev, chan, wid);
				drain_ret = (le16_to_cpu(hdr.flags) & XCHAN_F_MORE) ?
					xchan_recv_drain(xdev, chan, true) : 0;
				ret = drain_ret ? drain_ret : -EFAULT;
				goto out;
			}

			xchan_repost_rxbuf_locked(xdev, chan, rb);

			/*
			 * Release the window buffer as soon as the copy
			 * completes, not when userspace finishes with the
			 * data. Sent even on the -EFAULT path above would also
			 * be correct (the driver is done reading the window
			 * either way) but ordering it after a successful copy
			 * keeps this call's only externally visible side
			 * effect on success.
			 */
			xchan_send_release(xdev, chan, wid);
		} else {
			u32 len = le32_to_cpu(hdr.len);

			/*
			 * Never assume len matches what was actually
			 * delivered: the transport's own reported byte count
			 * (rb->len, set by the rx_vq ISR from
			 * virtqueue_get_buf(), never from anything inside the
			 * frame itself) must cover header + this many payload
			 * bytes before they are trusted to sit inside rb->data
			 * at all.
			 */
			if ((u64)sizeof(hdr) + len > rb->len) {
				unsigned long flags;

				spin_lock_irqsave(&xdev->lock, flags);
				chan->torn_down = true;
				xchan_repost_rxbuf(xdev, chan, rb);
				spin_unlock_irqrestore(&xdev->lock, flags);
				ret = -ECONNRESET;
				goto out;
			}

			if (len && copy_to_user((u8 __user *)(unsigned long)msg->addr + offset,
						(u8 *)rb->data + sizeof(hdr), len)) {
				int drain_ret;
				bool had_more = le16_to_cpu(hdr.flags) & XCHAN_F_MORE;

				/* Reaching this branch means WINDOW_REF was
				 * unset, so there is no window buffer to
				 * release for this specific fragment, but
				 * the drain below still applies if it had
				 * MORE set, same mid-message reasoning as
				 * both branches above. (MORE here is now the
				 * ordinary case rather than an impossible
				 * one: inline fragments are how every message
				 * above XCHAN_INLINE_MAX travels.)
				 */
				xchan_repost_rxbuf_locked(xdev, chan, rb);
				drain_ret = had_more ?
					xchan_recv_drain(xdev, chan, true) : 0;
				ret = drain_ret ? drain_ret : -EFAULT;
				goto out;
			}

			xchan_repost_rxbuf_locked(xdev, chan, rb);
		}

		if (!have_first_seq) {
			first_seq = le64_to_cpu(hdr.seq);
			have_first_seq = true;
		}

		offset += le32_to_cpu(hdr.len);
		more = le16_to_cpu(hdr.flags) & XCHAN_F_MORE;
		if (!more)
			break;
	}

	msg->len = offset;
	msg->seq = first_seq;
	msg->flags = 0;
	ret = 0;
out:
	mutex_unlock(&chan->recv_lock);
	return ret;
}

/* ------------------------------------------------------------------ *
 * Per-channel file_operations.
 * ------------------------------------------------------------------
 */

static int xchan_chan_release(struct inode *inode, struct file *file)
{
	struct xchan_channel *chan = file->private_data;
	struct xchan_dev *xdev = chan->xdev;
	unsigned long flags;
	u32 slot = chan->slot;
	u32 channel_id;
	bool freed, removed;

	spin_lock_irqsave(&xdev->lock, flags);

	channel_id = chan->channel_id;

	/*
	 * This updates this driver's own authoritative slot state (the
	 * thing that gates whether a future ATTACHED for this slot may be
	 * accepted at all, in xchan_handle_attached() above) so the slot
	 * becomes reusable, on this driver's own view, the moment both
	 * halves, peer detach and this close, have landed, in either
	 * order.
	 *
	 * That local view is necessary but not sufficient: crosvm owns slot
	 * allocation, not this driver, so it also has to observe the close.
	 * xchan_post_channel_closed() below sends the wire notification that
	 * makes that possible, an earlier revision of the ABI had no
	 * driver->device path at all, which meant this local state update was
	 * the only thing that ever happened here, and crosvm could never learn
	 * of it.
	 */
	xchan_slot_close(chan);
	freed = (chan->state == XCHAN_SLOT_FREE);
	if (freed)
		xchan_slot_wipe(chan);

	/*
	 * Post the close notification unconditionally, regardless of
	 * `freed`: this is the driver's half of the slot-reuse gate, reported
	 * even when the peer has not detached yet (state -> SLOT_CLOSED
	 * rather than SLOT_FREE above). crosvm is the side that ANDs this
	 * with its own detach observation before reusing the slot, not this
	 * driver, see xchan_post_channel_closed() for why touching
	 * xdev->cmd_vq here, still under this same lock, is safe.
	 */
	xchan_post_channel_closed(xdev, slot, channel_id);

	/*
	 * xdev->vdev may already be a dangling pointer if the device was
	 * removed while this fd was still open (xdev/xdev->channels
	 * themselves are kept alive for exactly that case by xdev->refcnt,
	 * dropped below, but xdev->vdev is not ours to keep alive).
	 *
	 * A prior version of this function read xdev->removed here but then
	 * *used* xdev->vdev in dev_info() after unlocking, the lock
	 * serialised the read, not the later dereference, which is exactly
	 * the bug this comment used to (wrongly) claim was closed. Fixed by
	 * keeping the entire vdev-touching span, including the log call
	 * itself, inside the critical section below.
	 *
	 * This is safe: xchan_chardev_exit() sets xdev->removed to true
	 * under this same xdev->lock, and xchan_teardown() does not call
	 * virtio_reset_device()/del_vqs(), the point after which the
	 * device core may free *xdev->vdev, until xchan_chardev_exit() has
	 * returned. xchan_chardev_exit() cannot return while this critical
	 * section holds the lock it also needs, so for as long as we hold
	 * xdev->lock here, either removed is already true (teardown's
	 * removed-setting section has already run and completed, and
	 * nothing sets it back to false) or teardown has not yet reached
	 * virtio_reset_device()/del_vqs() at all. Either way xdev->vdev
	 * cannot be freed out from under the dev_info() call below.
	 *
	 * dev_info()/pr_info() are printk-based and do not sleep, so they
	 * are safe to call with this spinlock held (spin_lock_irqsave, IRQs
	 * off), unlike, e.g., a GFP_KERNEL allocation would be.
	 */
	removed = xdev->removed;

	if (removed)
		pr_info("xchan: slot %u channel %u fd closed%s (device already removed)\n",
			slot, channel_id, freed ? ", slot released" : "");
	else
		dev_info(&xdev->vdev->dev,
			"xchan: slot %u channel %u fd closed%s\n",
			slot, channel_id, freed ? ", slot released" : "");

	spin_unlock_irqrestore(&xdev->lock, flags);

	/*
	 * xchan_put() may free *xdev (including the xdev->lock we just
	 * released) if this was the last reference, it must run after the
	 * unlock above, and xdev must not be touched again afterward.
	 */
	xchan_put(xdev);
	return 0;
}

static __poll_t xchan_chan_poll(struct file *file, poll_table *wait)
{
	struct xchan_channel *chan = file->private_data;
	struct xchan_dev *xdev = chan->xdev;
	__poll_t mask = 0;
	unsigned long flags;

	poll_wait(file, &chan->poll_wq, wait);

	spin_lock_irqsave(&xdev->lock, flags);
	/*
	 * torn_down too: a channel that failed a check fails every later
	 * send and recv with ECONNRESET, so a poller must be told now rather
	 * than left to its timeout. No EPOLLIN for it either, nothing queued
	 * on a torn-down stream is delivered (xchan_rx_pop_ready()).
	 */
	if (chan->state == XCHAN_SLOT_DETACHED || chan->torn_down)
		mask |= EPOLLHUP | EPOLLERR;
	if (!list_empty(&chan->rx_ready) && !chan->torn_down)
		mask |= EPOLLIN | EPOLLRDNORM;
	/*
	 * "Send credit available" used to be approximated here as "at least
	 * one window buffer is free". Every send is now inline (see
	 * xchan_do_send()), and an inline send needs no window credit, only
	 * chan->tx_vq ring space, which xchan_tx_reap() reclaims
	 * opportunistically inside xchan_tx_post() rather than being tracked
	 * here. So EPOLLOUT is unconditional: a send is always a candidate,
	 * and a momentarily full ring is handled by that function's bounded
	 * retry rather than by withholding this bit.
	 *
	 * TODO(inline): once the window is retired, chan->tx_win_inuse and
	 * chan->slice_size go with it and this comment's history goes too. Not
	 * a behaviour change now: nothing sets a tx_win_inuse bit any more, so
	 * the old condition already evaluated true on every call.
	 */
	mask |= EPOLLOUT | EPOLLWRNORM;
	spin_unlock_irqrestore(&xdev->lock, flags);

	return mask;
}

static int xchan_chan_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct xchan_channel *chan = file->private_data;
	struct xchan_dev *xdev = chan->xdev;
	struct virtio_shm_region region;
	unsigned long size = vma->vm_end - vma->vm_start;
	phys_addr_t tx_phys, rx_phys_unused;
	unsigned long flags;
	bool have_region;
	int ret;

	/*
	 * Only the TX region may ever be mapped: the RX direction is never
	 * exposed to userspace, which is what makes the driver's receive-side
	 * copy safe against a peer mutating data mid-read. A non-zero vm_pgoff
	 * would be an attempt to reach past the TX region, towards the RX
	 * region or beyond, and is rejected outright rather than clamped.
	 *
	 * These two checks only look at vma (caller-controlled, not shared
	 * state) and xdev->window_slice_size (fixed at probe time, never
	 * changes), so they run before taking xdev->lock below.
	 */
	if (vma->vm_pgoff != 0)
		return -EPERM;

	if (size == 0 || size > xdev->window_slice_size)
		return -EINVAL;

	/*
	 * Everything that touches xdev->vdev (state, feature check,
	 * shm-region lookup) happens inside this one critical section, and
	 * nothing here is used again after unlocking, region is copied
	 * onto the stack, and every value derived from it below is derived
	 * from that copy, never from xdev->vdev again.
	 *
	 * Why this is safe against a concurrent xchan_remove(): a first
	 * version of this function read xdev->removed under the lock but
	 * then called virtio_has_feature()/virtio_get_shm_region(), both
	 * of which dereference xdev->vdev, and the latter makes an indirect
	 * call through vdev->config->get_shm_region, *after* unlocking.
	 * xchan_chardev_exit() sets xdev->removed to true under this same
	 * xdev->lock, and xchan_teardown() does not call
	 * virtio_reset_device()/del_vqs() (the point after which the device
	 * core may free *xdev->vdev) until xchan_chardev_exit() has
	 * returned. xchan_chardev_exit() cannot return while this critical
	 * section holds the lock it also needs. So for the entire time this
	 * function holds xdev->lock, either xdev->removed is already true
	 * (teardown's removed-setting section already ran to completion,
	 * and nothing ever sets it back to false, so bailing out below is
	 * correct) or teardown has not yet reached
	 * virtio_reset_device()/del_vqs() at all, either way xdev->vdev
	 * cannot be freed or reset while we are using it here.
	 *
	 * virtio_has_feature() is a plain bitmask test and
	 * virtio_get_shm_region() ultimately reads capability-set state the
	 * transport already parsed at probe time; neither sleeps, so both
	 * are safe to call with this spinlock held (spin_lock_irqsave, IRQs
	 * off).
	 */
	spin_lock_irqsave(&xdev->lock, flags);

	if (xdev->removed) {
		spin_unlock_irqrestore(&xdev->lock, flags);
		return -ENODEV;
	}

	if (chan->state == XCHAN_SLOT_DETACHED) {
		spin_unlock_irqrestore(&xdev->lock, flags);
		return -ECONNRESET;
	}

	if (!virtio_has_feature(xdev->vdev, VIRTIO_XCHAN_F_WINDOW)) {
		spin_unlock_irqrestore(&xdev->lock, flags);
		return -ENODEV;
	}

	/*
	 * The window layout (it replaces an earlier guess that used a
	 * per-slot region id and a fixed RX-then-TX sense): there is exactly
	 * ONE shared-memory region for the whole device, id 0, sized
	 * max_channels * 2 * window_slice_size. Slot k owns the contiguous
	 * pair at offset k * 2 * window_slice_size, and the two halves are
	 * addressed by direction of travel, not by local role: the first
	 * half (offset k*2*wss) always travels toward the hub, the second
	 * (offset k*2*wss + wss) always travels toward the client.
	 *
	 * Each endpoint derives its own TX half from that and xdev->endpoint,
	 * not a fixed sense: endpoint B's TX is the first (toward-A) half and
	 * its RX the second; endpoint A's are the reverse. xdev->endpoint is
	 * read from config space by xchan_validate_config(), not inferred
	 * from max_channels, which is a capacity rather than a role signal.
	 *
	 * A region that does not fit this shape fails mmap with -ENODEV
	 * rather than mapping the wrong memory.
	 */
	have_region = virtio_get_shm_region(xdev->vdev, &region, 0);

	spin_unlock_irqrestore(&xdev->lock, flags);

	if (!have_region)
		return -ENODEV;

	/*
	 * region.addr/region.len are device-supplied, so untrusted: a hostile
	 * addr near U64_MAX must not be allowed to silently wrap this
	 * arithmetic down to some unrelated low physical address that then
	 * gets mapped into userspace. xchan_slot_phys_offsets() rejects that
	 * with -ENODEV instead of computing a wrapped value, and is the same
	 * arithmetic xchan_setup_windows() uses for its own kernel-side
	 * mapping of both halves, extracted so the two can never drift out
	 * of sync with each other. Only the TX half is wanted here (RX is
	 * never mapped into userspace); the RX result is discarded.
	 */
	if (xchan_slot_phys_offsets(&region, xdev->window_slice_size,
				    xdev->endpoint, chan->slot, &tx_phys,
				    &rx_phys_unused))
		return -ENODEV;

	/*
	 * window_slice_size and region.addr are device-supplied and nothing
	 * checks their alignment. A TX half starting mid-page would be mapped
	 * from the truncated pfn below, exposing the bytes before it: this
	 * slot's RX half, or the previous slot's window. Refuse rather than
	 * round.
	 */
	if (!PAGE_ALIGNED(tx_phys))
		return -EINVAL;

	ret = io_remap_pfn_range(vma, vma->vm_start, tx_phys >> PAGE_SHIFT,
				 size, vma->vm_page_prot);
	if (ret)
		return -EAGAIN;

	return 0;
}

static long xchan_chan_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct xchan_channel *chan = file->private_data;
	struct xchan_dev *xdev = chan->xdev;
	unsigned long flags;
	enum xchan_slot_state state;
	bool torn_down, nonblock;
	struct xchan_msg msg;
	int ret;

	spin_lock_irqsave(&xdev->lock, flags);
	state = chan->state;
	torn_down = chan->torn_down;
	spin_unlock_irqrestore(&xdev->lock, flags);

	/*
	 * A real peer detach and a local protocol violation (torn_down) are
	 * deliberately different pieces of state (see torn_down's field
	 * comment in xchan_priv.h), but both present identically to userspace
	 * from here: ECONNRESET, fail closed. This is only a fast pre-check,
	 * xchan_do_send()/xchan_do_recv() re-verify both under their own
	 * locking before touching anything, since this snapshot is stale the
	 * instant the lock above is released.
	 */
	/*
	 * XCHAN_RECV on a detached channel is let through: frames the peer
	 * sent before detaching may still be queued, and xchan_rx_pop_ready()
	 * hands those over before it reports ECONNRESET.
	 */
	if (torn_down || (state == XCHAN_SLOT_DETACHED && cmd != XCHAN_RECV))
		return -ECONNRESET;

	nonblock = file->f_flags & O_NONBLOCK;

	switch (cmd) {
	case XCHAN_SEND:
		if (copy_from_user(&msg, (void __user *)arg, sizeof(msg)))
			return -EFAULT;
		return xchan_do_send(xdev, chan, nonblock, &msg);

	case XCHAN_RECV:
		if (copy_from_user(&msg, (void __user *)arg, sizeof(msg)))
			return -EFAULT;
		ret = xchan_do_recv(xdev, chan, nonblock, &msg);
		if (ret)
			return ret;
		if (copy_to_user((void __user *)arg, &msg, sizeof(msg)))
			return -EFAULT;
		return 0;

	default:
		return -ENOTTY;
	}
}

static const struct file_operations xchan_chan_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = xchan_chan_ioctl,
	.poll           = xchan_chan_poll,
	.mmap           = xchan_chan_mmap,
	.release        = xchan_chan_release,
	.llseek         = noop_llseek,
};

/* ------------------------------------------------------------------ *
 * /dev/xchan0 device-node file_operations.
 * ------------------------------------------------------------------
 */

static int xchan_dev_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct xchan_dev *xdev = container_of(misc, struct xchan_dev, miscdev);

	/*
	 * Guards against opening a device node whose backing xdev is mid
	 * teardown (base reference already dropped): once that has
	 * happened misc_deregister() also ensures no *new* open can find
	 * this node at all, but the two are not the same lock, so this is
	 * the belt to that braces.
	 */
	if (!xchan_get(xdev))
		return -ENODEV;

	return 0;
}

static int xchan_dev_release(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct xchan_dev *xdev = container_of(misc, struct xchan_dev, miscdev);

	xchan_put(xdev);
	return 0;
}

static __poll_t xchan_dev_poll(struct file *file, poll_table *wait)
{
	struct miscdevice *misc = file->private_data;
	struct xchan_dev *xdev = container_of(misc, struct xchan_dev, miscdev);
	__poll_t mask = 0;
	unsigned long flags;

	poll_wait(file, &xdev->wait_q, wait);

	spin_lock_irqsave(&xdev->lock, flags);
	if (!list_empty(&xdev->ready_list))
		mask |= EPOLLIN | EPOLLRDNORM;
	spin_unlock_irqrestore(&xdev->lock, flags);

	return mask;
}

static long xchan_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct miscdevice *misc = file->private_data;
	struct xchan_dev *xdev = container_of(misc, struct xchan_dev, miscdev);
	struct xchan_channel_info info;
	struct xchan_channel *chan;
	unsigned long flags;
	u32 channel_id;
	int fd, ret;

	if (cmd != XCHAN_WAIT_CHANNEL)
		return -ENOTTY;

	for (;;) {
		spin_lock_irqsave(&xdev->lock, flags);

		if (xdev->removed) {
			spin_unlock_irqrestore(&xdev->lock, flags);
			return -ENODEV;
		}

		chan = list_first_entry_or_null(&xdev->ready_list,
						struct xchan_channel, ready_link);
		if (chan) {
			list_del(&chan->ready_link);
			chan->waiting = false;
		}

		spin_unlock_irqrestore(&xdev->lock, flags);

		if (chan)
			break;

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		ret = wait_event_interruptible(xdev->wait_q,
			!list_empty(&xdev->ready_list) || xdev->removed);
		if (ret)
			return ret;
	}

	/*
	 * chan is ours alone from here: removed from ready_list under the
	 * lock above, and nothing else can claim it (xchan_handle_attached()
	 * only ever adds a XCHAN_SLOT_FREE slot to that list, and this slot
	 * is not FREE again until this fd, or the unwind below, says
	 * so). Fill the ioctl's output struct BEFORE creating the fd: if
	 * copy_to_user() faults, there is then no fd to have to clean back
	 * out of the caller's descriptor table.
	 */
	spin_lock_irqsave(&xdev->lock, flags);
	info.channel_id = chan->channel_id;
	info.flags = chan->flags;
	info.window_slice_size = xdev->window_slice_size;
	memcpy(info.peer_identity, chan->peer_identity, sizeof(info.peer_identity));
	spin_unlock_irqrestore(&xdev->lock, flags);

	if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
		ret = -EFAULT;
		goto err_return_chan;
	}

	if (!xchan_get(xdev)) {
		/* Racing with teardown; extremely unlikely (removed was just
		 * checked above under the same lock this drops the last
		 * reference under), but handled rather than assumed away.
		 */
		ret = -ENODEV;
		goto err_return_chan;
	}

	/*
	 * Per-channel fd, and the security property it exists for: a
	 * server can hand each channel fd to a separate worker or process,
	 * and this fd's file_operations (xchan_chan_fops) take the channel
	 * purely from file->private_data, set exactly once, here. There is
	 * no ioctl argument or other path on this fd that lets a caller
	 * redirect it to a different slot's channel.
	 */
	fd = anon_inode_getfd("[xchan-chan]", &xchan_chan_fops, chan,
			      O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		xchan_put(xdev);
		ret = fd;
		goto err_return_chan;
	}

	return fd;

err_return_chan:
	spin_lock_irqsave(&xdev->lock, flags);
	if (chan->state == XCHAN_SLOT_ACTIVE) {
		/* Still attached: give it back to the ready list exactly as
		 * found, for the next XCHAN_WAIT_CHANNEL call to pick up.
		 */
		chan->waiting = true;
		list_add_tail(&chan->ready_link, &xdev->ready_list);
		wake_up_interruptible(&xdev->wait_q);
	} else {
		/*
		 * The peer detached while we were between claiming the
		 * channel and installing its fd (the lock was dropped for
		 * copy_to_user()). No fd was ever created, so our half of
		 * the slot-reuse gate is immediately satisfied, and,
		 * same as a real fd's .release(), crosvm still needs to be
		 * told: it does not know or care that no fd ever reached
		 * userspace, only that this driver considers the channel
		 * closed. Capture channel_id before xchan_slot_close() /
		 * xchan_slot_wipe() so a slot that also just went FREE does
		 * not report a zeroed id.
		 */
		channel_id = chan->channel_id;
		xchan_slot_close(chan);
		xchan_post_channel_closed(xdev, chan->slot, channel_id);
		if (chan->state == XCHAN_SLOT_FREE)
			xchan_slot_wipe(chan);
	}
	spin_unlock_irqrestore(&xdev->lock, flags);
	return ret;
}

static const struct file_operations xchan_dev_fops = {
	.owner          = THIS_MODULE,
	.open           = xchan_dev_open,
	.release        = xchan_dev_release,
	.unlocked_ioctl = xchan_dev_ioctl,
	.poll           = xchan_dev_poll,
	.llseek         = noop_llseek,
};

/* ------------------------------------------------------------------ *
 * Init / exit, called from xchan_drv.c's probe()/xchan_teardown().
 * ------------------------------------------------------------------
 */

int xchan_chardev_init(struct xchan_dev *xdev)
{
	unsigned int i, depth, posted;
	int ret;

	spin_lock_init(&xdev->lock);
	init_waitqueue_head(&xdev->wait_q);
	INIT_LIST_HEAD(&xdev->ready_list);
	xdev->removed = false;
	refcount_set(&xdev->refcnt, 1); /* the driver's own base reference */

	for (i = 0; i < xdev->max_channels; i++) {
		struct xchan_channel *chan = &xdev->channels[i];

		chan->xdev = xdev;
		chan->slot = i;
		chan->state = XCHAN_SLOT_FREE;
		chan->peer_gone = false;
		chan->fd_closed = true;
		chan->waiting = false;
		INIT_LIST_HEAD(&chan->ready_link);
		init_waitqueue_head(&chan->poll_wq);

		/* Frame data path. */
		INIT_LIST_HEAD(&chan->rx_ready);
		mutex_init(&chan->send_lock);
		mutex_init(&chan->recv_lock);
	}

	/*
	 * Window mappings and RX buffer pools. Both run here, still
	 * lock-free: no fd exists yet (misc_register() has not happened) and
	 * nothing else can be touching xdev->channels concurrently, the same
	 * reasoning the eventq buffer posting below already relies on.
	 * xchan_setup_windows() is best-effort per channel (see its own
	 * comment) and never fails channel setup as a whole; a channel whose
	 * rx_vq has no usable descriptors simply gets rx_depth == 0 and never
	 * receives anything, which is a device misconfiguration this driver
	 * cannot repair, not something worth failing the whole probe over
	 * when other channels may still be usable.
	 */
	xchan_setup_windows(xdev);
	for (i = 0; i < xdev->max_channels; i++)
		xchan_setup_rx_pool(xdev, &xdev->channels[i]);

	depth = min_t(unsigned int, XCHAN_EVENT_QUEUE_DEPTH,
		     virtqueue_get_vring_size(xdev->event_vq));
	if (depth == 0) {
		dev_err(&xdev->vdev->dev,
			"xchan: eventq has no usable descriptors\n");
		return -ENODEV;
	}

	xdev->event_bufs = kcalloc(depth, sizeof(*xdev->event_bufs), GFP_KERNEL);
	if (!xdev->event_bufs)
		return -ENOMEM;
	xdev->event_depth = depth;

	for (posted = 0; posted < depth; posted++) {
		ret = xchan_post_event_buf(xdev, &xdev->event_bufs[posted]);
		if (ret)
			break;
	}
	if (posted == 0) {
		dev_err(&xdev->vdev->dev,
			"xchan: failed to post any eventq buffer: %d\n",
			ret);
		/*
		 * Nothing was ever added to the queue, so xdev->event_bufs
		 * could safely be freed right here, but it is deliberately
		 * left for the caller's xchan_teardown() instead, which frees
		 * it unconditionally (kfree(NULL) included) after resetting
		 * the device. One cleanup path for every xchan_chardev_init()
		 * failure, rather than a special case for "0 buffers posted"
		 * that has to keep being proven safe as this function changes.
		 */
		return ret;
	}
	/* A partial post (posted < depth) still leaves the queue usable at
	 * reduced depth; the unposted tail entries are simply never used.
	 */

	virtqueue_kick(xdev->event_vq);

	xdev->miscdev.minor = MISC_DYNAMIC_MINOR;
	xdev->miscdev.name = "xchan0";
	xdev->miscdev.fops = &xchan_dev_fops;

	ret = misc_register(&xdev->miscdev);
	if (ret) {
		dev_err(&xdev->vdev->dev, "xchan: misc_register failed: %d\n", ret);
		/*
		 * xdev->event_bufs is NOT freed here: buffers are already
		 * posted as live inbufs on the eventq at this point, and the
		 * queue itself is still fully live (misc_register() failing
		 * says nothing about virtqueue state). Freeing them before
		 * the caller's xchan_teardown() has quiesced the device via
		 * virtio_reset_device()/del_vqs() would free memory the
		 * device could still DMA into.
		 */
		return ret;
	}
	xdev->chardev_ready = true;

	return 0;
}

/*
 * Quiesces the userspace-facing surface only: no new /dev/xchan0 opens
 * (misc_deregister()), every existing waiter on this device's wait queues
 * kicked awake to re-check xdev->removed, and the ready/blocked ioctl and
 * poll paths all gated on that same flag from here on.
 *
 * Deliberately does NOT touch xdev->event_bufs: those buffers are still
 * posted as inbufs on the (still-live at this point) eventq, and freeing
 * them before the device has been quiesced would be a use-after-free from
 * the device's side if it DMAs into one after this call returns.
 * xchan_teardown() in xchan_drv.c frees them itself, after
 * virtio_reset_device()/del_vqs() have made that safe.
 */
void xchan_chardev_exit(struct xchan_dev *xdev)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&xdev->lock, flags);
	xdev->removed = true;
	wake_up_all(&xdev->wait_q);
	for (i = 0; i < xdev->max_channels; i++)
		wake_up_all(&xdev->channels[i].poll_wq);
	spin_unlock_irqrestore(&xdev->lock, flags);

	if (xdev->chardev_ready) {
		misc_deregister(&xdev->miscdev);
		xdev->chardev_ready = false;
	}
}
