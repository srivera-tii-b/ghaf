/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * virtio-xchan guest driver: virtio probe and configuration-space handling.
 *
 * virtio-xchan is a cross-guest message and bulk-data transport implemented by
 * crosvm. crosvm runs in the host, which this project treats as a named,
 * untrusted adversary (the pKVM threat model): every field this driver reads
 * out of configuration space is attacker-controlled and must be bounds-checked
 * before it is used for anything, in particular before it feeds a virtqueue
 * count or an allocation size.
 *
 * This file establishes the device, probe, configuration-space
 * validation, feature negotiation and virtqueue discovery, and owns the
 * struct xchan_dev / struct xchan_channel lifetime (probe/remove). The
 * character device and channel-acquisition path, and the frame data path,
 * are built on top of this and wired in at the end of probe()/remove().
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "xchan_priv.h"
#include "xchan_uapi.h"

/*
 * Config space is untrusted. These are the hard ceilings the driver enforces
 * regardless of what the device advertises:
 *
 *   - max_channels: 0 is meaningless (no channels at all) and anything
 *     above this bound turns straight into an oversized virtqueue count
 *     and an oversized channel-array allocation below.
 *   - window_slice_size: 0 is a legitimate "no window" device (see
 *     struct virtio_xchan_config below); anything above this bound is
 *     rejected before it can reach a future allocation.
 *
 * Neither limit is part of the ABI; both are this driver's own defensive
 * posture and may be revisited without touching xchan_uapi.h.
 */
#define XCHAN_MAX_CHANNELS		256U
#define XCHAN_MAX_WINDOW_SLICE_SIZE	(256U * 1024 * 1024)

/*
 * struct xchan_channel / struct xchan_dev now live in xchan_priv.h: the
 * character device (xchan_chardev.c) needs the same layout, so it can no
 * longer be private to this file. This file still owns their lifetime.
 */

/*
 * Validate configuration space against the device-hostile threat model.
 * Returns 0 and fills *max_channels / *window_slice_size / *endpoint on
 * success, or a negative errno if the device's config is out of bounds.
 */
static int xchan_validate_config(struct virtio_device *vdev,
				 u32 *max_channels, u32 *window_slice_size,
				 u32 *endpoint)
{
	u32 mc, wss, ep;

	virtio_cread_le(vdev, struct virtio_xchan_config, max_channels, &mc);
	virtio_cread_le(vdev, struct virtio_xchan_config, window_slice_size,
			&wss);
	virtio_cread_le(vdev, struct virtio_xchan_config, endpoint, &ep);

	if (mc == 0 || mc > XCHAN_MAX_CHANNELS) {
		dev_err(&vdev->dev,
			"rejecting max_channels=%u from device (must be 1..%u)\n",
			mc, XCHAN_MAX_CHANNELS);
		return -EINVAL;
	}

	if (wss > XCHAN_MAX_WINDOW_SLICE_SIZE) {
		dev_err(&vdev->dev,
			"rejecting window_slice_size=%u from device (must be <= %u bytes)\n",
			wss, XCHAN_MAX_WINDOW_SLICE_SIZE);
		return -EINVAL;
	}

	/* endpoint is a role signal, unlike max_channels (a capacity), a
	 * hostile or buggy device could otherwise make this driver map its
	 * Tx half onto memory mapped read-only into it.
	 */
	if (ep != 0 && ep != 1) {
		dev_err(&vdev->dev,
			"rejecting endpoint=%u from device (must be 0 or 1)\n",
			ep);
		return -EINVAL;
	}

	*max_channels = mc;
	*window_slice_size = wss;
	*endpoint = ep;
	return 0;
}

/* Free a vq_names array as built by xchan_alloc_vq_names(). */
static void xchan_free_vq_names(const char **names, unsigned int nvqs)
{
	unsigned int i;

	if (!names)
		return;

	for (i = 0; i < nvqs; i++)
		kfree(names[i]);
	kfree(names);
}

/*
 * Build the per-virtqueue debug names virtio_find_vqs() wants. The names
 * must outlive the call (struct virtqueue keeps the pointer it is given for
 * later diagnostics), so they are owned by struct xchan_dev and freed at
 * remove() rather than immediately after find_vqs().
 *
 * Layout: 0 = eventq, 1 = commandq, then slot k's RX/TX pair at 2+2k / 3+2k.
 */
static int xchan_alloc_vq_names(struct xchan_dev *xdev, const char ***names_out)
{
	const char **names;
	unsigned int i;

	names = kcalloc(xdev->nvqs, sizeof(*names), GFP_KERNEL);
	if (!names)
		return -ENOMEM;

	names[0] = kasprintf(GFP_KERNEL, "xchan.event");
	names[1] = kasprintf(GFP_KERNEL, "xchan.cmd");
	if (!names[0] || !names[1])
		goto err;

	for (i = 0; i < xdev->max_channels; i++) {
		names[2 + 2 * i] = kasprintf(GFP_KERNEL, "xchan.rx%u", i);
		names[3 + 2 * i] = kasprintf(GFP_KERNEL, "xchan.tx%u", i);
		if (!names[2 + 2 * i] || !names[3 + 2 * i])
			goto err;
	}

	*names_out = names;
	return 0;

err:
	xchan_free_vq_names(names, xdev->nvqs);
	return -ENOMEM;
}

/* Forward declaration: defined after xchan_probe() below, which needs it on
 * its own late failure path; shared with remove().
 */
static void xchan_teardown(struct xchan_dev *xdev);

static int xchan_probe(struct virtio_device *vdev)
{
	struct xchan_dev *xdev;
	struct virtqueue **vqs = NULL;
	struct virtqueue_info *vqs_info = NULL;
	const char **names = NULL;
	u32 max_channels, window_slice_size, endpoint;
	unsigned int nvqs, i;
	int ret;

	ret = xchan_validate_config(vdev, &max_channels, &window_slice_size,
				    &endpoint);
	if (ret)
		return ret;

	xdev = kzalloc(sizeof(*xdev), GFP_KERNEL);
	if (!xdev)
		return -ENOMEM;

	xdev->vdev = vdev;
	xdev->max_channels = max_channels;
	xdev->window_slice_size = window_slice_size;
	xdev->endpoint = endpoint;

	/*
	 * Eventq (0) and commandq (1), plus an RX/TX pair per channel slot.
	 * Total is 2 + 2 * max_channels, an earlier revision of the ABI had
	 * a single control queue and no driver->device path, which left the
	 * guest no way to tell crosvm it had closed a channel fd, so crosvm
	 * could never safely reuse a slot.
	 */
	nvqs = 2 + 2 * max_channels;
	xdev->nvqs = nvqs;

	xdev->channels = kcalloc(max_channels, sizeof(*xdev->channels),
				 GFP_KERNEL);
	if (!xdev->channels) {
		ret = -ENOMEM;
		goto err_xdev;
	}

	vqs = kcalloc(nvqs, sizeof(*vqs), GFP_KERNEL);
	vqs_info = kcalloc(nvqs, sizeof(*vqs_info), GFP_KERNEL);
	if (!vqs || !vqs_info) {
		ret = -ENOMEM;
		goto err_vqs;
	}

	ret = xchan_alloc_vq_names(xdev, &names);
	if (ret)
		goto err_vqs;

	/*
	 * Index 0 (eventq) delivers XCHAN_EV_ATTACHED/DETACHED, which
	 * XCHAN_WAIT_CHANNEL and the per-channel state machine depend on.
	 * Index 1 (commandq) is driver->device, so its callback only reclaims
	 * buffers this driver posted once the device has consumed them,
	 * there is nothing to process on the way in.
	 *
	 * Per slot k, index 2+2k (RX) gets xchan_rx_vq_isr: it drains
	 * completed inbufs, fully handles RELEASE frames inline, and hands
	 * real data frames to XCHAN_RECV via xchan_channel.rx_ready. Index
	 * 3+2k (TX) stays uncallbacked, XCHAN_SEND reclaims completed
	 * outbufs opportunistically on its own next call rather than needing
	 * an interrupt for it, which keeps the TX side out of interrupt
	 * context entirely.
	 */
	for (i = 0; i < nvqs; i++)
		vqs_info[i].name = names[i];
	vqs_info[0].callback = xchan_event_vq_isr;
	vqs_info[1].callback = xchan_cmd_vq_isr;
	for (i = 2; i < nvqs; i++)
		vqs_info[i].callback =
			((i - 2) % 2 == 0) ? xchan_rx_vq_isr : NULL;

	ret = virtio_find_vqs(vdev, nvqs, vqs, vqs_info, NULL);
	kfree(vqs_info);
	vqs_info = NULL;
	if (ret) {
		dev_err(&vdev->dev, "failed to find %u virtqueues: %d\n",
			nvqs, ret);
		goto err_names;
	}

	xdev->event_vq = vqs[0];
	xdev->cmd_vq = vqs[1];
	for (i = 0; i < max_channels; i++) {
		xdev->channels[i].rx_vq = vqs[2 + 2 * i];
		xdev->channels[i].tx_vq = vqs[3 + 2 * i];
	}

	xdev->vqs = vqs;
	xdev->vq_names = names;
	vdev->priv = xdev;

	dev_info(&vdev->dev,
		 "xchan: probed device %u, max_channels=%u window_slice_size=%u bytes (window=%s)\n",
		 XCHAN_DEVICE_ID, max_channels, window_slice_size,
		 virtio_has_feature(vdev, VIRTIO_XCHAN_F_WINDOW) ? "yes" : "no");

	/*
	 * Everything above is vqs/names/channels as local variables; from
	 * here on they are committed into *xdev, so a failure past this
	 * point unwinds through xchan_teardown() (shared with remove())
	 * rather than the err_* labels above, which assume those variables
	 * are not yet owned by *xdev.
	 */
	ret = xchan_chardev_init(xdev);
	if (ret) {
		vdev->priv = NULL;
		xchan_teardown(xdev);
		return ret;
	}

	return 0;

err_names:
	xchan_free_vq_names(names, nvqs);
err_vqs:
	kfree(vqs_info);
	kfree(vqs);
	kfree(xdev->channels);
err_xdev:
	kfree(xdev);
	return ret;
}

/*
 * Shared teardown for a fully-constructed struct xchan_dev, i.e. one where
 * probe() has already stored vqs/vq_names/channels into it (used both by a
 * xchan_chardev_init() failure late in probe() and by remove()).
 *
 * Tears down the chardev layer and the virtio side unconditionally, then
 * drops the driver's own reference on xdev. If a channel fd is still open
 * at this point, xdev/xdev->channels stay alive (kept up by that fd's own
 * reference, taken in XCHAN_WAIT_CHANNEL and dropped in the channel's
 * .release()) until it closes, see struct xchan_dev's refcnt comment.
 *
 * xdev->vdev and anything reachable only through it (virtqueues, config
 * space) must not be touched by any chardev code path once this returns:
 * xchan_chardev_exit() marks xdev->removed for exactly that purpose before
 * this function goes on to reset the device and free the queues.
 *
 * xdev->event_bufs is freed here rather than in xchan_chardev_exit(),
 * deliberately after virtio_reset_device()/del_vqs(): those buffers are
 * still posted as inbufs on the eventq up to that point, and freeing memory
 * the device might still DMA into would itself be a use-after-free, just on
 * the device's side of the boundary instead of the guest's.
 *
 * The commandq and every channel's tx_vq have no array to free here: their
 * outbufs are individually kmalloc()'d (struct xchan_command, and TX frames
 * of up to XCHAN_FRAME_BUF_SIZE bytes) and normally reclaimed only by
 * xchan_cmd_vq_isr() or by a later send on the same slot (xchan_tx_reap()).
 * Neither happens once the device is reset, so xchan_free_unused_outbufs()
 * collects whatever is left, between the reset and del_vqs().
 */
static void xchan_free_unused_outbufs(struct xchan_dev *xdev)
{
	unsigned int i;
	void *buf;

	for (i = 0; xdev->channels && i < xdev->max_channels; i++) {
		struct virtqueue *vq = xdev->channels[i].tx_vq;

		if (!vq)
			continue;
		while ((buf = virtqueue_detach_unused_buf(vq)) != NULL)
			kfree(buf);
	}

	if (xdev->cmd_vq)
		while ((buf = virtqueue_detach_unused_buf(xdev->cmd_vq)) != NULL)
			kfree(buf);
}

static void xchan_teardown(struct xchan_dev *xdev)
{
	xchan_chardev_exit(xdev);

	virtio_reset_device(xdev->vdev);
	xchan_free_unused_outbufs(xdev);
	xdev->vdev->config->del_vqs(xdev->vdev);

	kfree(xdev->event_bufs);
	xdev->event_bufs = NULL;

	/*
	 * Per-channel data-path resources, same reasoning as event_bufs above:
	 * rx_bufs are still posted as live inbufs on each rx_vq up to this
	 * point, so they are only safe to free once the device has been reset
	 * and the queues deleted. tx_window/rx_window are kernel memremap()
	 * mappings of the shared-memory region rather than DMA targets, so
	 * their ordering here is not itself safety-critical, but unwinding
	 * everything in one place after the device is quiesced keeps this
	 * function's structure easy to audit. xdev->channels is guaranteed
	 * non-NULL here (xchan_teardown() is only ever called on a struct xdev
	 * past the point probe() installed it), and every per-channel field
	 * below is zero-initialised by probe()'s kcalloc() even on a setup
	 * path that never ran or bailed out partway through, so each check is
	 * safe unconditionally.
	 */
	if (xdev->channels) {
		unsigned int i;

		for (i = 0; i < xdev->max_channels; i++) {
			struct xchan_channel *chan = &xdev->channels[i];
			unsigned long flags;
			unsigned int j;

			/*
			 * Drain: an XCHAN_SEND/XCHAN_RECV already in flight on
			 * this channel fd (this device can be removed while a
			 * channel fd is still open, that is the entire
			 * reason xdev/xdev->channels carry their own refcnt,
			 * see xdev->refcnt's comment) holds chan->send_lock or
			 * chan->recv_lock for the call's WHOLE duration,
			 * including a copy_from_user()/copy_to_user() that may
			 * still be executing right now against chan->rx_bufs[]
			 * .data, chan->tx_window or chan->rx_window. Freeing
			 * those out from under such a call would be a
			 * use-after-free indistinguishable from the vdev one
			 * this driver has already been bitten by once.
			 * Acquiring and immediately releasing both mutexes
			 * here is a synchronisation barrier, not a new source
			 * of blocking: xchan_chardev_exit() above already set
			 * xdev->removed and woke every channel's poll_wq (both
			 * this function's own wait_event_interruptible() calls
			 * and xchan_rx_pop_ready()'s check it), so any call
			 * still in flight is either already unwinding via its
			 * own removed-check or performing a single bounded
			 * user-memory copy, never waiting on anything this
			 * thread must supply.
			 */
			mutex_lock(&chan->send_lock);
			mutex_unlock(&chan->send_lock);
			mutex_lock(&chan->recv_lock);
			mutex_unlock(&chan->recv_lock);

			if (chan->tx_window)
				memunmap(chan->tx_window);
			if (chan->rx_window)
				memunmap(chan->rx_window);

			/*
			 * rx_ready links entries of rx_bufs[] itself. A channel
			 * fd can outlive the device, and when it closes
			 * xchan_slot_wipe() walks rx_ready, which must not
			 * lead into the array freed below. The queues are gone,
			 * so nothing can add to it again.
			 */
			spin_lock_irqsave(&xdev->lock, flags);
			INIT_LIST_HEAD(&chan->rx_ready);
			spin_unlock_irqrestore(&xdev->lock, flags);

			for (j = 0; j < chan->rx_depth; j++)
				kfree(chan->rx_bufs[j].data);
			kfree(chan->rx_bufs);
			chan->rx_bufs = NULL;
			chan->rx_depth = 0;
		}
	}

	xchan_free_vq_names(xdev->vq_names, xdev->nvqs);
	kfree(xdev->vqs);

	xchan_put(xdev);
}

static void xchan_remove(struct virtio_device *vdev)
{
	struct xchan_dev *xdev = vdev->priv;

	if (!xdev)
		return;

	vdev->priv = NULL;
	xchan_teardown(xdev);
}

static const struct virtio_device_id id_table[] = {
	{ .device = XCHAN_DEVICE_ID, .vendor = VIRTIO_DEV_ANY_ID },
	{ 0 },
};
MODULE_DEVICE_TABLE(virtio, id_table);

/*
 * Feature bits this driver negotiates. VIRTIO_XCHAN_F_ATTESTED_ID is
 * deliberately absent: attested peer identity is not implemented, so
 * peer_identity carries nothing meaningful. VIRTIO_XCHAN_F_SESSION is
 * reserved and must never be negotiated (see xchan_uapi.h). Listing only
 * WINDOW means the virtio core will never let either be negotiated on by
 * this driver, regardless of what the device offers.
 */
static unsigned int features[] = {
	VIRTIO_XCHAN_F_WINDOW,
};

static struct virtio_driver xchan_driver = {
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.driver.name		= KBUILD_MODNAME,
	.id_table		= id_table,
	.probe			= xchan_probe,
	.remove			= xchan_remove,
};

module_virtio_driver(xchan_driver);

MODULE_AUTHOR("TII (SSRC) and the Ghaf contributors");
MODULE_DESCRIPTION("virtio-xchan cross-guest transport driver");
MODULE_LICENSE("GPL");
