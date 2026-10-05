/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libxchan: thin userspace wrapper over the virtio-xchan character device.
 * See libxchan.h for the API contract. This file only marshals struct
 * xchan_msg for the two channel ioctls and translates the kernel's error
 * conventions, it carries no buffer-lifetime tracking, no fragmentation
 * logic of its own, and no security-relevant checks: the driver owns all of
 * that, which is exactly what keeps this file this short.
 */
#include "libxchan.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define XCHAN_DEFAULT_DEVICE "/dev/xchan0"

int xchan_open(const char *path)
{
	return open(path ? path : XCHAN_DEFAULT_DEVICE, O_RDWR | O_CLOEXEC);
}

int xchan_wait_channel(int devfd, struct xchan_channel_info *out)
{
	struct xchan_channel_info info;
	int fd;

	/*
	 * XCHAN_WAIT_CHANNEL is unusual among ioctls: on success its return
	 * value IS the new channel fd (the driver's xchan_dev_ioctl()
	 * returns it directly), not a 0/-1 status alongside an out
	 * parameter. glibc's ioctl() wrapper passes the raw syscall return
	 * straight through, so this is exactly what comes back here.
	 */
	fd = ioctl(devfd, XCHAN_WAIT_CHANNEL, &info);
	if (fd < 0)
		return -1;

	if (out)
		*out = info;

	return fd;
}

ssize_t xchan_send(int chanfd, const void *buf, size_t len)
{
	struct xchan_msg msg;

	/*
	 * struct xchan_msg.len is a wire-sized __u32; a caller-provided
	 * length that cannot even be expressed in the ioctl ABI is refused
	 * here rather than silently truncated.
	 */
	if (len > UINT32_MAX) {
		errno = EMSGSIZE;
		return -1;
	}

	msg.seq = 0;
	msg.flags = 0;
	msg.len = (__u32)len;
	msg.addr = (__u64)(uintptr_t)buf;

	/*
	 * A 0 ioctl() return means every byte of `len` went out: the driver
	 * either moves the whole message, one inline frame, or every
	 * fragment of a larger one, or fails the call and returns a
	 * negative errno instead of a partial count.
	 *
	 * That is NOT the same as "a failed call never put anything on the
	 * wire". A multi-fragment send can fail after earlier fragments
	 * already reached the peer, this function cannot undo that, and does
	 * not try to. What it does not have to worry about is the peer
	 * mistaking that prefix for a delivered message: on any such
	 * mid-message failure the kernel driver itself posts an explicit abort
	 * frame before returning the error here, so the peer's XCHAN_RECV
	 * fails with ECANCELED instead of hanging or misreading the next
	 * message's fragments as this one's continuation. See libxchan.h's
	 * xchan_send()/xchan_recv() doc comments for the full contract this
	 * call now actually provides.
	 */
	if (ioctl(chanfd, XCHAN_SEND, &msg) < 0)
		return -1;

	return (ssize_t)len;
}

ssize_t xchan_recv(int chanfd, void *buf, size_t cap)
{
	struct xchan_msg msg;

	msg.seq = 0;
	msg.flags = 0;
	/*
	 * Input: destination capacity. A larger buffer than the ioctl can
	 * describe is still a valid place to receive into; clamp rather than
	 * fail, which would report EMSGSIZE ("message larger than cap") for a
	 * message that fits.
	 */
	msg.len = cap > UINT32_MAX ? UINT32_MAX : (__u32)cap;
	msg.addr = (__u64)(uintptr_t)buf;

	/*
	 * XCHAN_RECV overwrites msg.len with the actual byte count received
	 * (reassembled across fragments if the sender split the message)
	 * before returning it to userspace, that is what is reported back
	 * here, not the input capacity.
	 */
	if (ioctl(chanfd, XCHAN_RECV, &msg) < 0)
		return -1;

	return (ssize_t)msg.len;
}
