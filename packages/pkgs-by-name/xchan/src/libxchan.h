/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libxchan: thin userspace wrapper over the virtio-xchan character device. A
 * channel fd returned by xchan_wait_channel() is a plain POSIX file descriptor,
 * close() it directly, no xchan_close() is needed or provided.
 *
 * xchan_send()/xchan_recv() hide fragmentation entirely: every message travels
 * inline, split into XCHAN_INLINE_MAX-byte fragments above that size, and
 * callers never see a XCHAN_F_MORE frame. (The shared window cannot be mapped
 * into a second protected guest under pKVM, so the driver no longer uses it to
 * send.) Every security-relevant check is enforced by the kernel driver, not
 * here, this library only marshals struct xchan_msg for
 * XCHAN_SEND/XCHAN_RECV and maps the driver's error conventions onto the
 * customary -1/errno.
 */
#ifndef _LIBXCHAN_H
#define _LIBXCHAN_H

#include <sys/types.h>

#include "xchan_uapi.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opens the device node XCHAN_WAIT_CHANNEL is issued against, `path`, or
 * "/dev/xchan0" if `path` is NULL. Returns an open device fd, or -1 with errno
 * set.
 */
int xchan_open(const char *path);

/*
 * Blocks until a channel is available on `devfd` and returns a NEW file
 * descriptor bound to it (one fd per channel, for the fd's whole lifetime),
 * filling *out with the channel's identity, flags, window_slice_size and
 * peer_identity. Honours O_NONBLOCK on `devfd`. Returns the channel fd, or -1
 * with errno set (EAGAIN if `devfd` is O_NONBLOCK and no channel is waiting).
 */
int xchan_wait_channel(int devfd, struct xchan_channel_info *out);

/*
 * Sends `len` bytes from `buf` on channel `chanfd`, transparently split into
 * inline fragments above XCHAN_INLINE_MAX, callers never think about it.
 *
 * This call is atomic from the PEER's point of view, not on the wire: the
 * peer's xchan_recv() either returns this complete message or fails, it
 * never hands its caller a truncated one, but a message that needs more than
 * one fragment can fail locally (a bad user pointer, an allocation failure, a
 * full ring under O_NONBLOCK, a signal) AFTER earlier fragments have already
 * reached the peer, and this call cannot un-send those. (An earlier version of
 * this comment promised no partial send in any sense; that was false the
 * moment fragmentation existed.) On any such mid-message failure the kernel
 * driver posts an explicit abort frame of its own accord so the peer's
 * xchan_recv(), which by then may already be blocked waiting for the rest of
 * this message, fails with -1/ECANCELED instead of hanging forever or
 * misreading a later message's fragments as this one's continuation, nothing
 * a caller of xchan_send() needs to do to make that happen.
 *
 * Returns `len` on success, or -1 with errno set, notably EAGAIN if `chanfd`
 * is O_NONBLOCK and the call would otherwise block, ECONNRESET if the peer
 * detached or the channel failed a protocol check, and EMSGSIZE if `len`
 * exceeds UINT32_MAX.
 */
ssize_t xchan_send(int chanfd, const void *buf, size_t len);

/*
 * Receives one complete message into `buf` (capacity `cap`), transparently
 * reassembling it if the sender fragmented it. Returns the number of bytes
 * written to `buf` on success, or -1 with errno set, notably EAGAIN if no
 * frame is available and `chanfd` is O_NONBLOCK, ECONNRESET if the peer
 * detached (only once every message it sent before detaching has been
 * returned) or the channel failed a protocol check, EMSGSIZE if the message is
 * larger than `cap` (the rest of the message is then discarded and the channel
 * stays usable; an oversized message is never returned as a truncated one),
 * and ECANCELED if the SENDER abandoned this message partway through, it
 * failed on its own send path after already transmitting part of the message
 * and told the driver so via an explicit abort frame, which is neither a
 * sizing problem on this end (EMSGSIZE) nor a broken channel (ECONNRESET): the
 * very next xchan_recv() call on `chanfd` is expected to work normally.
 * `buf`'s contents are undefined on any error return, ECANCELED included.
 */
ssize_t xchan_recv(int chanfd, void *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* _LIBXCHAN_H */
