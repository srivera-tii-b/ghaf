/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _XCHAN_FRAME_H
#define _XCHAN_FRAME_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#else
#include <errno.h>
#endif

/*
 * xchan_uapi.h pulls in <linux/types.h> itself (unconditionally, so it is
 * safe for userspace too) and that is what supplies __u8/__u32/__le16/...
 * here. Do not re-typedef them from <stdint.h>: on hosts where
 * <linux/types.h> is real (any Linux box with kernel headers, which this
 * driver already requires), redeclaring e.g. __u64 via stdint conflicts
 * with the system definition (both 64-bit, different base type).
 */
#include "xchan_uapi.h"

#define XCHAN_FLAGS_KNOWN \
	(XCHAN_F_WINDOW_REF | XCHAN_F_RELEASE | XCHAN_F_MORE | XCHAN_F_ABORT)

/* Maximum window buffers per slot per direction. */
#define XCHAN_WINDOW_BUFS 16

/*
 * Validate a frame header received from the device.
 *
 * The device is in the untrusted host: treat every field as adversarial.
 * Returns 0 if the frame may be acted on, -EMSGSIZE if it carries more than
 * dst_cap bytes, or -EINVAL for a protocol violation, on which the caller
 * must tear the channel down, never clamp, truncate or ignore.
 *
 * -EMSGSIZE is decided after the flag checks but BEFORE the WINDOW_REF
 * geometry checks and the window_id bounds check, so a frame that gets it is
 * not yet known to be well formed: a caller that uses its window_id
 * afterwards (to RELEASE the buffer) must bounds-check it itself.
 * xchan_do_recv() keeps the channel on -EMSGSIZE, it drains the rest of
 * the message and returns the error, unless the frame is a WINDOW_REF with
 * an out-of-range window_id or the drain meets a bad fragment; both tear the
 * channel down.
 */
int xchan_frame_validate(const struct xchan_frame *f, __u32 slice_size,
			 __u32 dst_cap);

#endif /* _XCHAN_FRAME_H */
