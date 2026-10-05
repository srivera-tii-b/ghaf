/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>
#include <string.h>
#include "../src/xchan_frame.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct xchan_frame f;
	__u32 slice_size;
	__u32 dst_cap;

	if (size < sizeof(f) + 8)
		return 0;

	memcpy(&f, data, sizeof(f));
	memcpy(&slice_size, data + sizeof(f), 4);
	memcpy(&dst_cap, data + sizeof(f) + 4, 4);

	/* Must never crash, never hang, and never return an undefined value. */
	int rc = xchan_frame_validate(&f, slice_size, dst_cap);
	if (rc != 0 && rc != -EINVAL && rc != -EMSGSIZE)
		__builtin_trap();

	return 0;
}
