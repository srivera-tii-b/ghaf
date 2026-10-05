/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* The five device operations g2gchan uses: /dev/pkvm-g2g, or the simulator. */
#ifndef G2GC_DEV_H
#define G2GC_DEV_H

#include <linux/pkvm_g2g.h>

#ifdef G2GC_SIM
/* The test simulator (G2GC_SIM builds only): the /dev/pkvm-g2g driver's
 * code unchanged, on a model of EL2. A window EL2 took away reads as
 * PROT_NONE there, so its fault is SIGSEGV. */
#include <signal.h>
#include "sim_ops.h"
#define G2GC_FAULT_SIGNAL_2 SIGSEGV
#else
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

static inline int dev_open(void)
{
	return open("/dev/pkvm-g2g", O_RDWR | O_CLOEXEC);
}

static inline int dev_ioctl(int fd, unsigned long cmd, void *arg)
{
	return ioctl(fd, cmd, arg);
}

static inline void *dev_mmap(int fd, size_t len, int prot, uint64_t off)
{
	return mmap(NULL, len, prot, MAP_SHARED, fd, (off_t)off);
}

static inline int dev_munmap(void *p, size_t len)
{
	return munmap(p, len);
}

static inline void dev_close(int fd)
{
	close(fd);
}
#endif

#endif
