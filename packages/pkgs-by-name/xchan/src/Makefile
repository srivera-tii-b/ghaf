# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: GPL-2.0-only
#
# Out-of-tree build Makefile for the virtio-xchan guest driver.
#
# Usage:
#   make KERNELDIR=/path/to/kernel/build
#   sudo insmod xchan.ko
#   ... test ...
#   sudo rmmod xchan

KERNELRELEASE ?= $(shell uname -r)
KERNELDIR     ?= /lib/modules/$(KERNELRELEASE)/build
PWD           := $(shell pwd)

obj-m := xchan.o
xchan-objs := xchan_drv.o xchan_frame.o xchan_chardev.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
