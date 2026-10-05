# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Makefile for the inference benchmark client.
#
# Default target builds the sock-backend client + mock server; both build
# and run on any Linux machine with no external dependencies.
#
# The xchan backend needs libxchan to link and a real /dev/xchan* node to
# run, so it is only compiled when explicitly requested via `make xchan`,
# pointing at where libxchan's headers and library live (package.nix
# builds every backend against pkgs.libxchan, natively and for aarch64):
#
#   make xchan \
#       LIBXCHAN_DIR=/path/to/xchan/src \
#       LIBXCHAN_LIB=/path/to/libxchan.a
#
# LIBXCHAN_DIR must contain libxchan.h and xchan_uapi.h.
# LIBXCHAN_LIB is the library to link against (.a, .o or .so; pkgs.libxchan
# provides libxchan.so).

CC      ?= gcc
# _POSIX_C_SOURCE 200809L gives us clock_gettime/CLOCK_MONOTONIC, getopt,
# nanosleep, etc under strict -std=c99 (c99 alone hides POSIX declarations).
CFLAGS  ?= -std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -O2 -g
LDFLAGS ?=

BUILD_DIR := build

.PHONY: all sock vsock xchan check clean

all: sock vsock

# ---- sock backend (default, builds standalone on any Linux box) ----
sock: $(BUILD_DIR)/bench_client $(BUILD_DIR)/mock_server

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/bench_client: client.c transport_sock.c proto.h transport.h stats.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ client.c transport_sock.c $(LDFLAGS)

# The server links a backend too, now that it must be able to listen on
# xchan: a unix socket cannot cross guests, so guest-to-guest measurement
# needs the server on every arm the client can use.
$(BUILD_DIR)/mock_server: mock_server.c transport_sock.c proto.h transport.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ mock_server.c transport_sock.c $(LDFLAGS)

$(BUILD_DIR)/mock_server_vsock: mock_server.c transport_vsock.c proto.h transport.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DUSE_VSOCK -o $@ mock_server.c transport_vsock.c $(LDFLAGS)

# ---- llama_shim: throwaway shim that replaces mock_server with a real
# llama-server backend (see llama_shim.c header). Standalone, no
# dependency on transport.h/transport_sock.c. Its HTTP client half is
# llama_http.c. ----
$(BUILD_DIR)/llama_shim: llama_shim.c llama_http.c llama_http.h proto.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ llama_shim.c llama_http.c $(LDFLAGS)

# The bench client against a server that closes channels (sock backend).
$(BUILD_DIR)/test_client: test_client.c client.c transport_sock.c proto.h transport.h stats.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ test_client.c transport_sock.c $(LDFLAGS)

check: $(BUILD_DIR)/test_client
	$(BUILD_DIR)/test_client

# ---- xchan backend (target only: requires libxchan + /dev/xchan*) ----
# LIBXCHAN_DIR: directory containing libxchan.h and xchan_uapi.h
# LIBXCHAN_LIB: path to the built libxchan archive/object to link
LIBXCHAN_DIR ?=
LIBXCHAN_LIB ?=

# ---- vsock backend (third arm of the transport comparison) ----
# Needs only linux/vm_sockets.h, so it builds anywhere Linux headers exist;
# it needs a real vsock device to RUN.
vsock: $(BUILD_DIR)/bench_client_vsock $(BUILD_DIR)/mock_server_vsock $(BUILD_DIR)/vsock_relay

# Host-side relay: vsock cannot address guest-to-guest, so the vsock arm needs
# this on the host. Built with _GNU_SOURCE for splice(), hence its own rule.
$(BUILD_DIR)/vsock_relay: vsock_relay.c | $(BUILD_DIR)
	$(CC) -std=c99 -D_GNU_SOURCE -Wall -Wextra -O2 -g -o $@ vsock_relay.c $(LDFLAGS)

$(BUILD_DIR)/bench_client_vsock: client.c transport_vsock.c proto.h transport.h stats.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DUSE_VSOCK -o $@ client.c transport_vsock.c $(LDFLAGS)

xchan: $(BUILD_DIR)
	@if [ -z "$(LIBXCHAN_DIR)" ] || [ -z "$(LIBXCHAN_LIB)" ]; then \
		echo "error: xchan build needs LIBXCHAN_DIR and LIBXCHAN_LIB set, e.g.:"; \
		echo "  make xchan LIBXCHAN_DIR=/path/to/xchan/src LIBXCHAN_LIB=/path/to/libxchan.a"; \
		exit 1; \
	fi
	$(CC) $(CFLAGS) -DUSE_XCHAN -I$(LIBXCHAN_DIR) \
		-o $(BUILD_DIR)/bench_client_xchan \
		client.c transport_xchan.c \
		$(LIBXCHAN_LIB) $(LDFLAGS)
	$(CC) $(CFLAGS) -DUSE_XCHAN -I$(LIBXCHAN_DIR) \
		-o $(BUILD_DIR)/mock_server_xchan \
		mock_server.c transport_xchan.c \
		$(LIBXCHAN_LIB) $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
