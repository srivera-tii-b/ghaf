/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* vsock_relay.c, host-side relay making guest-to-guest vsock possible.
 *
 * vsock is guest-to-HOST. Two guests cannot address each other over it, so
 * comparing vsock against xchan for guest-to-guest traffic requires a relay
 * on the host, and the relay's cost is part of what vsock actually costs in
 * that topology. xchan needs no equivalent: its two crosvm processes meet on
 * a host unix socket without a separate daemon.
 *
 * Listens on <listen-port> (VMADDR_CID_ANY). For each connection, dials
 * <dest-cid>:<dest-port> and pumps both directions until either side closes.
 *
 * Uses splice() through a pipe rather than a read/write buffer loop. That is
 * deliberate: a naive relay would add two copies per direction, and quoting a
 * number from a deliberately weak relay would understate vsock. splice keeps
 * the payload in kernel buffers, which is what a competent implementation
 * would do, so the comparison is fair to the alternative.
 *
 * One connection pair at a time, sequentially, the benchmark drives a
 * single client, and concurrency here would add scheduling noise to the
 * measurement rather than realism.
 */
/* _GNU_SOURCE (for splice) comes from the build rule, not from here. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <linux/vm_sockets.h>

#define PIPE_CHUNK (64 * 1024)

static int dial(unsigned int cid, unsigned int port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = cid;
    addr.svm_port = port;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

/* Move whatever is readable on `from` to `to` via the pipe. Returns 1 if
 * bytes moved, 0 on clean EOF, -1 on error. */
static int pump(int from, int to, int pipefd[2]) {
    ssize_t n = splice(from, NULL, pipefd[1], NULL, PIPE_CHUNK,
                       SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (n == 0) return 0;
    if (n < 0) {
        if (errno == EAGAIN || errno == EINTR) return 1;
        return -1;
    }

    while (n > 0) {
        ssize_t w = splice(pipefd[0], NULL, to, NULL, (size_t)n, SPLICE_F_MOVE);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        n -= w;
    }
    return 1;
}

static void relay(int a, int b) {
    int pab[2], pba[2];
    if (pipe(pab) != 0) return;
    if (pipe(pba) != 0) { close(pab[0]); close(pab[1]); return; }

    struct pollfd pfd[2];
    pfd[0].fd = a; pfd[1].fd = b;
    pfd[0].events = pfd[1].events = POLLIN;

    for (;;) {
        if (poll(pfd, 2, -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pfd[0].revents & POLLIN) { if (pump(a, b, pab) <= 0) break; }
        if (pfd[1].revents & POLLIN) { if (pump(b, a, pba) <= 0) break; }
        if ((pfd[0].revents | pfd[1].revents) & (POLLHUP | POLLERR)) break;
    }

    close(pab[0]); close(pab[1]);
    close(pba[0]); close(pba[1]);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <listen-port> <dest-cid> <dest-port>\n"
        "\n"
        "  Relays vsock connections between two guests, which cannot address\n"
        "  each other directly. Run on the host.\n"
        "\n"
        "  e.g. %s 9000 3 9000   # accept on 9000, forward to CID 3 port 9000\n",
        argv0, argv0);
}

int main(int argc, char **argv) {
    if (argc != 4) { usage(argv[0]); return 2; }

    unsigned int lport = (unsigned int)strtoul(argv[1], NULL, 10);
    unsigned int dcid  = (unsigned int)strtoul(argv[2], NULL, 10);
    unsigned int dport = (unsigned int)strtoul(argv[3], NULL, 10);

    int lfd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket(AF_VSOCK)"); return 1; }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = lport;

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { perror("bind"); return 1; }
    if (listen(lfd, 16) != 0) { perror("listen"); return 1; }

    fprintf(stderr, "vsock-relay: %u -> cid %u port %u\n", lport, dcid, dport);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        int dfd = dial(dcid, dport);
        if (dfd < 0) {
            fprintf(stderr, "vsock-relay: dial cid %u port %u failed: %s\n",
                    dcid, dport, strerror(errno));
            close(cfd);
            continue;
        }

        relay(cfd, dfd);
        close(dfd);
        close(cfd);
    }

    close(lfd);
    return 0;
}
