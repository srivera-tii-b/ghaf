/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * g2gchan: message channels between two protected pKVM guests over pages EL2
 * shares between them (/dev/pkvm-g2g). No host is in the data path.
 *
 * One process per VM may use it: EL2's mailbox has one slot and one reader.
 * Not fork-safe: device mappings are not inherited.
 *
 * Threads: one thread at a time in g2gc_connect() and g2gc_accept(), per
 * process. Each reads the mailbox and drops every message that is not its
 * own, so two at once discard each other's answers (a second connect takes
 * the first one's ACCEPTED and drops it). Calls on one channel may come from
 * several threads (sends are serialised, as are receives), except
 * g2gc_close(): it frees the channel, so no other call on that channel may
 * run during or after it.
 *
 * Every call returns -1 / NULL with errno: ECONNRESET (peer closed or gone),
 * ECONNREFUSED (no such live peer, or it refused), EMSGSIZE, ETIMEDOUT, EPROTO
 * (the peer broke the protocol), or the error of a failed system call (the
 * device's open, ioctl or mmap, memory, the poller thread). After EPROTO,
 * ETIMEDOUT from a stall, a peer that vanished, or a peer that closed while
 * a send was inside a message (ECONNRESET), the channel is torn down: every
 * later send or recv on it fails with the same errno (except that a send over
 * 16 MiB still fails with EMSGSIZE first); g2gc_fd() still returns the fd, and
 * g2gc_close() still frees it.
 *
 * Time limits, set at build time (-DG2GC_STALL_MS=..., -DG2GC_CLOSE_DRAIN_MS=...;
 * in ghaf, pkgs.g2gchan.override { stallMs = ...; closeDrainMs = ...; }). The
 * defaults are first guesses, to be set from measurements:
 *   G2GC_STALL_MS (30000)       a peer that stops inside a message, or gives no
 *                               credit back (between messages too), for this
 *                               long: ETIMEDOUT, and the channel is torn down.
 *   G2GC_CLOSE_DRAIN_MS (2000)  g2gc_close() waits this long for the peer to take
 *                               what was sent and acknowledge; after it the
 *                               shares go anyway, and data the peer has not
 *                               taken by then is lost (its next read faults:
 *                               ECONNRESET). xchan, by contrast, hands a reader
 *                               everything that arrived before a close, then
 *                               reports ECONNRESET; here a slow reader can miss
 *                               the last messages.
 *
 * Faults: the peer can take its share away at any moment, and the next read
 * of it then faults (SIGBUS). The library installs a SIGBUS handler, for the
 * life of the process, at the start of the first g2gc_connect() (even one
 * that fails) or when g2gc_accept() first takes a CONNECT, and turns such a
 * fault into ECONNRESET. It takes only a fault inside the share bytes the
 * faulting thread is accessing at that moment (or one that reports no address
 * while it is). Any other fault goes to the handler that was installed before
 * (so install yours before the first g2gc_connect() or g2gc_accept(); one
 * installed after replaces the library's), called from the library's
 * handler, so its own sa_mask and flags other than SA_SIGINFO do not apply;
 * with none before (default or ignored), the process dies as it would have.
 * A thread that blocks SIGBUS must not call into g2gchan: the kernel forces
 * a blocked fault and the process dies. The library's poller thread, which
 * reads every open channel's share, inherits the signal mask of the thread
 * whose g2gc_connect() or g2gc_accept() starts it.
 */
#ifndef G2GCHAN_H
#define G2GCHAN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct g2gc g2gc_t;
typedef struct g2gc_listener g2gc_listener_t;

/* "probe-id": the identity's low half that the guest kernel's boot-time
 * probe registers (a predictable name, for bring-up). */
#define G2GC_PROBE_ID_LO 0x70726f62652d6964ULL

g2gc_listener_t *g2gc_listen(void);
/* The next client. timeout_ms < 0 waits forever. */
g2gc_t *g2gc_accept(g2gc_listener_t *l, int timeout_ms);
void g2gc_listener_close(g2gc_listener_t *l);

g2gc_t *g2gc_connect(uint64_t id_hi, uint64_t id_lo, int timeout_ms);

/* One whole message each way, at most 16 MiB. Both block; recv until a
 * message arrives. A message larger than cap fails recv with EMSGSIZE and
 * consumes nothing, so a retry with a larger buffer gets it (xchan, by
 * contrast, discards such a message). */
ssize_t g2gc_send(g2gc_t *c, const void *buf, size_t len);
ssize_t g2gc_recv(g2gc_t *c, void *buf, size_t cap);

/*
 * An eventfd for poll(): readable (POLLIN) while g2gc_recv() would not wait
 * for a message to start, as last seen by the poller thread (it looks about
 * every millisecond) or by g2gc_recv(), which refreshes it as it returns. It
 * reports POLLIN only; POLLOUT means nothing (an eventfd is always writable),
 * and g2gc_send() blocks for credit. Poll it only: a read of it loses
 * wake-ups, a write fakes a POLLIN that stays on, and g2gc_close() closes it.
 */
int g2gc_fd(g2gc_t *c);

/* Lets the peer drain (bounded by G2GC_CLOSE_DRAIN_MS), then ends both shares
 * and frees c. */
void g2gc_close(g2gc_t *c);

#endif
