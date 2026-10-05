/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* test_client.c, the bench client against a server that closes channels.
 *
 * An xchan channel handed out by WAIT_CHANNEL may already be dead: crosvm
 * opens a connector's next channel in advance, and a server that stopped
 * since leaves it detached but still handed out. The bench client must then
 * take the next channel, as xchan-demo-client does, a bounded number of
 * times, and never once a request has gone through, which would hide a
 * server dying mid-run. Over the sock backend, a connection the server
 * closes before its first reply stands in for such a channel.
 *
 *   cc -std=c99 -D_POSIX_C_SOURCE=200809L -o test-client test_client.c transport_sock.c
 *   ./test-client
 */
#define main bench_client_main
#include "client.c"
#undef main

#include <signal.h>
#include <sys/wait.h>

/* What the server does with the i-th connection it accepts. */
#define DROP  0   /* close it before reading anything */
#define SERVE -1  /* answer every request until the client closes */
/* n > 0: answer n requests, then close */

static void serve(transport_t *t, int n) {
    bench_msg_t msg;
    for (int done = 0; n == SERVE || done < n; done++) {
        if (transport_recv(t, &msg, sizeof(msg)) < 0) return;
        bench_chunk_t c;
        memset(&c, 0, sizeof(c));
        c.magic = BENCH_MAGIC;
        c.type = MSG_CHUNK;
        c.request_id = msg.request.request_id;
        c.text_len = 1;
        c.text[0] = 'x';
        for (uint32_t i = 0; i < 2; i++) {
            c.token_index = i;
            if (transport_send(t, &c, bench_chunk_wire_len(&c)) < 0) return;
        }
        bench_done_t d;
        memset(&d, 0, sizeof(d));
        d.magic = BENCH_MAGIC;
        d.type = MSG_DONE;
        d.request_id = msg.request.request_id;
        d.total_tokens = 2;
        if (transport_send(t, &d, bench_done_wire_len()) < 0) return;
    }
}

/* Runs the bench client (-n 3) against a server that follows plan[] for its
 * connections, then exits (later connects are refused). Returns the client's
 * exit status; *accepted is how many connections the server took. */
static int run(const char *path, const int *plan, int nplan, int *accepted) {
    int p[2];
    if (pipe(p)) { perror("pipe"); exit(2); }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(2); }
    if (pid == 0) {
        close(p[0]);
        transport_listener_t *l = transport_listen(path);
        if (!l) _exit(2);
        if (write(p[1], "R", 1) != 1) _exit(2);
        for (int i = 0; i < nplan; i++) {
            transport_t *t = transport_accept(l);
            if (!t || write(p[1], "A", 1) != 1) _exit(2);
            if (plan[i] != DROP) serve(t, plan[i]);
            transport_close(t);
        }
        transport_listener_close(l);
        _exit(0);
    }
    close(p[1]);
    char c;
    if (read(p[0], &c, 1) != 1 || c != 'R') { fprintf(stderr, "server did not start\n"); exit(2); }

    char *argv[] = { "bench-client", "-e", (char *)path, "-n", "3", NULL };
    optind = 1;
    int rc = bench_client_main(5, argv);

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    *accepted = 0;
    while (read(p[0], &c, 1) == 1) (*accepted)++;
    close(p[0]);
    return rc;
}

static int failures;

static void check(const char *name, const int *plan, int nplan, int want_rc, int want_accepted) {
    char path[64];
    snprintf(path, sizeof(path), "/tmp/test-client.%d.sock", (int)getpid());
    int accepted;
    int rc = run(path, plan, nplan, &accepted);
    int ok = rc == want_rc && accepted == want_accepted;
    printf("%s  %s (exit %d, %d connection(s); want exit %d, %d)\n", ok ? "PASS" : "FAIL",
           name, rc, accepted, want_rc, want_accepted);
    fflush(stdout);
    failures += !ok;
}

int main(void) {
    /* A send to a closed socket must fail with EPIPE, as xchan's does with
     * ECONNRESET, not kill the test. */
    signal(SIGPIPE, SIG_IGN);
    alarm(30);

    static const int stale_first[] = { DROP, SERVE };
    check("a channel closed before its first reply is skipped", stale_first, 2, 0, 2);

    static const int all_stale[] = { DROP, DROP, DROP, DROP, DROP };
    check("at most 3 stale channels are skipped", all_stale, 5, 1, 4);

    static const int dies_mid_run[] = { 1, SERVE };
    check("a server that closes after a reply is a failure, not a stale channel",
          dies_mid_run, 2, 1, 1);

    printf("test-client: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
