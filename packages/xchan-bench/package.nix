# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Inference benchmark harness. Measures request/response latency and
# throughput over interchangeable transports (unix socket, vsock, xchan,
# g2gchan), so the cost of the transport can be separated from the cost of
# the model. Also carries the encrypted guest-to-guest LLM demo
# (xchan-demo-server/-client).
{
  stdenv,
  lib,
  libxchan,
  libsodium,
  g2gchan,
}:
stdenv.mkDerivation {
  pname = "xchan-bench";
  version = "0.1.0";
  src = ./src;

  buildInputs = [
    libxchan
    libsodium
    g2gchan
  ];

  # -D_POSIX_C_SOURCE=200809L: clock_gettime/CLOCK_MONOTONIC, getopt and
  # nanosleep are hidden by -std=c99 on its own.
  buildPhase = ''
    runHook preBuild
    CF="-std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -O2 -g"

    # Socket backend: the baseline. Runs anywhere, needs no device node, and
    # is what the xchan numbers are measured against.
    $CC $CF -o bench-client client.c transport_sock.c
    $CC $CF -o bench-mock-server mock_server.c transport_sock.c
    $CC $CF -o bench-llama-shim llama_shim.c llama_http.c

    # vsock backend: the third arm. Needs only linux/vm_sockets.h to build;
    # a real vsock device to run.
    $CC $CF -DUSE_VSOCK -o bench-client-vsock client.c transport_vsock.c
    $CC $CF -DUSE_VSOCK -o bench-mock-server-vsock mock_server.c transport_vsock.c

    # Host-side relay for the vsock arm. vsock cannot address guest-to-guest,
    # so the vsock comparison needs this running on the host; xchan needs no
    # equivalent. Built with _GNU_SOURCE for splice().
    $CC -std=c99 -D_GNU_SOURCE -Wall -Wextra -O2 -g -o bench-vsock-relay vsock_relay.c

    # xchan backend: needs libxchan and a real /dev/xchan* node, so it only
    # builds where libxchan does.
    $CC $CF -DUSE_XCHAN -I${libxchan}/include \
      -o bench-client-xchan client.c transport_xchan.c \
      -L${libxchan}/lib -lxchan
    $CC $CF -DUSE_XCHAN -I${libxchan}/include \
      -o bench-mock-server-xchan mock_server.c transport_xchan.c \
      -L${libxchan}/lib -lxchan

    # g2g backend: guest-to-guest over pKVM shared pages (g2gchan), with no
    # host in the data path. Needs /dev/pkvm-g2g in two protected guests.
    $CC $CF -pthread -I${g2gchan}/include \
      -o bench-client-g2g client.c transport_g2g.c -L${g2gchan}/lib -lg2gchan
    $CC $CF -pthread -I${g2gchan}/include \
      -o bench-mock-server-g2g mock_server.c transport_g2g.c -L${g2gchan}/lib -lg2gchan

    # Encrypted guest-to-guest LLM demo: mutually authenticated, end-to-end
    # encrypted request/response between guests, so the host relaying the
    # xchan traffic only ever sees ciphertext. Protocol: demo_crypto.c.
    # -e /dev/xchan0 (xchan) or -e g2g (g2gchan, guest-to-guest shared memory).
    $CC $CF -pthread -I${libxchan}/include -I${g2gchan}/include \
      -o xchan-demo-server demo_server.c demo_crypto.c demo_session.c llama_http.c \
      -L${libxchan}/lib -lxchan -L${g2gchan}/lib -lg2gchan -lsodium
    $CC $CF -pthread -I${libxchan}/include -I${g2gchan}/include \
      -o xchan-demo-client demo_client.c demo_crypto.c demo_session.c \
      -L${libxchan}/lib -lxchan -L${g2gchan}/lib -lg2gchan -lsodium
    runHook postBuild
  '';

  # Tests for the encrypted guest-to-guest demo (demo_crypto.c,
  # demo_session.c): handshake and records over socketpairs with a
  # tampering relay as the host, the request service with a fake model and
  # a fake llama-server on loopback, and seed->pk for the committed test
  # keys. mkDerivation skips this when cross-compiling (the image build); a
  # native build (x86_64 or aarch64) runs it.
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    CF="-std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -O2 -g"
    $CC $CF -pthread -o test-demo test_demo.c demo_crypto.c demo_session.c llama_http.c -lsodium
    ./test-demo ${./test-keys}

    # The bench client skips a channel closed before its first reply (an xchan
    # channel left by a server that stopped), at most 3 times, and never once a
    # request has gone through. Sock backend, a server that closes on purpose.
    $CC $CF -o test-client test_client.c transport_sock.c
    ./test-client

    # The two binaries parse their arguments and keys, then fail cleanly
    # (no xchan device here) with the lines a deployment reads: the client's
    # DEMO lines on stdout, which the orchestrator relays to the host journal,
    # and the server's DEMO-SERVER lines on stderr, which its unit sends to
    # the guest's journal only.
    K=${./test-keys}
    if ./xchan-demo-server -e /nonexistent/xchan0 --key $K/admin-vm.seed --clients $K \
        --llama http://127.0.0.1:8080 2> server.log; then
      echo "xchan-demo-server succeeded without a device"; exit 1
    fi
    cat server.log
    grep -q '^DEMO-SERVER start fp=df0172a6 clients=.*client-vm:094e377f' server.log
    grep -q '^DEMO-SERVER fatal: open /nonexistent/xchan0' server.log
    if ./xchan-demo-client -e /nonexistent/xchan0 --name net-vm --key $K/net-vm.seed \
        --server-pk $K/admin-vm.pk -n 2 -p hello > client.log; then
      echo "xchan-demo-client succeeded without a device"; exit 1
    fi
    cat client.log
    grep -q '^DEMO client=net-vm ok=0 failed=2$' client.log
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    install -m755 bench-client        $out/bin/bench-client
    install -m755 bench-mock-server   $out/bin/bench-mock-server
    install -m755 bench-llama-shim    $out/bin/bench-llama-shim
    install -m755 bench-client-vsock  $out/bin/bench-client-vsock
    install -m755 bench-mock-server-vsock $out/bin/bench-mock-server-vsock
    install -m755 bench-mock-server-xchan $out/bin/bench-mock-server-xchan
    install -m755 bench-vsock-relay   $out/bin/bench-vsock-relay
    install -m755 bench-client-xchan  $out/bin/bench-client-xchan
    install -m755 bench-client-g2g    $out/bin/bench-client-g2g
    install -m755 bench-mock-server-g2g $out/bin/bench-mock-server-g2g
    install -m755 xchan-demo-server   $out/bin/xchan-demo-server
    install -m755 xchan-demo-client   $out/bin/xchan-demo-client
    runHook postInstall
  '';

  meta = {
    description = "Inference benchmark client and mock server over unix-socket, vsock, xchan and g2g transports";
    license = lib.licenses.asl20;
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
    ];
  };
}
