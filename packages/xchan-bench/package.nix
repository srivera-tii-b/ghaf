# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Inference benchmark harness. Measures request/response latency and
# throughput over interchangeable transports (unix socket, vsock, xchan,
# g2gchan), so the cost of the transport can be separated from the cost of
# the model.
{
  stdenv,
  lib,
  libxchan,
  g2gchan,
}:
stdenv.mkDerivation {
  pname = "xchan-bench";
  version = "0.1.0";
  src = ./src;

  buildInputs = [
    libxchan
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
    runHook postBuild
  '';

  # mkDerivation skips this when cross-compiling (the image build); a native
  # build (x86_64 or aarch64) runs it.
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    CF="-std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -O2 -g"

    # The bench client skips a channel closed before its first reply (an xchan
    # channel left by a server that stopped), at most 3 times, and never once a
    # request has gone through. Sock backend, a server that closes on purpose.
    $CC $CF -o test-client test_client.c transport_sock.c
    ./test-client
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
