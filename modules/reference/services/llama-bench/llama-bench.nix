# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# The inference benchmark's host-model arm: a REAL model on the host, fed by
# one guest over vsock.
#
# Topology, and why it is this shape:
#
#   llama-server (host, 127.0.0.1:httpPort)
#        ^ plain HTTP, streaming SSE
#   bench-llama-shim (host, AF_VSOCK:vsockPort)
#        ^ guest-to-host vsock, the direction vsock supports natively
#   bench-client-vsock (net-vm, `-e 2:<vsockPort>`)
#
# No relay anywhere. The host-side relay (bench-vsock-relay) exists only
# because vsock cannot address guest-to-GUEST; with the model on the host there
# is nothing to relay, so a vsock number from this arm is one hop and is NOT
# comparable to the guest-to-guest arms' numbers (xchan, or vsock through the
# host relay).
#
# llama-server binds 127.0.0.1 deliberately: the only thing that should reach
# it is the shim, in the same network namespace. The guest's entry point is the
# vsock port, which is the socket the benchmark is supposed to measure.
#
# Also imported INSIDE admin-vm for the encrypted guest-to-guest demo
# (vm-xchan-demo.nix), with `shim.enable = false`: there llama-server is
# reached only by xchan-demo-server on the guest's own loopback, and nothing
# listens on vsock at all. Same unit, same model knob, same health endpoint.
#
# BRING-UP ONLY. Remove with the other BRING-UP ONLY blocks: it puts a model,
# an inference server and a measurement harness on the host, none of which
# belong in a release image.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.ghaf.reference.services.llama-bench;
  inherit (lib)
    mkEnableOption
    mkOption
    mkIf
    types
    ;
in
{
  _file = ./llama-bench.nix;

  options.ghaf.reference.services.llama-bench = {
    enable = mkEnableOption "the llama.cpp inference benchmark backend";

    model = mkOption {
      type = types.path;
      default = pkgs.llama-bench-model;
      defaultText = lib.literalExpression "pkgs.llama-bench-model";
      description = ''
        GGUF weights to serve. THE SINGLE KNOB THAT CHANGES MODEL SIZE: the
        default is a 0.5B Q4_K_M (491 MB) because it exercises exactly the same
        path as an 8B for a tenth of the image, and image size is flash time.

        To move to an 8B, point this at another pinned derivation, e.g.

          ghaf.reference.services.llama-bench.model =
            pkgs.llama-bench-model.overrideAttrs { url = ...; hash = ...; };

        or add a sibling of `packages/pkgs-by-name/llama-bench-model`. Nothing
        else in this module, in the shim, or in the guest driver depends on
        which model it is.

        The host has NO NETWORK (net-vm owns the NIC), so this must be a store
        path baked into the image. A runtime download cannot work here.
      '';
    };

    package = mkOption {
      type = types.package;
      default = pkgs.llama-cpp-prebuilt;
      defaultText = lib.literalExpression "pkgs.llama-cpp-prebuilt";
      description = ''
        llama.cpp build providing `llama-server`.

        The default is MEASURED, not arbitrary. `pkgs.llama-cpp-prebuilt` is the
        stock nixpkgs aarch64 build, which Hydra has already built: a 10 MiB
        substitute and zero derivations. `pkgs.llama-cpp`, the same package
        through ghaf's overlays, cross-compiled, needs 32 derivations built
        with nothing cached, including nodejs (the server's web UI is an
        unconditional nativeBuildInput upstream) and openblas. Since a flash
        already costs about an hour, spending another on a compile to get the
        same binary was not worth it.

        The cost of the prebuilt is ~135 MB of duplicated runtime libraries in
        the image: it brings its own gcc-lib, gfortran-lib and openblas, though
        glibc and openssl turn out to be shared with the existing image closure
        already. Set this to `pkgs.llama-cpp` to trade that back for build time.
      '';
    };

    httpPort = mkOption {
      type = types.port;
      default = 8899;
      description = ''
        Loopback port llama-server listens on. Host-internal: only the shim
        connects to it.
      '';
    };

    vsockPort = mkOption {
      type = types.ints.positive;
      default = 9100;
      description = ''
        AF_VSOCK port the shim listens on, reachable from any guest as
        `2:<port>` (CID 2 is the host). Deliberately NOT 9000: that is
        bench-vsock-relay's port for the guest-to-guest arm, and having both up
        at once is what lets one boot measure both topologies.
      '';
    };

    contextSize = mkOption {
      type = types.ints.positive;
      default = 4096;
      description = ''
        llama-server context window, in TOTAL across all slots: with
        `parallel` = N each slot gets contextSize / N (llama-server splits it
        evenly unless the KV cache is unified, as it is under "auto"). A
        slot must hold a request's prompt AND everything generated for it:
        the harness caps the prompt at BENCH_MAX_PROMPT (proto.h) = 4096
        bytes, which can be as many tokens, but not n_predict, so a 4096-token
        slot is only enough for short prompts (vm-xchan-demo.nix sizes one
        for the worst case).
      '';
    };

    parallel = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = ''
        Server slots (`--parallel`): how many requests are decoded
        concurrently, batched together. null passes nothing, i.e. llama-server's
        "auto" (4 slots sharing one unified KV cache in the pinned build),
        which is what the host-model arm was first measured with, so the
        default keeps those numbers reproducible. Set it explicitly where
        memory is budgeted, and scale `contextSize` with it.
      '';
    };

    shim.enable = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Run bench-llama-shim on AF_VSOCK `vsockPort` in front of llama-server.
        That is the host-model topology (model on the host, guests reach it
        over vsock). Turn it off where something else is the model's only
        client, inside admin-vm for the demo, xchan-demo-server on loopback.
      '';
    };

    threads = mkOption {
      type = types.ints.positive;
      default = 4;
      description = ''
        Decode threads. The Orin host does not own all the cores, the guests
        are running on the same package, so this is deliberately modest:
        oversubscribing the host would show up as jitter in the guest's
        inter-token timings and get misread as transport cost.
      '';
    };

    extraServerArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "--n-gpu-layers"
        "99"
      ];
      description = ''
        Extra llama-server arguments. The obvious use is GPU offload once the
        iGPU is reachable from the host; the host-model arm is CPU-only on
        purpose, so that the number being compared against is a model cost,
        not a driver bring-up result.
      '';
    };

    echoBytes = mkOption {
      type = types.ints.unsigned;
      default = 120;
      description = ''
        Bytes of each completion the shim logs to the journal. The bench client
        measures arrival times and throws the text away, so without this there
        is nothing anywhere that distinguishes real tokens from empty strings,
        which is precisely the thing a first inference demo has to prove. 0
        disables.
      '';
    };
  };

  config = mkIf cfg.enable {
    systemd.services.llama-server = {
      description = "llama.cpp inference server (host-model benchmark backend)";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        Restart = "always";
        RestartSec = "5s";
        # --no-webui: the UI would be dead weight here, and this server is not
        # meant to be reachable by anything but its one local client (the
        # shim on the host; xchan-demo-server inside admin-vm).
        ExecStart = lib.escapeShellArgs (
          [
            "${cfg.package}/bin/llama-server"
            "--model"
            "${cfg.model}"
            "--host"
            "127.0.0.1"
            "--port"
            (toString cfg.httpPort)
            "--ctx-size"
            (toString cfg.contextSize)
            "--threads"
            (toString cfg.threads)
            "--no-webui"
          ]
          ++ lib.optionals (cfg.parallel != null) [
            "--parallel"
            (toString cfg.parallel)
          ]
          ++ cfg.extraServerArgs
        );
        # The host rootfs is read-only; llama-server writes nothing, but giving
        # it a writable HOME keeps any stray cache attempt from being a startup
        # failure.
        Environment = [ "HOME=/tmp" ];
      };
    };

    systemd.services.llama-bench-shim = mkIf cfg.shim.enable {
      description = "bench protocol to llama-server shim, on vsock";
      wantedBy = [ "multi-user.target" ];
      after = [ "llama-server.service" ];
      wants = [ "llama-server.service" ];
      serviceConfig = {
        Type = "simple";
        Restart = "always";
        RestartSec = "5s";
        ExecStart = lib.escapeShellArgs [
          "${pkgs.xchan-bench}/bin/bench-llama-shim"
          "-e"
          "vsock:${toString cfg.vsockPort}"
          "--host"
          "127.0.0.1"
          "--port"
          (toString cfg.httpPort)
          "--echo"
          (toString cfg.echoBytes)
        ];
        # Wait for the model to finish loading before accepting guests. Without
        # this the first pass of the guest's driver reports failed=N against a
        # server that is merely still mmap-ing weights, which reads as a broken
        # transport. The shim does recover on the next pass, but a first boot
        # that prints a clean number is worth one loop here.
        #
        # TimeoutStartSec must exceed the loop: ExecStartPre counts against
        # it, and the 90 s default would kill a 120 s wait before it finished.
        TimeoutStartSec = "150s";
        ExecStartPre = pkgs.writeShellScript "llama-bench-wait-ready" ''
          for _ in $(seq 1 120); do
            if ${pkgs.curl}/bin/curl -fsS --max-time 2 \
                 http://127.0.0.1:${toString cfg.httpPort}/health > /dev/null; then
              echo "llama-bench: llama-server ready"
              exit 0
            fi
            sleep 1
          done
          echo "llama-bench: llama-server not ready after 120s; starting anyway"
        '';
      };
    };

    # Measurement tooling on the host: the shim comes from here, and having the
    # client here too makes a host-local sanity check possible without a guest.
    environment.systemPackages = [
      pkgs.xchan-bench
      cfg.package
    ];
  };
}
