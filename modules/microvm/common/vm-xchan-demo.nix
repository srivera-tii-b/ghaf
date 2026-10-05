# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# BRING-UP ONLY. Guest side of the encrypted guest-to-guest LLM demo: one
# model guest (the xchan listener, admin-vm) serving mutually distrusting
# client guests (connectors: net-vm, client-vm), every message end-to-end
# encrypted between the guests so the host carries only ciphertext.
#
# What this module does, and nothing more:
#   - installs this guest's demo identity under /etc/xchan-demo/ (the fixed
#     interface with the xchan-demo-{server,client} binaries in xchan-bench):
#       identity.seed  this guest's Ed25519 seed, 0400 root    (every guest)
#       identity.pk    this guest's public key                 (every guest)
#       clients/<vm>.pk  each client's public key              (listener only)
#       server.pk      the model guest's public key            (connectors only)
#   - on the listener, runs llama-server on loopback and xchan-demo-server in
#     front of it, the latter only once the model is healthy and /dev/xchan0
#     exists;
#   - on a connector, puts xchan-demo-client on PATH, and the wrapper
#     xchan-demo-run that the host orchestrator actually calls: it runs the
#     client with its output both on stdout (relayed to the host) and in this
#     guest's own journal (`journalctl -t xchan-demo-client`), so the evidence
#     of every run is readable inside the guest, not only on the host. Nothing
#     runs either at boot.
#
# Key material: each file is copied into the store ON ITS OWN (builtins.path
# per file, never the key directory), so a guest's closure holds its own seed
# and public keys only. That is NOT runtime isolation on this image: guests
# mount the host's whole /nix/store read-only over virtiofs ("ro-store"), so
# any guest that knows a store path can read another guest's seed, and so can
# the (untrusted) host. Acceptable for committed test keys only; real keys
# need per-device provisioning that never touches host-visible storage.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  xcfg = config.ghaf.virtualization.microvm.xchan;
  cfg = xcfg.demo;
  llama = config.ghaf.reference.services.llama-bench;
  inherit (lib)
    mkEnableOption
    mkOption
    mkIf
    mkMerge
    mkDefault
    types
    ;

  isServer = xcfg.role == "listener";

  # One store path per file, see the header. `keyDir + "/..."` stays a path
  # value, so only the named file is copied, never its siblings.
  keyFile =
    vm: ext:
    builtins.path {
      path = cfg.keyDir + "/${vm}.${ext}";
      name = "xchan-demo-test-${vm}.${ext}";
    };

  pubEntry = target: vm: {
    name = "xchan-demo/${target}";
    value = {
      source = keyFile vm "pk";
      # A copy, not a symlink into the store: a reader that walks
      # clients/ and filters on regular files must see them as files.
      mode = "0444";
    };
  };

  # Client side. Each line goes to stdout AND, separately, to this guest's
  # journal, so the guest keeps its own record of every run. One systemd-cat
  # per line rather than tee to /dev/fd/N (which cannot be reopened if sshd's
  # stdout is a socket) or a process substitution (which nothing waits for).
  # The exit status is the client's alone: a journal hiccup must not turn a
  # passing run into a failing one, nor the reverse.
  clientRun = pkgs.writeShellApplication {
    name = "xchan-demo-run";
    runtimeInputs = [
      pkgs.xchan-bench
      config.systemd.package
    ];
    text = ''
      set +o errexit
      xchan-demo-client "$@" 2>&1 | {
        while IFS= read -r line || [ -n "$line" ]; do
          printf '%s\n' "$line"
          printf '%s\n' "$line" | systemd-cat -t xchan-demo-client || true
        done
      }
      exit "''${PIPESTATUS[0]}"
    '';
  };

  # The device the server uses must exist first: /dev/xchan0 appears when the
  # xchan module probes; /dev/pkvm-g2g is registered at boot by the built-in
  # driver, and only if EL2 advertises the guest-to-guest calls.
  serverWaitReady =
    device:
    pkgs.writeShellScript "xchan-demo-server-wait-ready" ''
      # The server has nothing to do until its device exists.
      for _ in $(seq 1 60); do
        [ -e ${device} ] && break
        sleep 1
      done
      if [ ! -e ${device} ]; then
        echo "xchan-demo-server: ${device} still missing after 60s; retrying"
        exit 1
      fi

      # Same health wait as llama-bench-shim: do not accept a client before the
      # model can answer it, or the first demo request fails against a server
      # that is merely still loading weights.
      for _ in $(seq 1 ${toString cfg.readyTimeoutSeconds}); do
        if ${pkgs.curl}/bin/curl -fsS --max-time 2 \
             http://127.0.0.1:${toString llama.httpPort}/health > /dev/null; then
          echo "xchan-demo-server: llama-server ready"
          exit 0
        fi
        sleep 1
      done
      echo "xchan-demo-server: llama-server not healthy after ${toString cfg.readyTimeoutSeconds}s; retrying"
      exit 1
    '';

  # The demo server unit, on an xchan device or on g2g (g2gchan: shared memory
  # EL2 maps into both guests, no host in the data path).
  demoServer =
    {
      description,
      endpoint,
      device,
    }:
    {
      inherit description;
      after = [
        "systemd-modules-load.service"
        "llama-server.service"
      ];
      wants = [ "llama-server.service" ];
      wantedBy = [ "multi-user.target" ];
      # Never give up: the host orchestrator waits for this unit to be
      # active, and a model that loads late must not leave it failed.
      startLimitIntervalSec = 0;
      serviceConfig = {
        Type = "simple";
        Restart = "always";
        RestartSec = "2s";
        # ExecStartPre counts against this, so it must outlast both waits.
        TimeoutStartSec = "${toString (cfg.readyTimeoutSeconds + 90)}s";
        ExecStartPre = serverWaitReady device;
        ExecStart = lib.escapeShellArgs [
          "${pkgs.xchan-bench}/bin/xchan-demo-server"
          "-e"
          endpoint
          "--key"
          "/etc/xchan-demo/identity.seed"
          "--clients"
          "/etc/xchan-demo/clients"
          "--llama"
          "http://127.0.0.1:${toString llama.httpPort}"
        ];
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        # Guest journal ONLY, unlike the bench units: the guest console is
        # captured by the (untrusted) host as `journalctl -u microvm@<vm>`,
        # and this is the one process that holds plaintext prompts and
        # replies. Read it with `journalctl -u <this unit>` in the guest.
        StandardOutput = "journal";
        StandardError = "journal";
      };
    };
in
{
  _file = ./vm-xchan-demo.nix;

  # The model service. Imported here so the option exists in every guest;
  # inert unless enabled, which the listener side below does by default.
  imports = [ ../../reference/services/llama-bench/llama-bench.nix ];

  options.ghaf.virtualization.microvm.xchan.demo = {
    enable = mkEnableOption ''
      the encrypted guest-to-guest LLM demo on this guest (BRING-UP ONLY).
      The xchan role decides the side: the listener serves the model, a
      connector is a client'';

    name = mkOption {
      type = types.str;
      example = "net-vm";
      description = ''
        This guest's demo identity: selects `<keyDir>/<name>.seed` and
        `<name>.pk`, and is the name the server knows a client by
        (`clients/<name>.pk`) and that the orchestrator passes as `--name`.
      '';
    };

    keyDir = mkOption {
      type = types.path;
      example = lib.literalExpression "../../packages/xchan-bench/test-keys";
      description = ''
        Directory holding `<vm>.seed` and `<vm>.pk` for every demo guest. Pass
        a path literal, not a string: each file is then copied into the store
        individually, and only the ones this guest needs are referenced.
      '';
    };

    server = mkOption {
      type = types.str;
      default = "admin-vm";
      description = "Name of the model guest; a client installs its key as server.pk.";
    };

    clients = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "net-vm"
        "client-vm"
      ];
      description = "Listener only: the clients whose public keys the server accepts.";
    };

    readyTimeoutSeconds = mkOption {
      type = types.ints.positive;
      default = 300;
      description = ''
        Listener only: how long xchan-demo-server waits for llama-server's
        /health before failing (and being restarted). 120 s was enough on the
        Orin host for the 0.5B model; the guest reads the weights over
        virtiofs, so this allows more.
      '';
    };
  };

  config = mkIf (xcfg.enable && cfg.enable) (mkMerge [
    {
      assertions = [
        {
          assertion = !xcfg.benchService;
          message = ''
            ghaf.virtualization.microvm.xchan.demo and benchService cannot both
            run: WAIT_CHANNEL hands each xchan channel to exactly one consumer,
            so the bench server/client would take channels meant for the demo.
            Keep benchTools for the binaries and turn benchService off.
          '';
        }
        {
          assertion = !xcfg.smokeTest;
          message = "ghaf.virtualization.microvm.xchan.demo and smokeTest compete for /dev/xchan0; pick one.";
        }
      ];

      environment.etc = {
        "xchan-demo/identity.seed" = {
          source = keyFile cfg.name "seed";
          mode = "0400";
          user = "root";
          group = "root";
        };
        "xchan-demo/identity.pk" = {
          source = keyFile cfg.name "pk";
          mode = "0444";
        };
      };

      # The g2g step's g2gchan needs this VM's one-slot EL2 mailbox to itself:
      # keep the kernel's boot-time ping and share test off it.
      boot.kernelParams = [ "arm_pkvm_guest.g2g_runtime_test=0" ];
    }

    (mkIf isServer {
      assertions = [
        {
          assertion = cfg.clients != [ ];
          message = "ghaf.virtualization.microvm.xchan.demo.clients is empty: the server would accept nobody.";
        }
        {
          assertion = cfg.name == cfg.server;
          message = "ghaf.virtualization.microvm.xchan.demo: the listener is the server, so name must equal server (\"${cfg.server}\").";
        }
        {
          assertion = !(lib.elem cfg.name cfg.clients);
          message = "ghaf.virtualization.microvm.xchan.demo: the server's own name is listed as a client.";
        }
      ];

      environment.etc = lib.listToAttrs (map (vm: pubEntry "clients/${vm}.pk" vm) cfg.clients);

      # The model, on this guest's loopback only. Defaults sized for the demo:
      # one slot per client so all of them can be served at once. With an
      # explicit --parallel N the KV cache is split, each slot getting
      # contextSize / N tokens, and one slot must hold a whole request:
      #   prompt     <= BENCH_MAX_PROMPT = 4096 bytes (proto.h), and Qwen2.5's
      #                 byte-level BPE makes at least one byte per token, so
      #                 <= 4096 tokens (a string of digits gets there: one
      #                 token per digit)
      #   generation <= XD_MAX_PREDICT = 2048 tokens (demo_session.h; the
      #                 server clamps n_predict to it)
      # = 6144 tokens at worst, so 8192 per slot (well inside the model's
      # 32768 training context). At 4096 per slot such a prompt is refused
      # outright (HTTP 400, "exceeds the available context size"), and a
      # shorter one has its reply cut off.
      # Memory: f16 KV cache is 24 layers x 2 (K, V) x 2 KV heads x 64 dims x
      # 2 B = 12 KiB per token, so 8192 x 2 slots = 192 MiB. Measured on
      # x86_64 with the same llama.cpp build and model (Qwen2.5-0.5B Q4_K_M),
      # ctx 16384 / 2 slots, two concurrent worst-case requests (4096-token
      # prompt, 2048 tokens generated, neither truncated): peak RSS 0.86 GB,
      # weights included, against admin-vm's 4096 MB.
      ghaf.reference.services.llama-bench = {
        enable = mkDefault true;
        shim.enable = mkDefault false;
        parallel = mkDefault (lib.length cfg.clients);
        contextSize = mkDefault (8192 * lib.length cfg.clients);
        # Leave a vCPU for the demo server, virtio and sshd.
        threads = mkDefault (lib.max 1 (config.microvm.vcpu - 1));
        # llama-server's host-RAM prompt cache defaults to 8 GiB, more than
        # this whole guest; bound it.
        extraServerArgs = mkDefault [
          "--cache-ram"
          "256"
        ];
      };

      systemd.services.xchan-demo-server = demoServer {
        description = "encrypted guest-to-guest LLM demo server (xchan, bring-up only)";
        endpoint = "/dev/xchan0";
        device = "/dev/xchan0";
      };
      # The same server over g2gchan. One g2gchan process per VM: EL2's
      # mailbox has one slot and one reader.
      systemd.services.xchan-demo-server-g2g = demoServer {
        description = "encrypted guest-to-guest LLM demo server (g2g shared memory, bring-up only)";
        endpoint = "g2g";
        device = "/dev/pkvm-g2g";
      };
    })

    (mkIf (!isServer) {
      assertions = [
        {
          assertion = cfg.name != cfg.server;
          message = "ghaf.virtualization.microvm.xchan.demo: a connector cannot be the server (\"${cfg.server}\").";
        }
      ];

      environment.etc = lib.listToAttrs [ (pubEntry "server.pk" cfg.server) ];

      # No unit: the host orchestrator runs the client over vsock ssh, through
      # xchan-demo-run. Both only have to be on root's PATH.
      environment.systemPackages = [
        pkgs.xchan-bench
        clientRun
      ];
    })
  ]);
}
