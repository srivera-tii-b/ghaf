# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# virtio-xchan: guest-to-guest message transport.
#
# Adds the xchan vendor device to a crosvm-hosted microVM and loads the guest
# driver. Every link has exactly two ends: one listens on a unix socket on the
# host, the other connects to it. The two crosvm processes meet on that socket;
# the guests never see it, and talk to each other only through the frames the
# two crosvm processes relay.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.ghaf.virtualization.microvm.xchan;
  vmm = config.microvm.hypervisor;
  inherit (lib)
    types
    mkEnableOption
    mkOption
    mkIf
    ;

  # Built against this VM's own kernel, not the default linuxPackages. Getting
  # this wrong is a runtime failure rather than a build one: the .ko lands
  # under the wrong modDirVersion and modprobe simply never finds it.
  xchanModule = pkgs.xchan-module.override {
    linuxPackages = config.boot.kernelPackages;
  };
in
{
  _file = ./vm-xchan.nix;

  options.ghaf.virtualization.microvm.xchan = {
    enable = mkEnableOption "virtio-xchan guest-to-guest transport";

    role = mkOption {
      type = types.enum [
        "listener"
        "connector"
      ];
      description = ''
        Which end of the link this VM is. The listener binds `socket`; the
        connector connects to it. Exactly one VM per link must be the listener,
        and it must be running before the connector starts.

        This also fixes the window layout: the listener is endpoint A and the
        connector endpoint B, which the device publishes in config space so the
        guest driver never has to infer it.
      '';
    };

    socket = mkOption {
      type = types.path;
      default = "/run/xchan/xchan.sock";
      description = ''
        Host path both crosvm processes meet on. Must be identical at the two
        ends of a link, and must live somewhere both microvm services can
        reach, see `socketDir` below.
      '';
    };

    socketDir = mkOption {
      type = types.path;
      default = "/run/xchan";
      description = ''
        Directory holding `socket`, created on the host by the module that
        instantiates these VMs. Declared here so the two halves cannot drift
        apart silently.
      '';
    };

    debug = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Debugging aid: raises the guest console loglevel to 7 so the
        driver's probe and channel log lines reach the guest console, which
        the host journal captures.
      '';
    };

    smokeTest = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Run xchan-smoke at boot and log the result to the console. The
        listener echoes one message; the connector sends one and times the
        round trip.
      '';
    };

    iterations = mkOption {
      type = types.ints.positive;
      default = 10;
      description = ''
        Round trips the connector measures after one unmeasured warm-up.
        Reported as min/median/max, a single sample cannot distinguish the
        transport's floor from scheduler jitter, which is how the first
        hardware run produced a 102 ms figure for a path that is not
        inherently slow.
      '';
    };

    repeatSeconds = mkOption {
      type = types.ints.positive;
      default = 60;
      description = ''
        Seconds the connector waits between sweeps. It holds its channel
        across the wait rather than exiting, because releasing it would trap
        the slot against a long-lived listener.
      '';
    };

    benchTools = mkOption {
      type = types.bool;
      default = false;
      description = ''
        BRING-UP ONLY. Installs the xchan-bench harness (socket and xchan
        clients, mock server, llama shim) into the VM. Measurement tooling,
        not part of the transport, remove before any release build.
      '';
    };

    vsockLogin = mkOption {
      type = types.bool;
      default = false;
      description = ''
        BRING-UP ONLY. Turns on sshd so the host can reach this guest with
        `ssh root@vsock/<cid>`, and adds xchan-vsock-diag, which reports the
        vsock and sshd state to the console at boot.

        No socket unit is defined here: systemd's ssh-generator emits
        `sshd-vsock.socket` by itself. What it needs is an sshd for that
        socket to start; with `services.openssh.enable` off, a host-side
        connect gets ECONNRESET although something is listening. The guest
        also needs a vsock CID.
      '';
    };

    benchService = mkOption {
      type = types.bool;
      default = false;
      description = ''
        BRING-UP ONLY. Runs the benchmark from systemd and logs results to the
        guest console, so `journalctl -u microvm@<vm>` on the host shows them.

        It was added while there was no way into the guests (vsock ssh got a
        connection reset, so `microvm -s` could not be used). Driving the
        benchmark from a unit still removes the dependency on guest login, and
        reuses the pattern xchan-smoke proved on this board.

        The listener runs the servers long-lived; the connector runs each client
        in turn on a loop. Requires `benchTools`.
      '';
    };

    llamaVsockPort = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = ''
        BRING-UP ONLY. When set, the connector gains a fourth arm that drives a
        REAL model running on the host, over guest-to-host vsock:
        `bench-client-vsock -e 2:<port>`. The host side is llama-server behind
        bench-llama-shim, see `ghaf.reference.services.llama-bench.vsockPort`,
        which this must match.

        This is the only arm whose numbers are real inference rather than the
        mock server's configured delays. Its numbers are NOT comparable with
        the guest-to-guest arms: one hop instead of two, no relay, and a model
        instead of a sleep loop.

        Requires `benchTools` and `benchService`.
      '';
    };

    maxChannels = mkOption {
      type = types.ints.positive;
      default = 16;
      description = ''
        Channel slot capacity. A capacity, not a role signal, the endpoint
        comes from `role`. Costs two virtqueues and two interrupt vectors per
        channel, so size it to expectation rather than setting it high
        speculatively.
      '';
    };

    windowSize = mkOption {
      type = types.ints.positive;
      # 8 MiB, crosvm's floor. crosvm rejects anything smaller at parse time,
      # so a lower value here is not a degraded window, it is both guests
      # failing to start. This default was 1 MiB until the floor was enforced.
      default = 8388608;
      description = ''
        Per-channel, per-direction size in bytes of the shared window crosvm
        allocates and maps into the guest when a channel attaches (the
        device's shared-memory region is maxChannels x 2 x windowSize). The
        guest driver does not put data in the window: every message travels
        as inline fragments of at most 4 KiB that crosvm relays. The value
        still sets that layout, and crosvm requires at least 8 MiB.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.benchService -> cfg.benchTools;
        message = ''
          ghaf.virtualization.microvm.xchan.benchService needs benchTools, which
          is what puts the bench binaries in the VM.
        '';
      }
      {
        assertion = cfg.llamaVsockPort != null -> cfg.benchService;
        message = ''
          ghaf.virtualization.microvm.xchan.llamaVsockPort only does anything
          with benchService on, it adds an arm to the driver that unit runs.
        '';
      }
      {
        assertion = !(cfg.benchService && cfg.smokeTest);
        message = ''
          benchService and smokeTest cannot both run: they compete for xchan
          channel 0. Pick one.
        '';
      }
      {
        assertion = vmm == "crosvm";
        message = ''
          ghaf.virtualization.microvm.xchan requires the crosvm hypervisor;
          this VM uses "${vmm}". The device is a crosvm vendor device and has
          no qemu equivalent.
        '';
      }
    ];

    # --vendor-devices is parsed by crosvm itself, so socket and role are host
    # command-line state, not anything the guest can influence.
    microvm.crosvm.extraArgs = lib.mkAfter [
      "--vendor-devices"
      "xchan,socket=${cfg.socket},role=${cfg.role},max_channels=${toString cfg.maxChannels},window=${toString cfg.windowSize}"
    ];

    boot.extraModulePackages = [ xchanModule ];

    # Stage 2 is enough: nothing in the boot path needs the transport, unlike
    # the TPM case where initrd has to unlock storage.
    boot.kernelModules = [ "xchan" ];

    environment.systemPackages = [
      pkgs.libxchan
    ]
    ++ lib.optional cfg.benchTools pkgs.xchan-bench;

    # The driver logs its probe at dev_info. NixOS boots quiet, so without
    # this the single line that proves the guest bound the device never
    # reaches the console, and the guests have no password, no ssh keys and
    # PermitRootLogin=prohibit-password, so there is no shell to read dmesg
    # from either. Raising the console loglevel is what makes the guest
    # observable at all during bring-up.
    #
    # Through boot.consoleLogLevel, not a loglevel= of our own in
    # boot.kernelParams: NixOS already puts loglevel=<consoleLogLevel> on the
    # command line, the kernel keeps whichever loglevel= comes last, and ours
    # came first, so it never took effect.
    boot.consoleLogLevel = lib.mkIf cfg.debug 7;

    # Reports outward instead of requiring a way in: stdout goes to the guest
    # console, which the host journal already captures, so results are
    # readable with `journalctl -u microvm@<vm>` on the host.
    systemd.services.xchan-smoke = lib.mkIf cfg.smokeTest {
      description = "virtio-xchan smoke test (${cfg.role})";
      after = [ "systemd-modules-load.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        # BOTH roles are long-lived now. A channel is freed only once the
        # guest has closed its fd AND the peer has detached, so a one-shot
        # connector against a long-lived listener traps the slot: the
        # connector exits, the listener never detaches, and no later
        # connector can ever attach, it blocks in wait_channel forever.
        # Holding the channel and looping avoids that, and makes the boot run
        # and an on-demand run the same code path.
        Type = "simple";
        Restart = "always";
        RestartSec = "2s";
        ExecStart = "${pkgs.libxchan}/bin/xchan-smoke ${cfg.role} ${toString cfg.iterations} ${toString cfg.repeatSeconds}";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

    # ---- benchmark, driven by systemd so it needs no guest login ----

    # Listener side: the servers, long-lived. Both transports at once, they are
    # independent, and having both up means the connector can measure either
    # without a restart on this side.
    systemd.services.xchan-bench-server = lib.mkIf (cfg.benchService && cfg.role == "listener") {
      description = "xchan benchmark server (xchan transport)";
      after = [ "systemd-modules-load.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        Restart = "always";
        RestartSec = "2s";
        # ttft/itl chosen to imitate an 8B model's timing profile, so the ratio
        # of transport cost to inference cost is realistic without running a
        # model: ~50 ms to first token, ~20 ms between tokens.
        ExecStart = "${pkgs.xchan-bench}/bin/bench-mock-server-xchan -e /dev/xchan0 --ttft-ms 50 --itl-ms 20 --tokens 32";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

    systemd.services.xchan-bench-server-vsock = lib.mkIf (cfg.benchService && cfg.role == "listener") {
      description = "xchan benchmark server (vsock transport)";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        Restart = "always";
        RestartSec = "2s";
        ExecStart = "${pkgs.xchan-bench}/bin/bench-mock-server-vsock --vsock 9000 --ttft-ms 50 --itl-ms 20 --tokens 32";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

    # ---- vsock login: sshd for the ssh-generator's socket, plus a diagnostic ----

    # NO static socket here, deliberately. An earlier revision defined
    # `xchan-ssh-vsock.socket` (ListenStream=vsock::22, Accept=yes) plus a
    # matching sshd template, on the theory that systemd's ssh-generator never
    # emitted `sshd-vsock.socket` because it runs before the virtio-vsock device
    # is probed and so cannot read a local CID.
    #
    # Hardware disproved that. The generator DOES emit both
    # `sshd-vsock.socket` and `sshd-vsock@.service`, the generator's socket comes
    # up active, and ours failed with the address already in use, dead weight
    # that only put the guest into a degraded state. What actually made vsock
    # login work is the one line below: with `services.openssh.enable` off there
    # is no sshd for the generator's socket to activate, which is why a host-side
    # connect got ECONNRESET with something apparently listening.

    # sshd_config and host keys have to exist for the above to work at all.
    services.openssh.enable = lib.mkIf cfg.vsockLogin true;

    # Diagnostic, so that if vsock login still fails the next boot explains why
    # rather than costing another flash cycle. Everything goes to the console,
    # which the host captures as `journalctl -u microvm@<vm>`.
    systemd.services.xchan-vsock-diag = lib.mkIf cfg.vsockLogin {
      description = "report vsock/sshd state to the console";
      after = [
        "sockets.target"
        "systemd-modules-load.service"
      ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        echo "VSOCKDIAG device:      $(ls -l /dev/vsock 2>&1)"
        echo "VSOCKDIAG vsock mods:  $(grep -i vsock /proc/modules 2>/dev/null || echo '(built-in, no modules)')"
        echo "VSOCKDIAG listeners:"
        ${pkgs.iproute2}/bin/ss -l --vsock 2>&1 | sed 's/^/VSOCKDIAG   /' || true
        echo "VSOCKDIAG generator units:"
        ls -1 /run/systemd/generator/ 2>/dev/null | grep -i ssh | sed 's/^/VSOCKDIAG   /'           || echo "VSOCKDIAG   (generator emitted no ssh units)"
        echo "VSOCKDIAG gen socket:  $(systemctl is-active sshd-vsock.socket 2>&1)"
        echo "VSOCKDIAG sshd:        $(systemctl is-active sshd 2>&1)"
        # NixOS writes users.users.<u>.openssh.authorizedKeys.keys to
        # /etc/ssh/authorized_keys.d/<u>, NOT ~/.ssh/authorized_keys. An earlier
        # revision checked the latter and reported "no authorized_keys" while
        # login worked perfectly, a false negative that nearly sent us chasing
        # a problem that did not exist.
        echo "VSOCKDIAG authorized:  $(ls /etc/ssh/authorized_keys.d/ 2>/dev/null | tr '\n' ' ' || echo 'none')"
      '';
    };

    # Connector side: run each arm in turn and print results to the console.
    systemd.services.xchan-bench-client = lib.mkIf (cfg.benchService && cfg.role == "connector") {
      description = "xchan benchmark client (all arms)";
      after = [ "systemd-modules-load.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        Restart = "always";
        RestartSec = "10s";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
        ExecStart = pkgs.writeShellScript "xchan-bench-driver" ''
                    set -u
                    B=${pkgs.xchan-bench}/bin

                    # Arm 1: unix socket, both ends inside this guest. Crosses no VM
                    # boundary, so it measures the harness's own overhead, the floor
                    # that makes the other two numbers interpretable.
                    run_control() {
                      rm -f /tmp/bench-control.sock
                      "$B/bench-mock-server" -e /tmp/bench-control.sock \
                        --ttft-ms 50 --itl-ms 20 --tokens 32 &
                      local srv=$!
                      sleep 1
                      echo "BENCH arm=control(unix,in-guest)"
                      "$B/bench-client" -e /tmp/bench-control.sock -n 20 -t 32 || true
                      kill "$srv" 2>/dev/null || true
                      wait "$srv" 2>/dev/null || true
                    }

                    # Arm 2: xchan, guest to guest. The real measurement. ONE xchan
                    # client per pass, carrying a payload ABOVE the inline cap.
                    #
                    # Why not two arms (small then large): with an earlier driver whose
                    # recv did not return when the peer detached, the single-threaded
                    # server never got back to accept() after the first client exited,
                    # and the second client blocked forever in wait_channel, seen on
                    # hardware. The driver's recv now returns ECONNRESET once the peer
                    # has detached; one client per pass stays the shape proven there.
                    #
                    # The prompt is 4080 bytes, so wire length (header + prompt) lands just
                    # past XCHAN_INLINE_MAX (4096) and forces a two-fragment XCHAN_F_MORE
                    # chain. Before the inline conversion this same message took the
                    # shared-window path, which under pKVM kills the listener's vCPU with
                    # -EREMOTEIO, so ok=N failed=0 here is unambiguous proof that inline
                    # fragmentation works end to end.
                    #
                    # Small-payload xchan numbers were measured on an earlier image (TTFT
                    # within a millisecond of the vsock arm, the same throughput), so
                    # nothing is lost by not measuring them again.
                    run_xchan() {
                      echo "BENCH arm=xchan(guest-to-guest, payload over inline cap)"
                      P=$(${pkgs.gawk}/bin/awk 'BEGIN{for(i=0;i<4080;i++)printf "x"}')
                      echo "BENCH   prompt_bytes=''${#P}"
                      "$B/bench-client-xchan" -e /dev/xchan0 -n 10 -t 8 -p "$P" || true
                    }

                    # Arm 3: vsock via the host relay. vsock cannot address guest-to-guest,
                    # so this is two hops through bench-vsock-relay on the host; that relay
                    # cost is part of what vsock costs in this topology.
                    run_vsock() {
                      echo "BENCH arm=vsock(via host relay)"
                      "$B/bench-client-vsock" -e 2:9000 -n 20 -t 32 || true
                    }
          ${lib.optionalString (cfg.llamaVsockPort != null) ''
            # Arm 4: the REAL model. llama-server on the host, reached through
            # bench-llama-shim on AF_VSOCK port ${toString cfg.llamaVsockPort}.
            # Guest-to-host is vsock's native direction, so there is no relay in
            # this path and it is one hop, not two, do not line these numbers up
            # against the guest-to-guest arms above.
            #
            # -v prints per-request TTFT and tok/s. This is the only arm with
            # real inference, so the per-request spread matters as much as the
            # median: request 1 carries prompt-cache cold cost and will be the
            # outlier.
            run_llama() {
              echo "BENCH arm=llama(real model on host, vsock 2:${toString cfg.llamaVsockPort})"
              "$B/bench-client-vsock" -e 2:${toString cfg.llamaVsockPort} -n 10 -t 32 \
                -v -p "Explain in one sentence why satellites stay in orbit." || true
            }
          ''}
                    echo "BENCH driver starting; repeating every ${toString cfg.repeatSeconds}s"
                    while :; do
                      echo "BENCH ==== pass start ===="
                      run_control
                      run_xchan
                      run_vsock
          ${
            lib.optionalString (cfg.llamaVsockPort != null) "            run_llama\n"
          }            echo "BENCH ==== pass end ===="
                      sleep ${toString cfg.repeatSeconds}
                    done
        '';
      };
    };
  };
}
