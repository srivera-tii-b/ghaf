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
        assertion = vmm == "crosvm";
        message = ''
          ghaf.virtualization.microvm.xchan requires the crosvm hypervisor;
          this VM uses "${vmm}". The device is a crosvm vendor device and has
          no qemu equivalent.
        '';
      }
    ];

    # --vendor-device is parsed by crosvm itself, so socket and role are host
    # command-line state, not anything the guest can influence.
    microvm.crosvm.extraArgs = lib.mkAfter [
      "--vendor-device"
      "xchan,socket=${cfg.socket},role=${cfg.role},max_channels=${toString cfg.maxChannels},window=${toString cfg.windowSize}"
    ];

    boot.extraModulePackages = [ xchanModule ];

    # Stage 2 is enough: nothing in the boot path needs the transport, unlike
    # the TPM case where initrd has to unlock storage.
    boot.kernelModules = [ "xchan" ];

    environment.systemPackages = [ pkgs.libxchan ];

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
  };
}
