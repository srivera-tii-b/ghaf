# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Client VM Base Module
#
# BRING-UP ONLY. The smallest system VM that can act as an xchan client: a
# second guest, distrusting both net-vm and admin-vm, that talks to the model in
# admin-vm over the guest-to-guest transport. It exists for the encrypted demo
# and has no other job.
#
# Deliberately NOT a copy of netvm-base: no NIC, no internal network, no
# gateway/DNS/time server, no GIVC agent, no log forwarding, no persistent
# storage. Everything it needs, the xchan device, vsock login, its demo
# identity, is layered on by the target through vmConfig.sysvms.clientvm.
#
# It is still a "system-vm", which is what gives it a vsock CID from the
# central allocation in modules/common/networking/hosts.nix. NOTE that joining
# that allocation shifts the CIDs of the VMs listed after it (admin-vm moves
# from 3 to 4, net-vm from 4 to 5 on Orin): read CIDs off the built runner or
# config.ghaf.networking.hosts, never from memory.
#
# Takes globalConfig and hostConfig via specialArgs, like the other bases:
#   lib.nixosSystem {
#     modules = [ inputs.self.nixosModules.clientvm-base ];
#     specialArgs = { inherit globalConfig hostConfig; };
#   }
{
  lib,
  inputs,
  globalConfig,
  hostConfig,
  ...
}:
let
  vmName = "client-vm";
  timezoneEnabled = lib.ghaf.features.isEnabledFor globalConfig "timezone" vmName;
in
{
  _file = ./clientvm-base.nix;

  imports = [
    # The shared VM modules reference options from these (preservation via
    # storagevm, ghaf.givc via common.nix), so they are imported for their
    # option declarations even though neither is enabled here.
    inputs.preservation.nixosModules.preservation
    inputs.self.nixosModules.givc
    inputs.self.nixosModules.hardware-x86_64-guest-kernel
    inputs.self.nixosModules.vm-modules
    inputs.self.nixosModules.profiles
  ];

  ghaf = {
    # Profiles - from globalConfig, same as every other system VM
    profiles.debug.enable = lib.mkDefault (globalConfig.debug.enable or false);
    profiles.release.enable = lib.mkDefault (globalConfig.release.enable or false);

    nix.enable = lib.mkDefault (globalConfig.nix.enable or false);
    development = {
      debug.tools.enable = lib.mkDefault (globalConfig.development.debug.tools.enable or false);
    };

    # /etc/hosts and anything that looks a peer up by name
    networking.hosts = hostConfig.networking.hosts or { };

    common = hostConfig.common or { };

    users = {
      profile = hostConfig.users.profile or { };
      admin = hostConfig.users.admin or { };
      managed = hostConfig.users.managed or [ ];
    };

    # What puts this VM in ghaf.common.systemHosts, and so in the CID/IP
    # allocation. Without it the VM would have no vsock CID to log in on.
    type = "system-vm";

    # EXACTLY net-vm's systemd build, name included, so this VM reuses that
    # derivation instead of compiling its own. A new name (or any differing
    # flag) is a fresh systemd build, and on the dev box that drags in an LLVM
    # build from source (systemd's BPF programs need clang, and the daemon
    # cannot substitute it), an hour of build for a bring-up VM. withAudit
    # matches net-vm, where it comes from the logging stack this VM does not
    # run. Same feature set is also what vsock login is proven on: the
    # ssh-generator that emits sshd-vsock.socket is part of it.
    # BRING-UP ONLY: give it its own name if client-vm outlives the demo.
    systemd = {
      enable = true;
      withName = "netvm-systemd";
      withAudit = true;
      withLocaled = true;
      withNss = true;
      withResolved = true;
      withPolkit = true;
      withTimesyncd = true;
      withDebug = globalConfig.debug.enable or false;
      withHardenedConfigs = true;
    };

    # No network, so nothing to talk GIVC over and nowhere to ship logs.
    givc.enable = false;
    logging.enable = false;

    # Stateless: the demo identity comes from the image, not from storage.
    storagevm.enable = false;

    security = {
      ssh.debug.enable = lib.mkDefault (globalConfig.security.ssh.debug.enable or false);
      audit.enable = lib.mkDefault (globalConfig.security.audit.enable or false);
    };
  };

  # vm-networking is what normally sets this; this VM does not use it.
  networking.hostName = vmName;

  time.timeZone = lib.mkIf (!timezoneEnabled) (lib.mkDefault globalConfig.platform.timeZone);

  system.stateVersion = lib.trivial.release;

  nixpkgs = {
    buildPlatform.system = globalConfig.platform.buildSystem or "x86_64-linux";
    hostPlatform.system = globalConfig.platform.hostSystem or "x86_64-linux";
  };

  microvm = {
    optimize.enable = false;
    # One client process at a time; nothing here needs more. Overridable via
    # vmConfig.sysvms.clientvm.{mem,vcpu}.
    vcpu = lib.mkDefault 1;
    mem = lib.mkDefault 1024;
    # No fallback on purpose: a missing CID should fail evaluation, not
    # silently collide with another guest's.
    vsock.cid = hostConfig.networking.thisVm.cid;
  };
}
