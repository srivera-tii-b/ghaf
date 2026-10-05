# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{
  config,
  lib,
  pkgs,
  ...
}:
let
  jetsonKernelDrv = pkgs.callPackage ./packages/linux-pkvm-jetson {
    argsOverride.defconfig = "guest_defconfig";

    structuredExtraConfig = with lib.kernel; {
      # The guest side of the host's PKVM_GUEST_TO_GUEST (orin-pkvm-host.nix):
      # /dev/pkvm-g2g, which registers only when EL2 advertises the calls.
      # Without this option the guest has no device; on a host without it
      # EL2 never offers the calls, so the device is absent too and the
      # guest's own self-test logs SKIP.
      PKVM_GUEST_TO_GUEST = yes;
      # Registers a predictable identity for this guest at boot and tests
      # the calls with every peer. /dev/pkvm-g2g registers no identity, so
      # g2gchan and pkvm-g2g-test need this. Testing only: a host can start
      # a protected VM of its own that claims a predictable identity first.
      # Its ping and share test then runs with every peer for about 15
      # minutes after boot and competes with g2gchan and pkvm-g2g-test for
      # this guest's one-slot mailbox meanwhile; put
      # arm_pkvm_guest.g2g_runtime_test=0 on the guest's kernel command
      # line to skip it.
      PKVM_GUEST_TO_GUEST_SELFTEST = yes;
      GOLDFISH = lib.kernel.yes;
      BATTERY_GOLDFISH = lib.kernel.module;
      # virtio device support
      VSOCKETS = yes;
      VSOCKETS_LOOPBACK = yes;
      VIRTIO_VSOCKETS = yes;
      VIRTIO_BALLOON = module;
      VIRTIO_FS = module;
      SCSI_VIRTIO = module;
      # FS support
      BLK_DEV_LOOP = module;
      EROFS_FS = module;
      EROFS_FS_ZIP_DEFLATE = yes;
      EROFS_FS_ZIP_ZSTD = yes;
      OVERLAY_FS = module;
      FUSE_FS = yes;
      # Realtek Wifi drivers
      RTW88 = module;
      RTW88_8822CE = module;
      RTW88_DEBUG = yes;
      RTW88_DEBUGFS = yes;
    };
  };

  jetsonKernelPackages = pkgs.linuxPackagesFor jetsonKernelDrv;
in
{
  _file = ./orin-pkvm-guest.nix;

  ghaf.virtualization.microvm.protected-vm.enable = true;
  ghaf.virtualization.crosvm.package = pkgs.callPackage packages/crosvm { };

  boot.kernelPackages =
    if config.hardware.graphics.enable then
      (jetsonKernelPackages.extend pkgs.nvidia-jetpack.kernelPackagesOverlay).extend (
        _final: prev: {
          nvidia-oot-modules = prev.nvidia-oot-modules.overrideAttrs (prevAttrs: {
            patches = (prevAttrs.patches or [ ]) ++ [
              ../passthrough/gui-vm/0002-nvgpu-stub-the-GPC-disable-fuse-read-for-guest-passt.patch
            ];
          });
        }
      )
    else
      jetsonKernelPackages;

  boot.kernelParams = [
    "clk_ignore_unused"
    "pd_ignore_unused"
  ];

  # The /dev/pkvm-g2g two-guest test, and g2gchan with g2gc-echo (byte-exact
  # streaming between two guests), in every protected guest. Both need the
  # two options above: without PKVM_GUEST_TO_GUEST the device is absent and
  # the test exits 2 ("cannot open"); without the self-test option the guest
  # has no identity, so the test exits 2 ("this VM has no identity") and
  # g2gchan's connect fails with EPERM.
  environment.systemPackages = [
    pkgs.pkvm-g2g-test
    pkgs.g2gchan
  ];

  hardware.enableAllHardware = false;
  boot.initrd.includeDefaultModules = false;
  boot.initrd.availableKernelModules = [
    "virtiofs"
    "virtio_net"
    "virtio_pci"
    "virtio_mmio"
    "virtio_blk"
    "virtio_scsi"
    "virtio_console"
    "vsock"
  ];

  ghaf.virtualization.crosvm.features = [ "bpmp" ];
}
