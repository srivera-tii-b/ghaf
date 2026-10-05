# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Out-of-tree build of the virtio-xchan cross-guest transport driver.
#
# Takes `linuxPackages` rather than a bare `kernel` so the call site can pin it
# to the kernel the module will actually be inserted into, matching this tree's
# existing convention for out-of-tree modules (see pkgs-by-name/rtl8126):
#
#   (pkgs.xchan-module.override { linuxPackages = config.boot.kernelPackages; })
#
# Getting that wrong is not a build failure but a runtime one, the .ko lands
# under the wrong modDirVersion and modprobe simply never finds it.
{
  stdenv,
  lib,
  linuxPackages,
}:
let
  inherit (linuxPackages) kernel;
in
stdenv.mkDerivation {
  pname = "xchan-module";
  version = "0.1.0";
  src = ./src;

  hardeningDisable = [ "pic" ];

  nativeBuildInputs = kernel.moduleBuildDependencies;

  # Do NOT use kernel.makeFlags here: those are the flags for building the
  # kernel itself (they carry O=$(buildRoot) and --eval=undefine modules), and
  # an out-of-tree module build dies on them with "empty variable name".
  # Only ARCH and CROSS_COMPILE are actually needed to cross-build a module,
  # and they are taken from the stdenv rather than the kernel derivation.
  makeFlags = [
    "ARCH=${stdenv.hostPlatform.linuxArch}"
    "CROSS_COMPILE=${stdenv.cc.targetPrefix}"
    "KERNELDIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "INSTALL_MOD_PATH=${placeholder "out"}"
  ];

  buildFlags = [ "all" ];
  installTargets = [ "install" ];

  meta = {
    description = "virtio-xchan cross-guest transport driver";
    # GPL-2.0, matching MODULE_LICENSE("GPL") in xchan_drv.c, which is forced
    # by register_virtio_driver being EXPORT_SYMBOL_GPL. Only the sources that
    # link into xchan.ko are GPL; xchan_uapi.h is dual-licensed with the
    # Linux-syscall-note so libxchan (Apache-2.0) can still include it.
    license = lib.licenses.gpl2Only;
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
    ];
  };
}
