# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{
  stdenv,
  lib,
}:
stdenv.mkDerivation {
  pname = "libxchan";
  version = "0.1.0";
  src = ./src;

  buildPhase = ''
    runHook preBuild
    $CC -shared -fPIC -Wall -O2 -o libxchan.so libxchan.c
    # Statically linked against the same libxchan.c rather than the .so: the
    # smoke test runs as a guest systemd service at boot, and a
    # missing shared library at that point would be one more thing to
    # diagnose over a serial console.
    $CC -Wall -Wextra -O2 -o xchan-smoke xchan_smoke.c libxchan.c
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib $out/include $out/bin
    install -m755 libxchan.so $out/lib/libxchan.so
    install -m755 xchan-smoke $out/bin/xchan-smoke
    install -m644 xchan_uapi.h $out/include/xchan_uapi.h
    install -m644 libxchan.h $out/include/libxchan.h
    runHook postInstall
  '';

  meta = {
    description = "Userspace library for the virtio-xchan cross-guest transport";
    license = lib.licenses.asl20;
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
    ];
  };
}
