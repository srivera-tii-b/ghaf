# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# BRING-UP ONLY. libg2gchan: message channels between two protected pKVM
# guests over pages EL2 shares between them (/dev/pkvm-g2g), no host in the
# data path. The sources are a copy of a standalone g2gchan tree, where they
# are tested on a simulator that runs the /dev/pkvm-g2g driver on a model of
# EL2 (not part of ghaf); src/linux/pkvm_g2g.h is the kernel uapi header at
# the commit linux-pkvm-jetson builds. Re-copy both when that pin moves.
#
# stallMs and closeDrainMs are first guesses, to be set from measurements on
# the board (what each bounds: src/g2gchan.h). Override with
#   pkgs.g2gchan.override { stallMs = ...; closeDrainMs = ...; }
# A program that links libg2gchan statically takes the values from here.
{
  stdenv,
  lib,
  stallMs ? 30000,
  closeDrainMs ? 2000,
}:
stdenv.mkDerivation {
  pname = "g2gchan";
  version = "0.1.0";
  src = ./src;

  buildPhase = ''
    runHook preBuild
    $CC -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -I. \
      -DG2GC_STALL_MS=${toString stallMs} -DG2GC_CLOSE_DRAIN_MS=${toString closeDrainMs} \
      -c g2gchan.c g2gc_proto.c
    $AR rcs libg2gchan.a g2gchan.o g2gc_proto.o
    # g2gc-echo: byte-exact streaming between two guests, and a peer that
    # vanishes mid-stream (the board check the simulator cannot do).
    $CC -std=gnu11 -O2 -g -Wall -Wextra -Werror -I. -o g2gc-echo g2gc-echo.c libg2gchan.a -lpthread
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm644 libg2gchan.a $out/lib/libg2gchan.a
    install -Dm644 g2gchan.h $out/include/g2gchan.h
    install -Dm755 g2gc-echo $out/bin/g2gc-echo
    runHook postInstall
  '';

  meta = {
    description = "Guest-to-guest message channels over pKVM shared pages";
    license = lib.licenses.asl20;
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
    ];
  };
}
