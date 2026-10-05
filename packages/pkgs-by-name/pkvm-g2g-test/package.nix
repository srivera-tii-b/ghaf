# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# BRING-UP ONLY. pkvm-g2g-test: guest-to-guest shared memory end to end from
# user space, through /dev/pkvm-g2g. Run it as root in two protected guests,
# one as owner and one as borrower (see the usage line it prints).
#
# The sources are copies, not a fork: src/pkvm-g2g-test.c comes from the
# /dev/pkvm-g2g driver's test tree, where it is checked as two guests on a
# simulator of the driver and EL2 (not part of ghaf), and src/linux/pkvm_g2g.h
# is the kernel's uapi header at the commit linux-pkvm-jetson builds.
# Re-copy both when that pin moves; the header must match the guest kernel.
{
  stdenv,
  lib,
}:
stdenv.mkDerivation {
  pname = "pkvm-g2g-test";
  version = "0.1.0";
  src = ./src;

  buildPhase = ''
    runHook preBuild
    $CC -O2 -Wall -Wextra -Werror -I. -o pkvm-g2g-test pkvm-g2g-test.c
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm755 pkvm-g2g-test $out/bin/pkvm-g2g-test
    runHook postInstall
  '';

  meta = {
    description = "Two-guest test of pKVM guest-to-guest sharing through /dev/pkvm-g2g";
    # Matches the SPDX line of pkvm-g2g-test.c; the header is GPL-2.0-only
    # WITH Linux-syscall-note.
    license = lib.licenses.gpl2Only;
    platforms = [ "aarch64-linux" ];
  };
}
