# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
{ inputs, ... }:
{
  # keep-sorted start skip_lines=1
  flake.overlays.own-pkgs-overlay = final: _prev: {
    audit-rules = final.callPackage ./pkgs-by-name/audit-rules/package.nix { };
    chrome-extensions = final.callPackage ./chrome-extensions { };
    dendrite-pinecone = final.callPackage ./pkgs-by-name/dendrite-pinecone/package.nix { };
    falcon-launcher = final.callPackage ./falcon-launcher/package.nix { };
    fingwit = final.callPackage ./pkgs-by-name/fingwit/package.nix { };
    flash-script = final.callPackage ./pkgs-by-name/flash-script/package.nix { };
    fleet-desktop = final.callPackage ./pkgs-by-name/fleet-desktop/package.nix { };
    fleet-orbit = final.callPackage ./pkgs-by-name/fleet-orbit/package.nix { };
    g2gchan = final.callPackage ./pkgs-by-name/g2gchan/package.nix { };
    gala = final.callPackage ./pkgs-by-name/gala/package.nix { };
    ghaf-build-helper = final.callPackage ./pkgs-by-name/ghaf-build-helper/package.nix { };
    ghaf-installer = final.callPackage ./pkgs-by-name/ghaf-installer/package.nix { };
    ghaf-intro = final.callPackage ./pkgs-by-name/ghaf-intro/package.nix { };
    ghaf-open = final.callPackage ./pkgs-by-name/ghaf-open/package.nix { };
    ghaf-powercontrol = final.callPackage ./ghaf-powercontrol/package.nix { };
    ghaf-vms = final.callPackage ./pkgs-by-name/ghaf-vms/package.nix { };
    gpu-vm-partition-manager-sdk = inputs.gpu-partition-manager.lib.mkSdk { pkgs = final; };
    hardware-scan = final.callPackage ./pkgs-by-name/hardware-scan/package.nix { };
    libxchan = final.callPackage ./pkgs-by-name/xchan/package.nix { };
    llama-bench-model = final.callPackage ./pkgs-by-name/llama-bench-model/package.nix { };
    # Stock nixpkgs llama.cpp for the TARGET system, deliberately NOT routed
    # through ghaf's overlays. The overlaid/cross-compiled llama-cpp is a ~32
    # derivation build including nodejs and openblas with nothing in any cache;
    # this one is a 10 MiB substitute, because Hydra has already built it. It
    # costs ~135 MB of duplicated runtime libs in the image (its own gcc-lib,
    # gfortran-lib and openblas; glibc and openssl are already shared) and buys
    # back an hour or more of build time plus the risk of a cross build of the
    # server's npm web UI failing outright.
    #
    # Only defensible because this is BRING-UP ONLY measurement tooling. Nothing
    # shipped should pull a package from outside the project's own package set.
    llama-cpp-prebuilt = inputs.nixpkgs.legacyPackages.${final.stdenv.hostPlatform.system}.llama-cpp;
    logseald = inputs.logseald.lib.mkPackage { pkgs = final; };
    make-checks = final.callPackage ./pkgs-by-name/make-checks/package.nix { };
    memsocket = final.callPackage ./pkgs-by-name/memsocket/package.nix { };
    pci-binder = final.callPackage ./pkgs-by-name/pci-binder/package.nix { };
    pkvm-g2g-test = final.callPackage ./pkgs-by-name/pkvm-g2g-test/package.nix { };
    rtl8126 = final.callPackage ./pkgs-by-name/rtl8126/package.nix { };
    update-docs-depends = final.callPackage ./pkgs-by-name/update-docs-depends/package.nix { };
    user-provision = final.callPackage ./pkgs-by-name/user-provision/package.nix { };
    wait-for-unit = final.callPackage ./pkgs-by-name/wait-for-unit/package.nix { };
    windows-launcher = final.callPackage ./pkgs-by-name/windows-launcher/package.nix { };
    xchan-bench = final.callPackage ./xchan-bench/package.nix { };
    xchan-module = final.callPackage ./pkgs-by-name/xchan/module.nix { };
  };
  # keep-sorted end
}
