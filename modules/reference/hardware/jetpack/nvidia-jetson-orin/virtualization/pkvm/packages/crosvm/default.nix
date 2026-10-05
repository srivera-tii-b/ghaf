# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# tiiuae fork of crosvm to bring pKVM patches, with the xchan vendor device
#
{
  crosvm,
  fetchFromGitHub,
  rustPlatform,
  dbus,
}:
let
  version = "0-develop-xchan";

  # tiiuae/crosvm develop at 86d84c3f9 plus the xchan vendor device
  # (ghaf.virtualization.microvm.xchan). It is on a fork of tiiuae/crosvm
  # until it is merged there; this source then moves back to tiiuae at the
  # merged revision.
  src = fetchFromGitHub {
    owner = "srivera-tii-b";
    repo = "crosvm";
    rev = "452249cbe394540f50ecd17738f215149e536974"; # feat/xchan, on develop 86d84c3f9
    fetchSubmodules = true;
    hash = "sha256-I9IElcVx4m9hh32WcA9KbUUd9NxoyqKC4XeYD3JeYKA=";
  };
  cargoHash = "sha256-vNZ0IhvmYp8aEe7LDqBZocol7vF82MTePtHAH0vGUHc=";
in
crosvm.overrideAttrs (prev: {
  inherit version src cargoHash;

  # We need to also pass cargoHash to fetchCargoVendor, otherwise cargoDeps retains
  # the original value from nixpkgs in its scope.
  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit (prev) pname;
    inherit src version;
    hash = cargoHash;
  };
  buildInputs = (prev.buildInputs or [ ]) ++ [ dbus ];
  patches = [
    ./0001-vhost-user-handle-ACCESS_PLATFORM-for-protected-guest.patch
  ];

  cargoBuildFeatures = (prev.cargoBuildFeatures or [ ]) ++ [
    "gdb"
    "pci-hotplug"
    "vtpm"
    "bpmp"
    # The vendor devices, xchan among them, and the --vendor-devices option
    # that adds one to a VM are compiled in only with this feature.
    "vendor-devices"
  ];
})
