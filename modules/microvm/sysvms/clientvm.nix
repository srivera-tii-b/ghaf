# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Client VM Configuration Module
#
# BRING-UP ONLY, see clientvm-base.nix for what this VM is and is not.
#
# Same shape as gpuvm.nix: the orin profile exports clientvmBase and wires
# evaluatedConfig; this module is inert until a target sets enable.
{
  config,
  lib,
  inputs,
  ...
}:
let
  vmName = "client-vm";

  cfg = config.ghaf.virtualization.microvm.clientvm;
in
{
  _file = ./clientvm.nix;

  options.ghaf.virtualization.microvm.clientvm = {
    enable = lib.mkEnableOption "ClientVM, a minimal xchan client guest (bring-up demo only)";

    evaluatedConfig = lib.mkOption {
      type = lib.types.nullOr lib.types.unspecified;
      default = null;
      description = "Pre-evaluated NixOS configuration for Client VM set via profile's clientvmBase.extendModules.";
    };

    extraNetworking = lib.mkOption {
      type = lib.types.networking;
      description = "Extra Networking option";
      default = { };
    };
  };

  config = lib.mkMerge [
    {
      ghaf.virtualization.microvm.sysvm.vms.clientvm = {
        inherit vmName;
        inherit (cfg) enable evaluatedConfig extraNetworking;
      };
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.evaluatedConfig != null;
          message = ''
            ghaf.virtualization.microvm.clientvm.evaluatedConfig must be set.
            Use a profile that provides clientvmBase (orin):
              clientvm.evaluatedConfig = config.ghaf.profiles.orin.clientvmBase.extendModules {
                modules = lib.ghaf.vm.applyVmConfig {
                  inherit config;
                  vmName = "clientvm";
                };
              };
          '';
        }
      ];

      microvm.vms."${vmName}" = {
        autostart = !config.ghaf.microvm-boot.enable;
        restartIfChanged = false;
        inherit (inputs) nixpkgs;
        inherit (cfg) evaluatedConfig;
      };
    })
  ];
}
