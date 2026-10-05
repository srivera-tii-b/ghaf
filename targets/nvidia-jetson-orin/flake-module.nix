# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
#  Configuration for NVIDIA Jetson Orin AGX/NX
#
{
  lib,
  self,
  inputs,
  ...
}:
let
  inherit (inputs) jetpack-nixos nixpkgs;
  system = "aarch64-linux";
  pkgsX86 = nixpkgs.legacyPackages.x86_64-linux;
  lazyPackage =
    name: drv:
    (lib.lazyDerivation {
      derivation = drv;
    })
    // {
      inherit name;
    };

  # Unified Ghaf configuration builder
  ghaf-configuration = self.builders.mkGhafConfiguration {
    inherit self inputs;
    inherit (self) lib;
  };

  # Orin-specific modules (UEFI patches, OP-TEE, format modules)
  orinSpecificModules = [
    ../../modules/reference/hardware/jetpack/nvidia-jetson-orin/format-module.nix
    jetpack-nixos.nixosModules.default
  ];

  # Common modules shared across all Orin configurations
  commonModules = orinSpecificModules ++ [
    self.nixosModules.reference-host-demo-apps
    self.nixosModules.reference-profiles-orin
    self.nixosModules.profiles
    # In-tree targets are TII's reference images; the profiles stay
    # org-free so a downstream can reuse them with its own org module.
    { ghaf.reference.org.tii.enable = true; }
  ];

  # BRING-UP ONLY. One fixed, unprivileged test SSH key for hardware
  # bring-up: the private half is copied into the host (root's ~/.ssh, and the
  # demo orchestrator's runtime dir), the public half is authorized for root on
  # every demo guest. It lands world-readable in the nix store. It must not
  # survive into anything shipped and must never be added to a PR; remove it
  # together with every use (authorizedKeys, the tmpfiles copy, the demo's
  # sshKey).
  bringupTestKey = builtins.path {
    path = /home/census/srivera/census/testkey/id_ed25519;
    name = "xchan-bringup-test-key";
  };
  bringupTestKeyPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJxw+TJWc5PLTaHP9Q4c9/3YmRrBHhgUrNZk1rI4a1gN xchan-bringup-test-key";

  # BRING-UP ONLY, committed test identities for the encrypted demo, one
  # Ed25519 key per guest (packages/xchan-bench/test-keys/README.md). A path
  # literal on purpose: vm-xchan-demo.nix copies each file into the store on
  # its own, so a guest's closure holds only its own seed.
  demoTestKeys = ../../packages/xchan-bench/test-keys;

  # Host side of the xchan link. The crosvm processes meet on a unix socket
  # in the host namespace; the guests never see it.
  # A module function rather than a bare attrset: it needs `pkgs` and
  # `config`, which the outer scope here does not provide (only lib/self/inputs).
  xchanHostModule =
    { config, pkgs, ... }:
    let
      cfg = config.ghaf.xchan-bringup;
      inherit (config.ghaf.networking) hosts;
      connectorOrdering = {
        after = [ "microvm@admin-vm.service" ];
        wants = [ "microvm@admin-vm.service" ];
        partOf = [ "microvm@admin-vm.service" ];
      };
    in
    {
      options.ghaf.xchan-bringup = {
        vsockBenchRelay.enable = lib.mkEnableOption ''
          bench-vsock-relay on the host, the host half of the bench's vsock
          arm (net-vm -> host -> admin-vm). Only meaningful with
          ghaf.virtualization.microvm.xchan.benchService on in both guests,
          which the encrypted demo excludes'';
      };

      config = {
        # BRING-UP ONLY. The benchmark binaries stay on the host for manual
        # runs; nothing here starts them any more (see vsockBenchRelay).
        environment.systemPackages = [ pkgs.xchan-bench ];

        # The model is no longer on the host. It used to run here (llama-server
        # behind the vsock shim, measured from net-vm over guest-to-host vsock);
        # the demo runs the same llama-bench module INSIDE admin-vm instead, on
        # its loopback only, behind xchan-demo-server (vm-xchan-demo.nix). To
        # bring the host-model arm back, set
        # ghaf.reference.services.llama-bench.enable here and llamaVsockPort +
        # benchService in net-vm, and turn the demo off, which competes for
        # /dev/xchan0 with the bench.

        # Arm 3 of the benchmark: vsock cannot address guest-to-guest, so net-vm
        # reaches admin-vm's vsock bench server only through a relay here. Off
        # with the bench; the CID is read from the central allocation, which
        # client-vm shifts (admin-vm is 5 with it, 4 without).
        systemd.services.bench-vsock-relay = lib.mkIf cfg.vsockBenchRelay.enable {
          description = "vsock relay for the guest-to-guest benchmark arm";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "simple";
            Restart = "always";
            RestartSec = "5s";
            ExecStart = "${pkgs.xchan-bench}/bin/bench-vsock-relay 9000 ${toString hosts.admin-vm.cid} 9000";
          };
        };

        # BRING-UP ONLY. The encrypted guest-to-guest LLM demo, sequenced from
        # here: modules/reference/services/xchan-demo/xchan-demo.nix. Runs once
        # per boot from a timer; `systemctl start xchan-demo` to run it again,
        # `journalctl -u xchan-demo` to read it. The host only starts/stops
        # guests and runs the client inside them; it holds no demo key.
        ghaf.reference.services.xchan-demo = {
          enable = true;
          sshKey = bringupTestKey;
        };

        # crosvm binds/connects this path at device creation, before either guest
        # runs, so it has to exist on the host first.
        # microvm:kvm, not root: microvm@.service sets PrivateUsers=true, so each
        # crosvm is root inside its own user namespace but an unmapped UID against
        # host-owned files, CAP_DAC_OVERRIDE does not cross that boundary. Its
        # effective host identity is microvm:kvm, which is what owns
        # /var/lib/microvms. A root-owned 0750 directory here is unreachable from
        # both ends: the listener fails bind() and the connector then fails
        # connect(), both with EACCES (observed on first boot).
        systemd.tmpfiles.rules = [
          "d /run/xchan 0770 microvm kvm -"
          # BRING-UP ONLY. Copies (C, not symlinks) the test private key into
          # root's ~/.ssh with 0600 so `ssh root@vsock/<cid>` can reach the
          # guests without a password, the guests have no root password and
          # no other keys. A symlink would point into the world-readable nix
          # store and ssh would refuse it. See bringupTestKey above.
          "d /root/.ssh 0700 root root -"
          "C /root/.ssh/id_ed25519 0600 root root - ${bringupTestKey}"
        ];

        # Both connectors (net-vm, client-vm) are ordered against the hub the
        # same way.
        #
        # The connector's crosvm connects when its device is created and, if the
        # hub has not bound the socket yet, retries with bounded backoff for a
        # few seconds before failing that VM. Ordering makes the common case
        # right; "After" only means admin-vm's unit started, not that its crosvm
        # reached bind(), so the retry budget covers the rest.
        #
        # PartOf, not merely Wants: propagate the hub's stop/restart to the
        # connector, which comes back through its own Restart=always with a
        # fresh channel. This dates from a crosvm whose connector treated peer
        # loss as terminal, which left the guest blocked in wait_channel
        # indefinitely with no error. The current connector also reconnects by
        # itself once its old channel is settled (the guest closed the fd and
        # the peer detached).
        #
        # PartOf is one-way: stopping a connector (demo step 3) leaves the hub
        # and the other connector alone, and Wants on an already-active hub is a
        # no-op, so starting a connector again (step 5) does not restart it.
        systemd.services."microvm@net-vm" = connectorOrdering;
        systemd.services."microvm@client-vm" = connectorOrdering;
      };
    };

  # Exercise the complete manager/CDI integration in an existing CI-built
  # image without making example workloads part of Ghaf. The manager-owned
  # mock plugin is sufficient for build and boot validation; downstream
  # configurations replace this default with real workload plugins.
  nxGpuPartitioningDebugModule =
    { pkgs, ... }:
    let
      managerSdk = inputs.gpu-partition-manager.lib.mkSdk { inherit pkgs; };
      managerMockPlugin = pkgs.stdenv.mkDerivation {
        pname = "gpu-partition-manager-mock-plugin";
        version = "1.0";

        dontUnpack = true;
        dontConfigure = true;

        buildPhase = ''
          runHook preBuild
          $CC -std=c11 -Wall -Wextra -Werror -fPIC -shared \
            -I${managerSdk}/include \
            -I${pkgs.nvidia-jetpack.cudaPackages.cuda_cudart}/include \
            ${inputs.gpu-partition-manager}/tests/mock-plugin.c \
            -o plugin.so
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          install -Dm755 plugin.so \
            $out/lib/gpu-partition-manager/plugin.so
          runHook postInstall
        '';

        passthru = {
          gpuPartitionPluginName = "mock";
          requiredPluginAbiVersion = managerSdk.pluginAbiVersion;
        };

        meta = {
          description = "Manager-owned mock plugin for NX debug integration validation";
          platforms = [ "aarch64-linux" ];
        };
      };
    in
    {
      ghaf.hardware.nvidia.passthroughs.gpu_vm = {
        containerRuntime.enable = true;
        partitionManager = {
          enable = true;
          plugins = lib.mkDefault [ managerMockPlugin ];
        };
      };
    };

  # A/B verity boot targets: LVM-based A/B slots + UKI instead of the sd-card
  # format module
  orinVerityModules = [
    jetpack-nixos.nixosModules.default
    self.nixosModules.reference-host-demo-apps
    self.nixosModules.reference-profiles-orin
    self.nixosModules.profiles
    { ghaf.reference.org.tii.enable = true; }
    ../../modules/reference/hardware/jetpack/nvidia-jetson-orin/verity-image.nix
    ../../modules/reference/hardware/jetpack/nvidia-jetson-orin/partition-template-verity.nix
    inputs.nix-store-veritysetup-generator.nixosModules.ghaf-store-veritysetup-generator
    ../../modules/partitioning/verity-volume.nix
    ../../modules/partitioning/firstboot-persist.nix
    # Enable dm-verity and erofs in the kernel (not in the BSP default config)
    {
      boot.kernelPatches = [
        {
          name = "dm-verity-support";
          patch = null;
          structuredExtraConfig = with lib.kernel; {
            DM_VERITY = module;
            DM_CRYPT = module; # encrypted swap (randomEncryption)
            EROFS_FS = module;
            EROFS_FS_ZIP = yes; # lz4 compression support (lz4 is default, auto-selects LZ4_DECOMPRESS)
            # TODO: switch to zstd when kernel >= 6.10 (EROFS_FS_ZIP_ZSTD, commit 7c35de4df105)
          };
        }
      ];
    }
  ];

  # Shared by the AGX and NX accelerated-guivm variants.
  acceleratedGuivmUsbRules = [

    {
      description = "USB Devices for GUIVM";
      targetVm = "gui-vm";
      allow = [
        {
          interfaceClass = 3;
          interfaceProtocol = 1;
          description = "HID Keyboard";
        }
        {
          interfaceClass = 3;
          interfaceProtocol = 2;
          description = "HID Mouse";
        }
        {
          interfaceClass = 11;
          description = "Chip/SmartCard (e.g. YubiKey)";
        }
        {
          interfaceClass = 8;
          interfaceSubclass = 6;
          description = "Mass Storage - SCSI (USB drives)";
        }
        {
          interfaceClass = 17;
          description = "USB-C alternate modes supported by device";
        }
      ];
      deny = [
        {
          vendorId = "046d";
          productId = "c52b";
          description = "Logitech Unifying Receiver: evdev-only on Orin (usb-host interrupt-IN broken)";
        }
      ];
    }
  ];

  # Non-verity Orin configurations using mkGhafConfiguration
  target-configs = [
    # ============================================================
    # Debug Configurations
    # ============================================================

    (ghaf-configuration {
      name = "nvidia-jetson-orin-agx";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-agx;
      variant = "debug";
      extraModules = commonModules;
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
      };
    })

    (ghaf-configuration {
      name = "nvidia-jetson-orin-agx-accelerated-guivm";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-agx;
      variant = "debug";
      extraModules = commonModules;
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
        # Accelerated topology has one combined GPU/display owner.
        hardware.nvidia.passthroughs.gui_vm.enable = true;
        hardware.nvidia.passthroughs.gpu_vm.enable = lib.mkForce false;
        hardware.nvidia.passthroughs.disp_vm.enable = lib.mkForce false;

        # Keep the Unifying receiver on the working evdev path.
        hardware.passthrough.usb.guivmRules = lib.mkForce acceleratedGuivmUsbRules;
      };
    })

    (ghaf-configuration {
      name = "nvidia-jetson-orin-agx64";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-agx64;
      variant = "debug";
      extraModules = commonModules;
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
      };
    })

    (ghaf-configuration {
      name = "nvidia-jetson-orin-agx64-pvm";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-agx64;
      variant = "debug";
      extraModules = commonModules ++ [ xchanHostModule ];
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;

        host.kernel.hardening.hypervisor.enable = true;
        guest.hardening.protected.enable = true;

        # BRING-UP ONLY. The third guest of the encrypted demo: a second
        # xchan client, distrusting net-vm and admin-vm alike. Minimal by
        # design (modules/microvm/sysvms/clientvm-base.nix). Joining the
        # central allocation shifts CIDs: client-vm 3, gui-vm 4, admin-vm 5,
        # net-vm 6.
        virtualization.microvm.clientvm.enable = true;
      };
      vmConfig = {
        # xchan: admin-vm listens; net-vm and client-vm both connect to the
        # same hub socket, each crosvm holding one channel. Exactly one
        # listener per link.
        #
        # The encrypted guest-to-guest LLM demo runs on top:
        # the model in admin-vm, the two clients asking it over xchan with
        # every message end-to-end encrypted between guests. benchService is
        # OFF in every guest because WAIT_CHANNEL hands each channel to one
        # consumer, the bench server would take admin-vm's channels from the
        # demo server (vm-xchan-demo.nix asserts this). benchTools stays on,
        # so the binaries are still there for manual runs.
        sysvms.netvm = {
          extraModules = [
            (
              { hostConfig, ... }:
              {
                ghaf.virtualization.microvm.xchan = {
                  enable = true;
                  role = "connector";
                  benchTools = true;
                  benchService = false;
                  # BRING-UP ONLY. Gives `ssh root@vsock/<cid>` from the host, so
                  # measurements and poking around stop costing a reflash, and
                  # is how the demo orchestrator drives the client. Pairs with
                  # the test key in authorizedKeys below.
                  vsockLogin = true;
                  # BRING-UP ONLY. Demo client: its own identity + admin-vm's
                  # public key. Run by the host orchestrator, not at boot.
                  demo = {
                    enable = true;
                    name = "net-vm";
                    keyDir = demoTestKeys;
                  };
                };
                # BRING-UP ONLY, see bringupTestKey.
                users.users.root.openssh.authorizedKeys.keys = [ bringupTestKeyPub ];
                # netvm-base assigns no CID, which is why `microvm -s net-vm`
                # reported no VSOCK. Take it from the same central allocation
                # the other sysvms use rather than a literal: client-vm
                # moved net-vm from 5 to 6.
                # BRING-UP ONLY. cid alone is NOT enough: microvm.vsock.ssh is a
                # separate option, and without it no sshd listens on vsock, so
                # `microvm -s net-vm` gets a connection reset and the test key
                # is unusable. Found the hard way, the key was installed for
                # three builds before anyone tried to connect through it.
                microvm.vsock = {
                  inherit (hostConfig.networking.thisVm) cid;
                  ssh.enable = true;
                };
              }
            )
          ];
        };
        sysvms.adminvm = {
          # The model guest. 4096 MB already covers the model with room to
          # spare: llama-server at ctx 16384 / 2 slots (8192 tokens each, see
          # vm-xchan-demo.nix) with two concurrent worst-case requests peaked
          # at 0.86 GB RSS (weights included) when measured with the same
          # llama.cpp build and model. 4 vCPUs: 3 decode threads plus one for
          # the demo server, virtio and sshd.
          vcpu = 4;
          extraModules = [
            {
              ghaf.virtualization.microvm.xchan = {
                enable = true;
                role = "listener";
                benchTools = true;
                benchService = false;
                # BRING-UP ONLY. See the note on net-vm.
                vsockLogin = true;
                # BRING-UP ONLY. Demo server: llama-server (Qwen2.5-0.5B, 2
                # slots, 127.0.0.1 only) + xchan-demo-server, which accepts
                # only the clients listed here by public key.
                demo = {
                  enable = true;
                  name = "admin-vm";
                  keyDir = demoTestKeys;
                  clients = [
                    "net-vm"
                    "client-vm"
                  ];
                };
              };
              # BRING-UP ONLY. See the note on net-vm: the cid comes from
              # networking.thisVm, but the vsock sshd has to be asked for
              # separately or the test key cannot be reached.
              microvm.vsock.ssh.enable = true;
              # BRING-UP ONLY, see bringupTestKey.
              users.users.root.openssh.authorizedKeys.keys = [ bringupTestKeyPub ];
            }
          ];
        };
        # BRING-UP ONLY. A second demo client and nothing else: no NIC, no
        # network, no storage. 1 vCPU / 1 GiB is the system-VM default memory
        # and runs one client process at a time.
        sysvms.clientvm = {
          mem = 1024;
          vcpu = 1;
          extraModules = [
            {
              ghaf.virtualization.microvm.xchan = {
                enable = true;
                role = "connector";
                # BRING-UP ONLY. The orchestrator's way in, as on net-vm.
                vsockLogin = true;
                demo = {
                  enable = true;
                  name = "client-vm";
                  keyDir = demoTestKeys;
                };
              };
              # The cid comes from networking.thisVm (clientvm-base.nix); the
              # vsock sshd has to be asked for separately.
              microvm.vsock.ssh.enable = true;
              # BRING-UP ONLY, see bringupTestKey.
              users.users.root.openssh.authorizedKeys.keys = [ bringupTestKeyPub ];
            }
          ];
        };
        # BRING-UP ONLY. gui-vm is a protected guest with the same guest
        # kernel, so its guest-to-guest self-test would ping and share pages
        # with admin-vm, net-vm and client-vm for about 15 minutes after boot,
        # through the one-slot mailboxes the demo's g2gchan step needs to
        # itself. Keep that test off, as the demo guests do
        # (vm-xchan-demo.nix).
        sysvms.guivm.extraModules = [
          { boot.kernelParams = [ "arm_pkvm_guest.g2g_runtime_test=0" ]; }
        ];
      };
    })

    (ghaf-configuration {
      name = "nvidia-jetson-orin-agx-industrial";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-agx-industrial;
      variant = "debug";
      extraModules = commonModules;
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
      };
    })

    (ghaf-configuration {
      name = "nvidia-jetson-orin-nx";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-nx;
      variant = "debug";
      extraModules = commonModules ++ [ nxGpuPartitioningDebugModule ];
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
        # Crucial for Orin devices to use the correct render device
        # Also needs 'mesa' to be in hardware.graphics.extraPackages
        graphics.cosmic.renderDevice = "/dev/dri/renderD128";
      };
      vmConfig = {
        sysvms.netvm = {
          # 4 vCPUs is the minimum that keeps QEMU USB emulation (libusb
          # redirection of the ethernet dongle) from starving when alloy, givc
          # node + stunnel, and spire-agent are all active on Orin NX. At 2 vCPUs
          # the xhci_hcd guest driver desyncs with the QEMU event ring under load
          # ("Transfer event TRB DMA ptr not part of current TD" + NETDEV WATCHDOG
          # TX timeouts). AGX is unaffected because it has more cores per slice.
          vcpu = 4;
          # 2GB headroom: alloy + stunnel + spire-agent + givc-agent + auditd
          # pile up on net-vm with the givc/logging stack enabled, and the
          # 1GB default OOMs during the first-boot burst on Orin NX. The kernel
          # then evicts page cache backing the USB-eth driver and the dongle
          # disconnects, killing sshd on the test-net IP.
          mem = 2048;
        };
        # The split topology reserves ~2.1GiB after dropping the old 4GiB VRAM
        # bank. Keep the VM total at or under 7GiB until this reduced layout is
        # validated on NX; 10.1GiB under the former ~6.1GiB layout OOM-killed a
        # VM and hung PID 1 on every boot.
        sysvms.gpuvm = {
          mem = 2048;
        };
        # disp-vm runs on the 1:1 dispram carveout; -m only backs the
        # machine's default RAM window.
        sysvms.dispvm = {
          mem = 1536;
        };
      };
    })

    (ghaf-configuration {
      name = "nvidia-jetson-orin-nx-accelerated-guivm";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-nx;
      variant = "debug";
      extraModules = commonModules;
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
        # Accelerated topology has one combined GPU/display owner.
        hardware.nvidia.passthroughs.gui_vm.enable = true;
        hardware.nvidia.passthroughs.gpu_vm.enable = lib.mkForce false;
        hardware.nvidia.passthroughs.disp_vm.enable = lib.mkForce false;

        # Pin APP so the flash script carries no embedded image: every flash
        # supplies one with -s, which also keeps the script buildable without
        # the image.
        hardware.nvidia.orin.flashScriptOverrides.appPartitionSizeBytes = 34359738368;

        # Keep the Unifying receiver on the working evdev path.
        hardware.passthrough.usb.guivmRules = lib.mkForce acceleratedGuivmUsbRules;
      };
      vmConfig = {
        sysvms.netvm = {
          vcpu = 4;
          mem = 2048;
        };
        # VFIO pins all guest RAM up front, so 4096 only fits alongside the
        # host zram in orin-nx.nix; without it this OOM-crash-looped.
        sysvms.guivm = {
          mem = 4096;
        };
      };
    })

    # ============================================================
    # Release Configurations
    # ============================================================

    (ghaf-configuration {
      name = "nvidia-jetson-orin-agx";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-agx;
      variant = "release";
      extraModules = commonModules;
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
      };
    })

    (ghaf-configuration {
      name = "nvidia-jetson-orin-agx64";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-agx64;
      variant = "release";
      extraModules = commonModules;
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
      };
    })

    (ghaf-configuration {
      name = "nvidia-jetson-orin-agx-industrial";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-agx-industrial;
      variant = "release";
      extraModules = commonModules;
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
      };
    })

    (ghaf-configuration {
      name = "nvidia-jetson-orin-nx";
      inherit system;
      profile = "orin";
      hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-nx;
      variant = "release";
      extraModules = commonModules;
      extraConfig = {
        reference.profiles.mvp-orinuser-trial.enable = true;
        # Crucial for Orin devices to use the correct render device
        # Also needs 'mesa' to be in hardware.graphics.extraPackages
        graphics.cosmic.renderDevice = "/dev/dri/renderD128";
      };
    })

  ];

  # A/B Verity Boot Configurations (AGX only)
  verity-target-configs =
    map
      (
        variant:
        (ghaf-configuration {
          name = "nvidia-jetson-orin-agx-verity";
          inherit system;
          profile = "orin";
          hardwareModule = self.nixosModules.hardware-nvidia-jetson-orin-agx;
          inherit variant;
          extraModules = orinVerityModules;
          extraConfig = {
            reference.profiles.mvp-orinuser-trial.enable = true;
            partitioning.verity.enable = true;
            partitioning.verity.uki-signing-key-dir = lib.mkIf (
              variant == "debug"
            ) ../../modules/secureboot/dev-keys;
            hardware.nvidia.orin.secureboot.enable = true;
            # Debug builds enroll the dev certs so they match the dev signing
            # keys, outranking the org's production certs; release builds keep
            # the org value.
            hardware.nvidia.orin.secureboot.keysSource = lib.mkIf (variant == "debug") (
              lib.mkForce ../../modules/secureboot/dev-keys
            );
          };
        })
        // {
          isVerity = true;
          # `extraConfig` above sets `hardware.nvidia.orin.secureboot.enable = true`
          # unconditionally, so `flashTarget`'s `mkForce true` would yield the same
          # value and a bit-identical derivation -- at the cost of a second full
          # Jetson fixpoint (several GB of eval). Keep this in sync with that line.
          secureBootAlwaysOn = true;
        }
      )
      [
        "debug"
        "release"
      ];
  all-target-configs = target-configs ++ verity-target-configs;

  generate-nodemoapps =
    tgt:
    tgt
    // rec {
      name = tgt.name + "-nodemoapps";
      # Consumed by `flashCrossTargets` below to skip generating flash attributes
      # for these; marked here rather than matched on the name, matching how
      # verity targets carry `isVerity`.
      isNoDemoApps = true;
      hostConfiguration = tgt.hostConfiguration.extendModules {
        modules = [
          {
            ghaf.reference = {
              host-demo-apps.demo-apps.enableDemoApplications = lib.mkForce false;
              programs.windows-launcher.enable = lib.mkForce false;
            };
          }
        ];
      };
      package = hostConfiguration.config.system.build.ghafImage;
    };

  generate-cross-from-x86_64 =
    tgt:
    tgt
    // rec {
      name = tgt.name + "-from-x86_64";
      hostConfiguration = tgt.hostConfiguration.extendModules {
        modules = [ self.nixosModules.cross-compilation-from-x86_64 ];
      };
      package = lazyPackage name hostConfiguration.config.system.build.ghafImage;
    };

  generate-luks =
    tgt:
    tgt
    // rec {
      name = tgt.name + "-luks";
      hostConfiguration = tgt.hostConfiguration.extendModules {
        modules = [
          {
            ghaf.hardware.nvidia.orin.diskEncryption.enable = true;
            ghaf.hardware.nvidia.orin.diskEncryption.deviceUniqueKey.enable = true;
          }
        ];
      };
      package = hostConfiguration.config.system.build.ghafImage;
    };

  generate-luks-uki =
    tgt:
    tgt
    // rec {
      name = tgt.name + "-luks-uki";
      hostConfiguration = tgt.hostConfiguration.extendModules {
        modules = [
          {
            ghaf.hardware.nvidia.orin.diskEncryption.enable = true;
            ghaf.hardware.nvidia.orin.diskEncryption.deviceUniqueKey.enable = true;
            ghaf.image.sdcard.uki.enable = true;
          }
        ];
      };
      package = hostConfiguration.config.system.build.ghafImage;
    };

  # LUKS and dm-verity are mutually exclusive root strategies (see the assertion
  # in jetson-orin.nix), so the verity targets get no -luks variant.
  luksable-target-configs = builtins.filter (t: !isVerityTarget t) all-target-configs;

  # Add nodemoapps targets
  targets =
    all-target-configs
    ++ (map generate-nodemoapps all-target-configs)
    ++ (map generate-luks luksable-target-configs)
    ++ (map generate-luks-uki luksable-target-configs)
    ++ (map (t: generate-luks (generate-nodemoapps t)) luksable-target-configs)
    ++ (map (t: generate-luks-uki (generate-nodemoapps t)) luksable-target-configs);
  crossTargets = map generate-cross-from-x86_64 targets;
  flashTarget =
    t: qspiOnly:
    let
      # Shared by both secureboot variants so the two cannot drift apart.
      nxDiskOverrides = lib.optionalAttrs (lib.strings.hasInfix "nx" t.name && !qspiOnly) {
        # NX boots from USB or NVMe; the flash script targets NVMe.
        ghaf.hardware.nvidia.orin.flashScriptOverrides.deviceDisk = lib.mkForce "nvme0n1";
        ghaf.hardware.nvidia.orin.flashScriptOverrides.deviceDiskEspPartition = lib.mkForce "nvme0n1p1";
        ghaf.hardware.nvidia.orin.flashScriptOverrides.deviceDiskRootfsPartition = lib.mkForce "nvme0n1p2";
      };
      noSBCfg = t.hostConfiguration.extendModules {
        modules = [
          (
            {
              ghaf.hardware.nvidia.orin.flashScriptOverrides.onlyQSPI = qspiOnly;
            }
            // nxDiskOverrides
          )
        ];
      };
      noSB = noSBCfg.pkgs.nvidia-jetpack.signedFlashScript;
      # Targets that already enable secureboot unconditionally get the identical
      # derivation back from `mkForce true`, so skip the second fixpoint entirely.
      withSB =
        if t.secureBootAlwaysOn or false then
          noSB
        else
          (t.hostConfiguration.extendModules {
            modules = [
              (
                {
                  ghaf.hardware.nvidia.orin.secureboot.enable = lib.mkForce true;
                  ghaf.hardware.nvidia.orin.flashScriptOverrides.onlyQSPI = qspiOnly;
                }
                // nxDiskOverrides
              )
            ];
          }).pkgs.nvidia-jetpack.signedFlashScript;
    in
    # Single `*-flash-script` entrypoint that picks between two
    # pre-built QSPI firmware variants at flash time.
    #
    # Why two variants instead of one profile-level toggle:
    #
    # `ghaf.hardware.nvidia.orin.secureboot.enable` is evaluated at Nix
    # build time. When true, it bakes the `UefiDefaultSecurityKeys`
    # device-tree overlay and PK/KEK/db ESLs into the QSPI firmware, so
    # the device enrolls keys and turns Secure Boot on at first boot.
    # Flipping it on unconditionally in the Orin profile would brick the
    # default unsigned flash path: the QSPI carries enrollment material
    # but BOOTAA64.EFI is unsigned, leaving the board in the UEFI
    # Interactive Shell with no recoverable boot entry.
    #
    # The QSPI variant has to be selected *before* the inner script runs
    # (it cannot be influenced at run time), which is what the wrapper
    # does on its own `--secure-boot` flag:
    #
    #   - default        → unsigned QSPI (no DTBO, no ESLs)
    #   - --secure-boot  → SB-enabled QSPI (DTBO + ESLs); pair it with a
    #                      *signed* sd-image via `-s`, or the enrolled
    #                      firmware will refuse the unsigned BOOTAA64.EFI
    #                      and fall through to PXE/UEFI shell.
    #
    # `-s/--signed-sd-image` itself is deliberately NOT the selector:
    # with `appPartitionSizeBytes` set the flash script carries no
    # embedded image and `-s` is how *every* flash (signed or not)
    # supplies one, so keying Secure Boot off it bricked all unsigned
    # flashes.
    #
    # Use the `-u` flag if the image contains a UKI.
    #
    # Both variants share substituted store paths (jetpack-nixos
    # `flashScript` is a thin wrapper around the same per-target
    # derivations), so the second build is mostly a Nix-eval cost.
    pkgsX86.writeShellApplication {
      name = "flash-ghaf-host";
      text = ''
        sb=0
        args=()
        for arg in "$@"; do
          case "$arg" in
            --secure-boot) sb=1 ;;
            *) args+=("$arg") ;;
          esac
        done
        if [ "$sb" = 1 ]; then
          exec ${lib.getExe withSB} "''${args[@]}"
        else
          exec ${lib.getExe noSB} "''${args[@]}"
        fi
      '';
    };

  # Filter verity targets without forcing every hostConfiguration.config during
  # package-set evaluation.
  isVerityTarget = t: t.isVerity or false;
  verityCrossTargets = builtins.filter isVerityTarget crossTargets;

  # Targets that get their own flash attributes.
  #
  # `nodemoapps` only removes demo applications from the *image*, and no flash
  # script embeds an image any more: every Orin board pins
  # `appPartitionSizeBytes`, so flash.xml carries static ESP/APP sizes and the
  # image is supplied at run time with `-s`. The variant therefore cannot change
  # the flash script, and a census over all 125 flash attributes confirmed it --
  # 63 distinct derivations, and all 62 duplicates were exactly an
  # `X` / `X-nodemoapps` pair.
  #
  # Each duplicate cost a full Jetson derivation-graph construction during CI
  # eval, which is where the eval memory goes. Flash a `nodemoapps` image with the
  # base target's script and `-s <image>`.
  flashCrossTargets = builtins.filter (t: !(t.isNoDemoApps or false)) crossTargets;
in
{
  flake = {
    nixosConfigurations = builtins.listToAttrs (
      map (t: lib.nameValuePair t.name t.hostConfiguration) (targets ++ crossTargets)
    );

    packages = {
      aarch64-linux = builtins.listToAttrs (map (t: lib.nameValuePair t.name t.package) targets);
      x86_64-linux =
        builtins.listToAttrs (map (t: lib.nameValuePair t.name t.package) crossTargets)
        // builtins.listToAttrs (
          map (
            t:
            #Note: secureTarget does not toggle between secureboot on/off!!
            lib.nameValuePair "${t.name}-flash-script" (
              lazyPackage "${t.name}-flash-script" (flashTarget t false)
            )
          ) flashCrossTargets
        )
        // builtins.listToAttrs (
          map (
            t:
            #Note: secureTarget does not toggle between secureboot on/off!!
            lib.nameValuePair "${t.name}-flash-qspi" (lazyPackage "${t.name}-flash-qspi" (flashTarget t true))
            # `onlyQSPI` is read only by partition-template.nix, whose config is
            # gated on `!verity`; the verity partition template never reads it. A
            # verity `-flash-qspi` is therefore the same derivation as its
            # `-flash-script`, so emitting it costs a full Jetson eval for a
            # duplicate.
          ) (builtins.filter (t: !(isVerityTarget t)) flashCrossTargets)
        )
        # OTA update artifacts for verity targets
        // builtins.listToAttrs (
          map (
            t: lib.nameValuePair "${t.name}-ghafImage" t.hostConfiguration.config.system.build.ghafImage
          ) verityCrossTargets
        );
    };
  };
}
