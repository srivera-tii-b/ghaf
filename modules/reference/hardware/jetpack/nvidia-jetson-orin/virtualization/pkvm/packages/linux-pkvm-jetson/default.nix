# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Stable Linux 6.18 kernel with pKVM patches for arm64.
# The same kernel is used for both host and guests on pvm target, only with different defconfigs.
#
{
  nvidia-jetpack7,
  fetchFromGitHub,
  structuredExtraConfig ? { },
  argsOverride ? { },
  ...
}@args:
nvidia-jetpack7.kernel.override {
  inherit structuredExtraConfig;

  argsOverride =
    args
    // {
      pname = "linux-pkvm-jetson";
      version = "6.18.0";
      extraMeta.branch = "pkvm-v6.18-dev";

      # The pKVM guest-to-guest kernel: tiiuae/linux-pkvm-jetson pkvm-v6.18-dev
      # at 269039945fcb plus guest identity, messages and page sharing between
      # protected VMs (vendor hypervisor calls 12-20), the EL2 self-checks that
      # gate them, and /dev/pkvm-g2g in guests, all behind
      # CONFIG_PKVM_GUEST_TO_GUEST, with the guest's tests behind
      # CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST. orin-pkvm-host.nix and
      # orin-pkvm-guest.nix turn them on, and then:
      #   - protected guests see the nine calls, all implemented; all but the
      #     two queries (a VM's own identity, a peer lookup) change hypervisor
      #     state;
      #   - every protected guest registers a predictable identity at boot,
      #     which a host that starts a protected VM of its own could claim
      #     first, and pings and shares pages with its peers for about 15
      #     minutes unless arm_pkvm_guest.g2g_runtime_test=0 is on its command
      #     line;
      #   - EL2 VM teardown routes every page through the guest-to-guest
      #     decision and dismantles a dying VM's shares, and the host keeps
      #     (leaks) a page EL2 refuses to reclaim;
      #   - the host logs the EL2 reclaim, mailbox and share self-check verdicts
      #     at boot; if one fails, the calls are not advertised.
      #
      # The series is on a fork of tiiuae/linux-pkvm-jetson until it is merged
      # there; this source then moves back to tiiuae at the merged revision.
      src = fetchFromGitHub {
        owner = "srivera-tii-b";
        repo = "linux-pkvm-jetson";
        rev = "00f6837b307d877dde69a73367acb4b961e66354"; # feat/pkvm-g2g, on pkvm-v6.18-dev 269039945fcb
        hash = "sha256-+4Maic3w9BXiGBfcx98jNglzJZLGP0r50Vc6y0f1GFM=";
      };
    }
    // argsOverride;
}
