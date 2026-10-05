<!--
    SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
    SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Test identity keys for the encrypted xchan demo, NOT FOR PRODUCTION

One Ed25519 identity per guest, generated 2026-10-02 with OpenSSL:

- `<vm>.seed`, the 32-byte Ed25519 private seed, hex, one line. libsodium:
  `crypto_sign_seed_keypair(pk, sk, seed)`.
- `<vm>.pk`, the matching 32-byte public key, hex, one line.

Installed so that each guest holds only its own seed; admin-vm (the model
guest) holds the client guests' public keys; each client holds admin-vm's.

These are committed in the clear and land world-readable in the nix store, the
same posture as the bring-up SSH key. Acceptable only while provisioning is out of
scope (testing phase). Must be replaced by per-device provisioning, with keys that
never touch host-visible storage, and this directory deleted, before any PR.
