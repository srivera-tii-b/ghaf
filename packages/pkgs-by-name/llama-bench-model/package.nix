# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# GGUF weights for the inference benchmark and the encrypted demo's model
# guest, baked into the image.
#
# BRING-UP ONLY, and it exists because of a hard constraint: net-vm owns the
# NIC, so the HOST HAS NO NETWORK. Nothing can be downloaded on the device at
# runtime, which means the model has to be a build-time dependency like any
# other store path. A pinned fetchurl is the only honest way to do that, an
# impure fetch would make the image unreproducible, and a stub that serves
# canned text would make every benchmark number a lie.
#
# WHY A 0.5B MODEL AND NOT AN 8B: the measurement being made is the cost of
# the transport relative to the cost of a model, and that ratio is already
# decided at 15 ms/token (the three-arm benchmark measured single-digit ms of
# transport in TTFT and nothing measurable in throughput). A 0.5B Q4_K_M
# exercises byte-for-byte the same path as an 8B: llama-server, HTTP streaming,
# the shim, vsock, the bench client. What it does NOT cost is ~4.5 GB of image
# and the extra flash time that comes with it, and a flash is about an hour.
#
# Swapping in an 8B is therefore a config change, not a code change: point
# `ghaf.reference.services.llama-bench.model` at a different derivation (or add
# a second one next to this file) and nothing else moves.
#
# Pinned to a repository REVISION, not `main`: a GGUF re-quantised upstream
# under the same filename would otherwise silently change the hash and break
# the build at the worst possible moment.
{
  lib,
  fetchurl,
}:
fetchurl {
  name = "qwen2.5-0.5b-instruct-q4_k_m.gguf";
  url = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf";
  hash = "sha256-dKTajJ/bzRW9H20B1iFBDTHG/ACYb162h4JOe5PXqds=";

  meta = {
    description = "Qwen2.5-0.5B-Instruct, Q4_K_M GGUF quantisation (491 MB)";
    homepage = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF";
    license = lib.licenses.asl20;
    platforms = lib.platforms.all;
  };
}
