---
title: Nix and OCI
description: How mvm positions Nix-built microVM artifacts and OCI image compatibility.
---

`mvm` supports two input families, but they do not carry the same trust story.

| Input | Best for | Security posture |
| --- | --- | --- |
| Nix flake | Reproducible workloads, internal tools, audited deployments. | Preferred path: pinned inputs, builder VM isolation, artifact provenance, signed launch plans. |
| OCI image | Compatibility with existing images and package ecosystems. | Compatibility path: resolve immutable digests, verify layers, scope caches, and apply launch policy. |

Nix is the core path because it gives `mvm` a better audit surface. The builder VM evaluates and builds Linux artifacts behind the project execution boundary, then `mvm` launches the resulting microVM rootfs through the selected backend.

OCI support is still useful: teams already have images, scanners, registries, and base-image policies. `mvm` should accept those inputs only after turning the mutable registry world into verified local artifacts.

On Apple Silicon macOS, OCI `machine run` / `run` with `--allow-host` stays on
the HVF no-guest-NIC host-vsock-proxy path. If that helper path is not
launchable, `mvmctl` refuses the run before any OCI pull or boot work rather
than widening to guest-networking.

## Builder VM as the secure build boundary

Developers run `mvmctl machine build` from the host. The Linux work happens inside the builder VM:

```text
host mvmctl
  -> builder VM: nix eval / nix build / image assembly
  -> host artifact cache
  -> runtime microVM backend
```

That boundary matters for DX and security. The developer gets a normal local command, while `mvm` controls the Linux environment that produces the kernel/rootfs artifacts. Runtime boot, cold-mode restore, and benchmarks should start from already-built artifacts rather than folding build time into runtime behavior.

## Production rules for OCI examples

- Prefer digest-pinned references.
- Treat mutable tags as local development shorthand.
- Record requested ref and resolved digest.
- Verify manifest and blob digests.
- Apply whiteout, symlink, hardlink, mode, ownership, and size policies during unpack.
- Scope caches by workload or deployment boundary.
- Emit audit events for resolve, fetch, cache hit, materialize, verify, launch, and delete.

## Production rules for Nix examples

- Pin flake inputs.
- Build Linux artifacts inside the builder VM.
- Avoid ad-hoc host-side downloads in build hooks.
- Preserve derivation and artifact identifiers in audit records.
- Use signed execution plans for launch.
