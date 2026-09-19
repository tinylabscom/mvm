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
- Expect the paths `mvm` writes to be its own. `/etc/mvm`, `/mvm`, and `/usr/lib/mvm` are emptied of anything the image shipped there before `mvm` writes into them. `/etc/passwd` and `/etc/group` keep the image's entries, but are rewritten as new root-owned files with mode `0644`. Those paths, the mount points `mvm` creates, and the directories leading to them are root-owned in the built rootfs whatever owner the image's layers declare. An image is refused if it ships one of those paths as a symbolic link, as something other than a regular file where `mvm` writes one, or under a name the host filesystem folds onto `mvm`'s spelling (for example `etc/Mvm` on a case-insensitive macOS volume). Images that ship `/data`, `/work`, `/mnt`, `/home`, `/tmp`, or `/dev/shm` as symbolic links are refused for the same reason.
- Expect `mvmctl run --prod --image` and a foreground `mvmctl machine run --prod --image` to boot their own sealed rootfs. The sealed and dev builds of an image are cached separately, these runs never reuse the dev build, and one whose image is not sealed is refused. The trust policy is checked before anything is built or signed. `--prod` also refuses `--profile dev`, and an ad-hoc command after `--` or a `--launch-plan`, before anything is pulled: a sealed image serves neither. Not covered yet: a persistent `mvmctl machine run --prod -d`, and `--prod` with `--runtime-pack`, `--deployment`, `--flake` or `--manifest` (issue #3480).
- Scope caches by workload or deployment boundary.
- Emit audit events for resolve, fetch, cache hit, materialize, verify, launch, and delete.

## Production rules for Nix examples

- Pin flake inputs.
- Build Linux artifacts inside the builder VM.
- Avoid ad-hoc host-side downloads in build hooks.
- Preserve derivation and artifact identifiers in audit records.
- Use signed execution plans for launch.
