---
title: "ADR-013: Pivot to libkrun + libkrun + microvm.nix"
description: Architecture Decision Record for the cross-platform microVM pivot — libkrun as the macOS/Windows execution path, Firecracker preferred on Linux, microvm.nix as the Nix foundation.
---

## Status

Proposed. Implementation tracked in [Plan 60](https://github.com/tinylabscom/mvm/blob/main/specs/plans/60-mvm-libkrun-migration.md). Phase 0 + Phase 1 deliver the build/exec pivot; subsequent phases compose on top.

> **Note (superseded in part):** `DockerBackend` (item 5 below) was not adopted — Docker was removed as a backend; the no-`/dev/kvm` path is the dev/test QEMU backend (`--hypervisor qemu`).

## Invariant — host does not need Nix

`mvmctl` runs on a stock host. **Nix is not a prerequisite.** On first build, mvm bootstraps a small Linux builder microVM (libkrun-backed), runs `nix build` inside it, and extracts the resulting rootfs to the host. The runtime path stays Nix-free; the builder path keeps Nix inside the sandbox where it belongs.

Host-side Nix is optional and only affects commands users run themselves:

- contributors hacking on mvm itself may want Nix for editor tooling or direct `nix build` debugging;
- users with [`nix-darwin`'s `linux-builder`](https://nix.dev/manual/nix/stable/installation/installing-binary) can use it for direct Nix commands;
- users with a remote `nix-daemon` URL can use it outside mvm's normal build path.

The full design is in [§"Linux builder via libkrun (no Lima)"](#linux-builder-via-libkrun-no-lima) below.

The user-facing contract is documented in [Builder VM](/guides/builder-vm/): `mvmctl build` is a host command, while Nix evaluation and image construction happen inside the builder VM.

## Context

The previous iteration of mvm used Lima as the macOS dev-VM hop and Firecracker as the production hypervisor on Linux. Two pain points motivated the pivot:

1. **macOS dev experience was indirect** — every guest action traversed `host → Lima Ubuntu → Firecracker microVM`. Boot times were dominated by Lima warm-up; first-launch UX was brittle.
2. **Build pipeline lacked portability** — Nix builds ran inside ephemeral Firecracker builder VMs, gated by KVM availability. macOS and Windows hosts had no clean path.

## Decision

Three coupled choices:

1. **libkrun** (Apache-2.0, libkrun-backed) becomes the **builder** and the **macOS/Windows execution path**. libkrun gives us native Hypervisor.framework on macOS and KVM on Linux without a wrapping Lima VM.
2. **Firecracker** stays as the preferred Linux production execution path because of its smaller attack surface, faster cold boot, and existing security work (jailer, dm-verity, seccomp tier).
3. **microvm.nix** (MIT) becomes the Nix-flake foundation for microVM image generation. It abstracts Firecracker / Cloud Hypervisor / QEMU / crosvm / kvmtool / stratovirt as a NixOS module — adding a new backend later is a config change, not a kernel rewrite.

**Lima is dropped entirely.** The macOS path is libkrun-direct; no intermediate Linux VM.

### Backend selection ladder

```
1. KVM available           → Firecracker (Linux production target)
2. has_libkrun()      → LibkrunBackend (macOS + non-KVM Linux)
3. macOS Container         → AppleContainerBackend (legacy; scheduled for removal)
4. raw libkrun             → LibkrunBackend (legacy; scheduled for removal)
5. Docker                  → DockerBackend (Tier 3 fallback; banner emitted)
```

`mvmctl run --hypervisor libkrun <flake>` always selects libkrun explicitly regardless of the host's KVM status.

## Linux builder via libkrun (no Lima)

macOS hosts can't `nix build` Linux derivations natively. The previous iteration solved that with a Lima VM as the Linux builder; this iteration drops Lima entirely. The replacement: **bootstrap a Linux builder inside libkrun itself**.

`mvmctl build` does:

1. Stages the user's flake source and selected profile as a builder job.
2. Boots or reuses the pinned Linux builder image.
3. Mounts the staged source, job metadata, cache volumes, and artifact output directory into the builder boundary.
4. Runs `nix build .#default` or the selected profile inside the builder VM.
5. Extracts the kernel/rootfs artifacts back to the host cache.
6. Hands the finished artifacts to the runtime path (which uses libkrun's `RootfsSource::DiskImage` per the OCI non-goal — the *runtime* never pulls OCI).

**Why this is consistent with the OCI non-goal.** The non-goal banned OCI from the **runtime/boot path** — where user workloads run, where reproducibility, offline-by-default, and no-registry-trust matter. The **builder** lives in a different trust zone: it has to fetch caches, talk to the network, and run arbitrary `nix build` derivations. Builder VMs and runtime VMs are governed by different policies; using OCI for the builder doesn't compromise the runtime's invariants.

**Cache reuse.** The builder VM keeps a warm Nix store/cache across builds. Host-side Nix may still be useful for direct developer commands, but mvm image construction goes through the builder VM so the behavior is consistent across macOS, Linux, and WSL2.

**This replaces every previous reference to "configure `nix-darwin`'s `linux-builder`" as a prerequisite for mvm builds.** Users can still configure one for their own direct Nix workflows; `mvmctl build` does not require it.

## Non-goal: OCI / container images

**mvm is microVMs, not containers.** Even though libkrun's API exposes both — `RootfsSource::Oci(reference)` for OCI image pulls and `RootfsSource::DiskImage { path, format, fstype }` for raw disk images — we deliberately use **only the `DiskImage` path**.

Why this is a stated invariant, not a default:

1. **Architectural commitment.** The project's value prop is microVM isolation backed by Nix-built rootfs images. OCI brings registry pulls, layered images, image index resolution, and a different trust model — none of which we want in the trust boundary.
2. **Reproducibility.** Nix-built rootfs images are byte-reproducible given the same flake inputs (gated in CI). OCI images resolve through a registry, can be re-tagged, and don't carry the same guarantees by construction.
3. **Trust boundary minimalism.** Pulling from an OCI registry adds an external network dependency to the boot path. The microVM path is offline-by-default once the rootfs is built.
4. **Runtime path consistency.** The bridge between our `.ext4` rootfs files and libkrun's `.disk()` builder (a sibling `.raw` hard-link with explicit `fstype("ext4")`) keeps the disk path entirely host-local. No registry, no auth, no pull cache.

## Consequences

### Positive

- Single fewer hop on macOS (`host → libkrun → guest`) — faster boot, cleaner UX.
- microvm.nix gives multi-hypervisor portability for free.
- Builder pipeline runs on every host class.
- Reduced surface: no more Lima-specific code paths.

### Negative

- Adds a third-party dep (microvm.nix) to the build trust boundary — pinned by hash and CI-audited (`xtask audit-flake`).
- Some Linux-specific guarantees (dm-verity at boot, seccomp tier "strict") only hold on the Firecracker path. The libkrun path uses image-hash-on-load + HMAC chain instead. Documented in the per-backend tier matrix in [ADR-002](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/002-microvm-security-posture.md).

### Fallback (named explicitly)

If a microvm.nix per-bump audit (`xtask audit-flake`) surfaces a security regression we can't accept, fall back to the previous iteration's hand-rolled NixOS modules. The fallback is a **named, ready-to-execute escape hatch**, not just a sentence in this document. Cost: ~5K LOC of NixOS-module maintenance returns to our scope. Benefit: smaller trust boundary.

## Alternatives considered

- **Keep Lima as a fallback** — rejected. Maintains a code path that doesn't get exercised in the pivot's primary use case. Either Lima is good enough to be the macOS path (it isn't, per UX measurements) or it's dead code.
- **Cloud Hypervisor as primary** — rejected for now. CH is heavier than Firecracker and lacks the existing security work; revisit when GPU passthrough (VFIO) is needed (covered in ADR-030 in the spec tree).
- **Hand-rolled Nix flake (no microvm.nix)** — rejected. The previous iteration's hand-rolled flake was ~5000 LOC of NixOS module work; microvm.nix replaces most of that and is actively maintained.

## Threat model impact

- **microvm.nix** as a third-party dep widens the supply-chain surface. Mitigated by hash-pinning in `flake.lock`, CI re-audit on every bump, and reproducibility double-build.
- **libkrun** is itself a third-party dep. Same mitigation.
- The per-backend tier matrix from ADR-002 is updated: Firecracker tier remains "strict"; libkrun tier is "standard" until parity work lands (post-Phase 6).

## Related

- [Plan 60: mvm-libkrun migration](https://github.com/tinylabscom/mvm/blob/main/specs/plans/60-mvm-libkrun-migration.md) — full implementation roadmap
- [ADR-002: microVM security posture](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/002-microvm-security-posture.md) — per-backend tier matrix
- [ADR-014: VmBackend single trait](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/014-vmbackend-single-trait.md) — the trait surface libkrun implements
- [ADR-031: Cross-platform strategy](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/031-cross-platform-strategy.md) — Linux native, macOS native, Windows Tauri-only
