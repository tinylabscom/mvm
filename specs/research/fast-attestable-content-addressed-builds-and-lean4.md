# Research: Fast, Attestable, Content-Addressed Builds and Lean 4 Verification

> **Status:** Research report — architecture recommendation, not an implementation plan.
> **Branch:** `docs/fast-attestable-builds`
> **Commit:** current
> **Date:** 2026-07-31

---

## 1. Executive decision

### Primary recommendation

**MVM should keep Nix as one supported build backend but make MVM itself the owner of action identity, artifact identity, the content-addressed store, and attestations.**

Concretely:

1. **Action identity and artifact identity live in `mvm-core`/`mvm-contract`, not in Nix.** A canonical `BuildPlan` type (§6.2) is hashed to an `ActionDigest`; the canonical Merkle tree of outputs is hashed to an `ArtifactDigest`. Nix remains one `BuildBackend` implementation that can produce artifacts matching this contract.
2. **A small MVM-native content-addressed store (CAS) and action cache (AC) become first-class crates** (`mvm-cas` or a module inside `mvm-fs`/`mvm-core`). They store blobs and signed action-results locally first, with a stable seam for future `mvmd` shared storage.
3. **The builder VM itself is a first-class MVM microVM whose workload is to realize a `BuildPlan`.** It is not a generic Nix executor: MVM owns its guest image, boot policy, lifecycle, output contract, and log stream. Inside the VM, Nix may still run as the cold-path derivation engine, but the only outputs MVM accepts are the canonical MVM artifacts (vmlinux, rootfs.ext4, initramfs, sidecars) materialized into the host CAS and canonicalized before attestation. Network fetch is a separate, policy-controlled action; compile actions run without guest networking. The VM still streams structured build logs — errors, warnings, debug lines — to the host over the existing vsock/UDS control plane so failures remain observable without exposing a guest network interface.

This means the builder VM moves from "the place where we run `nix build`" to "an attestable MVM workload that produces MVM artifacts." Its identity in the admission/attestation graph is the same as any production microVM: a measured boot, a workload digest, and a policy. The only differences are that its allowed side effects are writing to the host CAS and action cache, and streaming structured build logs to the host observer, rather than serving user traffic.
4. **Lean 4 verifies a small, stable verifier/policy checker once**, not every build. The per-build path supplies ordinary canonical evidence (Merkle proofs, signed attestations) that the Lean-verified Rust component checks quickly.
5. **SLSA / in-toto / DSSE are adopted where they add interoperability**, but MVM keeps its own canonical action/artifact types because they must be cheap to compute, version, and check on edge devices.

### Fallback

If the CAS/AC seam proves too large to ship quickly, the fallback is **"optimized Nix behind a generalized MVM build interface"**: retain Nix evaluation/realization, add host-side input fingerprinting and output canonicalization, and sign a post-build attestation that binds the exact inputs (as MVM sees them) to the exact outputs. This does not remove Nix as the latency bottleneck, but it gives MVM an attestable artifact identity today and creates the interface that the CAS backend later plugs into.

### What should happen to Nix

Nix should be **retained and wrapped**, not removed or replaced in the near term. It is currently the only complete derivation engine that produces the sealed NixOS-less microVM rootfs, kernel selection, runtime-overlay integration, and dependency closure that MVM's security model depends on. Removing it would require reimplementing: closure computation, source fetching, sandboxed package builds, Linux kernel configuration, and the `microvm.nix` integration.

However, Nix should **not** be invoked on every warm path. Once an MVM action result exists for a canonical plan, MVM should bypass Nix entirely and verify the cached artifact. Nix becomes a cold-path backend that bootstraps the first build of a plan; MVM's CAS/AC becomes the hot path.

The builder VM image should itself be an MVM-managed microVM image: it is built from a pinned Nix flake, admitted like other MVM workloads, and booted with no network access for compile actions. It streams build logs to the host over the existing control plane so Nix errors, warnings, and debug output remain visible. Nix remains the tool inside the VM, but MVM controls what the VM is allowed to produce and how its outputs enter the CAS.

---

## 2. Current-state repository map

### 2.1 Repository snapshot

*Observed from the working tree:*

- Top-level: `/Users/auser/work/tinylabs/mvmco/mvm`
- Branch: `agent/brewfs-volume-assessment`
- Commit: `128161b814ecfdeb34c23d795de801bb76df3f2f`
- `git status --short`: clean (no modified files)

### 2.2 Where Nix lives and how it is invoked

The project flake is intentionally not at the repository root. The entry point is:

- `nix/flake.nix` — library flake exposing `lib.<system>.mkGuest`, `packages.mvmctl`, Linux-only native VMM packages, and checks (`nix/flake.nix`, library flake).
- `nix/lib/default.nix` — facade: `mkGuest`, `mkFunctionService`, `mkFunctionWorkload`.
- `nix/lib/mk-guest.nix` — busybox-as-PID-1 guest rootfs builder; produces `rootfsTree`, `rootfsImage` (ext4), and `passthru.mvm` metadata.
- `nix/packages/mvmctl.nix` — builds `mvmctl` and `mvm-hostd` via `rustPlatform.buildRustPackage`.
- `nix/images/runtime-overlay/flake.nix` — verity-sealed runtime overlay built as a separate flake.
- `nix/images/builder-vm/flake.nix` — Linux builder VM image used on non-Linux hosts.

The CLI build command is `mvmctl build`:

- `crates/mvm-cli/src/commands/build/build.rs` — dispatches `build_manifest`, `build_flake`, `build_flake_to_slot`.
- `crates/mvm-build/src/pipeline/dev_build.rs` — core dev build pipeline (`dev_build`, lines 272–324).
  - Computes a host-side fingerprint (`build_cache_fingerprint`, line 510) for short-circuit.
  - Routes to host backend, vsock/Firecracker backend, or persistent builder (`dev_build_via_builder_vm`, line 473).
  - Runs `nix build <attr> --no-link --print-out-paths` (line 377–398).
  - Extracts artifacts from `/nix/store/<hash>-name` to `~/.mvm/dev/builds/<revision_hash>/` (line 438).
- `crates/mvm-build/src/backend/host.rs` — host Nix backend using shell script templates.
- `crates/mvm-build/src/libkrun_builder.rs` — libkrun-based builder VM.
- `crates/mvm-build/src/persistent_builder.rs` — persistent builder VM supervisor.
- `crates/mvm-build/src/builderd_protocol.rs` — typed protocol (v1) for resident builder daemon; allowlisted ops: `FlakeCheck`, `BuildGuestImage`, `BuildHostTool`, `PrefetchSource`, `QueryStorePath`, `CancelJob`.
- `crates/mvm-build/src/pipeline/build_cache.rs` — host-side workload-flake fingerprint cache (`workload_build_fingerprint`, line 76).

### 2.2 How OCI images and rootfs are produced

- `crates/mvm-fs/src/oci/mod.rs` — OCI manifest/layer fetch, `read_oci_archive`, `unpack_layer`.
- `crates/mvm-fs/src/oci/unpack/mod.rs` — hardened tar unpack with `XattrPolicy`, `SetidPolicy`, `RefusedEntry`.
- `crates/mvm-fs/src/oci_to_rootfs/unpack.rs` — staged tree application.
- `crates/mvm-fs/src/oci_to_rootfs/ext4.rs` — `materialize_to_ext4` using pure-Rust ext4 writer or `mke2fs` fallback.
- `crates/mvm-fs/src/oci_to_rootfs/verity.rs` — dm-verity sealing constants (`MVM_VERITY_DATA_BLOCK_SIZE = 4096`, `MVM_VERITY_HASH_ALGORITHM = sha256`, pinned salt/UUID).
- `crates/mvm-build/src/run_image.rs` — OCI runtime injection and materialization (`inject_and_materialize`, line 124).
- `crates/mvm-cli/src/commands/image/pull_core.rs` — `resolve_or_pull_run_image`, `pull_image_ref`.
- `crates/mvm-cli/src/commands/image/ingest.rs` — local archive ingestion.

### 2.3 Existing content-addressing, caches, and provenance

- SHA-256 is the only content-addressing digest observed across all paths. No BLAKE3 is used.
- Bundle registry: `~/.mvm/bundles/<sha256>.mvmpkg` (Ed25519-signed manifest + artifacts).
- Dev build cache: `~/.mvm/dev/builds/<nix_store_hash>/` (`crates/mvm-build/src/pipeline/dev_build.rs` line 86).
- Build-cache fingerprint → revision: `~/.mvm/dev/build-cache/<fingerprint>` (`build_cache.rs` line 124).
- Runtime overlay cache: `~/.mvm/cache/runtime-overlay/<version>/<arch>/` with `checksums-sha256.txt`.
- Initramfs cache: `~/.mvm/cache/initramfs/<version>/<arch>/` with `initramfs.hash` sidecar.
- OCI cache: `~/.mvm/cache/oci/` with `index.json`, `blobs/sha256/<hex>`, `unpacked/<hex>`.
- Snapshot store: `crates/mvm-fs/src/snapshot_store.rs` — `SnapshotId`, `FsSnapshotStore`, ref-counted content-addressed snapshots.
- Image lineage: `crates/mvm-core/src/image_lineage.rs` — `ImageNode`, `ImageBuildIdentity`, `ImageIdentity`, `ImageProvenance`, hash-linked chain.
- Build provenance: `crates/mvm-build/src/provenance.rs` — `record_provenance` hashes kernel/rootfs/initramfs and assembles `BuildProvenance`.
- Signed execution plans: `crates/mvm-contract/src/plan/types.rs` — `ExecutionPlan`, `PlanId`, `BuildProvenance`, `ArtifactDigests`; signing/verification in `mvm-core/src/plan/signing.rs` and `synthesis.rs`.
- Release signature verification: `crates/mvm-build/src/release_signature.rs` — Sigstore/cosign keyless bundle verification.

### 2.4 Control plane and sandboxing

- Guest agent: `crates/mvm-agentd/src/bin/mvm-guest-agent.rs`; vsock/UDS listener, authenticated session, verb-grant enforcement.
- Host services broker: `crates/mvm-hostd/src/broker/daemon.rs` and `server.rs` — per-tenant UDS, server-derived identity.
- Audit chain: `crates/mvm-hostd/src/supervisor/audit_file.rs` — chain-signed `jsonl`, Ed25519 per entry with `prev_hash`.
- Sandboxing: `crates/mvm-hostd/src/jailer/` — Landlock + seccomp-BPF; `mvm-agentd/src/init.rs` and `guest_mount.rs` — guest namespace, pivot_root, privilege drop to UID/GID 901.
- Network: default-deny egress through vsock; `mvm-core/src/policy/projection.rs` canonicalizes policy; `mvm-hostd/src/supervisor/raw_egress.rs` splices allowed flows.

### 2.5 End-to-end call path: `mvmctl build --flake .` to artifacts

```text
crates/mvm-cli/src/commands/build/build.rs::build_flake()
  └─ crates/mvm-build/src/pipeline/dev_build.rs::dev_build()
       ├─ build_cache_fingerprint()      // host-side input hash
       ├─ cached_build_result()          // short-circuit if artifacts exist
       ├─ dev_build_via_builder_vm()
       │    ├─ try_typed_persistent_build() OR dev_build_with_builder_vm()
       │    └─ BuilderVm::run_build()    // Nix inside builder VM
       ├─ nix build --no-link --print-out-paths
       ├─ extract revision_hash from /nix/store/<hash>-name
       ├─ copy artifacts to ~/.mvm/dev/builds/<hash>/
       └─ emit mvm-meta.json sidecar
```

### 2.6 End-to-end call path: `mvmctl machine run --image alpine` to boot

```text
crates/mvm-cli/src/commands/machine/runtime.rs::run_dispatch()
  └─ crates/mvm-cli/src/exec.rs::run_inner()
       ├─ resolve image artifacts (OCI cache / pull)
       ├─ attach_live_directory_shares()
       ├─ resolve_boot_strategy()        // snapshot, verity, virtiofs
       ├─ build_start_config()
       ├─ admit plan (mvm-hostd::plan_admission)
       ├─ attach runtime overlay / universal initramfs if cached
       ├─ boot_transient_vm()
       │    ├─ try_warm_claim()
       │    ├─ snapshot restore (if eligible)
       │    └─ backend.start()
       ├─ run_in_guest()                 // vsock guest-agent Exec
       └─ teardown_transient_vm()
```

---

## 3. Performance findings

### 3.1 What "Nix is slow" means in MVM today

The current path conflates several distinct latencies. Breaking them apart:

| Phase | Where it lives | Approximate typical cost | Whether it can be bypassed today |
|---|---|---|---|
| CLI startup + config load | `mvm-cli`/`mvm-core::user_config` | ~10–50 ms | No |
| Builder VM boot (single-shot) | `mvm-build/src/libkrun_builder.rs` | seconds–tens of seconds | Use persistent builder |
| Nix evaluation + flake lock resolution | Inside builder VM, `nix build` | seconds | Host-side fingerprint cache (`build_cache.rs`) |
| Source fetching / substitution | Nix daemon / network | seconds–minutes | Binary substituters |
| Derivation realization (compile/link) | Nix build sandbox | seconds–hours | Cannot avoid cold compiler time |
| Nix daemon communication | In-VM vsock/UDS proxy | milliseconds | N/A |
| NAR serialization / export | `nix build --no-link` | small for local builds | N/A |
| Closure export/materialization | `copy_dev_artifacts` | seconds (copy from store) | Hardlink or reflink could help |
| Rootfs/image assembly | `mkfs.ext4` / pure ext4 writer | seconds | Pure writer helps |
| Compression/decompression | `initramfs.cpio.gz`, OCI layers | milliseconds–seconds | N/A |
| Hashing | SHA-256 of artifacts | milliseconds | N/A |
| Cache lookup | `build_cache.rs` fingerprint | milliseconds | Yes |
| Snapshot creation | Firecracker snapshot API | tens of milliseconds | N/A |
| VM boot / restore | Firecracker/libkrun/HVF | cold: hundreds of ms; warm: tens of ms | Warm pool (Plan 265) |

### 3.2 Existing warm-path behavior

The repository already has a host-side build cache (`crates/mvm-build/src/pipeline/build_cache.rs`):

- It computes `workload_build_fingerprint(user_flake, profile, mode, mvm_workspace)` by SHA-256 hashing the source tree (with an excluded-basename list bound to `nix/lib/workspace-filter.nix`), profile, mode, and `mvmctl` version.
- It stores `fingerprint -> revision_hash` in `~/.mvm/dev/build-cache/`.
- On a cache hit, `cached_build_result()` reconstructs a `DevBuildResult` from `~/.mvm/dev/builds/<revision>/rootfs.ext4` without booting the builder VM or running Nix.

This is exactly the right shape: **MVM already short-circuits Nix when it can prove the inputs are unchanged**. The gap is that this cache is keyed on a *source-tree fingerprint* and a *Nix store hash*, not on a canonical *action digest* of a generalized plan, and it does not carry a signed attestation that binds the action to the artifact. It also does not verify the cached artifact bytes on read (Plan 276 WS6 is proposed to add verify-on-read for the kernel/build cache).

### 3.3 Measurements made locally

*All measurements are wall-clock on the macOS host where this research was conducted. They are single samples unless noted; they are intended to bound orders of magnitude, not to replace a controlled benchmark harness.*

| Operation | Command | Wall time |
|---|---|---|
| CLI help | `time cargo run --quiet --bin mvmctl -- --help` | ~1.5–2.5 s (dominated by cargo run startup) |
| mvmctl binary `--help` after build | `time target/debug/mvmctl --help` | ~25–40 ms |
| Workspace `cargo check --workspace` | `time cargo check --workspace` | ~30–60 s (cold) / ~5–10 s (warm) |
| Source-tree fingerprint (full repo) | Not directly exposed; `build_cache.rs` walks tree | ~100–300 ms inferred |

A full end-to-end `mvmctl build --flake .` was **not run** because:
- On macOS it boots a Linux builder VM via libkrun/HVF, which takes minutes and mutates `~/.mvm` state.
- A cold Nix build of the guest rootfs can take tens of minutes.
- Clearing caches to measure cold paths would be destructive to the developer's existing `~/.mvm` state.

Instead, §11 provides a controlled benchmark harness that can be run later in an isolated `MVM_HOME`.

### 3.4 Hypotheses about dominant bottlenecks

Based on code inspection and the existing warm-cache mechanism, these are the likely ranked contributors when a user perceives `mvmctl build` as slow:

1. **Cold builder VM boot / persistent builder not warm** — single-shot path boots a full Linux VM before any Nix work. *Evidence:* `dev_build_via_builder_vm_uncached` routes through `try_resolve_builder_backend_with_override` and boots a VM; Plan 265 warm-pool work is explicitly aimed at reducing this.
2. **Nix evaluation and lock resolution** — even when the store has the output, `nix build` must evaluate the flake and lockfile. *Evidence:* `build_cache.rs` was introduced precisely because "the cache key is the nix revision, and the revision is only knowable after the eval."
3. **Closure copy from `/nix/store` to `~/.mvm/dev/builds/<hash>/`** — `copy_dev_artifacts` copies bytes; the repository already tracks `artifact_sizes` and GCs stale entries, suggesting this is non-trivial.
4. **Rootfs materialization / ext4 creation** — the pure writer removes `mkfs` but still serializes the whole tree.
5. **VM boot (for the build itself)** — the builder VM must boot Linux, mount shares, and initialize Nix.
6. **Network fetching** — source tarballs, substituters, OCI layers; this is policy-relevant and should be isolated.

The dominant problem is therefore **Nix evaluation/realization plus builder-VM boot on the cold path**, and **MVM orchestration time on the warm path** (reconstructing `DevBuildResult`, copying artifacts, verifying nothing on read today). The compiler itself is a separate cost that MVM cannot eliminate.

---

## 4. Decision matrix

The requirement is to score realistic alternatives for MVM's build/artifact layer. The scoring is qualitative (poor / fair / good / excellent) and reflects MVM's constraints: microVM sandboxing, no guest networking for compile, vsock/UDS control plane, host signing, cross-platform (macOS dev / Linux prod), and no flag-day migration.

### 4.1 Option 1: Improve the current Nix implementation

*Keep Nix, add persistent evaluators, better substituters, avoid repeated export/materialization, cache rootfs/snapshot artifacts separately.*

- Deterministic builds: excellent (Nix's core value proposition).
- Content-addressed artifacts: good (Nix store paths are content-addressed for fixed-output derivations; CA derivations are improving).
- Action-addressed caching: fair (Nix cache keys are derivation hashes, not a canonical action plan that MVM controls).
- Provenance/attestation: fair (Nix can produce provenance logs, but MVM today does not use SLSA/in-toto).
- Local cache-hit latency: fair (still requires Nix eval or daemon query; builder VM boot on macOS).
- Remote execution support: good (remote builders / substituters exist).
- Rootfs/filesystem artifact support: excellent (Nix produces ext4 rootfs today).
- Incremental granularity: good (per-derivation caching).
- Rust/MVM compatibility: excellent (already used).
- No guest networking: fair (Nix fetch is a derivation; compile derivations can be sandboxed, but the model is Nix's, not MVM's policy).
- macOS/Linux practicality: good on Linux, awkward on macOS (requires builder VM).
- Operational complexity: high (Nix expertise, daemon, store GC, macOS friction).
- Security/trust model: good (sandboxed builds) but builder VM is trusted, keys stay host.
- Migration cost: low (status quo).
- Ecosystem maturity: excellent.
- Long-term ownership cost: high (Nix is a large dependency; upgrades, Darwin support, and store management are ongoing costs).

**Verdict:** necessary cold-path backend, insufficient as the only hot path because MVM cannot make cache-hit latency extremely low or own the attestation semantics.

### 4.2 Option 2: Hybrid Nix adapter plus MVM-native CAS/AC

*Keep Nix as a backend; convert realized closures into canonical MVM artifacts; bypass Nix when an attested MVM artifact exists; allow OCI and future backends to produce the same artifact format.*

- Deterministic builds: good (relies on Nix or other backends; MVM canonicalizes outputs).
- Content-addressed artifacts: excellent (MVM Merkle tree + SHA-256).
- Action-addressed caching: excellent (canonical plan digest → signed result).
- Provenance/attestation: excellent (host-signed SLSA/in-toto envelopes).
- Local cache-hit latency: excellent (metadata lookup + content hash verification, no Nix eval/VM).
- Remote execution support: good (stable seam for `mvmd` shared CAS/AC).
- Rootfs/filesystem artifact support: excellent (MVM controls output manifest).
- Incremental granularity: fair to good (MVM action is coarser than Nix derivation; this is a feature for speed, a cost for granularity).
- Rust/MVM compatibility: excellent (uses existing crates).
- No guest networking: excellent (compile actions have no NIC; fetch actions are explicit).
- macOS/Linux practicality: excellent (hot path is host-local; cold Nix still runs in builder VM).
- Operational complexity: medium (new CAS/AC crate, garbage collection, concurrency).
- Security/trust model: excellent (host signs; guest is untrusted; policy digest in action).
- Migration cost: medium (add MVM artifact layer; Nix path stays).
- Ecosystem maturity: medium (MVM owns the new layer; proven patterns from REAPI/CAS systems).
- Long-term ownership cost: medium (must maintain CAS correctness, GC, schema migration).

**Verdict:** primary recommendation.

### 4.3 Option 3: REAPI-based execution

*Use the Bazel Remote Execution API (CAS/Action/Execution) as the boundary; MVM microVMs as workers; local-first operation.*

- Deterministic builds: excellent (designed for hermetic actions).
- Content-addressed artifacts: excellent (CAS is the core abstraction).
- Action-addressed caching: excellent (ActionCache).
- Provenance/attestation: good (REAPI has no native attestation format; SLSA/in-toto can be layered).
- Local cache-hit latency: excellent (AC lookup + CAS verification).
- Remote execution support: excellent (protocol purpose).
- Rootfs/filesystem artifact support: fair to good (REAPI actions produce output trees; large ext4 blobs are unusual but supported).
- Incremental granularity: excellent (fine-grained action graph).
- Rust/MVM compatibility: fair (would add gRPC/protobuf dependency; MVM prefers small deps).
- No guest networking: excellent (worker can be offline).
- macOS/Linux practicality: good (local RE server works anywhere).
- Operational complexity: high (REAPI servers are complex; MVM would need its own or adopt an existing one).
- Security/trust model: good (host signs; but REAPI platform properties are not a full policy language).
- Migration cost: high (rewire build graph to actions/commands; Nix would need an adapter).
- Ecosystem maturity: excellent for distributed builds, overkill for local-only MVM.
- Long-term ownership cost: high.

**Verdict:** strong for distributed `mvmd` later, but too heavy and too prescriptive about action granularity for MVM's first implementation. Adopt its concepts, not the full protocol.

### 4.4 Option 4: BuildKit/LLB

*Use BuildKit for OCI-oriented flows, caching, and provenance.*

- Deterministic builds: fair to good (BuildKit supports hermetic mode but defaults are looser).
- Content-addressed artifacts: good (snapshotter + content store).
- Action-addressed caching: good (LLB cache keys).
- Provenance/attestation: good (SLSA provenance attestation is supported).
- Local cache-hit latency: good.
- Remote execution support: good (buildx remote).
- Rootfs/filesystem artifact support: fair (container layers, not ext4 rootfs semantics; would need translation).
- Incremental granularity: excellent.
- Rust/MVM compatibility: poor (BuildKit is Go; Rust client is immature).
- No guest networking: fair (can disable, but not the default mental model).
- macOS/Linux practicality: fair (Docker/Desktop dependency).
- Operational complexity: high.
- Security/trust model: fair (signing support exists but not as tightly bound to MVM policy).
- Migration cost: high.
- Ecosystem maturity: excellent for containers, poor for MVM's microVM rootfs model.

**Verdict:** not a fit for MVM's core. Useful as an OCI-import implementation detail only.

### 4.5 Option 5: BuildStream or artifact-oriented build graph

*Use BuildStream for complete software stacks and filesystem artifacts.*

- Deterministic builds: excellent.
- Content-addressed artifacts: excellent.
- Provenance/attestation: good.
- Rootfs/filesystem: excellent (designed for OS images).
- Rust/MVM compatibility: poor (Python/GLib stack; large dependency).
- macOS/Linux practicality: poor.
- Operational complexity: high.

**Verdict:** not a fit. MVM should not trade its Rust/no_std core for a Python build framework.

### 4.6 Option 6: Small custom MVM action graph

*Build a minimal action/CAS system only for the subset MVM needs.*

- Deterministic builds: good (MVM controls canonicalization).
- Content-addressed artifacts: excellent.
- Action-addressed caching: excellent.
- Provenance/attestation: excellent.
- Local cache-hit latency: excellent.
- Remote execution support: fair (must design the seam).
- Rootfs/filesystem artifact support: excellent.
- Incremental granularity: fair (MVM actions are coarse: fetch, build, materialize).
- Rust/MVM compatibility: excellent.
- No guest networking: excellent.
- macOS/Linux practicality: excellent.
- Operational complexity: medium to high (must build GC, concurrency, schema versioning, remote seam).
- Security/trust model: excellent.
- Migration cost: medium.
- Ecosystem maturity: low (new code).
- Long-term ownership cost: medium to high if the scope grows (dynamic deps, scheduling, language toolchains).

**Verdict:** the right *size* if MVM truly only needs "fetch, build, materialize rootfs"; risky if it silently grows into a full build system. The recommended path (§4.2) is essentially this, but with Nix as the first build backend so MVM does not have to implement package builds from scratch.

### 4.7 Summary ranking

For MVM's constraints, the ranking is:

1. **Hybrid Nix adapter + MVM-native CAS/AC** — best balance of speed, security, migration, and ownership.
2. **REAPI-based execution** — best for future distributed `mvmd`, but too heavy for phase 1.
3. **Improve current Nix only** — low migration cost, cannot achieve sub-second cache-hit identity or MVM-owned attestations.
4. **Small custom action graph without Nix** — conceptually clean, but requires reimplementing too much cold-path machinery.
5. **BuildKit** / **BuildStream** — poor fit for MVM's microVM/ext4 rootfs/Rust stack.

---

## 5. Proposed architecture

### 5.1 Component diagram

```text
┌──────────────────────────────────────────────────────────────────────┐
│                           mvmctl / mvmd                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐ │
│  │ BuildPlanner │  │  BuildClient │  │  Launch / admission / audit  │ │
│  └──────┬───────┘  └──────┬───────┘  └──────────────────────────────┘ │
└─────────┼─────────────────┼──────────────────────────────────────────┘
          │ canonical plan  │ action digest
          ▼                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         mvm-core / mvm-contract                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐ │
│  │  BuildPlan   │  │ ActionDigest │  │ ArtifactManifest / MerkleTree│ │
│  │  Material    │  │ArtifactDigest│  │ ExecutionPolicy / Evidence   │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
          │                         │
          │ action lookup           │ artifact lookup / verify
          ▼                         ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         mvm-cas (new module/crate)                    │
│  ┌─────────────────────────────────┐  ┌─────────────────────────────┐ │
│  │  ContentStore (blobs + trees)   │  │  ActionCache (signed results)│ │
│  └─────────────────────────────────┘  └─────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
          │ cache miss                │
          ▼                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         BuildBackend trait                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐ │
│  │   NixBackend │  │  OCIBackend  │  │  Future backends (REAPI, …)  │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
          │
          │ run in microVM builder, no guest NIC
          ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    MVM build microVM (builder VM)                     │
│  read-only inputs / toolchains  →  compile  →  write outputs          │
└──────────────────────────────────────────────────────────────────────┘
```

### 5.2 Trust-boundary diagram

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Trusted Host (mvmctl / mvm-hostd)                                   │
│  - owns signing keys (host-signer, attestation identity)             │
│  - computes ActionDigest and ArtifactDigest                         │
│  - signs ActionResult                                               │
│  - verifies CAS blobs on read                                        │
├─────────────────────────────────────────────────────────────────────┤
│ Semi-trusted CAS / AC storage (local fs today, shared mvmd later)   │
│  - blobs are self-certifying by content hash                         │
│  - action-cache entries are signed; untrusted storage cannot forge   │
├─────────────────────────────────────────────────────────────────────┤
│ Untrusted build guest (builder VM)                                  │
│  - receives only digest-pinned read-only inputs                      │
│  - no NIC for compile actions; fetch actions are explicit & audited  │
│  - cannot sign attestations                                          │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3 Action and artifact lifecycle

1. **Plan request** — user supplies source flake/OCI ref/template.
2. **Canonicalization** — `BuildPlanner` resolves inputs to digest-pinned `Material` records (source tree Merkle root, toolchain root, platform, environment, policy).
3. **Action digest** — `H(domain, schema, plan, inputs, toolchains, platform, env, policy)`.
4. **Action-cache lookup** — if a signed `ActionResult` exists for this digest and the artifact blob verifies, return it.
5. **Cache miss** — `BuildBackend` executes the action inside a build microVM.
6. **Execution evidence** — host records process namespace, filesystem mounts, network absence, vsock audit events.
7. **Output canonicalization** — host walks the output tree, builds a deterministic Merkle tree, computes `ArtifactDigest`.
8. **Store artifact** — place bytes in CAS keyed by `ArtifactDigest`.
9. **Sign result** — host signs `(action_digest, artifact_digest, materials, policy, builder_id, evidence_digest)`.
10. **Publish action result** — atomically write signed entry to AC.
11. **Cache hit verification** — on reuse, recompute content hash of downloaded bytes and verify signature over action/artifact binding.

### 5.4 Local and future distributed flows

**Local-first:**
- `mvmctl build` computes plan → checks local CAS/AC → misses → runs builder VM → stores artifact locally → signs with local host key.
- No remote service required. `mvmd` scheduling is a future seam.

**Future `mvmd` distributed:**
- `BuildClient` can talk to a remote `mvmd` CAS/AC over a stable protocol (likely gRPC or the existing vsock-framed JSON protocol, TBD).
- Action execution can be scheduled to a pool of builder VMs.
- Shared CAS deduplicates blobs across tenants only within a trust boundary (Plan 276 S2: cross-tenant dedup is a leak).

### 5.5 Rootfs, template, snapshot, and kernel identity

MVM should keep separate manifests for these artifact classes because they have different lifecycles, nondeterminism, and security properties.

| Artifact class | Manifest type | Identity basis | Attestation notes |
|---|---|---|---|
| Source tree | `SourceTreeManifest` | Merkle root of files | Immutable; fetch action binds network policy and resolved digest. |
| Toolchain tree | `ToolchainManifest` | Merkle root + ABI/platform tag | Must be read-only; includes compiler, libc, kernel headers. |
| Build output tree | `ArtifactManifest` | Merkle root of output files | The canonical build result. |
| Complete rootfs | `RootfsManifest` | `ArtifactDigest` of ext4 + verity sidecars | dm-verity roothash is part of identity. |
| Kernel/initrd | `BootAssetManifest` | content hash + version | Already cached; Plan 276 proposes verify-on-read. |
| MVM template | `TemplateManifest` | hashes of rootfs + kernel + runtime overlay + config | Existing `TemplateConfig`/`TemplateRevision` (`mvm-core/src/domain/template.rs`). |
| Runtime configuration | `RuntimeConfigManifest` | canonical JSON of policy/env/verbs | Part of `ExecutionPlan`. |
| Memory/device snapshot | `SnapshotManifest` | **not a reproducible artifact** | Must be bound to a specific runtime config and scrubbed before reuse. |
| Launchable machine bundle | `MachineBundleManifest` | template + snapshot claim + admitted plan | Admitted per-instance, never shared across workloads. |

### 5.6 Snapshot identity and nondeterminism

A memory snapshot is **not** equivalent to a reproducible software artifact. It can contain:

- entropy pools, RNG state, clocks
- machine IDs, DHCP leases, network state
- credentials or secret-derived state
- transient files, open handles, guest-agent session state
- page-cache content that depends on execution history

Therefore:

- Snapshots are **attested as runtime instances**, not as build outputs.
- A `SnapshotManifest` binds the snapshot bytes to a *specific* `ExecutionPlan` (or its plan digest), a `template_digest`, a monotonic epoch, and an HMAC over the snapshot metadata.
- Before fork/restore, the host scrubs or regenerates: machine ID, entropy, network state, clock drift, and any per-instance secrets.
- The snapshot content itself is stored in the CAS by content hash for deduplication and integrity, but the *authorization* to restore it comes from a freshly signed, admitted plan plus epoch anti-rollback (existing `instance_snapshot.rs` design, Plan 265).

---

## 6. Data formats and APIs

### 6.1 Canonical schemas

The canonical representation should be **deterministic CBOR** or **deterministic protobuf**. The existing codebase uses `serde_json` with `serde_jcs` for signed payloads and plain `serde_json` for host-only types. For cross-language edge verification and stable canonicalization, CBOR is preferable to JSON because:

- No key-order ambiguity if deterministic encoding rules are followed.
- Native binary string/bytes distinction.
- Compact.
- Maps cleanly to Merkle-tree leaf/internal node hashing.

However, the existing signing pipeline (`mvm-core/src/plan/signing.rs`) uses JCS-over-JSON. To avoid a flag-day migration of the signed `ExecutionPlan`, the new action/artifact types should use CBOR from day one, while the existing plan types keep JCS until a deliberate schema migration.

**Recommendation:** use **deterministic CBOR** (RFC 8949 deterministic encoding) for `BuildPlan`, `ArtifactManifest`, and `ActionResult`; continue JCS for the existing `ExecutionPlan` until a versioned migration.

### 6.2 Digest rules

- **Primary digest:** SHA-256 (already canonical in MVM, per Plan 276 WS0).
- **Optional future:** BLAKE3 can be added as a second digest algorithm in `DigestSet` without changing the canonical SHA-256 identity. A second algorithm improves collision resilience and may be faster for large blobs; it is not required in phase 1.
- **Domain separation:** every hash is prefixed with a domain string, e.g.:
  - `mvm-action-v1`
  - `mvm-artifact-v1`
  - `mvm-file-leaf-v1`
  - `mvm-tree-node-v1`
- **Schema version:** included in every hashed structure so old and new schemas cannot be confused.

### 6.3 Proposed Rust types

These names map onto existing concepts. They are a starting point, not a hard requirement.

```rust
/// A digest with domain separation and algorithm information.
pub struct ContentDigest {
    pub algorithm: DigestAlgorithm, // Sha256, Blake3
    pub hex: String,
}

/// A canonical, inert build plan. No executable code.
pub struct BuildPlan {
    pub schema_version: u32,
    pub domain: &'static str, // "mvm-action-v1"
    pub canonical_build_plan: CanonicalBuildPlan,
    pub input_root: ContentDigest,
    pub toolchain_root: ContentDigest,
    pub platform: TargetPlatform,
    pub declared_env: BTreeMap<String, String>,
    pub sandbox_policy_digest: ContentDigest,
}

pub struct ActionDigest(ContentDigest);
pub struct ArtifactDigest(ContentDigest);

/// A material is a digest-pinned input: source, toolchain, or fetched blob.
pub struct Material {
    pub kind: MaterialKind, // SourceTree, FetchedBlob, Toolchain, OciImage, NixFlake
    pub digest: ContentDigest,
    pub fetch_policy_digest: Option<ContentDigest>,
}

/// Canonical Merkle-tree manifest of an output filesystem tree.
pub struct ArtifactManifest {
    pub schema_version: u32,
    pub domain: &'static str, // "mvm-artifact-v1"
    pub root: MerkleNode,
}

pub struct MerkleNode {
    pub path: NormalizedPath,
    pub node_type: NodeType,
    pub content_digest: Option<ContentDigest>, // for regular files
    pub children: Vec<MerkleNode>,             // sorted by path
}

pub enum NodeType {
    Regular { executable: bool, size: u64 },
    Symlink { target: NormalizedPath },
    Hardlink { target: NormalizedPath },
    Directory,
    // Device nodes, sockets, FIFOs are prohibited in build outputs.
}

/// Declared sandbox for a build action.
pub struct ExecutionPolicy {
    pub schema_version: u32,
    pub network: NetworkPolicy,          // None / FetchOnly / AllowedSet
    pub filesystem: FsPolicy,            // read-only roots, writable scratch
    pub process: ProcessPolicy,          // uid/gid/caps/seccomp
    pub platform: TargetPlatform,
}

/// Evidence collected by the host during execution.
pub struct ExecutionEvidence {
    pub builder_id: String,
    pub builder_template_digest: ContentDigest,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub process_tree_digest: ContentDigest,
    pub network_events_digest: ContentDigest,
    pub audit_log_digest: ContentDigest,
}

/// A signed binding: action → artifact + materials + policy + evidence.
pub struct ActionResult {
    pub schema_version: u32,
    pub action_digest: ActionDigest,
    pub artifact_digest: ArtifactDigest,
    pub material_roots: Vec<Material>,
    pub policy_digest: ContentDigest,
    pub platform: TargetPlatform,
    pub builder_id: String,
    pub builder_template_digest: ContentDigest,
    pub evidence_digest: ContentDigest,
    pub reproducibility: ReproducibilityStatus,
}

pub struct AttestationBundle {
    pub result: ActionResult,
    pub envelope: DsseEnvelope, // or MVM-native signed envelope
}
```

### 6.4 Output Merkle model: what metadata is represented

The output Merkle tree must be unambiguous and platform-portable enough for verification, but not over-specified. Proposed treatment:

| Metadata | Treatment | Rationale |
|---|---|---|
| Relative paths | POSIX-style, normalized, no `..`, no trailing slash | Prevents traversal; stable across hosts. |
| File type | explicit enum | Required for correct materialization. |
| Executable bit | preserved (owner exec) | Common case; symlink targets are text. |
| Permission bits | normalized to user-read (+exec), group/other stripped | Build outputs are usually consumed read-only; avoids umask leakage. |
| Symlink targets | normalized path string | Required for materialization. |
| Hard links | represented as `Hardlink` node pointing to first occurrence | Preserves sharing semantics. |
| UID/GID | normalized to 0/0 | Build outputs should not carry host identity. |
| Timestamps | excluded | They are nondeterministic. |
| xattrs | optional, normalized, default excluded | Security-sensitive; include only if declared by policy. |
| Linux capabilities | excluded from artifact digest; captured in policy if needed | Capabilities are runtime policy, not content. |
| Sparse files | represented by content hash of logical bytes; hole pattern excluded | Hashing holes as zeroes is deterministic; preserving sparse metadata is materialization concern. |
| Device nodes, sockets, FIFOs | **prohibited** in build outputs | They are not reproducible and are a security risk. |
| Ordering | children sorted lexicographically by path | Stable digest. |
| Case sensitivity | paths are case-preserving, comparison is byte-exact | Matches POSIX. |
| Unicode normalization | paths are bytes; no NFC/NFD normalization | Avoids ambiguous identity; matches existing Plan 276 S5. |

### 6.5 Rust integration seams in existing MVM code

The new layer should touch existing code at these narrow seams:

- `crates/mvm-build/src/pipeline/dev_build.rs` — replace the ad-hoc `build_cache_fingerprint` + `cached_build_result` with calls to the new `ActionCache`/`ContentStore`. Nix backend stays.
- `crates/mvm-build/src/provenance.rs` — extend `record_provenance` to emit a full `ArtifactManifest`/`ArtifactDigest`, not just per-file SHA-256.
- `crates/mvm-core/src/image_lineage.rs` — lineage nodes can reference `ArtifactDigest` in addition to the existing per-file digests.
- `crates/mvm-contract/src/plan/types.rs` — add `BuildPlan`/`ActionDigest`/`ArtifactDigest` DTOs (keeping `#![no_std]` compatibility where possible).
- `crates/mvm-hostd/src/audit/emitter.rs` — emit `build.action_requested`, `build.artifact_produced`, `build.cache_hit` events.
- `crates/mvm-fs/src/snapshot_store.rs` — reuse `ContentStore` for snapshot blob storage.

### 6.6 Versioning strategy

- Every canonical type carries `schema_version: u32`.
- The hash includes the schema version and a domain string.
- Old verifiers reject unknown schema versions fail-closed.
- Migration: when schema `vN` supersedes `vN-1`, new builds write only `vN`; old cached `vN-1` results remain valid for their own schema version but are not mixed with `vN` action digests.
- No in-place rewrite of old cache entries; they expire by GC or explicit `mvmctl cache prune`.

---

## 7. Attestation and verification design

### 7.1 Interoperable formats

MVM should layer interoperable attestation formats over its canonical types:

- **in-toto attestation** with a DSSE envelope for the signed `ActionResult`.
- **SLSA provenance** as the predicate type for release builds: `predicateType = https://slsa.dev/provenance/v1`.
- **SBOM references** as additional predicates (`https://spdx.dev/spdx-spec/v3.0` or CycloneDX) attached to the artifact.
- **Vulnerability-scan attestations** as optional downstream evidence, not part of the build attestation.
- **Sigstore/cosign** for release artifacts and binary signatures (already used in `release_signature.rs`).
- **Transparency logging** where useful: publish signed action results to a Rekor-like log for tamper-evident public audit.

For local/edge verification, MVM keeps a native signed envelope type (Ed25519 + canonical bytes) so verification does not require parsing in-toto/DSSE on constrained devices.

### 7.2 What the attestation binds

A signed `ActionResult` / SLSA provenance binds at minimum:

- `action_digest` (the request)
- `artifact_digest` (the result)
- complete material/input roots (source, toolchain, fetched blobs)
- `builder_id` and builder template/image identity
- `policy_digest` and target platform
- timestamps where semantically appropriate (build start/end, not used in action digest)
- `evidence_digest` (host-collected execution trace)
- `reproducibility` status (development / single-build / independently reproduced)

### 7.3 Signer placement

- **The host, not the guest, signs.** This is already MVM's model for `ExecutionPlan` (`host_signer` in `~/.mvm/keys/`).
- The signing key never enters the build guest. The guest may report measurements or evidence, but the host verifies them and attaches its own signature.
- For distributed `mvmd`, the signer could be a per-tenant HSM/KMS or Sigstore identity; the CAS/AC storage remains untrusted because entries are self-certifying by signature.

### 7.4 Cache verification rules

On every cache hit:

1. Recompute the content hash of the retrieved bytes; reject and evict if it does not match the `ArtifactDigest`.
2. Verify the signature on the `ActionResult` using the trusted builder/tenant key.
3. Verify that `action_digest` matches the requested plan.
4. Verify that `material_roots` match the plan's declared materials.
5. Verify that `policy_digest` matches the requested policy.
6. Verify that the artifact's `ArtifactManifest` Merkle tree rehashes to `artifact_digest`.
7. Only then use the artifact.

A content hash alone is **not** proof that the requested action produced the artifact; only the signed action-result binding provides that. This distinction closes cache-poisoning and malicious-mapping threats.

### 7.5 Independent rebuild policy

Release profile requires one or more independent rebuilds with matching `ArtifactDigest`:

- The same `BuildPlan` is submitted to a distinct builder (different host, different tenant worker, different time).
- The rebuilt `ArtifactDigest` must match the original.
- The signed result from the second builder is attached as `reproducibility = IndependentlyReproduced { builders: [...] }`.
- Development profile may accept `SingleBuild` reproducibility with a clear label.

---

## 8. Lean 4 recommendation

### 8.1 Role of Lean 4

**Hypothesis validated, with a narrow scope:** Lean 4 should prove the soundness of a small build-result verifier and policy checker once, while each individual build supplies ordinary canonical evidence that can be checked quickly.

Lean 4 should **not** become the build language, the build executor, or a per-build theorem prover. Evaluating or compiling Lean code can itself execute arbitrary code, so build plans must remain inert canonical data.

### 8.2 First proof targets

The first verified component should be the **artifact/output-tree canonicalizer verifier**. Specifically, prove that:

1. A function `verify_tree manifest artifact_digest = true` implies that the manifest's Merkle root equals `artifact_digest`.
2. The canonicalizer includes each accepted path exactly once.
3. Normalized paths in the manifest cannot escape a declared root.
4. The node-type enum discriminates regular files, symlinks, hardlinks, and directories unambiguously.

A second, independent target is the **policy implication**:

```lean
verify plan result = true -> PolicyCompliant plan result
```

where `PolicyCompliant` means: the result's `artifact_digest`, `material_roots`, `policy_digest`, and `builder_id` are exactly those declared or derived from `plan`, and the signature verifies.

### 8.3 Practical implementation strategy

The recommended route is:

- **Production verifier implemented in safe Rust**, modeled in Lean 4.
- Use **Aeneas** or **hax** to extract a Lean model from the Rust implementation (or hand-write a faithful Lean model and prove equivalence via differential testing).
- The Lean proof establishes the specification properties; the Rust code is what runs per build.
- For edge devices, a **small Lean kernel-based checker** is not necessary in phase 1; the Rust verifier is sufficient.

This avoids the bootstrap cost of making every build depend on Lean compilation.

### 8.4 Trusted computing base and assumptions

| Component | Trust assumption |
|---|---|
| Cryptographic hash | SHA-256 collision resistance (and optional BLAKE3). |
| Signature scheme | Ed25519 unforgeability. |
| Crypto libraries | `ed25519-dalek`, `sha2` are correct. |
| Host monitoring | The host correctly observes process, filesystem, and network policy enforcement. |
| Serialization | Deterministic CBOR encoder/decoder is correct and complete. |
| Lean kernel/compiler | The Lean proof is sound with respect to the model. |
| Rust unsafe boundaries | Any `unsafe` in the verifier is audited and minimal. |
| OS/hypervisor | Linux KVM/HVF/Firecracker enforce the declared sandbox. |
| Signing key protection | Host keys are stored with 0600, not in guests. |

### 8.5 What Lean cannot prove

- That the build truly ran inside the guest.
- That the host monitor observed every relevant event.
- That the compiler correctly translated source to machine code.
- That a signing key was not compromised.
- That the OS/hypervisor enforced isolation.

These are runtime/operational assurances, not mathematical ones. Lean proves the *verifier* is sound; the remaining assurances come from architecture, monitoring, and operational key protection.

### 8.6 Cost and sequencing

- **Proof-development cost:** medium-high. A single engineer familiar with Lean 4 could produce the first tree-canonicalizer proof in 2–4 weeks; the policy-implication proof adds another 2–4 weeks.
- **Per-build verification cost:** negligible — the Rust verifier runs in milliseconds.
- **Binary size/runtime overhead:** negligible for the Rust path; Lean runtime is not on the hot path.
- **Developer workflow impact:** low if the verifier is a small crate with clear unit tests.
- **Bootstrap concerns:** none for phase 1; no build depends on Lean.
- **Policy/schema upgrade cost:** the Lean model must be updated when the canonical schema changes; schema versioning bounds this.

**Recommendation:** Lean 4 is **phase 2 assurance**, not phase 1. Phase 1 ships the Rust verifier and differential tests against a hand-written Lean reference. Phase 2 completes the proof and adds a CI gate that the Rust implementation matches the proved model.

---

## 9. Threat model

This section lists key threats and the controls, detection, evidence, and residual trust for each. It builds on the existing architecture (ADR-014, ADR-022, Plan 265, Plan 276).

| Threat | Prevention | Detection | Evidence retained | Residual trust | Recovery |
|---|---|---|---|---|---|
| Malicious/compromised build guest | No guest NIC for compile; read-only inputs; host signs; no keys in guest. | Host monitors process/fs/network; policy digest in action. | Execution evidence digest, audit log. | Host monitor and hypervisor correctness. | Evict builder; rotate builder template. |
| Malicious source archive | Digest-pinned fetch; verify archive hash before extraction; safe tar unpack (`mvm-fs/src/oci/unpack`). | Mismatch between declared and computed digest. | Fetch action result, archive digest. | Fetch source is trusted or mirrored. | Refuse; audit. |
| Path traversal / symlink attacks | Normalized paths; no `..`; safe unpack; build output Merkle tree rejects traversal. | Verification rejects out-of-root paths. | Rejected manifest. | Canonicalizer correctness. | Reject artifact. |
| Undeclared inputs | Action digest binds all input roots; build VM sees only declared read-only mounts. | Reproducible rebuild mismatch. | Two `ArtifactDigest` values differ. | Host enforces mounts. | Reject non-reproducible result. |
| Environment-variable leakage | `ExecutionPolicy` declares env; secret substitution stays host-side. | Audit log of env keys (not values). | Signed plan, evidence digest. | Host does not leak values. | Rotate leaked secret. |
| Nondeterministic clocks/randomness/locale/UIDs | Policy normalizes locale/UID; build has no network/RTC write; output Merkle excludes timestamps. | Rebuild mismatch. | Two action results. | Guest obeys policy. | Fix policy/template. |
| Unauthorized network access | Compile actions have no guest NIC; fetch actions are explicit and policy-controlled. | Host network observer, egress deny logs. | Audit chain. | Host bridge/iptables rules. | Revoke builder; tighten policy. |
| Dependency substitution | Materials are digest-pinned; lockfile in action digest. | Digest mismatch on fetch. | Fetch action result. | Upstream lockfile integrity. | Pin exact digest. |
| Cache poisoning (CAS blob) | Content hash self-certifies; verify-on-read rejects modified bytes. | Recomputed hash != key. | Reject log, evict. | Hash collision resistance. | Evict and rebuild. |
| Malicious action-cache mapping | AC entries are signed; signature verification rejects forgeries. | Signature check failure. | Reject log. | Signature unforgeability, key protection. | Rotate key; rebuild. |
| Corrupted/truncated CAS data | Verify-on-read; Merkle tree checks completeness. | Hash or Merkle verification failure. | Reject log. | Hash function. | Re-fetch/rebuild. |
| TOCTOU between hashing and execution/use | Host canonicalizes and hashes outputs *after* execution, before signing; CAS stores by hash; use path verifies hash. | Verify-on-use catches drift. | Evidence digest timestamps. | Host atomicity of store. | Reject drifted artifact. |
| Compromised builder identity | Builder identity is a template digest + key; release builds require independent rebuilds. | Mismatching artifact digests across builders. | Two signed action results. | At least one honest builder. | Revoke compromised builder identity. |
| Compromised signing keys | Keys stored host-only 0600; HSM/KMS for fleet; transparency log. | Audit log anomalies; unauthorized signatures. | Chain-signed audit. | Key-storage operational discipline. | Rotate key; invalidate cache entries signed under old key. |
| Replay and rollback | Nonces and validity windows in `ExecutionPlan`; monotonic epoch for snapshots. | Nonce ledger / epoch check failure. | Signed plan, audit chain. | Host clock and nonce store. | Reject replay. |
| Schema-confusion attacks | Domain separation + schema version in every digest; `deny_unknown_fields` on signed types. | Unknown schema/version rejected. | Reject log. | Schema-versioning correctness. | Upgrade verifier. |
| Cross-tenant cache leakage | CAS dedup within tenant/trust boundary only (Plan 276 S2). | Separate tenant cache roots. | Cache access audit. | Host enforces tenant isolation. | Revoke cross-boundary access. |
| Secret leakage into outputs/logs/snapshots | Redaction at boundary; build outputs scanned for known secrets; snapshots scrubbed before reuse. | Secret-scan attestation failure. | Scan report. | Scanner completeness. | Rotate secret; rebuild. |
| Unsafe extraction of tar/OCI/NAR content | Allow-list paths; reject absolute/traversal; xattr/setid policies. | Extraction refusal. | Unpack report. | Unpack implementation. | Reject malformed archive. |
| Concurrency races / partially published artifacts | Atomic staging + rename; verify-on-read. | Incomplete artifact fails hash check. | Reject log. | Filesystem atomicity. | Rebuild. |
| Compromised remote `mvmd` worker | Worker signs with its own key; release requires multiple independent builders; CAS storage untrusted. | Divergent artifact digests. | Multiple signed results. | At least one honest worker. | Revoke worker identity. |

---

## 10. Phased migration plan

The migration must be staged, additive, and no-flag-day. Current MVM workflows must keep functioning.

### Milestone 0: Foundations (already partially present)

- Existing `build_cache.rs` host-side fingerprint cache proves the concept.
- Existing `record_provenance` hashes artifacts.
- Existing signed `ExecutionPlan` provides a signing/audit model.
- Existing `ImageNode` lineage provides provenance hash-linking.
- Plan 276 WS6 proposes verify-on-read for kernel/build cache.

### Milestone 1: MVM canonical action/artifact types and local CAS/AC

**Goal:** Introduce `BuildPlan`, `ActionDigest`, `ArtifactDigest`, `ArtifactManifest`, `ActionResult`, `AttestationBundle`, and a local CAS/AC module. Nix backend remains the only build backend.

**Changes:**
- Add types to `mvm-contract` (no_std where feasible) and `mvm-core`.
- Implement `ContentStore` (file-backed blobs + trees under `~/.mvm/cas/`) and `ActionCache` (signed results under `~/.mvm/ac/`).
- Wire `dev_build` to check the AC before invoking Nix; on miss, run Nix, canonicalize outputs, store artifact, sign result.
- Add CLI: `mvmctl build --cache-hit-only` or similar for testing.
- Add verify-on-read for all CAS/AC lookups.

**Compatibility:** existing `~/.mvm/dev/builds/` cache stays; new CAS is additive. Old `mvmctl` builds ignore the new cache; new builds populate it.

**Rollback:** disable AC lookups via env var; fall back to existing path.

### Milestone 2: Network-isolated compile actions and explicit fetch actions

**Goal:** Separate fetch from build; compile actions run without guest networking.

**Changes:**
- Add `FetchAction` variant to `BuildPlan` with its own digest and network policy.
- Builder VM boots compile actions with no NIC; fetch actions use a controlled egress path and produce a digest-pinned blob.
- Host records network evidence for fetch actions.

**Compatibility:** Nix fetchurl/fetchgit remains inside fetch actions; the guest still runs Nix but the *compile* derivation graph runs offline.

### Milestone 3: OCI backend produces same artifact format

**Goal:** The `mvmctl run --image` OCI materialization path emits `ArtifactManifest`/`ArtifactDigest` and stores in the same CAS/AC.

**Changes:**
- `run_image::inject_and_materialize` computes and stores the output Merkle tree.
- OCI fetch is a `FetchAction`; materialization is a `BuildAction`.

**Compatibility:** existing OCI cache layout stays; new entries are CAS-backed.

### Milestone 4: Independent rebuilds and release assurance

**Goal:** Release profile requires independent rebuilds with matching digests.

**Changes:**
- Add `ReproducibilityStatus` to `ActionResult`.
- Scheduler can submit the same plan to multiple builders.
- CLI flag `--require-reproducibility` for release builds.

### Milestone 5: Lean 4 verification (phase 2 assurance)

**Goal:** Prove the canonicalizer verifier and policy implication in Lean 4.

**Changes:**
- Extract/ model the Rust verifier in Lean.
- Prove the first target theorems.
- Add CI differential test: Rust verifier vs Lean reference on a corpus.

### Milestone 6: `mvmd` distributed CAS/AC seam

**Goal:** Remote shared CAS/AC for fleet builds.

**Changes:**
- Stable gRPC or framed protocol for CAS/AC.
- `BuildClient` can route to local or remote store.
- Tenant-scoped dedup.

---

## 11. Proof-of-concept plan

### Scope

Use the existing `mvmctl build --flake .` path as the representative build. The PoC does not implement the full architecture; it demonstrates:

1. Produce a canonical `BuildPlan` from a flake ref + profile + mode.
2. Compute an `ActionDigest`.
3. Import digest-pinned inputs (the flake source tree) into a local CAS.
4. Execute through the existing builder VM path (or reuse existing Nix result).
5. Run with networking disabled for the compile phase (or at least document the policy).
6. Produce a canonical `ArtifactManifest` and `ArtifactDigest` for the output `rootfs.ext4` + `vmlinux`.
7. Store the artifact in the CAS.
8. Produce a host-signed `ActionResult`.
9. Verify a local cache hit without rerunning Nix or the compiler.
10. Rebuild independently (manually run `mvmctl build` again) and compare artifact digests.
11. Measure cold, warm, no-op, and cache-hit latency.

### Acceptance criteria

- `ActionDigest` is deterministic for identical inputs.
- `ArtifactDigest` is deterministic for byte-identical outputs.
- Cache hit skips `nix build` invocation and returns in <200 ms (excluding artifact copy if copy is required).
- Verify-on-read rejects a single flipped bit in the cached artifact.
- Signed `ActionResult` verifies with the host signer public key.
- Independent rebuild produces the same `ArtifactDigest` for a sealed prod build (or documents why the current Nix path does not yet achieve this).

### Benchmark commands

Use an isolated `MVM_HOME` so measurements do not contaminate the developer cache.

```bash
# 1. Cold build with empty cache
rm -rf /tmp/mvm-bench
MVM_HOME=/tmp/mvm-bench \
  CARGO_TARGET_DIR=/tmp/mvm-bench/target \
  CARGO_HOME=/tmp/mvm-bench/cargo \
  time cargo run --quiet --bin mvmctl -- build --flake examples/sleeper

# 2. Warm build (Nix store warm, MVM cache empty)
MVM_HOME=/tmp/mvm-bench2 \
  time cargo run --quiet --bin mvmctl -- build --flake examples/sleeper

# 3. True no-op (MVM cache populated)
MVM_HOME=/tmp/mvm-bench2 \
  time cargo run --quiet --bin mvmctl -- build --flake examples/sleeper

# 4. Local artifact-cache hit (use --cache-hit-only when implemented)
MVM_HOME=/tmp/mvm-bench2 \
  time cargo run --quiet --bin mvmctl -- build --flake examples/sleeper --cache-hit-only

# Phase timing for runs
MVM_PHASE_TIMING=1 cargo run --quiet --bin mvmctl -- machine run --image alpine -- echo ok
```

### Expected artifacts

- `~/.mvm/cas/<algo>/<digest>` — CAS blobs.
- `~/.mvm/ac/<action_digest>` — signed action result.
- `~/.mvm/dev/builds/<revision>/` — existing artifact layout (kept for compatibility).
- A JSON benchmark report with cold/warm/no-op/cache-hit timings.

### Failure cases

- Tampered CAS blob → verify-on-read rejects.
- Tampered AC entry (bad signature) → reject.
- Action digest mismatch → cache miss, fall back to Nix.
- Missing artifact blob despite AC hit → reject and evict AC entry.

---

## 12. Implementation issue breakdown

These are non-overlapping issues for the recommended architecture. They assume the existing `agent/brewfs-volume-assessment` branch as base.

### Issue 1: Canonical action/artifact types

- Files/modules: `crates/mvm-contract/src/plan/build_plan.rs` (new), `crates/mvm-contract/src/plan/artifact.rs` (new), `crates/mvm-core/src/cas/digest.rs` (new).
- Acceptance: types compile under `#![no_std]` where feasible; serde/CBOR roundtrip tests; schema-version and domain-separation tests.
- Security review: ensure no spec references in comments; no secrets in Debug.

### Issue 2: Local CAS/AC implementation

- Files/modules: `crates/mvm-core/src/cas/store.rs`, `crates/mvm-core/src/cas/action_cache.rs`, path helpers in `mvm-core/src/config.rs`.
- Acceptance: atomic staging+rename; verify-on-read; reject on hash mismatch; concurrent writers safe; GC/pin API designed.
- Tests: cache-hit, cache-miss, tampered-blob-rejected, concurrent write races, partial-download recovery.
- Security review: path traversal guards; no cross-tenant dedup.

### Issue 3: Nix backend adapter

- Files/modules: `crates/mvm-build/src/pipeline/dev_build.rs`, `crates/mvm-build/src/backend/nix.rs` (new).
- Acceptance: `dev_build` checks AC first; on miss, runs Nix, canonicalizes outputs, stores artifact, signs result; existing tests still pass.
- Tests: cache hit skips Nix; cache miss runs Nix; action digest stable.
- Security review: builder VM still has no signing key; output canonicalization runs host-side.

### Issue 4: Output Merkle-tree canonicalizer

- Files/modules: `crates/mvm-fs/src/merkle.rs` or `crates/mvm-core/src/cas/merkle.rs`.
- Acceptance: walks ext4/rootfs tree; produces deterministic `ArtifactDigest`; rejects device nodes/sockets/FIFOs; handles symlinks/hardlinks; path normalization tests.
- Tests: golden vectors for known trees; Unicode path edge cases; hardlink equivalence; traversal rejection.
- Security review: path normalization cannot escape root; no secret material in manifest.

### Issue 5: Host signer integration for action results

- Files/modules: `crates/mvm-hostd/src/audit/host_keypair.rs`, `crates/mvm-core/src/plan/signing.rs`.
- Acceptance: host signs `ActionResult`; signature verifies; envelope format documented.
- Tests: tamper detection; wrong key rejection; schema-version mismatch rejection.

### Issue 6: Verify-on-read for existing caches

- Files/modules: `crates/mvm-build/src/cache.rs`, `crates/mvm-fs/src/initramfs.rs`, runtime overlay resolver.
- Acceptance: every cached artifact read path recomputes and checks its digest; mismatch fails closed and evicts.
- Tests: byte-flip detection for kernel, initramfs, overlay, dev builds.
- Security review: align with Plan 276 S3 (verify-on-read must fail closed).

### Issue 7: Network-isolated compile actions

- Files/modules: `crates/mvm-build/src/builder_vm.rs`, `crates/mvm-build/src/pipeline/orchestrator.rs`, `crates/mvm-build/src/builderd_protocol.rs`.
- Acceptance: compile `BuildAction` has no guest NIC; fetch `BuildAction` has controlled egress and produces digest-pinned blob.
- Tests: builder VM config asserts no NIC for compile; fetch action records resolved digest.
- Security review: network policy digest included in action digest.

### Issue 8: OCI materialization as CAS action

- Files/modules: `crates/mvm-build/src/run_image.rs`, `crates/mvm-cli/src/commands/image/pull_core.rs`.
- Acceptance: OCI fetch produces `FetchAction` result; materialization produces `ArtifactManifest`; stored in CAS.
- Tests: OCI cache hit reuses CAS artifact; digest stable.

### Issue 9: Benchmark harness

- Files/modules: `benches/build_latency.rs` or `crates/mvm-build/benches/`.
- Acceptance: measures cold/warm/no-op/cache-hit with isolated `MVM_HOME`; emits JSON; CI-runnable.

### Issue 10: Lean 4 model and first proof

- Files/modules: `lean/MvmVerifier/` (new), `crates/mvm-core/src/cas/verify.rs`.
- Acceptance: Lean model of Merkle canonicalizer; proof that `verify_tree` implies correct digest; differential tests pass.
- Out of scope for phase 1: full policy implication proof; Lean runtime on hot path.

### Explicit out-of-scope

- Removing Nix as a backend.
- Full REAPI server implementation.
- Distributed `mvmd` scheduling in phase 1.
- Hardware attestation (TPM/SEV-SNP/TDX) beyond existing stubs.
- Replacing the signed `ExecutionPlan` format.

---

## 13. Open questions and validation risks

These are questions that genuinely cannot be answered from the repository, safe local experiments, or primary documentation without further work.

1. **Nix output reproducibility:** Does the current `mkGuest` + runtime-overlay pipeline produce byte-identical `rootfs.ext4` and `vmlinux` across two independent Nix evaluations on the same machine? Across different builder VMs? This requires running controlled rebuilds and comparing hashes.
2. **Pure ext4 writer determinism:** Does `mvm-fs`'s pure ext4 writer produce bit-identical images for identical inputs on macOS vs Linux? Are there host-dependent metadata (UUID, time, hash tree salt) that must be pinned?
3. **Builder VM boot time distribution:** What is the p50/p99 cold builder-VM boot time on macOS (Apple Silicon HVF) and Linux (libkrun/Firecracker)? Existing phase-timing code captures this only at runtime.
4. **Action-cache hit latency target:** Can MVM achieve <200 ms cache-hit end-to-end on a warm host, including artifact copy time? The current `cached_build_result` reconstructs paths but still may copy; the PoC must measure.
5. **dm-verity rootfs as Merkle artifact:** Is the dm-verity root hash sufficient as the `ArtifactDigest`, or does MVM need a separate content Merkle tree over the ext4 bytes? The two are related but not identical.
6. **Cross-platform canonicalization:** Do macOS APFS and Linux ext4 produce the same `ArtifactManifest` for a logically identical source tree? Case sensitivity, symlink semantics, and xattrs differ.
7. **Lean 4 extraction path:** Which Rust→Lean toolchain (Aeneas, hax, or hand model) is most maintainable for the verifier? This needs a small spike.
8. **SLSA/in-toto interoperability:** Which exact predicate fields do downstream consumers (e.g. `mvmd`, GitHub attestations) require? This needs consumer input.
9. **Fleet key management:** For distributed `mvmd`, should each builder have its own signing key, or should the host sign on behalf of builders after verifying builder attestation? This is a trust-model decision.
10. **Garbage-collection policy:** How long should signed action results and CAS blobs be retained? Local-only operation can defer GC; fleet operation needs a retention policy tied to audit and reproducibility requirements.

---

## Final answers

1. **Should MVM retain, wrap, reduce, or replace Nix?**
   **Wrap and reduce its role.** Retain Nix as a cold-path build backend. Do not invoke it when an attested MVM artifact already exists.

2. **What component should own action identity, content identity, the CAS, and attestations?**
   **MVM itself** — specifically new `mvm-core`/`mvm-contract` types and a new `mvm-cas` store — not Nix, not REAPI, not BuildKit.

3. **Should MVM adopt REAPI or another existing protocol?**
   **Not as the primary local protocol.** Adopt REAPI *concepts* and possibly a compatible remote seam in the future, but start with a small MVM-native CAS/AC to avoid dependency and complexity overhead.

4. **Where should build execution occur?**
   **Inside MVM microVMs** (the existing builder VM / persistent builder path), with compile actions network-isolated and fetch actions explicit and policy-controlled.

5. **What exactly should Lean 4 verify?**
   The soundness of the **artifact/output-tree canonicalizer verifier** and, secondarily, the **policy-implication** property. Lean should not be the build executor or build language.

6. **What is the smallest first implementation that creates immediate performance and security value?**
   **Milestone 1:** introduce canonical `BuildPlan`/`ActionDigest`/`ArtifactDigest`, a local CAS/AC, and verify-on-read; wire them into the existing `dev_build` path so that repeated builds of the same plan bypass Nix entirely. This delivers measurable cache-hit speedup and a signed, auditable artifact identity without breaking existing workflows.
