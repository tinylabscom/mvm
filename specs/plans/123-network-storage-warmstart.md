# Plan 123 — `NetworkProvider` + `StorageProvider` + warm-start

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the remaining trait seams — `NetworkProvider` (provisioning + ingress/egress default-deny + DNS + audit, with the egress proxy 129 hangs on), `StorageProvider` (host-owned local/encrypted/content-addressed/snapshot volumes, consuming 122's crypto), and `MountProvider` (pluggable mount sources — host/volume/tmpfs built-in, S3/Hetzner/NFS as feature-gated external impls) — and the warm-start substrate, honestly per-backend: full live-memory fast-resume on Firecracker, save/restore on Vz (macOS 26+), disk-snapshot only on libkrun. Creates the 17th crate, `mvm-network`.

**Architecture:** Three subsystems behind traits, per ADR-066 §1–2 and ADR-064. `mvm-network` (new) owns `NetworkProvider`; `mvm-storage` (kept) owns `StorageProvider` and calls 122's `mvm_core::crypto` for the encrypted impl; warm-start extends the `VmBackend` capability the trait already models (`backend.rs` has `pause`/`resume` + a capability flag, with `pause_resume_unsupported_on_{libkrun,apple_container,microvm_nix}` tests today). The pieces exist in scattered form (`mvm-backend/network.rs`, the firewall/proxy in the old `mvm-supervisor` → `mvm-hostd`, `instance_snapshot.rs`'s Firecracker `vmstate.bin`/`mem.bin` store); this plan consolidates them behind the seams and fills the gaps.

**Tech Stack:** Rust (`mvm-network`, `mvm-storage`, `mvm-backend`), gvproxy/passt (egress), `instance_snapshot` (FC snapshot store), Virtualization.framework `saveMachineState` (Vz), `userfaultfd`/NBD/hugepages (Linux fast-resume), `mvm_core::crypto` (122). No new third-party crates beyond a Linux `userfaultfd` binding (gated; evaluate vs raw `libc` ioctls under the dep budget).

**Prereqs:** 121 (creates `mvm-network`, the `mvm-hostd` homes), 122 (the crypto engine for the encrypted `StorageProvider`). **Enables 129 D–E** — Phase A builds the egress proxy with the substitution + leak-scan seams 129 needs.

**Scope note:** this is three independent subsystems (A/B/C). It is written as one plan per the brief, but the phase boundaries are clean splits if you'd rather execute it as 123a/b/c.

**Execution order (chosen 2026-06-04): B → A → C.** Phase B first — cleanest continuation of plan 122 (which handed the encrypted-volume impl here), additive, no gated lanes needed. Then Phase A (`mvm-network` — unblocks plan 129). Phase C (warm-start) is **scheduled last, not dropped**: highest risk, needs the gated live-KVM + macOS-26 lanes *and* a `PostRestore` sender that does not exist yet (see below). Run as `123b` / `123a` / `123c` worktrees.

## Path reconciliation (post-121)

Plan 121 consolidated 32→15 crates *after* this plan was written, so several paths below are stale. Real current locations (verified 2026-06-04):

| Plan 123 reference | Real current path |
|---|---|
| `crates/mvm-ir/src/workload.rs` (`MountSource`, `NetworkMode`) | `crates/mvm-sdk/src/ir/workload.rs` — `MountSource` :418, `NetworkMode` :489 |
| firewall/proxy in "old `mvm-supervisor`" | `crates/mvm-hostd/src/supervisor/{firewall,proxy,l7_proxy,network}.rs` |
| `mvm-backend/src/network.rs` | unchanged: `crates/mvm-backend/src/network.rs` |
| egress proxy lib | `crates/mvm-build/src/egress_proxy/` (+ the builder-VM bin) |
| `instance_snapshot.rs` (one file) | spread: `crates/mvm-backend/src/base/snapshot_integrity.rs` + `mvm_core::crypto::snapshot_*` |
| `VmBackend` pause/resume capability flag | `VmCapabilities` (bool `pause_resume`/`snapshots`) in `crates/mvm-core/src/protocol/vm_backend.rs` — **no snapshot-capability enum yet**; C1 adds it |

**Phase A — build on, don't reinvent.** Plan 141 already shipped the in-line packet-observer pipeline that A2/A3 want: `crates/mvm-hostd/src/supervisor/network/{mod,packet,pipeline}.rs` (`Observer::on_packet` → `Verdict`, etherparse parse + checksum-correct rebuild, wired into `gateway_bridge.rs`). Default-deny substrate already exists: `FirewallEnforcer::install_default_deny` + `L4Policy::deny_all()`.

**Phase B — layering (confirmed 2026-06-04).** `mvm-storage` is deliberately mvm-side-minimal — its own module doc cites *plan 45 §D5, Path C*: it ships only the data-plane `VolumeBackend` + `LocalBackend`; `EncryptedBackend<B>` and `ObjectStoreBackend` live in **mvmd**. Plan 123's `StorageProvider` (provision/attach/detach/snapshot) and `MountProvider` (mount-source resolution) are **new host-side layers that sit beside** those, and do **not** re-home the mvmd backends. The `encrypted` `StorageProvider` arm (B2) wraps the *host's* volume bytes via `mvm_core::crypto::{aead,volume}` (122) — distinct from mvmd's data-plane `EncryptedBackend<B>`. The B4 S3 `MountProvider` (read-only sync-to-cache) is likewise a mount-source resolver, not the mvmd `ObjectStoreBackend`.

**Phase C — the `PostRestore` sender gap.** The guest handles `GuestRequest::PostRestore`, but **nothing on the host sends it today** (the same gap that deferred plan 122's VMGenID-token *delivery*). C2's VMGenID-rotate-and-reseed-on-resume depends on that sender being built first — track it as a C prerequisite, not an afterthought.

---

## Phase A — `NetworkProvider` (new crate `mvm-network`)

### Task A1: create `mvm-network` + the trait

ADR-064 generalized to provisioning. One seam an external consumer (mvmd) and the backends extend.

**Files:** `crates/mvm-network/{Cargo.toml,src/lib.rs,src/provider.rs}`; root `Cargo.toml` (the 17th member). Move `mvm-backend/src/network.rs` + the firewall/proxy modules (from the old `mvm-supervisor`, now `mvm-hostd`) into `mvm-network` behind the trait.

- [ ] **Step 1:** Author `mvm-network` and the trait:
  ```rust
  // Provisioning + policy + DNS + audit for one VM's network. Impls: gvproxy
  // (macOS default), passt (Linux default), TAP/bridge. Selection is per-OS
  // (MVM_NETWORKING) — the provider hides it from callers.
  pub trait NetworkProvider {
      fn provision(&self, vm: &VmId, spec: &NetworkSpec) -> Result<NetHandle>;
      fn policy(&self) -> &EgressPolicy;       // default-deny (claim 10)
      fn teardown(&self, h: NetHandle) -> Result<()>;
  }
  ```
- [ ] **Step 2:** Move the existing provisioning (`mvm-backend/network.rs`, the bridge/TAP/gvproxy/passt wiring) into `mvm-network` behind `provision`/`teardown`; re-point callers. Workspace builds.
- [ ] **Step 3:** Commit.

### Task A2: default-deny ingress **and** egress

Claim 10 is egress default-deny today; ADR-066 §"NetworkProvider owns … both ingress and egress" extends it.

- [ ] **Step 1:** Failing tests — `EgressPolicy::default()` denies all; an unresolved policy denies (`policy_default_is_deny_all` style); ingress mirrors it. Keep the `MVM_ACK_UNRESTRICTED_NETWORK` escape + warning (never in CI).
- [ ] **Step 2:** Implement the resolve + enforce (DNS allow-list + L4 filter in the gvproxy/passt bridge — the in-line wrap, not a native API; see `reference_gvproxy_passt_no_native_flow_api`). Tests green. Commit.

### Task A3: the egress proxy with the 129 seams

129 D–E attach here. Build the proxy so substitution and leak-scan are first-class stages, even though 129 fills them.

- [ ] **Step 1:** Failing test — the proxy exposes a `substitution_stage` hook (a request passes through unchanged when no secret binding applies) and a `scan_stage` hook (a byte pattern is observed + can drop). Both no-op by default; 129 supplies the real handlers.
- [ ] **Step 2:** Implement the in-line splice point (in-process, etherparse-level — the wrap, not a gateway API) with the two ordered stages. Bound buffering (fixed window, not full-body). Commit.

### Task A4: DNS + flow audit

- [ ] **Step 1:** Failing tests — DNS queries are logged + policy-checked (a denied host's lookup is sink-holed + audited); flow events emit to the shared audit log. Commit after green.

### Task A5: pluggable network modes (`NetworkMode::Custom`) — the WireGuard/Tailscale seam

The IR `NetworkMode` is a closed enum (`None`/`Bridge`/`Host`) — a mesh/VPN mode can't be expressed without a core edit. Same fix as `MountSource::External`: add an open `Custom { provider, config }` + a `NetworkProvider`-registry lookup. **WireGuard/Tailscale themselves are mvmd's** (the control-plane mesh); this plan only exports the *seam* so mvmd registers a `WireGuardNetworkProvider`, expresses it in the IR, and the guest's `netinit` (124) consumes the config delivered on the config-device (124 E1). mvm builds none of the mesh logic.

**Files:** `crates/mvm-ir/src/workload.rs` (`NetworkMode` ~line 489); `crates/mvm-network` (the registry).

- [ ] **Step 1:** Failing test — `NetworkMode::Custom { provider: "wireguard", config }` round-trips; an unregistered provider errors `UnknownNetworkProvider`; the built-in `None`/`Bridge`/`Host` still resolve.
- [ ] **Step 2:** Add the open variant + the registry lookup (built-ins stay); `netinit` reads a `Custom` config from the config-device. mvmd's WireGuard/Tailscale impl is a separate mvmd plan. Commit.

## Phase B — `StorageProvider` (`mvm-storage`)

### Task B1: the trait + `local` impl

**Files:** `crates/mvm-storage/src/provider.rs` (new — trait + `LocalStorage`; kept separate from `local.rs`, which is the data-plane `LocalBackend`).

- [x] **Step 1:** Failing test — `LocalStorage` provisions a volume, attaches it (returns a path/handle), round-trips bytes, detaches. (`provider::tests::local_storage_provision_attach_roundtrip_detach`)
- [x] **Step 2:** Defined sync `trait StorageProvider { kind; provision; attach; detach }` + `VolumeSpec`/`VolumeHandle`/`AttachedVolume`; implemented `LocalStorage`. `snapshot()` deferred to B3 (grow the trait when its test lands — TDD). Committed `584e2be7`.

### Task B2: the `encrypted` impl (consumes 122)

ADR-066 §5 — the encrypted volume impl lives here and calls 122's engine. Platform split: LUKS2 (Linux), per-file AEAD (macOS, 122 Task A2).

- [x] **Step 1 (macOS arm):** test — a detached `EncryptedStorage` volume is ciphertext at rest (plaintext marker gone), re-attach shows plaintext, a flipped tag byte fails open. (`encrypted::tests::{encrypted_volume_is_ciphertext_at_rest_and_roundtrips, tampered_ciphertext_fails_to_open}`)
- [x] **Step 2 (macOS arm):** `EncryptedStorage` (`crates/mvm-storage/src/encrypted.rs`, `#[cfg(not(target_os = "linux"))]`) seals on detach / opens on attach via `mvm_core::crypto::volume::{seal_dir,open_dir}` (122). It's the non-Linux arm, gated like the engine it wraps; selection by `target_os`. The per-volume DEK→content-hash+plan+audit-head binding (`WrappedKey.bound`, 122 B2) is verified at the **admit gate before unlock**, not re-checked here.
- [ ] **Step 2 (Linux LUKS2 arm) — DEFERRED (see follow-ups):** block-level LUKS2 over a loop device. Un-buildable + un-verifiable on a macOS dev host (needs Linux + root + loop devices; `cargo zigbuild`/zig 0.16 can't even compile the crate here). Land on Linux CI per the `mvm_core::rotate_luks_slot` precedent (direct `cryptsetup`, `MVM_LIVE_LUKS=1`-gated).

### Task B3: content-addressed + snapshot-upper volumes

- [x] **Step 1:** `ContentAddressedStore` (`content_addressed.rs`) dedups identical content by SHA-256 digest (one on-disk object, atomic put); `SnapshotUpper` (`snapshot.rs`) is COW over a read-only base — writes land in the upper, the base stays immutable, and `..`/absolute paths are rejected via `VolumePath` (claim-1 no-escape). Tests: `content_addressed_dedups_identical_content_by_digest`, `snapshot_upper_writes_only_delta_over_readonly_base`, `snapshot_upper_rejects_path_traversal`. (Storage half of the Phase C diff-snapshot; on Linux the production overlay is overlayfs/dm — same COW semantics.)

### Task B4: `MountProvider` — pluggable mount sources

The IR `MountSource` is a closed enum (`Volume`/`HostPath`/`Tmpfs`) — a new source means a core-enum edit. Add the seam so external sources (S3, Hetzner Volume, NFS) are "implement + register," and the cloud-SDK deps stay off the default build (dep budget). Lives in `mvm-storage` (no new crate).

**Files:** `crates/mvm-storage/src/mount_provider.rs` (new); `crates/mvm-sdk/src/ir/workload.rs:418` (the `MountSource` enum — post-121 home, not `mvm-ir`).

- [x] **Step 1:** `MountRegistry` resolves `HostPath` → `Mountable::HostPath` and `Volume` → an attached `StorageProvider` host path; an unknown `External { provider: "s3" }` returns `MountError::UnknownFsProvider` (no silent default). Tests `registry_resolves_host_path`, `registry_resolves_volume_via_storage_provider`, `registry_rejects_unknown_external_provider`. (Note: with `LocalStorage` a volume is a directory → `HostPath`; the `BlockDev` arm lands with the LUKS block provider.)
- [x] **Step 2:** Defined `MountProvider` trait + `Mountable {HostPath, Tmpfs}` + hand-written `MountError` (no thiserror dep) + `MountRegistry`; built-ins `HostPathFs`, `VolumeFs` (delegates to `StorageProvider`), `TmpfsFs`. `Mountable::{BlockDev,Fuse}` are declared only when their producers exist (LUKS arm / lazy-FUSE S3) — avoids dead-variant warnings. Original sketch:
  ```rust
  // Resolves a mount's *source* into something VmBackend can attach. The share
  // mechanism (virtiofs / virtio-blk) stays VmBackend's job; this is only "where
  // do the bytes come from". External sources register here without a core edit.
  pub enum Mountable { HostPath(PathBuf), BlockDev(PathBuf), Fuse(FuseHandle) }
  pub trait MountProvider: Send + Sync {
      fn kind(&self) -> &str;                          // "host_path" | "volume" | "s3" | "hetzner_volume" | ...
      fn resolve(&self, src: &MountSource) -> Result<Mountable>;
      fn release(&self, m: Mountable) -> Result<()>;
  }
  ```
  Built-ins: `HostPathFs`, `VolumeFs` (delegates to `StorageProvider`), `TmpfsFs`. VmBackend attaches the `Mountable` (virtiofs for a path, virtio-blk for a device).
- [x] **Step 3:** Added the open `External { provider: String, config: serde_json::Value }` variant to the IR `MountSource` (`mvm-sdk`, internally-tagged, `deny_unknown_fields`); the variant broke no `match` anywhere (only the IR file references it). `mount_source_external_roundtrips_json` covers serde; the registry test covers unknown-provider rejection.
- [ ] **Step 4: Build a real S3 `MountProvider`** (the one external impl), feature-gated `s3` via the lean `object_store` crate — **not `aws-sdk-s3`** (the official AWS SDK pulls the `aws-config`/`aws-smithy-*` closure + `aws-lc-rs`, the C crypto dep the budget rejects). Pin `object_store`'s TLS to the **`ring`** provider (rustls 0.23+ defaults to `aws-lc-rs` — don't reinforce it; ADR-066 drives `aws-lc-rs`→`ring`). `resolve` reads bucket + prefix from `MountSource::External { provider: "s3", config }`, syncs the prefix **read-only** to a local cache volume (reuse `StorageProvider`), and returns it as the `Mountable`. Failing test against `object_store`'s in-memory backend (no network): a seeded object lands in the mounted cache path; and `s3` off → `object_store` absent from the default `cargo tree`. Read-write / lazy-FUSE S3 + a Hetzner-Volume impl are follow-ups — the registry makes them drop-in. **One S3 client for the whole repo:** 126 replaces the existing optional `opendal` (`crates/mvm/Cargo.toml`, template-registry-s3, ~70 crates) with this same `object_store`, dropping opendal. Commit.

## Phase C — warm-start (per-backend capability matrix)

The honest matrix from the capability check. `VmBackend` already carries a pause/resume capability flag; extend it to snapshot/restore with the same per-backend disposition.

### Task C1: extend the `VmBackend` snapshot capability

- [ ] **Step 1:** Failing test — `backend.snapshot_capability()` returns `LiveMemory` for Firecracker, `SaveRestore` for Vz (macOS 26+), `DiskOnly` for libkrun, `Unsupported` for microvm_nix — mirroring the existing `pause_resume_*` tests. No path silently degrades; an unsupported request returns a typed error (ADR-053).
- [ ] **Step 2:** Add the capability enum + per-backend disposition next to the existing pause/resume flag. Commit.

### Task C2: Firecracker fast-resume substrate (Linux)

ADR-066 §7 — the ~1s resume recipe. Builds on `instance_snapshot.rs` (`vmstate.bin`/`mem.bin`/`PostRestore`).

- [ ] **Step 1:** Failing test (live-KVM gated) — a snapshot + restore round-trips: the guest resumes, vsock re-auths via `PostRestore`, and **the VMGenID rotates + the guest CSPRNG reseeds** (122 Phase D — composes here).
- [ ] **Step 2:** Wire: diff/layered snapshots (one read-only golden base + a COW per-VM delta — Phase B3's snapshot-upper), a `userfaultfd` page-fault handler streaming from a content-addressed memfile, an NBD-served rootfs, 2 MB hugepages. Evaluate `userfaultfd` crate vs raw `libc` ioctls (dep budget). Snapshot artifacts are content-addressed + signed (122 Phase C). Commit per sub-piece.
- [ ] **Step 3:** SIGUSR1 ready-barrier — a workload signals "primed"; the host snapshots at that point for a deterministic warm base. Test the barrier. Commit.

### Task C3: Vz save/restore (macOS 26+)

The wireable macOS live-memory path. Coarser than UFFD (a full save/restore), but real live-memory.

- [ ] **Step 1:** Failing test (macOS 26+ gated) — `saveMachineState`/`restoreMachineState` round-trips a Vz VM; VMGenID rotates + guest reseeds on restore.
- [ ] **Step 2:** Wire `VZVirtualMachine.saveMachineState(to:)`/`restoreMachineState(from:)` (the apple_container/Vz backend, currently `pause_resume_unsupported`); flip the capability to `SaveRestore`. Commit.

### Task C4: libkrun disk-only fallback + `doctor`

- [ ] **Step 1:** libkrun has no memory snapshot — warm-start is a fast re-boot from the overlay/rootfs disk snapshot (Phase B3). Implement that path; the capability stays `DiskOnly`; a request for live-memory returns the typed unsupported error with the recovery hint.
- [ ] **Step 2:** `doctor` reports the per-backend warm-start capability + probes the Linux substrate (NBD module loaded, HugeTLB reservation). Failing test on the doctor lines. Commit.

## Acceptance

- [ ] `mvm-network` exists (17th crate); `NetworkProvider` provisions gvproxy/passt/TAP behind the trait; ingress **and** egress default-deny; DNS + flow audit; the egress proxy carries the substitution + leak-scan seams (no-op until 129).
- [ ] `StorageProvider` with `local` + `encrypted` (122-backed, both platforms) + content-addressed + snapshot-upper impls; encrypted on-disk bytes are ciphertext, guest sees plaintext.
- [ ] `MountProvider` resolves host/volume/tmpfs mounts; the IR's open `MountSource::External` + a **real feature-gated S3 impl** (`object_store`, read-only sync-to-cache) prove external sources plug in without a core edit; `s3` off → no `object_store` in the default tree.
- [ ] Warm-start is a per-backend capability: **Firecracker** live-memory fast-resume (UFFD/NBD/hugepages, ~1s, VMGenID-reseeded), **Vz** save/restore (macOS 26+), **libkrun** disk-only — each surfaced by `doctor`, none silently degrading.
- [ ] `cargo test --workspace` (host tiers) + the gated live-KVM/macOS lanes + clippy + fmt green.

### deferred follow-ups

- [ ] **B2 Linux LUKS2 arm** — block-level `EncryptedStorage` (`cryptsetup luksFormat`/`luksOpen` + `mkfs`/`mount` over a loop device), gated `#[cfg(target_os = "linux")]`, with an `MVM_LIVE_LUKS=1`-gated live test. Deferred from B2: a macOS dev host can neither build nor verify it (no Linux/root/loop devices; local cross-tooling can't compile the crate). Do it on Linux. While there, dedup the cryptsetup shell-out with `mvm/src/security/encryption.rs` (the `run_in_vm` builder-VM path) and `mvm_core::rotate_luks_slot` (the direct-`Command` runtime path).
- [ ] Cloud-Hypervisor snapshot parity (if CH stays a backend).
- [ ] Soften the gap-analysis "live-memory resume" line to the per-backend matrix (Firecracker + Vz live-memory; libkrun disk-only).
- [ ] The diff-snapshot fast-resume on Vz (UFFD-equivalent) — VZ's save/restore is coarse; a faster macOS path is its own investigation.

## Self-review

- **Spec coverage (brief 123):** NetworkProvider provisioning + ingress/egress default-deny + DNS + audit (Phase A); StorageProvider local/encrypted/content-addressed/snapshot (Phase B); UFFD/NBD/hugepages fast-resume + SIGUSR1 ready-barrier + doctor probes (Phase C); named-profile matrices ride the trait dispositions (the capability enums). The 129 egress-proxy seam is A3.
- **Honesty:** warm-start is a capability matrix, not a blanket "live-memory" — libkrun is disk-only and says so; the gap-analysis overclaim is flagged for softening. VMGenID reseed (122 D) is wired into both live-memory paths, not assumed.
- **Deps:** only a possible gated `userfaultfd` binding, explicitly weighed against raw `libc` per the dep budget.
- **Voice:** comments mark the non-obvious (why the proxy buffers a bounded window, why an unsupported snapshot errors instead of degrading, the per-OS provider selection), not the calls.
