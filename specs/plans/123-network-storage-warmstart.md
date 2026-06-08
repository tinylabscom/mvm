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

> **Status (2026-06-05):** the **claims-gated lift is landed**, witness-by-witness, `xtask check-claim-catalog` green throughout — A1/L1 `BridgeTapNetworkProvider` (#626), A2 `EgressEnforcer` trait + `SupervisorEgressEnforcer` wired into `Supervisor::launch` + both teardown sites (#632/#633/#635), A3 the Plan 129 `SubstitutionStage`/`ScanStage` seam wired into `run_packet_pipeline` + threaded from `ObserverWiring` (#637/#639/#642), A4 `DnsSinkholeScan` egress sink-hole (#643), L3 slice A libkrun `LibkrunNetworkProvider` (#644). Plus A1 step 1 + A5 (IR `NetworkMode::Custom` + registry) from the original additive seam. **What remains is decisions/infra, not lift:** L3 slice B (re-point the two live libkrun selection sites — the workload site ignores `MVM_NETWORKING` while the builder honors it, so it's not a faithful no-op refactor), L2 `microvm_nix` (egress policy isn't in `VmStartConfig` — a product call), and the per-tenant enforce wiring (`NetworkPolicy→FlowPolicy` for the libkrun gateway-bridge, which is `AllowAll` today; `DnsSinkholeScan` per-tenant). See the deferred follow-ups.

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
  - [x] **Step 1 done:** `NetworkProvider` (kind/provision/policy/teardown) + `NetworkSpec`/`NetHandle`/`NetworkError` in `crates/mvm-network/src/provider.rs`. `policy()` returns `mvm_core`'s `NetworkPolicy` (reused, not a new `EgressPolicy`). The crate is the 17th workspace member.
- [x] **Step 2 (Firecracker path):** `BridgeTapNetworkProvider` (`crates/mvm-backend/src/network_provider.rs`) implements `NetworkProvider` over `bridge_ensure`/`tap_create`/`apply_network_policy`, **transactional** (drops the TAP if the policy apply fails, matching the old `TapGuard`) + symmetric best-effort `teardown`. Re-pointed the two Firecracker start sites (`microvm.rs` flake-start + restore) and the teardown site through the seam — behaviour-identical by construction (`VmSlot::new(name, index)` reproduces the exact slot). **Seam refinement (this branch):** `NetworkSpec.policy` is now `mvm_core::network_policy::NetworkPolicy` (the iptables type the provisioning actually enforces; `Default` = `deny_all()`, claim 10), with `slot_index` added — the supervisor's L4 bundle is a *separate* concern (A2). The mvm-backend test binary is codesign-SIGKILL'd on macOS, so the runtime path rides CI/E2E; the change is a faithful refactor.
- [x] **Step 2 (libkrun path — L3 slice A, #644):** `LibkrunNetworkProvider` (`crates/mvm-build/src/libkrun_network_provider.rs`, `builder-vm`-gated next to its selection logic) impls `NetworkProvider` for the gvproxy/passt path. Unlike L1 it owns **no host resource** — the gateway child + sockets live inside the supervisor process — so `provision` is a pure gateway *selection* (`resolve_networking_mode` → `"gvproxy"`/`"passt"` tag) and `teardown` is a no-op; `egress_enforcer()` is `None` (libkrun's chokepoint is the gateway-bridge `FlowPolicy`, not a separate object). Lives in mvm-build (Vz-free) so its 3 tests run locally. **Slice B deferred** — re-pointing the two live selection sites diverges (workload `cfg!(macos)` ignores `MVM_NETWORKING`, builder honors it), so it's not a faithful refactor; see follow-ups. The mvm-hostd firewall/L4/L7 lift landed as A2/A3/A4 below.
- [x] **Step 3:** Committed `4af31a45`.

### Task A2: default-deny ingress **and** egress

Claim 10 is egress default-deny today; ADR-066 §"NetworkProvider owns … both ingress and egress" extends it.

- [x] **Step 1:** `network_spec_default_policy_is_deny_all` asserts `NetworkSpec::default().policy` is the empty (deny-all) `NetworkPolicy` — the seam's default fails closed (claim 10). (No new `EgressPolicy` type; reuses the existing claim-10 policy.)
- [x] **Step 2 (enforce behind the trait — A2.1–A2.3, #632/#633/#635):** the `EgressEnforcer` trait (`crates/mvm-network/src/enforcement.rs`: `EgressWiring` + `EnforcementError` + `enforce`/`withdraw` over `network_policy::NetworkPolicy`) + a mvm-hostd `SupervisorEgressEnforcer` (`supervisor/firewall/seam.rs`) adapting the existing `FirewallEnforcer`. `Supervisor::launch` installs default-deny and both teardown sites withdraw **through the trait** — the first live-path change, behaviour-identical (the adapter delegates to `install_default_deny`). The claim-10 catalog witnesses test the policy *default*, not the enforcement location, so the relocation kept `xtask check-claim-catalog` green. **Follow-up:** the per-VM `NetworkPolicy→FlowPolicy` mapping for libkrun (the gateway-bridge is pinned to `AllowAll` today) + the DNS allow-list resolve + the `MVM_ACK_UNRESTRICTED_NETWORK` escape.

### Task A3: the egress proxy with the 129 seams

129 D–E attach here. Build the proxy so substitution and leak-scan are first-class stages, even though 129 fills them.

- [x] **Step 1 (the seam — A3.1, #637):** `crates/mvm-hostd/src/supervisor/network/stages.rs` — `SubstitutionStage` (`substitute → Option<Vec<u8>>`) + `ScanStage` (`scan → ScanOutcome`) traits + no-op `NoopSubstitution`/`NoopScan`. Designed to run *inside* `run_packet_pipeline` (the live claim-10 chokepoint every guest byte transits via `gateway_bridge.rs`), **not** the L7 inspector chain (off the default byte path = bypassable).
- [x] **Step 2 (wired live — A3.2/A3.3, #639/#642):** `run_packet_pipeline` runs the two stages on egress before the observer loop (scan `Drop` → `PacketDecision::Kill`; substitute `Some` → `rebuild_with_payload`), threaded from `ObserverWiring.substitution`/`scan` (default no-op) at all 4 gateway-bridge call sites. **Plan 129 now plugs in by setting two fields — no pipeline or call-site edit.** No live behaviour change (default stays no-op); the existing bridge tests run with the defaults and stay green.

### Task A4: DNS + flow audit

- [x] **Step 1 (DNS sink-hole — A4, #643):** `DnsSinkholeScan` (a `ScanStage` in `network/stages.rs`) inspects outbound UDP/53 queries, parses the question qname (dep-free; refuses compression pointers), and drops any lookup outside the tenant allow-list (dotted-suffix match — `corp.internal` admits `db.corp.internal`, never `evilcorp.internal`) — sink-holed at the gateway-bridge chokepoint, so the kill lands on the chain-signed flow audit. Non-DNS passes (least privilege); malformed DNS fails open (a parse failure must not silently drop). The **flow-audit half was already shipped by Plan 141** (`signer_task` chain-signs `gateway.flow_*` entries). **Follow-ups:** wire `ObserverWiring.scan = DnsSinkholeScan` per-tenant; synthesized NXDOMAIN answer; DNS-specific audit reason carrying the qname.

### Task A5: pluggable network modes (`NetworkMode::Custom`) — the WireGuard/Tailscale seam

The IR `NetworkMode` is a closed enum (`None`/`Bridge`/`Host`) — a mesh/VPN mode can't be expressed without a core edit. Same fix as `MountSource::External`: add an open `Custom { provider, config }` + a `NetworkProvider`-registry lookup. **WireGuard/Tailscale themselves are mvmd's** (the control-plane mesh); this plan only exports the *seam* so mvmd registers a `WireGuardNetworkProvider`, expresses it in the IR, and the guest's `netinit` (124) consumes the config delivered on the config-device (124 E1). mvm builds none of the mesh logic.

**Files:** `crates/mvm-sdk/src/ir/workload.rs:489` (`NetworkMode` — post-121 home, not `mvm-ir`); `crates/mvm-network/src/registry.rs`.

- [x] **Step 1:** `network_mode_custom_roundtrips_json` (serde), `registry_resolves_builtin_and_custom_modes`, `registry_rejects_unregistered_custom_provider` (→ `NetworkError::UnknownProvider`). Built-in `None`/`Bridge`/`Host` resolve by kind.
- [x] **Step 2:** Added the open `Custom { provider, config }` variant (dropping `Copy`/`Eq`; one match in `deploy.rs` fixed) + `NetworkProviderRegistry`. The guest `netinit` reading a `Custom` config off the config-device is plan 124's (E1); mvmd's WireGuard/Tailscale impl is a separate mvmd plan. Committed `4af31a45`.

### The lift — remaining increments (sequenced, researched 2026-06-05)

**Invariant for every increment below:** claim-10 stays *default-deny-unless-admitted* (never default-open, never silently un-filtered); claims 12/13 (broker/secrets) untouched; every path goes through the `mvm_network::NetworkProvider` trait, not direct calls.

- [x] **L1 — Firecracker bridge+TAP through the seam (done, PR #626).** `BridgeTapNetworkProvider` (`mvm-backend/src/network_provider.rs`) wraps `bridge_ensure`/`tap_create`/`apply_network_policy`, transactional like the old `TapGuard`; both `microvm.rs` start sites + teardown re-pointed. `NetworkSpec.policy` is the iptables `network_policy::NetworkPolicy` (`Default`=`deny_all()`), + `slot_index`.

- [ ] **L2 — microvm_nix (qemu) — RESEARCHED, BLOCKED ON A DESIGN/PRODUCT CALL.** `microvm_nix.rs:204-205` does `bridge_ensure`+`tap_create` with **no `apply_network_policy`** → that backend applies **zero egress filtering**. *Not* a quick re-point: the egress policy lives only in Firecracker's internal `FlakeRunConfig.network_policy` (`microvm.rs:581`) — it is **not** in the backend-agnostic `VmStartConfig`, and `MicrovmNixConfig` has no policy field. So there is no policy source to enforce. **Do NOT bulldoze `deny_all()`** onto it — with no admit/opt-in path that denies *all* egress (breaks legit workloads), which is not claim-10 (default-deny-*unless-admitted*). Two real options: **(a)** plumb `network_policy` into `VmStartConfig` so *every* backend enforces claim-10 uniformly (correct, but cross-cutting — touches the agnostic config + all backends + the `VmStartConfig` builders), or **(b)** document microvm_nix as a non-untrusted-workload backend (Tier-2 QEMU; CLAUDE.md is "Firecracker-only on Linux") so no enforcement is required. Needs a call on microvm_nix's role before code. **Verdict: L2 is not the clean first win it looked like — defer behind L3/A2.**

- [ ] **L3 — libkrun gvproxy/passt — NEEDS A SECOND SEAM SHAPE.** libkrun's networking is declared *on the krun context* (`krun.with_gvproxy`/`with_passt`, `libkrun.rs:108`) and **the supervisor spawns the gateway** (`libkrun.rs:104-105`) — it is *not* a host-side side-effecting step like bridge/TAP. So the provider can't fit the side-effecting `provision()` shape as-is. Approach: the libkrun `NetworkProvider` **produces the gateway config** (mode + mac + scratch) that the libkrun start path feeds to `with_gvproxy`/`with_passt`, keeping the claim-10 **gateway-audit bridge (no-bypass)** intact — *not* a host-state mutation. Highest backend-coverage value (default macOS path) and **locally verifiable** (libkrun boots on this Mac → `examples/agent_ping`).

- [ ] **L4 — claims-gated mvm-hostd relocation (A2 → A3 → A4) — the strategic core, Linux-CI per move.**
  - **A2:** firewall (`mvm-hostd/.../firewall/install_default_deny`) + L4 (`proxy/l4.rs`, `L4Policy::deny_all`) + L7 enforce path behind the seam, with the `MVM_ACK_UNRESTRICTED_NETWORK` escape (claim 10).
  - **A3:** egress proxy with the 129 `substitution_stage` + `scan_stage` hooks (no-op default) on Plan 141's shipped packet-observer pipeline — **this unblocks Plan 129** (the lift's stated purpose).
  - **A4:** DNS sink-hole + flow audit to the chain-signed log.
  - Each move carries its claim-10/12/13 witness; validate per move on Linux CI so `xtask check-claim-catalog` never goes red.

**Recommended order (revised after L2 research):** L1 done → **L3 (libkrun, locally verifiable)** and **A2→A3 (claims-gated core, unblocks 129)** are the two real tracks; L2 is deferred behind a product call on microvm_nix.

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
- [x] **Step 4:** `S3MountProvider` (`s3.rs`, feature `s3`) over the lean `object_store` (`aws` feature) — **not `aws-sdk-s3`**. Verified the dep tree: `s3` off → no `object_store` in `cargo tree`; `s3` on → TLS is **`ring`**, no `aws-lc-rs` (object_store's reqwest closure already resolves to ring here — no extra pinning needed). `resolve` reads `prefix` from `MountSource::External { provider: "s3", config }`, syncs it **read-only** into a per-prefix cache dir, returns `Mountable::HostPath`. Test `s3_provider_syncs_prefix_to_cache_dir` runs against `object_store`'s `InMemory` (no network): the seeded in-prefix object lands in the cache, an out-of-prefix object does not. `from_s3_config` builds the real `AmazonS3` (network leg) — compile-checked under `--features s3`. **Not done here (deferred):** the opendal→object_store consolidation is plan 126's; live-bucket validation + the resolve-from-async-context offload are follow-ups below.

## Phase C — warm-start (per-backend capability matrix)

The honest matrix from the capability check. `VmBackend` already carries a pause/resume capability flag; extend it to snapshot/restore with the same per-backend disposition.

> **Status (2026-06-05, branch `feat/plan-123c-warmstart`):** **C1 (the capability enum + per-backend disposition) is landed.** C2–C4 are **deferred**: they need gated lanes this dev host can't run (live-KVM for Firecracker UFFD/NBD, macOS-26 for Vz save/restore) **and a host `PostRestore` sender that doesn't exist yet** (the same gap that deferred plan 122's VMGenID-token delivery — C2's reseed-on-resume depends on it). C1 is the additive scaffolding the rest hangs off.

### Task C1: extend the `VmBackend` snapshot capability

- [x] **Step 1:** Tests in `backend.rs` (mirroring `pause_resume_unsupported_*`): `snapshot_capability_{live_memory_on_firecracker,disk_only_on_libkrun,unsupported_on_microvm_nix,vz_tracks_macos_support}` + a runnable `mvm-core` `snapshot_capability_defaults_to_unsupported`. (mvm-backend test binary is SIGKILL'd by macОS codesign — compiled here, run on Linux CI.)
- [x] **Step 2:** Added `SnapshotCapability {LiveMemory,SaveRestore,DiskOnly,Unsupported}` + a `VmBackend::snapshot_capability()` trait method (default `Unsupported` — fail-closed) in `mvm-core/src/protocol/vm_backend.rs`, dispatched by `AnyBackend`. Per-backend: FC `LiveMemory`, Vz `SaveRestore`(macos-gated)/`Unsupported`, libkrun `DiskOnly`, mock `LiveMemory`, rest default `Unsupported`. The typed-error-on-over-request (ADR-053) lands with the snapshot RPC (C2/C3 — not wired yet).

### Task C2: Firecracker fast-resume substrate (Linux)

ADR-066 §7 — the ~1s resume recipe. Builds on `instance_snapshot.rs` (`vmstate.bin`/`mem.bin`/`PostRestore`).

- [ ] **Step 1:** Failing test (live-KVM gated) — a snapshot + restore round-trips: the guest resumes, vsock re-auths via `PostRestore`, and **the VMGenID rotates + the guest CSPRNG reseeds** (122 Phase D — composes here). 122 D shipped the *substrate* (`vmgenid::fresh_generation_token` host mint; `mvm_guest::genid::GenIdReseeder` guest reseed); the piece to build here is the **delivery** — send `GuestRequest::PostRestore` carrying the `GenerationToken` and call `GenIdReseeder::on_genid` in the guest handler (no host `PostRestore` sender exists today). Entropy-source note: 122 D stirs `/dev/urandom`; 140 gap #2 may swap that for virtio-rng + `RNDADDENTROPY` — `GenIdReseeder` isolates the reseed source from the change-detection, so either composes.
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

- [x] `mvm-network` exists (17th crate); `NetworkProvider` provisions **TAP (L1) + gvproxy/passt (L3-A)** behind the trait; egress default-deny is **enforced behind the `EgressEnforcer` trait (A2)**; **DNS sink-hole (A4) + flow audit (Plan 141)**; the egress proxy carries the substitution + leak-scan seams (A3, no-op until 129). *Remaining wiring (follow-ups, not new machinery): the per-tenant `NetworkPolicy→FlowPolicy` mapping for libkrun — the gateway-bridge is `AllowAll` today — and L3 slice B's live re-point.*
- [x] `StorageProvider` with `local` + `encrypted` (122-backed; **macOS arm done**, Linux LUKS2 deferred) + content-addressed + snapshot-upper impls; encrypted on-disk bytes are ciphertext, guest sees plaintext.
- [x] `MountProvider` resolves host/volume/tmpfs mounts; the IR's open `MountSource::External` + a **real feature-gated S3 impl** (`object_store`, read-only sync-to-cache) prove external sources plug in without a core edit; `s3` off → no `object_store` in the default tree.
- [ ] Warm-start is a per-backend capability: **Firecracker** live-memory fast-resume (UFFD/NBD/hugepages, ~1s, VMGenID-reseeded), **Vz** save/restore (macOS 26+), **libkrun** disk-only — each surfaced by `doctor`, none silently degrading.
- [ ] `cargo test --workspace` (host tiers) + the gated live-KVM/macOS lanes + clippy + fmt green.

### deferred follow-ups

- [x] **Phase A claims-gated lift (A1/L1, A2, A3, A4, L3-A) — DONE** (#626/#632/#633/#635/#637/#639/#642/#643/#644). Each move carried its claim witness; `xtask check-claim-catalog` stayed green. What's left below is *not* lift — it's per-tenant wiring + two decisions:
  - [ ] **L3 slice B — re-point the two live libkrun selection sites through the provider.** They diverge: the workload site (`mvm_backend::libkrun::build_supervisor_config`, `libkrun.rs:107`) hardcodes `cfg!(target_os = "macos")` and **ignores `MVM_NETWORKING`**, while the builder site (`apply_networking_mode`) honors it via `resolve_networking_mode`. Re-pointing both is not a faithful no-op (it changes workload selection, with a macOS+passt footgun); reconcile the divergence first, then route both through the trait. Also revisit the `NetworkProvider`/`NetHandle` impedance — libkrun needs a config-production result (a `NetworkingPreference`/`KrunContext` mutation), not the stringly `tag` round-trip.
  - [ ] **A2/A4 per-tenant enforce wiring.** Map the per-VM `NetworkPolicy` onto the libkrun gateway-bridge `FlowPolicy` (the only host-side libkrun chokepoint, pinned `AllowAll` today — the sole live `FlowPolicy` impl), and set `ObserverWiring.scan = DnsSinkholeScan(allow_list)` per tenant. Plus the `MVM_ACK_UNRESTRICTED_NETWORK` escape on the resolve path.
  - [ ] **L2 `microvm_nix` egress policy — a product call.** The microVM start path (`VmStartConfig`) carries no egress policy field, so forcing `deny_all()` there would deny *all* egress (violates claim-10's default-deny-*unless-admitted*, not deny-everything). Threading an admitted policy through `VmStartConfig` is the decision to make before wiring this site.
- [x] **B4 S3 provider coverage — DONE, S3-free.** The provider's only S3-specific code is `from_s3_config` (build an `AmazonS3` from env); `AmazonS3Builder::build()` is offline and the wire behaviour is `object_store`'s own tested concern, so no live/minio bucket is needed. Added two tests (no S3/AWS/minio): `from_s3_config_rejects_missing_bucket` (the previously-untested input-validation leg, offline) and `syncs_nested_keys_from_a_real_on_disk_object_store` (drives the generic sync against `object_store::local::LocalFileSystem` — a real filesystem-backed store, not the `InMemory` HashMap — proving nested-key directory mirroring + prefix isolation). **Still deferred:** `resolve` owns a current-thread runtime and `block_on`s, so calling it from inside another tokio runtime (the mvm-backend async context) would panic — needs a `block_in_place`/offload path *when wired into the backend* (no caller yet, so untestable today).
- [ ] **B4 opendal → object_store consolidation** — plan 126 swaps the existing optional `opendal` (`crates/mvm/Cargo.toml`, `template-registry-s3`) for this same `object_store`, dropping opendal. Not done here (this plan only *adds* the first object_store consumer).
- [ ] **B2 Linux LUKS2 arm** — block-level `EncryptedStorage` (`cryptsetup luksFormat`/`luksOpen` + `mkfs`/`mount` over a loop device), gated `#[cfg(target_os = "linux")]`, with an `MVM_LIVE_LUKS=1`-gated live test. Deferred from B2: a macOS dev host can neither build nor verify it (no Linux/root/loop devices; local cross-tooling can't compile the crate). Do it on Linux. While there, dedup the cryptsetup shell-out with `mvm/src/security/encryption.rs` (the `run_in_vm` builder-VM path) and `mvm_core::rotate_luks_slot` (the direct-`Command` runtime path).
- [ ] Cloud-Hypervisor snapshot parity (if CH stays a backend).
- [ ] Soften the gap-analysis "live-memory resume" line to the per-backend matrix (Firecracker + Vz live-memory; libkrun disk-only).
- [ ] The diff-snapshot fast-resume on Vz (UFFD-equivalent) — VZ's save/restore is coarse; a faster macOS path is its own investigation.

## Self-review

- **Spec coverage (brief 123):** NetworkProvider provisioning + ingress/egress default-deny + DNS + audit (Phase A); StorageProvider local/encrypted/content-addressed/snapshot (Phase B); UFFD/NBD/hugepages fast-resume + SIGUSR1 ready-barrier + doctor probes (Phase C); named-profile matrices ride the trait dispositions (the capability enums). The 129 egress-proxy seam is A3.
- **Honesty:** warm-start is a capability matrix, not a blanket "live-memory" — libkrun is disk-only and says so; the gap-analysis overclaim is flagged for softening. VMGenID reseed (122 D) is wired into both live-memory paths, not assumed.
- **Deps:** only a possible gated `userfaultfd` binding, explicitly weighed against raw `libc` per the dep budget.
- **Voice:** comments mark the non-obvious (why the proxy buffers a bounded window, why an unsupported snapshot errors instead of degrading, the per-OS provider selection), not the calls.
