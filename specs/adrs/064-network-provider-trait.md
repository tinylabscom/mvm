# ADR 064 - NetworkProvider trait — composable network audit substrate

**Status**: Proposed
**Date**: 2026-05-29
**Cross-refs**: ADR-002 (security posture, claim 1 / claim 5 / claim 10), ADR-041 (signed/audited ExecutionPlan, claim 8), ADR-055 (passt/gvproxy cross-platform backends), ADR-058 (claim 10 leg 2 / "bytes leaving the trust boundary"), ADR-059 (host services broker — vsock-only scope boundary), Plan 102 (gateway audit substrate impl), Plan 112 (W6.A Phase 3c producer activation, merged 2026-05-29).

## Context

Plan 102 W6.A landed the **substrate** for the gateway audit log: per-VM bridge over the userspace network gateway (libkrun in-process via `BridgeFds`; Vz via the Swift `makeBridgedGvproxyDevice` device), parser-on-`catch_unwind` fault containment, bounded flow table, chain-signed `FlowOpened` / `FlowClosed` entries via `FileAuditSigner`. Plan 112 (merged) activated the substrate on libkrun by widening `VmStartConfig` and lifting substrate resolution into the shared `crates/mvm-backend/src/audit_substrate.rs` module. Today's state:

- **libkrun**: substrate active end-to-end. Bridge thread parses packets, emits `FlowOpened` / `FlowClosed` chain entries directly to `FileAuditSigner`.
- **Vz**: Swift bridge writes NDJSON `FlowEventWire` entries to `events_ingest_socket_path`; the Rust-side drainer that binds the socket and emits to the chain does not exist yet — substrate is half-built. Plan 112's "Vz carve-out" deferred this.
- **Firecracker**: no substrate. Claim 10 leg 2 (per-flow chain entries) does not fire on Linux KVM. Adding it requires a new bridge wrapping `passt` (the Linux user-space gateway).

Three concerns converge that the current shape can't cleanly absorb:

1. **Programmable networking.** The team wants tenant-policy-controlled observers (audit emit, hostname filter, rate limiter, egress secret detection) layered on top of the bridge. Today's substrate has one consumer: a single `FileAuditSigner` direct call from the bridge thread.
2. **Egress secret detection** (saved memory `project_egress_secret_detection_is_core`). Needs payload-byte visibility, plugs in as a wrapping layer above the leaf bridge. Today no wrap surface exists.
3. **Backend uniformity.** libkrun, Vz, and Firecracker each need to emit the same chain-entry shape from very different process models (in-process splice for libkrun; cross-process NDJSON drain for Vz; jailed sidecar process for Firecracker). Today the libkrun bridge is one-of-a-kind code.

This ADR resolves all three by introducing a **NetworkProvider trait** as the seam — already foreshadowed by Plan 112's `crates/mvm-backend/src/audit_substrate.rs` "trait extraction seam" subsection.

## Decision

mvm adopts a `NetworkProvider` trait as the canonical substrate boundary for network audit observation. Each backend implements a **leaf** provider; tenant policies declare a chain of **observers** that run on each leaf's events. Observers compose by **fan-out**, not chain decoration. Audit emission is structural (always-on) and the trait's first three impls (libkrun / Vz drainer / Firecracker bridge) ship together as a single coordinated plan.

The decision settles six load-bearing design questions answered during the brainstorm. They are recorded here so the next contributor — or AI session — can consult the rationale without re-deriving it.

### 1. Composability: composable providers (B from the brainstorm)

Leaf providers (libkrun, Vz, Firecracker) plus host-allowlisted observers (`AuditEmit`, `flow-count-metrics`, future `hostname-filter`, future `egress-redactor`). The trait is shaped for **observer-side composition**, not leaf-wrapping decoration. Egress secret detection drops in as an observer (and, eventually, as an inline payload transformer attached to the leaf) with no further trait changes.

### 2. Event granularity: hybrid (C from the brainstorm)

Trait yields `FlowOpened` / `FlowClosed` as the cheap-path default. Observers that need byte-level access (egress redactor) opt into a **per-flow payload tap** via `NetworkProvider::attach_tap`. Observers that only need flow metadata (AuditEmit, rate-counters) pay zero per-byte cost.

### 3. Wrapping primitive: builder with trait-object at the boundary

`Pipeline::new()` returns a builder; `.observe()` appends observers (capability-gated, depth-capped at 8); `.build_broadcast(signer)` materializes a `Broadcast` the leaf consumes; the leaf is the user-facing `Box<dyn NetworkProvider>`. Inside the leaf, observer fan-out is **fully monomorphized** — one v-table call per packet at the trait-object boundary, then all observer dispatch inlines. Best-of-both-worlds compared to per-layer trait objects (4 v-table calls per packet) and pure compile-time generic stacking (impractical per-tenant variation).

### 4. Process model: per-VM supervisor (A from the brainstorm)

- libkrun: trait runs in `mvm-libkrun-supervisor` (existing).
- Vz: trait runs in a **new** `mvm-vz-drainer` per-VM process that binds `events_ingest_socket_path`.
- Firecracker: trait runs in a **new** `mvm-firecracker-bridge` per-VM sidecar process spawned alongside the VM.

Each per-VM process signs its own chain entries into `~/.mvm/audit/<tenant>.jsonl` under cross-process `flock`. Centralised audit daemon (option B from the brainstorm) explicitly rejected: it would re-architect the post-PR-#459 chain-emit model and introduce a single-point-of-failure for chain signing.

### 5. Firecracker sidecar confinement: A2 — sibling jailed namespace

`mvm-firecracker-bridge` runs as a **sibling** to the Firecracker jailer (not inside it; jailer is single-process). The bridge applies its own seccomp + Landlock confinement via a new `mvm-jailer-lite` helper crate that wraps:

- **`seccompiler`** — Firecracker-team-maintained seccomp-BPF library. Pure Rust, battle-tested inside Firecracker itself.
- **`landlock`** — official Rust LSM binding. User-level filesystem confinement, no root, no setuid helper.

The bridge inherits the *same security tier* as `mvm-libkrun-supervisor` on macOS (user-level process, fs-scoped to `~/.mvm/`). On Linux this is `unshare(CLONE_NEWNS | CLONE_NEWPID)` + Landlock filesystem ruleset + seccomp filter. Higher-level crates (`hakoniwa`, `sandlock-core`, `sandbox-rs`) were rejected as bundling cgroups + namespace isolation we don't need; `bubblewrap`-based crates were rejected for the external-binary subprocess shape.

### 6. Bridge crash policy: hard-fail by default

Bridge process crash → supervisor SIGTERMs the VM → chain entry `VmStopped { reason: "audit_substrate_crashed", bridge_exit: N }`. The audit chain is a security feature; a silent retry-and-resume would hide a security-claim downgrade. Loud failure is the production-ready posture.

`SupervisorConfig.bridge_restart_policy: BridgeRestartPolicy` is reserved in the wire format with one accepted variant in this plan (`hard_fail`). Future variants (`restart_once_with_gap`, `restart_with_budget`) ship in a separate plan with their own ADR; when used, they emit a `GatewayAuditGap { from, to, dropped_estimate, restart_count }` chain entry on resume so the gap is structural and operator-visible.

### 7. Observer trust boundary: host-allowlisted, never tenant-shipped code

Observers are resolved through `~/.mvm/observers/allowlist.toml` (per-user) or `/etc/mvm/observers/allowlist.toml` (system-wide). Tenant policies reference *policy names*, not observer names; the host operator's policy file declares which observers the policy maps to. No `.so` / `.wasm` / dynamic loading of tenant-supplied code in this plan. This matches claim 10's existing pattern: tenant says "engineering-default"; host maps that to gateway rules AND observer chain.

### 8. Vz payload tap: not supported in this plan; capability-gated refusal

`mvm-vz-drainer` returns `Err(PayloadTapUnsupported)` from `attach_tap`. Observers that require `payload_tap` (future egress-redactor) refuse construction on the Vz backend at `Pipeline::observe` time with a clear "switch backend or change policy" message.

**Vz payload-tap is delivered by the Rust-`objc2` VZ supervisor (Plan 152), not a Swift extension** (decision 2026-06-04, superseding the earlier "Swift-side payload tee" sketch). Once the supervisor is Rust-native it owns the VZ device *and* the gateway bridge in one process, so the packet shuffle + observer pipeline (Plan 141's backend-agnostic core) run **in-process** against the socketpair Rust attaches to `VZFileHandleNetworkDeviceAttachment` — no Swift tee, no SCM_RIGHTS fd-handoff, no NDJSON ingest hop. **Plan 141 is rescoped to the libkrun + Firecracker `payload_tap` core**; Vz keeps this capability-gated refusal until Plan 152 lands. Rationale: a Swift-side tee / fd-handoff would be throwaway under the already-decided drop-Swift direction, and it would put cross-process fd-passing on the egress path only to delete it — see `project_vz_strong_support_direction`.

### 9. Tenant value resolution

The `--tenant` value resolves in fixed precedence order:

1. Built-in default `"local"`
2. `~/.mvm/config.toml` `[tenant] name = "..."`
3. `MVM_TENANT` env var
4. `--tenant` CLI flag

Walked highest precedence first. No identity backend, no auth state — tenant is still just a string label for the audit chain file. Identity / `mvmctl auth` is a separate ADR + plan.

## Trait surface (mvm-core)

```rust
// crates/mvm-core/src/network/mod.rs
// No runtime deps — mvm-core invariant preserved.

pub const MAX_OBSERVERS: usize = 8;
pub const DEFAULT_MAX_CONCURRENT_FLOWS: u32 = 4_096;    // Plan 102 W6.B
pub const DEFAULT_FLOW_RATE_CAP_PER_SEC: u32 = 1_000;   // Plan 102 W6.B

#[derive(Clone, Copy, Debug)]
pub struct ProviderCapabilities {
    pub flow_events: bool,         // always true for trait impls
    pub payload_tap: bool,         // libkrun + Firecracker: true; Vz: false in this plan
    pub max_concurrent_flows: u32, // leaf-defined; default 4096
}

pub trait NetworkProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> ProviderCapabilities;

    /// Begin IO. Leaf spawns its bridge thread / drainer / sidecar.
    fn start(&self) -> Result<(), ProviderError>;

    /// Tear down IO. Idempotent.
    fn stop(&self) -> Result<(), ProviderError>;

    /// Opt-in payload visibility. Returns `Err(PayloadTapUnsupported)`
    /// on leaves whose capability reports `payload_tap: false`.
    fn attach_tap(&self, flow_id: FlowId, sink: Arc<dyn TapSink>)
        -> Result<TapHandle, ProviderError>;

    fn detach_tap(&self, handle: TapHandle);
}

#[derive(Debug, Clone)]
pub enum FlowEvent {
    FlowOpened { id: FlowId, tuple: FiveTuple, opened_at: Instant,
                 vm_name: String, tenant: String },
    FlowClosed { id: FlowId, tx_bytes: u64, rx_bytes: u64, closed_at: Instant },
    FlowFlood  { ts: Instant, dropped_count: u32 },             // rate-cap aggregation
    FlowEvicted { id: FlowId, reason: EvictionReason },         // bounded-table evict
    GatewayAuditFault { flow_id: Option<FlowId>, detail: Cow<'static, str> },
}

pub trait Observer: Send + Sync {
    fn name(&self) -> &'static str;
    fn required_capabilities(&self) -> RequiredCapabilities;
    fn on_flow_event(&self, event: &FlowEvent);
}

pub trait TapSink: Send + Sync {
    /// `bytes` carries no Display/Debug. Observers that legitimately
    /// need plaintext (egress redactor) explicitly unwrap via
    /// `Opaque::unwrap_for_purpose(TapReason::Redact)`. The
    /// `xtask check-no-display-on-secret-types` lint covers this.
    fn on_packet(&self, dir: Direction, bytes: Opaque<&[u8]>);
}

pub struct Opaque<T>(T);  // no Display, no Debug, no public field access
```

## Pipeline + Broadcast (mvm-backend)

```rust
// crates/mvm-backend/src/network/pipeline.rs

pub struct Pipeline { observers: Vec<Arc<dyn Observer>> }

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("too many observers (max {MAX_OBSERVERS}); requested {requested}")]
    TooManyObservers { requested: usize },
    #[error("observer {observer} requires capability {missing:?}; leaf {leaf} does not provide it")]
    CapabilityMismatch { observer: &'static str, leaf: &'static str, missing: Vec<&'static str> },
    #[error("observer name {0:?} is not allowlisted in ~/.mvm/observers/allowlist.toml")]
    NotAllowlisted(String),
    #[error("observer constructor failed: {source}")]
    ConstructorFailed { observer: String, #[source] source: anyhow::Error },
}

impl Pipeline {
    pub fn new() -> Self;
    pub fn observe(self, observer: Arc<dyn Observer>, leaf_caps: ProviderCapabilities)
        -> Result<Self, BuildError>;
    pub fn build_broadcast(self, signer: Arc<dyn AuditSigner>) -> Arc<Broadcast>;

    /// Production entry: resolves tenant policy refs through the host
    /// allowlist + capability check against the leaf.
    pub fn from_admitted(
        plan: &AdmittedPlan,
        leaf_caps: ProviderCapabilities,
        allowlist: &ObserverAllowlist,
        signer: Arc<dyn AuditSigner>,
    ) -> Result<Arc<Broadcast>, BuildError>;
}

pub struct Broadcast { observers: Vec<Arc<dyn Observer>> }   // AuditEmit at index 0

impl Broadcast {
    /// Called from the leaf's IO thread on each flow event. Fan-out
    /// runs each observer under `catch_unwind`; a panicking observer
    /// surfaces `GatewayAuditFault` to AuditEmit (always at index 0)
    /// and does not propagate to siblings.
    pub fn publish(&self, event: FlowEvent);
}
```

## Leaf implementations

### Libkrun leaf — refactor of existing bridge

- **Location**: `crates/mvm-libkrun-supervisor/src/network/libkrun_leaf.rs`
- **Process**: existing `mvm-libkrun-supervisor`, one per VM
- **IO model**: in-process splice over `BridgeFds` socketpair (unchanged from PR #487)
- **Capability**: `payload_tap = true`
- **What changes**: today's bridge thread emits `FlowOpened` / `FlowClosed` directly to `FileAuditSigner`. After this plan it emits to a `Broadcast`; the `AuditEmit` observer (Broadcast index 0) wraps the same `FileAuditSigner`. Chain wire-shape is byte-identical (regression test asserts this).
- **New**: per-flow payload tap fan-out via `HashMap<FlowId, Vec<Arc<dyn TapSink>>>`.

### Vz leaf — new drainer crate

- **Location**: `crates/mvm-vz-drainer/` — new leaf crate, the Vz analog of `mvm-libkrun-supervisor`
- **Process**: spawned by `mvm-backend/src/vz.rs::start()` between Swift supervisor spawn and VM boot, one per VM
- **IO model**: binds `events_ingest_socket_path` (the path Swift bridge already writes to per PR #487 commit 6); reads NDJSON `FlowEventWire`; publishes `FlowEvent` to the `Broadcast`
- **Capability**: `payload_tap = false` in this plan (Swift bridge doesn't expose payload bytes yet). Closes the Vz carve-out from Plan 112.
- **Lifecycle**: crash propagates to the Vz VM via the same `AttachedGvproxyGuard` pattern PR #487 commit 6 established.

### Firecracker leaf — new bridge sidecar

- **Location**: `crates/mvm-firecracker-bridge/` — new leaf crate, the Firecracker analog
- **Process**: spawned by `mvm-backend/src/backend.rs::FirecrackerBackend::start()` alongside the Firecracker jailer, one per VM; calls `mvm_jailer_lite::confine_self()` immediately after argument parsing
- **IO model**: spawns `passt` as a child; reads packets from passt's stdout; parses via `etherparse` under `catch_unwind`; publishes to `Broadcast`
- **Capability**: `payload_tap = true`
- **Confinement** (A2 sibling jail):
  - Linux namespaces: `CLONE_NEWNS | CLONE_NEWPID`
  - Landlock ruleset: read on `passt` binary + `~/.mvm/keys/host-signer.ed25519`; read-write on `~/.mvm/audit/`; no network paths (passt's sockets are inherited fds, not opened by name)
  - Seccomp profile: allowlist of `socket`, `bind`, `connect`, `accept`, `splice`, `sendmsg`, `recvmsg`, `read`, `write`, `fsync`, `clock_gettime`, `exit_group`, `futex`, `mmap`, `munmap`, `rt_sigprocmask`, `openat` (restricted by Landlock), plus the set required by `etherparse` + chain emit. Documented in `crates/mvm-firecracker-bridge/SECCOMP.md`.
- **passt provenance**: bridge hash-verifies the `passt` binary at startup against `nix/images/passt-hashes.toml` (Plan 102's image hash-verification pattern, claim 6). Mismatch → bridge refuses to start.

### `mvm-jailer-lite` helper crate (new)

- ~300 lines of glue: `seccompiler` profile builder, `landlock` ruleset builder, a single `confine_self() -> Result<(), JailerError>` entry point.
- Used by `mvm-firecracker-bridge` initially; potentially by future per-VM processes on Linux that need the same confinement (e.g., a future Linux-side counterpart to mvm-vz-drainer if Firecracker grows multi-leaf shape).

## `ObserverAllowlist` + policy file extension

### Allowlist schema (host-operator-controlled)

```toml
# ~/.mvm/observers/allowlist.toml  (mode 0600)
schema_version = 1

[[observer]]
name = "flow-count-metrics"
# No config — increments a per-tenant counter exposed via the existing
# Prometheus endpoint.
```

`AuditEmit` is **not** in the allowlist file — it's always-on, injected at `Broadcast::publish` index 0 by `Pipeline::build_broadcast`.

### Policy schema extension

```toml
# ~/.mvm/policies/engineering-default.toml
schema_version = 2  # bumped from claim-10's v1

[gateway]
default = "deny"
allow = ["github.com:443", "registry-1.docker.io:443"]

[network_observers]
chain = ["flow-count-metrics"]    # optional; absence = AuditEmit only
```

The `[network_observers]` table is optional; absence keeps every existing claim-10 policy file backwards-compatible.

## Observer roster (this plan)

| Observer | Capability | Purpose | Config |
|---|---|---|---|
| `audit-emit` | flow_events | Chain-sign every event into `~/.mvm/audit/<tenant>.jsonl`. Always-on. | None |
| `flow-count-metrics` | flow_events | Per-tenant flow counter via existing `--metrics-port` Prometheus endpoint. | None |

Stress-tests the trust-store mechanism with one real tenant-facing observer. Hostname filter, rate limiter, egress redactor each ship in their own follow-up plans with their own ADRs.

## Security posture — claim review

| Claim | Status under this ADR | Notes |
|---|---|---|
| 1 (no host-fs access from guest beyond explicit shares) | **Preserved** | Firecracker bridge is sibling-process, not in-guest. If guest-controlled packet bytes compromise the bridge (in-scope threat per Plan 102 W6.B's `catch_unwind`), Landlock + seccomp confine post-compromise damage to `~/.mvm/{audit,keys}/`. Claim is about the guest's reach; A2 doesn't expand it. |
| 2 (no guest uid-0 elevation) | Preserved | Unrelated; bridge has no guest-facing surface. |
| 3 (tampered rootfs fails to boot) | Preserved | Unrelated. |
| 4 (guest agent has no `do_exec` in prod) | Preserved | Unrelated; bridge is host-side. |
| 5 (vsock + supervisor-config JSON fuzzed) | **Extended** | Plan 102 W6.B's planned `fuzz_gateway_bridge.rs` for libkrun's parser extends to the new Firecracker bridge via `crates/mvm-firecracker-bridge/fuzz/fuzz_gateway_bridge.rs`. New CI lane `firecracker-bridge-fuzz`. |
| 6 (pre-built dev image hash-verified) | Preserved | `mvm-firecracker-bridge` binary follows the same `resolve_supervisor_path()` resolution pattern as `mvm-libkrun-supervisor`. Plus: passt binary itself is hash-pinned against `nix/images/passt-hashes.toml`. |
| 7 (cargo deps audited) | **Extended** | New deps `seccompiler` and `landlock` pinned in `deny.toml`; the `deny` and `audit` CI jobs cover them on every PR. |
| 8 (signed audited ExecutionPlan) | Preserved | Bridge receives the signed envelope on stdin; re-verifies via `mvm_plan::verify_plan` before any IO. |
| 9 (signed bundles content-addressed) | Preserved | Bundle verification stays in admission. |
| 10 (default-deny egress) | Preserved | Bridge **observes**; policy enforcement stays at the gateway (pre-bridge). The trait can't accidentally weaken default-deny. |
| 11 (sealed deps volume) | Preserved | Unrelated. |
| 12 + 13 (host services broker) | **Boundary explicit** | `NetworkProvider` is virtio-net only. Vsock stays with the host-services broker (ADR-059). The ADR-002 §boundary table gains an entry. |
| 14 (OCI image provenance) | Preserved | Upstream of bridge. |

**Net**: 11 preserved unchanged, 2 require concrete additions (claim 5 fuzz extension, claim 7 cargo-deny pins), 1 boundary statement (claim 12/13 vs network/vsock split).

## Error taxonomy (summary; full enumeration in the plan)

- Construction-time errors (`BuildError::*`, `seccompiler` install failure, `landlock` apply failure, `passt` hash mismatch, allowlist file missing/loose-perms) **never produce a chain entry** — the plan never reaches `plan.launched`. Stderr only.
- Run-time errors emit a chain entry then degrade or stop:
  - `etherparse` panic → `GatewayAuditFault { flow_id, detail }`; that flow degrades to pass-through, sibling flows + observers continue.
  - Observer panic → `GatewayAuditFault { detail: "observer X panicked" }`; sibling observers continue (fan-out isolation via `catch_unwind`).
  - Bridge process crash → supervisor SIGTERMs the VM, chain entry `VmStopped { reason: "audit_substrate_crashed", bridge_exit: N }`.
- Tenant cross-check (`cfg.tenant_id != verified.plan.tenant.0`) refused inside the bridge before any chain entry.

## Out of scope

- **Egress secret detection / payload rewriting** — its own future plan and ADR (saved memory `project_egress_secret_detection_is_core`). This ADR ensures the trait *doesn't paint it into a corner* (hybrid event granularity, box-at-boundary monomorphization, observer allowlist) but ships zero rewriter logic.
- **Vz payload tap** — separate follow-up plan extends Swift `Config.swift` with `payload_tap_socket_path` and adds Swift-side payload tee + control channel. Vz returns `PayloadTapUnsupported` until then.
- **AppleContainer substrate** — Apple's `containerization` framework's network layer is opaque to mvm. Further-future plan needed.
- **Hostname filter, rate-limiter observers** — each gets its own ADR (DNS resolution semantics, SNI handling, etc., are real design decisions). This plan ships the infrastructure that lets them plug in.
- **Bridge retry policy variants** — `BridgeRestartPolicy::HardFail` is the only accepted value in this plan. `RestartOnceWithGap` / `RestartWithBudget` ship in a separate plan with their own ADR; when used, they emit `GatewayAuditGap` chain entries.
- **Per-VM signing-key derivation** — today the bridge reads `host-signer.ed25519` directly. A compromise leaks the master key. Better long-term: parent process keeps the key; bridge sends a chain-entry hash over a pipe and parent signs. Out of scope for this plan; tracked as a deferred hardening.
- **Centralised audit daemon** — rejected (item 4 above).
- **`mvmctl auth` / identity model** — its own ADR + plan (saved memory and brainstorm acknowledged separately).
- **Host-side rate-limit enforcement** — observers can observe rate (`FlowFlood`) but cannot enforce ceilings. Enforcement is at the gateway via policy refs (existing claim-10 surface).

## Alternatives considered

### A. Pluggable-backend trait only (no observer composition)

Trait is a backend cleanup: libkrun / Vz / Firecracker / AppleContainer each implement it. No observers, no fan-out. Egress secret detection becomes a separate post-plan with its own integration shape.

Rejected: forces a re-shape when the redactor lands. Saved memory `project_egress_secret_detection_is_core` explicitly notes "don't paint adjacent network/L7 features into a corner that blocks it"; (A) does exactly that.

### B (current decision). Composable observers with fan-out

See §Decision.

### C. First-class user programmability (WASM/eBPF callback surface)

Trait carries a user-supplied policy/filter callback API. Compile-time (Rust closures) or runtime (WASM/eBPF) plug-ins.

Rejected as premature for the first ship. No concrete WASM/eBPF callers exist; designing the surface speculatively risks getting it wrong. (C) is reachable from (B) without re-shape if the need materialises.

### Wrap-chain decoration ("decorator pattern" / `tower::Service` style)

Each observer wraps the next; layers can short-circuit / transform / drop.

Rejected because for network audit the bytes have *already crossed the wire* by the time the leaf observes them. A wrap-chain implies layers can prevent action — which they can't, the packet already flew. Fan-out observation is the honest shape. Policy enforcement (deny by hostname) belongs at the gateway via existing claim 10 mechanism, not in the observer trait.

### Centralised audit daemon (`mvm-audit-chaind`)

One long-running host-wide process holds the signing key + chain state for every tenant; backend supervisors emit raw flow events over a unix-socket control channel.

Rejected: re-architects the post-PR-#459 chain-emit model, introduces a single-point-of-failure for chain signing, requires per-VM/per-tenant policy resolution to flow into the daemon at every admission. The per-VM-supervisor model already works with cross-process `flock` coordination; no problem to solve here.

### Bridge inside Firecracker jailer (Alpha)

Run `mvm-firecracker-bridge` *inside* the existing Firecracker jailer process.

Rejected: jailer is single-process. There is no "inside the jailer" for a sibling process. The achievable shape ("bridge in a similar seccomp/namespace setup") is exactly A2.

### Bridge as unconfined host process (Beta)

Run `mvm-firecracker-bridge` with full host privileges.

Rejected: weakens claim 1 for the audit substrate (compromised bridge can reach anything). Saved memory `feedback_no_backcompat_first_version` argues for shipping the right shape from the start.

### Higher-level Rust sandbox crates (`hakoniwa`, `sandlock-core`, `sandbox-rs`)

Bundles namespace + cgroup + Landlock + seccomp in one opinionated package.

Rejected: more moving parts than we need. We don't want cgroup management or full namespace isolation; just fs + syscall confinement. `seccompiler` + `landlock` directly is more native, smaller dep tree, easier to audit.

### Bubblewrap-based sandboxes (`build-wrap`, `sandbox-runtime`, `ai-sandbox`)

Wrap the `bwrap` binary as a subprocess.

Rejected: adds an external binary dep on the host, introduces a new fork/exec layer, less configurable than the direct seccompiler + landlock combo.

## Consequences

### Positive

- **Single conceptual model across libkrun / Vz / Firecracker.** Future contributors don't re-derive the substrate shape per backend.
- **Claim 10 leg 2 reaches Linux KVM.** Firecracker workloads gain the same audit-substrate posture libkrun has had since PR #487.
- **Egress secret detection has a known integration shape.** When its plan lands, the redactor plugs in as an observer that opts into the payload tap — no trait redesign needed.
- **Vz substrate carve-out from Plan 112 closes.** The drainer ships as part of this plan.
- **Observer trust boundary is explicit.** Tenant ↔ host trust split mirrors claim 10's pattern; no new boundary to reason about.
- **`mvm-jailer-lite` helper crate** becomes reusable for future per-VM Linux processes that need the same confinement.

### Negative

- **Three new crates** (`mvm-vz-drainer`, `mvm-firecracker-bridge`, `mvm-jailer-lite`). Each adds CI build cost and a maintenance surface.
- **New deps** (`seccompiler`, `landlock`). Both maintained, version-pinned, audited; but the dep surface grows.
- **Cross-platform CI matrix expands.** Linux runners need to gain Landlock-supporting kernel (≥ 5.13; full API at 6.7+); current `cloud-hypervisor` CI lane runs Ubuntu LTS which already satisfies this.
- **passt provenance becomes a maintenance burden.** When upstream passt releases, the `nix/images/passt-hashes.toml` needs updating before contributor hosts can upgrade.

### Neutral

- **Wire format additions** (`tenant_id`, `plan_json`, `bundle_json` from Plan 112 stay; `bridge_restart_policy` added) but `#[serde(default)]` + backward-compatible schema means existing JSON corpora still parse.

## Related future work

- **Plan N+2** (Vz drainer payload tap): Swift `Config.swift` schema extension + Rust-side payload socket + control channel.
- **Plan N+3** (egress redactor observer): the redactor decorator + its inline payload rewriter plug-point on the leaf.
- **Plan N+4** (hostname-filter observer): DNS resolution shape, SNI handling, refusal-on-resolve-failure policy. Its own ADR.
- **Plan N+5** (rate-limiter observer): per-tenant ceilings, sliding-window vs token-bucket, enforcement at gateway vs observation only.
- **`mvmctl auth` / identity model**: separate ADR + plan; brainstormed independently of this work.
- **Per-VM signing-key derivation**: hardening pass to remove bridge read access to `host-signer.ed25519`.
- **AppleContainer substrate**: research into Apple's `containerization` framework's network layer; further-future.

## Implementation sequencing

A separate implementation plan (`specs/plans/113-network-provider-trait-firecracker-substrate.md`, to be created by the `superpowers:writing-plans` skill) will sequence the tasks: trait surface in mvm-core → Pipeline + AuditEmit in mvm-backend → ObserverAllowlist + policy schema bump → libkrun leaf refactor → Vz drainer → Firecracker bridge sidecar + jailer-lite → CI lanes + fuzz extension → plan-doc tick.
