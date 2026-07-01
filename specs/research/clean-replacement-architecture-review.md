# Research — Clean-replacement architecture review

**Status:** Research note
**Date:** 2026-06-27
**Owner:** mvm
**Relates to:** [ADR-002](../adrs/002-microvm-security-posture.md),
[ADR-097](../adrs/097-attested-downloadable-runtime-and-builder-packs.md),
[Plan 212](../plans/212-subsecond-machine-run.md),
[Plan 213](../plans/213-attested-fast-first-boot-packs.md),
[ADR-098](../adrs/098-macos-raw-hvf-performance-backend.md),
[Plan 214](../plans/214-clean-replacement-architecture.md)

## Why this note exists

An external reference design was reviewed as architectural research. The goal was
not to copy it, but to extract the design ideas worth adopting and to check them
against what mvm already has. This note records the source-review findings in
neutral terms, the full Keep/Rewrite/Delete/Defer inventory, and two decision
matrices (eager copy-on-write restore vs. userfaultfd; raw hypervisor vs.
high-level macOS virtualization). It is the input to [Plan 214](../plans/214-clean-replacement-architecture.md).

Throughout, the external work is referred to only as "the reviewed
implementation," "the reference design," or "the source review." No external
project, product, company, crate, repository, or website is named, here or in any
artifact this review produces.

## The single most important finding

mvm is not a greenfield. The target architecture described by the reference
design is, to a first approximation, already mvm's architecture. Concretely, mvm
already ships:

- A backend trait (`VmBackend`) with a closed dispatch enum (`AnyBackend`) and a
  descriptor registry, plus a capability model (`VmCapabilities`,
  `SnapshotCapability`).
- A warm-standby pool (`SupervisorStandbyPool`) with residency policy
  (`ResidencyPolicy`: warm / parked / cold) and TTL-driven reaping.
- A chain-signed, tamper-evident audit log keyed by `(plan_id, plan_version)`
  with per-tenant Ed25519 chains and JCS-canonical entries.
- Host-mediated secret handling: opaque per-session placeholders, a vsock
  substitution endpoint, destination-bound host-side substitution, egress redaction, and
  `zeroize`-on-drop secret material that never crosses the broker channel as raw
  bytes.
- Static, shell-free PID-1 init binaries already in production for several VM
  classes (guest agent over a busybox base, the verified-boot initramfs init, the
  builder-VM init, the Stage 0 bootstrap init).
- Signed `ExecutionPlan`s with a validity window, nonce replay protection, a
  content-addressed bundle pin, and a sealed deps-volume pin.
- Both an OCI image pipeline and a Nix flake/template pipeline that materialize
  deterministic rootfs/initramfs/kernel artifacts inside an isolated builder VM,
  never on the host.
- Decorator and runtime SDKs that compile a workload to a typed IR by static
  parse — never by executing user code on the host — emitting over a subprocess
  contract.
- A hard SSH ban: TCP/22 is a banned egress port enforced at admission and at
  runtime, and there is no sshd, SSH user, or SSH key in any rootfs.

So the clean-replacement work is **consolidation and completion**, not a rewrite.
The reference design is most valuable where mvm has a gap or a shape that has
drifted: a missing product-level library abstraction, the networking default, the
snapshot/restore substrate, and the proliferation of near-duplicate init
binaries. The project has no production users, so we are free to replace internal
shapes rather than shim them — but the product experience, security model, library
contract, SDK surface, deterministic build posture, and CLI ergonomics are
preserved or improved, not discarded.

## The reference design ideas, mapped onto mvm

The source review surfaced a coherent set of ideas. Each is recorded here with
mvm's current position and the gap.

### 1. One product-level `Machine` abstraction, CLI as a thin client

**Reference idea.** A single `Machine` / `MachineBuilder` library type is the
product surface. The CLI, embedders, and SDKs are all thin clients of it. The
backend is an implementation strategy behind the abstraction, never the place the
architecture lives.

**mvm today.** The backend trait is clean, but the *orchestration* — boot a fresh
VM, stage files, run a command, stream output, return the exit code, tear down —
lives inside CLI command handlers (`crates/mvm-cli/src/commands/machine/mod.rs` is
~2400 lines; `crates/mvm-cli/src/commands/vm/exec.rs` ~1400 lines; a separate
`crates/mvm-cli/src/exec.rs` runner). The runtime crate exposes `ExecBuilder` and
`WarmLease`, which are good building blocks but stop short of a fresh-boot
`Machine`. An embedder (mvmd, an external tool) must either shell out to `mvmctl`
and parse JSON, or copy the CLI's orchestration.

**Gap.** No `mvmctl::runtime::Machine` / `MachineBuilder` that an embedder calls
for the full lifecycle. This is the largest single divergence and the backbone of
Plan 214 Phase 1–2.

### 2. Backend capability model drives selection and rejection

**Reference idea.** Backends declare capabilities; plans and the scheduler choose
by capability; a plan that requires a capability a backend lacks is rejected, not
silently downgraded. No capability ever enables production SSH.

**mvm today.** `VmCapabilities` (pause_resume, snapshots, vsock, tap_networking,
balloon, fs_quick_checkpoint) and `SnapshotCapability` (LiveMemory / SaveRestore /
DiskOnly / Unsupported) exist and already fail closed on over-request. Selection
is platform-first in `AnyBackend::auto_select`.

**Gap.** The capability set does not yet name the dimensions the new substrate
needs: eager-CoW restore, fixed-address remap, device-state snapshot,
guest-memory mapping, no-guest-NIC, host-vsock-proxy, PTY exec, and an explicit
`supports_production_ssh: false` used to reject. No silent backend downgrade when
a security-relevant capability (eager-CoW on the macOS performance tier) is
required.

### 3. Default no guest NIC; host/vsock-mediated networking

**Reference idea.** Guests get no virtio-net device by default. Egress flows from
the app through a guest-local proxy, over vsock, to a host egress broker that does
DNS, TCP connect, HTTP CONNECT/SOCKS5, endpoint allowlisting, host-side secret substitution,
and audit. Ingress, when needed, is a host listener that policy-gates and routes
over vsock to a guest service. No path bypasses the host policy/audit layer.

**mvm today.** Egress is default-deny on the two workload backends (Firecracker
nftables; the libkrun gateway-bridge with `PlanFlowPolicy`). Secret substitution,
redaction, and a host-services broker over vsock all exist. But guests still get a
NIC by default on the workload path (libkrun mandates virtio-net by claim-10
no-bypass design), `--net` widens an L3/L4 allowlist rather than switching
transport, and there is no consolidated host egress broker + host ingress broker +
guest network daemon as the *default* transport. There is no `NetworkMode` field
in the plan; networking backend is chosen by a host-wide env var.

**Gap.** Introduce `NetworkMode::{None (default), HostVsockProxy}` as a typed plan
field; build the guest network daemon and the host egress/ingress brokers as the
no-NIC default; keep the existing NIC path available only as an opt-in
compatibility mode (or defer it). See
[the security/audit/trace/secret note](../notes/clean-replacement-security-audit-trace-secret-architecture.md).

### 4. Replace guest PID-1 with a single small static init

**Reference idea.** Guest PID-1 is a tiny static supervisor — not a shell, not an
init system, and not the workload itself. It mounts filesystems, reads flat launch
metadata, optionally receives env/secrets over vsock, starts the workload, reaps
zombies, forwards signals, emits lifecycle markers, and — critically — stays alive
and inspectable on fatal setup error rather than vanishing.

**mvm today.** There are already four static, shell-free PID-1 binaries, one per
VM class. They are correct but they are near-duplicates, and the workload guest's
PID-1 is the busybox base plus the agent rather than a single purpose-built
supervisor with lifecycle markers and a documented inspectable-failure state.

**Gap.** Consolidate to one `mvm-init` for the workload guest with: flat metadata
(no large JSON parse in PID-1), lifecycle markers, an inspectable failure state, a
vsock control channel, and a `snapshot_at` hook (PRE_EXEC / READY /
AFTER_WARMUP). This is the highest-confidence immediate direction.

### 5. Eager copy-on-write restore explored before assuming userfaultfd

**Reference idea.** For *local* warm-pool restore, an eager file-backed
`MAP_PRIVATE` mapping of the snapshot RAM section may be simpler and faster than a
userfaultfd page-fault handler: clean pages stay shared with the snapshot file via
the page cache, dirty pages become private only on write, and there is no
userspace fault round-trip. userfaultfd remains the right tool for *remote*
hydration, postcopy migration, lazy decompression, and tiered/eviction memory.

**mvm today.** The in-flight warm-start substrate is framed around userfaultfd
(the on-host slices effort). Full-memory restore is what ships today; the
userfaultfd lazy-paging and diff/CoW layering are carved out and live-KVM-gated.

**Gap.** Run the eager-CoW spike *before* committing to userfaultfd as the
foundation for local restore, and let the spike define the minimum backend
capability requirements. See the decision matrix below.

### 6. Hardened snapshot frame format

**Reference idea.** A versioned snapshot frame with magic, version, architecture,
backend kind, a length-prefixed section table, hard count and total-size caps,
page-alignment and bounds checks (no allocation before count validation,
overflow-safe offset math), an optional integrity hash and signature envelope,
recorded artifact digests, and a guarantee that secrets are excluded.

**mvm today.** Firecracker snapshots are sealed with HMAC-SHA256 + an Ed25519
signature sidecar and an epoch counter for replay defense — good integrity. But
there is no custom frame with cap-before-alloc parsing; the Firecracker API owns
serialization, and the high-level macOS path is opaque.

**Gap.** Define a frame v0 for the substrate mvm controls (the eager-CoW / raw-HVF
path), with the cap/bounds discipline and a fuzz target, recording artifact
digests and excluding secrets by construction.

### 6b. Filesystem snapshot-cache dedup via reflink

**Reference idea.** Derive a snapshot from a sibling cheaply: reflink-clone the base
(APFS `clonefile` / Linux `FICLONE`), then write only the 4 KiB pages that differ —
no content hashing, no refcount bookkeeping. A cheap dedup for the snapshot cache.

**mvm today.** The reflink primitive already exists (`mvm-backend` `cow.rs`), but the
snapshot cache does not use it for derive-from-sibling + page-diff.

**Gap.** Wire the snapshot cache to reflink-clone a base + `pwrite` the page delta,
with a plain-copy fallback on non-reflink filesystems. Pairs with eager-CoW restore
(a reflink'd snapshot maps `MAP_PRIVATE` identically). See
[Plan 214](../plans/214-clean-replacement-architecture.md) Phase 9 / MVM-214-30.

### 7. Resident-memory accounting as a first-class warm-pool primitive

**Reference idea.** Warm-pool density is governed by *measured* resident memory,
not by a configured per-VM cap. After the first restore, measure RSS / private
dirty / shared clean; charge subsequent siblings the learned resident estimate
plus a safety margin. Separate the spawn-concurrency gate from the
resident-memory accountant — they are different limits.

**mvm today.** Warm-pool size (`warm_pool_size`) is the only lever; it doubles as
the concurrency gate. There is no RSS/footprint accountant, and no learned
per-pool charge.

**Gap.** Add a `ResidentMemoryAccountant` distinct from a `SpawnConcurrencyGate`,
with learned per-pool charge and forward-progress timeouts so a min-pool-size that
exceeds the budget cannot deadlock.

### 8. Raw hypervisor performance path on macOS

**Reference idea.** For low-latency warm restore and snapshot internals on macOS,
prefer the raw hypervisor interface over the high-level virtualization framework,
because the high-level framework does not expose guest-memory mapping,
page-granular control, or device-state capture. Keep the high-level framework as a
stable compatibility backend. This stays within "no VMM lock-in" because it is one
more backend behind the same abstraction.

**mvm today.** The high-level macOS virtualization backend (Vz) is the macOS
performance default on the newest tier; the third-party in-process VMM is the
other macOS path. There is no raw-hypervisor backend.

**Gap.** [ADR-098](../adrs/098-macos-raw-hvf-performance-backend.md) decides this:
move macOS onto the raw hypervisor as the macOS backend, keeping the high-level
framework only as a transitional fallback that is sunset once the raw hypervisor
passes its acceptance criteria; the migration is gated on benchmarks. The intent is
to move *away* from the high-level framework, not to run both indefinitely.

### 9. Clean exec/attach API: streams plus an out-of-band signaler

**Reference idea.** Exec returns a child whose stdout/stderr are `Read`, whose
stdin is `Write`, and whose signaler is a `Clone + Send + Sync` handle so a caller
can deliver a signal without borrowing the stdio handles. Interactive shell uses
the same model with a PTY. The core need not require an async runtime; async
wrappers are optional.

**mvm today.** Host-side exec is buffered (`ExecBuilder::output()` returns a whole
`ExecOutcome`); console attach streams via a callback closure; PTY resize and
signal handling live in CLI code. The vsock transport trait is clean and
stateless. mvm-core is already runtime-free by gate, which matches the "no Tokio
in the core" preference.

**Gap.** Define an exec API with `Read`/`Write` stream handles and a detached
`Signaler`, used by both one-shot exec and PTY shell, factored into the library so
the CLI is a thin consumer.

## Inventory — Keep / Rewrite / Delete / Defer

The classification is by area. "Keep" means the shape is right and load-bearing.
"Rewrite" means the responsibility stays but the shape changes. "Delete" means the
clean architecture removes it (the project has no production users, so removal is
cheap). "Defer" means out of scope for the first clean cut.

| Area | Disposition | Note |
|---|---|---|
| CLI command structure (`machine` noun, Clap derive) | **Keep** | `machine` as sole workload noun aligns with the in-flight consolidation; flags map to the plan. |
| CLI orchestration logic (boot/stage/exec/teardown inside command handlers) | **Rewrite** | Move into the `Machine` library; CLI becomes arg-parse + UI. |
| Library facade (`mvmctl::{core,runtime,build,guest,backend,security}`) | **Keep** | Stable contract for mvmd; the new `Machine` slots under `runtime`. |
| `Machine` / `MachineBuilder` product abstraction | **Rewrite (new)** | Does not exist yet; this is the backbone. |
| `ExecBuilder` / `WarmLease` | **Rewrite** | Keep the warm-claim ergonomics; extend to `Read`/`Write` + `Signaler`; fold into `Machine::run`/`exec`/`shell`. |
| Host exec/console/PTY transport (vsock transport trait, guest console) | **Keep** | Clean and backend-agnostic; PTY raw-byte relay is correct. |
| SSH: TCP/22 ban, `--allow-host` rejection of `:22` | **Keep** | Production posture is correct. |
| SSH-agent forwarding (dev-tier, vsock relay, no key copy) | **Rewrite** | Keep as dev-only; feature-gate behind `dev-shell` so a sealed prod agent cannot link it, mirroring the console/`do_exec` gating. |
| Backend trait + enum dispatch + descriptor registry | **Keep** | Sound; enum is needed for platform policy. |
| `VmCapabilities` / `SnapshotCapability` | **Rewrite** | Extend with eager-CoW / no-NIC / host-vsock-proxy / production-ssh dimensions; move the capability type to `mvm-core` so plans reference it. |
| Backend selection (`auto_select`) | **Rewrite** | Make capability-aware; honor required restore-latency class; never downgrade past a required security capability. |
| Snapshot integrity (HMAC + Ed25519 + epoch) | **Keep** | Strong; reuse for the new frame's signature envelope. |
| Snapshot frame format | **Rewrite (new)** | Add the cap/bounds-checked frame v0 for the substrate mvm controls. |
| Warm-standby pool + residency policy | **Keep** | Reuse; it is prefix-agnostic and TTL-driven. |
| Memory accounting (warm-pool size as the only gate) | **Rewrite** | Add a resident-memory accountant separate from the spawn-concurrency gate. |
| userfaultfd-first local restore framing | **Rewrite** | Spike eager-CoW first; keep userfaultfd for remote/lazy/tiered. |
| macOS high-level virtualization backend (Vz) | **Delete (after sunset)** | Transitional fallback only; removed once HVF passes its ADR-098 acceptance criteria. Not the end state. |
| Raw-hypervisor (HVF) macOS backend | **Rewrite (new) → becomes the macOS backend** | New; the intended macOS backend; gated by [ADR-098](../adrs/098-macos-raw-hvf-performance-backend.md). |
| Egress default-deny (nftables / gateway-bridge) | **Keep** | Claim-10 foundation. |
| Guest NIC by default | **Rewrite** | Flip default to no-NIC + host-vsock-proxy; NIC becomes opt-in compat or deferred. |
| `gvproxy` / `passt` / native-gateway providers | **Defer** | Keep only as a future `CompatNat` mode; not on the first clean cut's hot path. |
| Host-services broker over vsock (framing, correlation-id reassignment, rate limits) | **Keep** | Reuse as the transport substrate for the egress/ingress brokers. |
| Guest network daemon (`mvm-netd`) | **Rewrite (new)** | Consolidate the guest-side proxy/substitution clients into one daemon. |
| Host egress broker / ingress broker as discrete components | **Rewrite** | Promote the in-process gateway pieces into named broker roles with full audit/trace. |
| Secret store, placeholders, host-side substitution, destination-bound substitution, redaction, zeroize | **Keep** | Already matches the target; secrets never enter the guest (host-side substitution only); extend redaction with per-destination actions and session-boundary enforcement. |
| Chain-signed audit (`AuditEmitter`, `verify_audit_chain`, JCS canonical) | **Keep** | Reuse; extend the canonical entry with trace/span fields. |
| Structured tracing (`trace_id` / `span_id` correlation across host hops) | **Rewrite (new)** | Only `correlation_id` exists today; add W3C-style trace context end to end. |
| Static PID-1 inits (guest agent base, verity-init, builder-vm init, stage0 init) | **Rewrite** | Consolidate the workload guest to one `mvm-init` with markers + inspectable failure + `snapshot_at`; keep the verity/builder/stage0 inits. |
| `ExecutionPlan` (signing, validity window, nonce, bundle pin, deps-volume pin) | **Keep** | Strong; extend, do not replace. |
| `ExecutionPlan` artifact-digest coverage | **Rewrite** | Record input-kind and all artifact digests (rootfs / initramfs / kernel / mvm-init / mvm-netd / snapshot-base). |
| OCI pipeline (`mvm-oci`, oci-to-rootfs, verity sealing) | **Keep** | Crate-isolated, attack-surface-tested. |
| Nix pipeline (mkGuest, builder-vm flake, default-tenant flake, determinism pins) | **Keep** | Core requirement; reuse to build `mvm-init` / `mvm-netd` deterministically. |
| Builder microVM (isolated build, brokered egress, content-addressed outputs) | **Keep** | Matches the target builder posture. |
| Decorator SDK (static parse to IR, no host execution) | **Keep** | Right boundary; extend IR fields only. |
| Runtime SDK (in-guest runner, vsock contract) | **Keep** | Thin and proven. |
| mvmd contract (`mvmctl::core::protocol`, runtime re-exports, core-runtime-free gate) | **Keep** | Durable; the new `Machine` must remain Tokio-free in the default build. |
| Existing tests | **Rewrite** | Re-target around the new `Machine`, brokers, and frame. |
| Existing config structures | **Rewrite where useful** | Replace stringly-typed networking selection with the typed `NetworkMode`. |

## Decision matrix A — eager CoW (`MAP_PRIVATE`) vs. userfaultfd, per backend

The question is *local warm-pool restore*, not remote hydration. For each backend
the gating question is whether mvm can present a host-mapped, file-backed RAM
region as guest RAM and restore vCPU/device state around it.

| Backend | Can map RAM as guest memory? | Eager CoW (`MAP_PRIVATE`) for local restore | userfaultfd still useful for | Verdict |
|---|---|---|---|---|
| Linux KVM (direct) | Yes — `KVM_SET_USER_MEMORY_REGION` over an mmapped region | **Promising — primary spike target** | remote hydration, lazy decompression, eviction | Spike here first |
| Raw hypervisor (macOS) | Yes — map guest IPA to a host VA region | **Promising** | postcopy, tiered memory | Spike second; gated by [ADR-098](../adrs/098-macos-raw-hvf-performance-backend.md) |
| Firecracker (external process) | Only if mvm controls the memory restore path | Conditional — depends on the memory-backing interface | the path it already targets | Keep current restore; revisit if mvm owns the backing |
| Third-party in-process VMM (macOS/Linux) | Depends on exposed memory API | Conditional | n/a until API exists | Investigate API; do not assume |
| High-level macOS virtualization (Vz) | No — opaque save/restore, no page-level control | **Blocked** | n/a | Cannot do eager CoW; keep coarse save/restore |
| QEMU (external process) | Difficult unless a supported memory-backend file is used | Difficult | n/a | Out of scope for warm restore (dev/test backend) |

**Conclusion.** Eager CoW is the right *primary* local-restore mechanism on the
backends where mvm controls guest memory (Linux KVM and raw macOS hypervisor).
userfaultfd is not discarded — it is repositioned as the mechanism for remote
hydration, postcopy, lazy decompression, and tiered/eviction memory. The spike
(Plan 214 Phase 9) proves eager CoW on Linux KVM, documents the raw-hypervisor
requirements, and measures both against the userfaultfd assumption before either
is made the foundation.

## Decision matrix B — raw hypervisor vs. high-level macOS virtualization

| Dimension | High-level virtualization (Vz) | Raw hypervisor (HVF) |
|---|---|---|
| Stable VM orchestration | Strong | Requires a device model we own |
| Guest-memory mapping / page control | Not exposed | Exposed |
| Device-state capture for snapshots | Opaque, coarse | Controllable |
| Eager-CoW local restore | Not possible | Possible |
| Sub-100 ms warm restore | Unlikely | Achievable target |
| Implementation + security commitment | Low (Apple owns it) | High (we own the device model + its fuzzing) |
| Fit with "no VMM lock-in" | One backend | One more backend behind the same trait |

**Conclusion.** Move macOS off the high-level framework (Vz) and onto the raw
hypervisor (HVF). HVF is the intended macOS backend; Vz is kept only as a
transitional fallback and is retired once HVF passes its acceptance criteria. The
staged path (add HVF, prove it, then sunset Vz) avoids removing a working backend
before its replacement is proven. This is
[ADR-098](../adrs/098-macos-raw-hvf-performance-backend.md).

## What this review explicitly does not do

- It does not clone the reviewed implementation. The ideas are adopted; the code
  is mvm's own.
- It does not name the external reference anywhere.
- It does not preserve mvm internals merely because they exist; it preserves the
  product experience, security model, library contract, SDK surface, deterministic
  build posture, and CLI ergonomics.
- It does not collapse mvm into a single from-scratch VMM; the backend trait and
  no-lock-in principle stay intact.
- It does not make the high-level macOS framework the performance path for
  snapshot work.
- It does not assume userfaultfd is required for local restore, nor that it is
  unnecessary everywhere.
- It does not weaken any security claim. Production SSH stays impossible; the guest
  gets no NIC by default; no egress or ingress path bypasses host policy/audit;
  no secret reaches a log, trace, snapshot, image, or rootfs.

## Open questions carried into Plan 214

1. Does the third-party in-process VMM expose enough of a memory API to support
   eager CoW, or is it save/restore-only like the high-level framework?
2. For the no-NIC default, what is the minimum cooperative-app surface
   (proxy env vars) vs. the transparent-redirect surface the guest network daemon
   must provide, and which workloads genuinely need a real NIC (UDP, ICMP, raw
   sockets) such that a `CompatNat` mode must be reintroduced rather than deferred?
3. Should the consolidated `mvm-init` and `mvm-netd` be Rust static musl builds
   (matching the existing init binaries and the embedded host-vm binaries) — and
   the answer is almost certainly yes for reuse, but the spike confirms binary size
   and boot cost.
4. What restore-latency class should each backend advertise so the scheduler can
   reject a sub-100 ms request on a backend that cannot meet it?
