# Plan 141 — Vz payload tap + Rust-owned shuffle (closes ADR-064 §Decision 8)

> **Status: design captured mid-brainstorm.** Q1–Q6 are owner-confirmed
> architectural decisions; Q7 is drafted but unconfirmed; Q8–Q10 are
> open. **This plan is not ready for execution** — resume the
> brainstorm to close Q7–Q10, then re-render the Tasks section through
> `superpowers:writing-plans`. The shape below is what the locked
> decisions imply.
>
> **RESOLVED with Plan 152 (2026-06-04 brainstorm) — scope split.** The
> Vz arm of this plan is **superseded by Plan 152**. 152 makes the VZ
> supervisor Rust-native (`objc2`), so Rust owns the VZ device *and* the
> bridge in one process — the SCM_RIGHTS fd-handoff to a *surviving* Swift
> supervisor (this plan's Q1–Q6 Vz mechanism) is unnecessary and would be
> throwaway. **This plan is rescoped to its backend-agnostic core**
> (`on_packet`/`Verdict`/etherparse observer pipeline) for **libkrun +
> Firecracker** `payload_tap`; **Vz `payload_tap` is delivered in-process
> by Plan 152.** The Swift-side files + Vz-specific Rust arm below are
> retained for reference but **move to Plan 152**. Decision record:
> ADR-064 §8. See [[project_vz_strong_support_direction]].

**Goal:** Close ADR-064 §Decision 8's "Vz catches up later" carve-out and
land the Rust-owned-shuffle architecture across all production
hypervisor backends. Vz post-this-plan reports
`ProviderCapabilities { flow_events: true, payload_tap: true }`;
observers that require `payload_tap` (egress redactor, hostname
filter, rate limiter, future egress secret detector) work identically
on libkrun, Firecracker, and Vz with one Rust implementation.

**Architecture (Q1–Q6 confirmed):**

- **Rust owns the packet shuffle on every backend.** Per-backend code
  becomes the smallest possible adapter that hands a data fd to
  `gateway_bridge::run_bridge_inner`. Firecracker is already there.
  Vz changes here: Swift's `BridgeWorker` deletes; Swift accepts an
  SCM_RIGHTS fd-handoff from Rust and wraps the fd in `FileHandle` for
  `VZFileHandleNetworkDeviceAttachment`. Future QEMU / AppleContainer /
  Hyper-V backends inherit the pattern.
- **Observer trait gains `on_packet(&self, ctx, pkt) -> Verdict`.**
  `gateway_bridge` parses each frame once via `etherparse` (a workspace
  dep) and hands observers `ParsedPacket { five_tuple, l4_payload,
  raw_frame }`. The `raw_frame` slice is the escape hatch for the rare
  L2-aware observer.
- **`Verdict = Forward | Drop | Modify(Vec<u8>)` with first-Drop-wins
  chaining.** Observers run in `NetworkPolicy.observers` array order;
  observer N sees the output of observer N-1's `Modify`; first `Drop`
  adds the flow to the bridge's per-VM `killed_flows: HashSet<FlowId>`
  and short-circuits subsequent packets on that flow. RST injection,
  `Defer`, and `DropPacket`-vs-`KillFlow` distinctions are deferred to
  future plans.
- **fd-handoff handshake.** New dedicated `fd_handoff_socket_path`
  field on `Config.swift`'s `NetworkConfig` variant (no multiplex onto
  `events_ingest_socket_path` or `control_socket_path`). The existing
  `gvproxy` variant is **replaced** (no backwards-compat shim per
  `feedback_no_backcompat_first_version`) with:
  ```swift
  case rustManaged(mac: MacAddress, fdHandoffSocketPath: String)
  ```
  Swift `bind`/`listen`/`accept`s the socket (mode 0700); Rust
  connects when ready to hand off the Vz-side fd via SCM_RIGHTS.
- **Per-VM flow-byte log, opt-in.**
  `NetworkPolicy.flow_byte_log: FlowByteLogSpec | None`. Default off.
  When enabled, bridge writes append-only length-prefixed records to
  `~/.mvm/audit/flow-bytes/<tenant>/<vm>-<utc_iso>.bin`; audit-chain
  entries reference records as `(file_name, record_id, sha256)`. Rotation
  + retention sweep integrate with `mvmctl cache prune`. The audit
  chain itself stays small (no payload bytes inline). Encryption-at-rest
  is its own follow-up plan.
- **Strict-sync observer execution + Prometheus latency observability.**
  Per-VM bridge thread runs the `recv → parse → observers → send` loop
  synchronously; each `on_packet` call is wrapped in
  `std::panic::catch_unwind` (matches Plan 113's `signer_task` pattern)
  and bracketed with `Instant::now()` measurements feeding
  `mvm_observer_latency_us{observer, vm, direction}` via the existing
  per-VM `.prom` scrape file convention. **No timeout enforcement in
  V1** — that policy ships in its own plan if a real observer needs it.
- **Per-flow state stays inside the observer impl.**
  `Mutex<HashMap<FlowId, FlowState>>` keyed off the existing
  `on_flow_event(FlowOpened/FlowClosed)` callbacks. No bridge-managed
  blackboard.

**Tech Stack:** Swift `crates/mvm-vz-supervisor/Sources/...`
(`Config.swift`, `Network.swift`); Rust `crates/mvm-bridge`
(rewrites `VzIngest` arm into `VzManaged`); `mvm-supervisor::network::Observer`
(new `on_packet` method, new `Verdict` enum); `mvm-supervisor::gateway_bridge`
(per-VM `killed_flows`, etherparse fan-in); `mvm-policy::NetworkPolicy`
(new `flow_byte_log` field); `mvm-backend::vz.rs` (producer side of
the new config shape). New `mvm-audit::flow_byte_log` module for the
append-only writer + retention sweep. `etherparse` (existing workspace
dep). No new third-party Rust crates.

**Prereqs:** Plan 113 merged (PR #512). Plan 121's crate consolidation
does not block but should ship first if its timeline allows — it
relocates `mvm-bridge` into the consolidated layout, making this plan's
file paths cleaner.

---

## Open design questions (resolve before executing)

The following must close in a follow-up brainstorm session before this
plan's task list is renderable. The brainstorm context is captured at
`/Users/auser/.claude/plans/context-for-resuming-plan-robust-brook.md`.

- **Q7 — Capability advertisement post-refactor (drafted, unconfirmed).**
  Recommended shape:
  - **7a:** Plan 141 stays **Vz-only**. AppleContainer (whose
    `containerization` network layer is undocumented) lands as its own
    plan when Apple's API is clearer. Memory
    `project_gateway_audit_substrate_backend_coverage` already records
    that boundary.
  - **7b:** Lift `ProviderCapabilities { flow_events: true, payload_tap:
    true }` into a `const BRIDGE_CAPS` in `mvm-bridge`. Every backend
    funnelling through the bridge advertises the same constant —
    duplication-driven drift becomes impossible.
- **Q8 — `Modify` failure modes.** What happens when an observer
  returns `Modify(bytes)` with `bytes.len() > MTU` and the bridge can't
  re-fragment? When the modified payload would produce an invalid
  TCP/UDP checksum? Options: drop the packet with a chain entry
  attributing the observer; fail closed and kill the flow; refuse the
  Modify at trait validation time. Needs a per-failure-mode decision
  matrix.
- **Q9 — Per-direction observer registration.** Today's `Observer`
  trait has no direction filter — every observer sees every packet
  in every direction. Performance optimization: let observers declare
  `required_directions: { egress, ingress, both }` at registration.
  The four V1 use cases skew strongly toward egress-only; the
  optimization is meaningful but adds API surface. Confirm V1 scope.
- **Q10 — `mvm-vz-drainer` deletion / VzIngest arm rename.** After the
  unification, the `BridgeEndpoints::VzIngest` arm inside `mvm-bridge`
  (the NDJSON ingest path Plan 113 shipped) deletes too — Rust owns
  the shuffle for Vz, so there's no Swift-side NDJSON to drain. The
  replacement is a new `BridgeEndpoints::VzManaged` arm carrying the
  fd-handoff socket path. Confirm this is the destination state.

---

## Files (planned — derived from the locked decisions above)

> **Scope (2026-06-04):** the **Swift side** + the **Vz-specific Rust
> bits** (the `VzIngest`→`VzManaged` arm, `parse.rs` rename, `vz.rs`
> `rust_managed` shape) are **superseded by Plan 152** (Vz goes
> Rust-native; the bridge runs in-process, no fd-handoff) — retained below
> for reference only. **In scope for this plan:** the backend-agnostic
> `Observer` / `gateway_bridge` core (`on_packet`/`Verdict`/`ParsedPacket`,
> etherparse pipeline, `killed_flows`, flow-byte-log, Prometheus) applied
> to **libkrun + Firecracker**. Q10 (`mvm-vz-drainer` deletion) and the Vz
> part of Q7 move to Plan 152; Q8/Q9 stay here.

### Swift side (Vz supervisor)

- **Modify** `crates/mvm-vz-supervisor/Sources/mvm-vz-supervisor/Config.swift`
  — replace `NetworkConfig.gvproxy(...)` with `NetworkConfig.rustManaged(mac, fdHandoffSocketPath)`. Update strict-keys allowlist. Delete the `events_ingest_socket_path` field (Rust now writes the audit chain directly; Swift doesn't emit NDJSON).
- **Rewrite** `crates/mvm-vz-supervisor/Sources/mvm-vz-supervisor/Network.swift`
  — delete `BridgeWorker` class, `makeBridgedGvproxyDevice`,
  `formatFlowOpenedLine`, `formatFlowClosedLine`,
  `VZ_BRIDGE_HANDSHAKE`. Replace `makeAttachment` body with a
  ~30-line "bind+listen, accept one connection, recv one SCM_RIGHTS
  fd, wrap in `FileHandle`, attach to
  `VZVirtioNetworkDeviceConfiguration`" implementation.
- **Delete** `crates/mvm-vz-supervisor/Tests/MvmVzSupervisorTests/BridgeWorkerTests.swift`.
- **Add** Swift XCTest covering the fd-handoff handshake (the
  socket-listener happy path; the connection-aborted-before-fd path).

### Rust side

- **Rewrite** `crates/mvm-bridge/src/endpoints.rs` — `BridgeEndpoints::VzIngest` becomes `BridgeEndpoints::VzManaged { fd_handoff_socket_path }`. The new arm runs the SCM_RIGHTS dial against Swift's listener, receives the Vz-side fd (closes it; Vz keeps the other half), opens its own gvproxy socket, runs the shuffle on the (gvproxy_fd, supervisor_socketpair_fd) pair.
- **Modify** `crates/mvm-bridge/src/parse.rs` — `EndpointSpec::VzIngest`
  variant renames to `VzManaged` with the new field shape.
- **Modify** `crates/mvm-backend/src/vz.rs` — emit the new
  `rust_managed { mac, fd_handoff_socket_path }` JSON shape into
  `SupervisorConfig.network`. Drop the
  `events_ingest_socket_path` field from the producer side.
- **Modify** `crates/mvm-supervisor/src/network/mod.rs` — extend the
  `Observer` trait with `on_packet(&self, ctx: &PacketCtx, pkt: &ParsedPacket<'_>) -> Verdict`. Add `Verdict` enum, `ParsedPacket` struct, `PacketCtx` struct. Default impl: `Verdict::Forward` (so existing observers continue to work unchanged).
- **Modify** `crates/mvm-supervisor/src/gateway_bridge.rs` —
  add `killed_flows: HashSet<FlowId>` per VM. In the shuffle loop:
  etherparse the inbound frame, build `ParsedPacket`, run the
  pipeline under `catch_unwind` + `Instant::now()` brackets, apply the
  verdict, re-serialize headers after `Modify` (with new IP length +
  TCP/UDP checksum via etherparse's `set_payload`), emit a
  `flow_byte_event` chain entry referencing the flow-byte log record
  when the flow-byte log is enabled.
- **Modify** `crates/mvm-policy/src/policies.rs` — add
  `NetworkPolicy.flow_byte_log: Option<FlowByteLogSpec>`. New
  `FlowByteLogSpec` struct (max_disk_bytes, max_age_days, directions).
- **Create** `crates/mvm-supervisor/src/audit/flow_byte_log.rs` —
  append-only writer (length-prefixed records, atomic rename for
  rotation). Sweep helper invoked from `mvmctl cache prune`.
- **Modify** `crates/mvm-cli/src/commands/cache.rs` (or wherever
  `cache prune` dispatches) — wire the flow-byte-log retention sweep.

### Tests + CI

- New `mvm-bridge/tests/scm_rights_handoff.rs` covering the
  fd-handoff handshake (Linux only; macOS XCTest covers the Swift
  side).
- Extend the existing `mvm-bridge/fuzz` harness to cover the
  `on_packet` parser surface.
- New CI lane `vz-payload-tap-property` mirroring the
  `jailer-lite-property` shape — self-hosted Apple Silicon runner,
  exercises the live Vz fd-handoff + observer chain end-to-end.

---

## Tasks (placeholder — to be rendered by `superpowers:writing-plans` after Q7–Q10 close)

The tasks will roughly follow Plan 113's shape — observer-trait
extension first, Swift refactor second, producer wiring third, audit
chain integration fourth, CI lanes fifth, plan-doc tick last. Holding
off on the per-task breakdown until the open questions resolve so the
task bodies don't drift.

---

## Out of scope (deferred follow-ups)

- **AppleContainer payload tap** — its own plan when Apple's
  `containerization` network API is clearer. Memory
  `project_gateway_audit_substrate_backend_coverage` documents the
  carve-out.
- **Encryption-at-rest for the flow-byte log** — own ADR (keyring
  sourcing, per-tenant key, rotation) + own plan. V1 flow-byte log
  files are mode 0600 with the parent dir at 0700, consistent with
  `~/.mvm` posture.
- **Per-observer timeout enforcement** — Q6 deliberately ships
  measurement without enforcement. The enforcement policy (fail-open
  vs fail-closed per-observer) is its own design.
- **TCP RST injection on `Drop`** — Q3 deliberately ships silent drop
  only. RST injection requires per-flow sequence-number tracking;
  meaningful on its own design merits.
- **Async / ring-buffered observer execution (Q6's option C)** — TCP
  reordering complexity for a problem V1 doesn't have. Defer.
- **`Defer` and `DropPacket`-vs-`KillFlow` verdict variants** — Q3
  deliberately minimal.
- **Bridge restart policy variants** — Plan 113's `BridgeRestartPolicy`
  schema reservation covers this; new variants land in their own plan
  + ADR.

---

## Status

🟡 **Design captured 2026-06-01; brainstorm paused mid-Q7.** Resume
via the brainstorm context at
`/Users/auser/.claude/plans/context-for-resuming-plan-robust-brook.md`,
close Q7–Q10, then re-render Tasks via `superpowers:writing-plans`.
Not yet on a branch.

---

## Self-review

- **Scope coverage** vs ADR-064 §Decision 8: closes the carve-out (Vz
  reports `payload_tap: true`), achieves cross-backend parity (Rust
  owns shuffle), establishes the architectural template AppleContainer
  inherits.
- **No placeholders** of the "engineer adapts" / "TBD" variety in the
  Files or Architecture sections — every field, struct, and call site
  named is real. The Tasks section is intentionally a placeholder
  pending Q7–Q10 closure; the **placeholder is named as such**, not
  hidden as fake content.
- **Plan numbering:** 141 is the next free slot — confirmed via
  `ls specs/plans/14[1-9]-*.md` (no matches). Plan 132's
  brainstorm-context guess was stale (132 became
  programmable-storage-io).
- **No backwards-compat shim** for the deleted
  `NetworkConfig.gvproxy` variant — matches memory
  `feedback_no_backcompat_first_version`.
- **References the existing memory + ADR base correctly:** ADR-064 for
  the architectural anchor, memory `project_gateway_audit_substrate_backend_coverage` for the AppleContainer carve-out, memory `feedback_no_placeholders_in_plans_or_code` for the no-placeholder discipline.
