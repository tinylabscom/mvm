# Workload service plane — named addressing, host-managed services, catalog provisioning

Backing: preview
Validation: none

Status: **IN PROGRESS** — A-1, B-1..B-7 and C-1/C-5/C-6 have landed. WS-B is
complete end-to-end except for a live witness (B-8). No claim in
`specs/adrs/001-microvm-security-posture.md` depends on this work yet.

## 1. Why

A survey of a commercial enterprise application-platform vendor was run on
2026-08-25 to ask where mvm should take inspiration. Their pitch is push-a-repo
provisioning, a service catalog you can launch from, isolated per-workload private
networks with authenticated service-to-service calls, managed databases/queues/
vector stores, and demand-driven scaling.

The survey's most useful output was not a feature list. It was the observation
that **mvmd has already grown that vendor's API surface, breadth-first, and it
provisions nothing.** `crates/mvmd-gateway/src/routes/` holds 143 modules and
~90k lines (plus a 17,858-line `state.rs` of DTOs), all mounted in `server.rs`.
Exactly six of them — `cluster`, `instance`, `sandbox`, `pool`, `storage`,
`tenant` — reference `AgentDispatcher`, `mvmctl::`, or instance lifecycle. The
other 137 are CRUD over an in-process store. `openapi.json` documents 38 paths,
all core.

So the lesson taken from the survey is inverted from the obvious one: **do not add
surface. Add depth on seams mvm already owns.** Three workstreams follow. Each one
lands on machinery that already exists, and each is scoped so that a reader can
tell from the checkboxes whether it provisions anything.

### What was explicitly rejected

- **Repo-inspection that provisions implicitly.** Incompatible with admission:
  every workload boots from a signed `ExecutionPlan`, and `--prod` fails closed.
  Inference may emit a plan for a human to sign; it may not become a runtime that
  side-effects. Tracked separately as a follow-up (see `specs/SPRINT.md`).
- **Breadth for its own sake** — GPU pooling, CDN, service mesh, multi-region.
  mvmd paid for these once already in route files that provision nothing.

## 2. WS-A — Named workload-to-workload addressing

**Problem.** An mvm workload cannot reach another mvm workload at all. Workload
microVMs boot with no NIC (`check-single-network-path` fails the build if one
appears); egress leaves only over the `NetworkFlow` channel to the per-VM
`mvm-network-endpoint`, whose `EgressGate` is the sole claim-10 decision point.
That is the right posture and is not being relaxed. What is missing is east-west.

**Approach.** Let a workload dial a *name*. The host resolves it. The guest never
learns an address and never gets a NIC, so the existing invariant is untouched —
the host endpoint still originates the connection and can authorize, substitute,
and audit it exactly as it does for outbound egress today.

The single interception point already exists. Both call sites that turn a
guest-supplied target into a verdict are:

- `crates/mvm-hostd/src/supervisor/flowmux.rs:662`
- `crates/mvm-hostd/src/supervisor/flowmux/session.rs:384`

both spelled `self.gate.decide_request(&format!("{host}:{port}"))`. Service-name
resolution goes *in front of* that call: if `host` matches a name bound in the
admitted plan, it resolves to the peer's host-side endpoint; otherwise the target
falls through to the existing DNS-pin path unchanged.

### Tasks

- [x] A-1. Add a `PeerName` newtype (named for distinctness: `ServiceId`,
      `ServiceCatalog` and `Catalog` already exist and mean other things) to `mvm-contract` (`no_std`) — a
      validated workload-local service name. Reject anything that could collide
      with a DNS name or a numeric target so fall-through stays unambiguous.
- [ ] A-2. Add a peer-binding list to the plan: which service names this workload
      may dial, and which workload each resolves to. Mirrors the existing
      `SynthesisInput.services` field (`crates/mvm-core/src/plan/synthesis.rs:192`)
      rather than inventing a second binding shape.
- [ ] A-3. Add `EgressGate::decide_service(&self, name, port)` beside the existing
      `decide_request` / `decide_addr` in
      `crates/mvm-vmm/src/vsock_egress_bridge/egress_gate.rs:167`. Default-deny on
      an unbound name, matching `default_deny()`.
- [ ] A-4. Build a host-side registry mapping a bound name to the live peer's
      endpoint socket. Fail closed when the peer is not running — a name that
      resolves to a dead VM refuses rather than hanging.
- [ ] A-5. Thread A-3 into both `decide_request` call sites (A-2 above). One
      resolution helper, called from both — not two copies.
- [ ] A-6. Emit a chain-signed audit entry per resolved service dial, carrying the
      binding and no payload bytes, following
      `stream_audit_entries_carry_the_binding_and_no_payload_bytes`.
- [ ] A-7. Tests: bound name resolves; unbound name denied; name resolving to a
      stopped peer denied; a numeric target still takes the DNS-pin path; a plan
      with no peer bindings admits nothing east-west.
- [ ] A-8. Extend `xtask check-single-network-path` so the new resolution helper is
      pinned to the one spawn site, i.e. the gate cannot be bypassed by a second
      resolver appearing later.

### Definition of done for WS-A

Two workloads launched from signed plans can address each other by name, neither
has a NIC, `check-single-network-path` is green, and every dial appears in the
audit chain.

## 3. WS-B — Managed services as broker handlers

**Problem.** The vendor sells databases and queues as first-class. mvm's analogous
seam already exists and is under-used: the host-services broker.

**Why this seam.** A handler registered here inherits, by construction, the
properties claims 12 and 13 are about — binding-gated dispatch before the handler
runs, and no raw credential crossing the channel. The workload gets its data store
**without a network path and without holding a credential**, which is a stronger
posture than the one being taken as inspiration.

The pattern to copy is already in-tree.
`crates/mvm-hostd/src/broker/handlers/` holds three handlers
(`host_time_v1`, `host_audit_v1`, `host_assurance_v1`), and
`register_bound_handlers` in that directory's `mod.rs` registers each one *only*
when its `ServiceId` appears in the admitted bindings. A service absent from the
bindings is never registered and therefore refuses with `NotBound` at the registry
gate (`crates/mvm-hostd/src/broker/registry.rs:274`).

### Tasks

- [x] B-1. Add `crates/mvm-hostd/src/broker/handlers/host_kv_v1.rs` implementing
      `ServiceHandler`, modelled on `host_time_v1.rs`. Verbs: get, put, delete,
      list-prefix.
- [x] B-2. Back it with a per-workload store rooted under a `mvm-core::config`
      helper. No inline `$HOME` joins — that path ignores `MVM_HOME` and breaks
      worktree isolation.
- [x] B-3. Register it in `register_bound_handlers`, gated on the binding exactly
      as `host.time.v1` is. Stateless registration; no entry in `BoundHandlers`.
- [x] B-4. `#[serde(deny_unknown_fields)]` on every request/response type, so an
      unexpected field fails closed (W4.1).
- [x] B-5. Namespace the store by workload id so one workload cannot read another's
      keys, and add the negative test for it.
- [x] B-6. Tests: unbound service returns `NotBound`; unknown envelope field
      rejected; cross-workload read refused; round-trip; oversized value refused.
- [x] B-7. Wire the CLI so a run can request the binding. **No new code was
      needed.** `parse_host_service_bindings`
      (`crates/mvm-cli/src/commands/vm/host_services.rs:16`) is generic over any
      well-formed `ServiceId`, and `crates/mvm-hostd/src/bin/mvm-broker.rs:127`
      registers from the admitted plan's binding list, so
      `--host-service host.kv.v1` already reaches the handler.
- [ ] B-8. Live witness. Every test so far drives the handler directly; nothing
      yet exercises a booted workload reading and writing through the broker.

### Definition of done for WS-B

A workload with the binding reads and writes keys over the broker; a workload
without it gets `NotBound`; neither ever sees a credential or a socket.

## 4. WS-C — Catalog entries that provision

**Problem.** `mvm_core::catalog::CatalogEntry`
(`crates/mvm-core/src/catalog.rs:9`) is `{ name, description, flake_ref, profile,
default_cpus, default_memory_mib, tags }`, and `mvmctl catalog` is `list` /
`search` / `info` only — a phone book. `mvmctl template` is deliberately read-only
too. There is no edge from "I found the entry" to "it is running".

**Approach.** Give an entry a bound workload shape and add the run edge. Every
downstream piece exists already: plan synthesis and signing, sealed dependency
volumes, the egress gate. This is the shortest path from the catalog to a running,
admitted workload.

### Tasks

- [x] C-1. Extend `CatalogEntry` with an optional bound workload shape (entrypoint,
      requested service bindings, resource ceiling). New fields carry
      `#[serde(default)]`, so no schema-version ceremony.
- [ ] C-2. Add `mvmctl catalog run <name>` to `CatalogAction`
      (`crates/mvm-cli/src/commands/catalog/mod.rs`).
- [ ] C-3. Map the entry to a `SynthesisInput` and admit through the existing
      `synthesize_plan` (`crates/mvm-core/src/plan/synthesis.rs:665`) — reusing the
      claim-8 admission path, not a parallel one.
- [ ] C-4. Populate `SynthesisInput.services` from C-1's requested bindings, so a
      catalog entry can ask for WS-B's store and WS-A's peers declaratively.
- [x] C-5. Refuse an entry whose resource shape exceeds the admission ceiling.
      `CatalogEntry::resolve` takes the ceiling as a parameter rather than
      reading it, so the caller passes the operator's configured limit and no
      second source of truth is introduced.
- [x] C-6. Under `--prod`, refuse an entry with no pinned artifact digest before
      any network fetch. Ordering is covered by
      `the_prod_pin_check_precedes_the_ceiling_check`.
- [ ] C-7. Tests. The resolution ladder is covered (`resolve_tests`, 9 cases:
      bindings parse into plan types, base image not runnable, prod-unpinned
      refused, pin-before-ceiling ordering, over-ceiling with both numbers,
      at-ceiling admitted, malformed service/peer named, legacy entry parses,
      round-trip). Still open: the admits-a-signed-plan case and CLI help text,
      both of which need C-2/C-3.

### Definition of done for WS-C

`mvmctl catalog run <name>` boots an admitted workload from a signed plan, and the
refusal paths above each have a test.

### Remaining for WS-C

Every bundled catalog entry is a base image — none declares an entrypoint
anywhere in the tree — so all five carry `workload: None` and `resolve` refuses
them as not runnable. Authoring real workload shapes means deciding what each
profile starts, which is a per-profile call and not something to infer from a
profile name.

## 5. Sequencing

WS-A first: it is the only architecturally novel piece, and WS-C's C-4 binds to
both of the others. WS-B is independent of WS-A and can proceed in parallel. WS-C
depends on both for its C-4 task only; C-1..C-3 can start immediately.

## 6. Gates

Every workstream runs the standard set before it is called done:

- [ ] `cargo fmt --all -- --check` (nightly, per CI Lint)
- [ ] `cargo nextest run --workspace`
- [ ] `cargo test --workspace --doc`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] `just check-gated`
- [ ] `cargo run -p xtask -- check-single-network-path` (WS-A especially)
- [ ] `cargo run -p xtask -- check-claim-catalog`
