# Workload service plane — named addressing, host-managed services, catalog provisioning

Backing: preview
Validation: none

Status: **IN PROGRESS** — WS-A is complete end-to-end: `--peer` authors a
binding that reaches the gate. WS-B is complete; B-8's live scenarios are written but unexecuted.
WS-C landed as C-1/C-3/C-4. WS-B is complete
except an executed live witness. WS-C landed as C-1/C-3/C-4 after a
correction: its premise was wrong, and no `catalog run` verb was needed. No claim in
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
- [x] A-2. Add a peer-binding list to the plan (`PeerBinding` in `mvm-contract`): which service names this workload
      may dial, and which workload each resolves to. Mirrors the existing
      `SynthesisInput.services` field (`crates/mvm-core/src/plan/synthesis.rs:192`)
      rather than inventing a second binding shape.
- [x] A-3. Add `EgressGate::decide_peer(&self, host, port)` beside the existing
      `decide_request` / `decide_addr` in
      `crates/mvm-vmm/src/vsock_egress_bridge/egress_gate.rs:167`. Default-deny on
      an unbound name, matching `default_deny()`.
- [x] A-4. ~~Build a host-side registry mapping a bound name to the live peer's
      endpoint socket.~~ **Design changed; no registry was built.** A peer already
      receives traffic through an admitted *ingress mapping*
      (`mvm_contract::plan::types::IngressMapping`), whose `host_addr`/`host_port`
      are in that peer's signed plan. Binding the resolved address into the
      caller's plan makes the peer set signed rather than resolved against
      mutable runtime state, which matches how egress destinations are handled
      and removes a component that could disagree with reality. Liveness needs
      no check: nothing listens at the address until the peer's endpoint binds
      it, so a dial to a stopped peer is refused by the connect itself.
- [x] A-5. Thread A-3 into both call sites through one helper. The helper is
      `EgressGate::decide_target`, on the gate itself rather than beside it, so
      the branch and the decision live in one type.
- [x] A-5b. A third call site turned up that the plan had missed:
      `network_endpoint_proxy.rs`, the secret-substitution HTTP leg. It now
      refuses peer destinations explicitly instead of falling through to
      `decide_request` and denying them by accident. **Open question, decided
      conservatively for now:** whether a peer request should ever receive a
      substituted credential. Refusing is the answer until someone decides
      otherwise.
- [x] A-6. Emit a chain-signed audit entry per resolved peer dial carrying the
      binding and no payload bytes. The entry already carried `target` (which
      *is* the binding, `name:port`) and `resolved_ips`; what was missing was
      which namespace decided it, so `decide_target` now returns a `Route`
      alongside the verdict and every connect-path entry carries it. The route
      comes back from the gate rather than being re-derived, because A-8
      forbids a second suffix test outside the gate.
      Payload-freedom is witnessed mechanically by `check_flow_audit_labels`:
      the connect paths may only build labels from an allow-list. That is a
      source-level property no runtime test can establish — it is about which
      keys can ever be constructed.
- [x] A-7. Tests (14 in `peer_tests`): bound route resolves to the peer's
      ingress address; a gate with no bindings admits no peer; a bound peer on
      an unbound port refused; an unbound name refused and the refusal lists
      what is admitted; a malformed peer name is `Malformed`, not allowed; a
      peer binding does not widen ordinary egress; first matching binding wins.
      Route coverage: a peer target is the peer route whether allowed, refused,
      or malformed; an ordinary host and a numeric target are the egress route.
      Liveness: a stopped peer is still admitted by the gate and refused by the
      connect — pinned deliberately so nobody later "fixes" the gate to probe
      liveness.
- [x] A-8. Extend `xtask check-single-network-path` (`check_single_peer_resolver`):
      the branch exists exactly once in the gate, both connect sites go through
      `decide_target`, neither calls `decide_peer` or re-derives the branch, and
      the refusal site resolves no peer. Both failure modes were mutation-checked
      against the live gate.

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
- [x] B-8. Live witness. **Starting it found that the store was not reachable
      from workload code at all**, so the witness could not have been written.
      Three things were missing and are now in place:
      the in-guest client (`mvm_agentd::host_kv`), four `host.kv.*` arms in the
      SDK cdylib's `dispatch_on` (which is a hardcoded match, not a generic
      passthrough — an unlisted method simply has no arm), and
      `host.kv.v1` in `SDK_HOST_SERVICES`, without which binding the service
      attached no sidecar and the guest had no library to call it with.
      Reachability is witnessed by
      `binding_the_key_value_store_attaches_the_sidecar`.

      This is the third time in this plan that a capability was complete on the
      host and unreachable from a workload — after the `--peer` flag (D-4) and
      the CLI-to-gate thread (A-9). The common cause is that unit tests cover
      the seam under test and say nothing about whether anything can call it.

- [x] B-8.1 `mvm.kv` — the Python SDK surface (`get`/`put`/`delete`/`list_keys`),
      matching the existing `mvm.audit` shape. `list_keys` rather than `list` so
      it does not shadow the builtin.
- [x] B-8.2 An in-guest fixture (`fixtures/kv_roundtrip.py`) speaking the C ABI
      directly rather than importing `mvm`, since the package is not in an
      arbitrary guest image. It covers absent-before-write, write, read-back,
      list, delete, and absent-after-delete.
- [x] B-8.3 Two `@live` scenarios: a bound workload round-trips a key, and an
      unbound one is refused from inside the guest.
- [x] B-8.4 `every_kv_method_routes_to_the_store`, driving the mock broker.
      **Necessary because the obvious check does not work:** running the fixture
      against the real cdylib on a macOS host returns a *transport* error for
      every method — including a method with no arm at all — because the vsock
      dial happens before dispatch. A missing arm would have been invisible.
      `an_unknown_method_is_not_routed` keeps that assertion from being vacuous.
- [x] B-8.5 Keep the live fixture on its sized, read-only ext4 `--volume`.
      The transient parser accepts that form and keeps the witness independent
      of directory-sharing support on Firecracker, HVF, and libkrun.

### Known limits of B-8

- **The `@live` bound-workload scenario is now witnessed.** On an Apple
  Silicon host, the sized read-only ext4 fixture was accepted by the transient
  path, the guest loaded the musl sidecar, and the broker round-trip returned
  `KV-OK`. The unbound refusal scenario still needs a fresh live run before the
  whole pair can be treated as current evidence.

### Definition of done for WS-B

A workload with the binding reads and writes keys over the broker; a workload
without it gets `NotBound`; neither ever sees a credential or a socket.

## 4. WS-C — Catalog entries that declare what they need

**The original framing here was wrong and is corrected in place.** It said the
catalog was a phone book with "no edge from *I found the entry* to *it is
running*". That is true of `mvm_core::catalog::Catalog` — the browse-only image
catalog behind `mvmctl catalog list/search/info` — but there are **two**
catalogs, and the other one already boots:
`mvm_core::runtime_catalog::RuntimeCatalog` resolves `--runtime <name>` to an
image and is also what project detection uses. `mvmctl run --runtime python`
has worked the whole time.

So no `catalog run` verb was added. Adding one would have created a second way
to boot a catalogued name, which is the drift this plan exists to avoid.

What was genuinely missing is narrower and more useful: **a catalog entry could
not declare what it needs.** An operator had to know that a given runtime wants
a key-value store and pass `--host-service host.kv.v1` every time, learning it
from a failure the first time.

- [x] C-1. ~~Extend `CatalogEntry` with a bound workload shape.~~ Done first on
      the *browse* catalog, which was the wrong type — it is not the one that
      boots. Reverted in full (`catalog.rs` and its CLI table are byte-identical
      to main again) and redone on `RuntimeEntry`, so there is one
      runnable-entry concept rather than two overlapping ones.
- [x] C-3. `RuntimeEntry` gains `services` and `peers`. `Detection` carries them
      through **parsed**, not as strings, so a malformed entry is a catalog
      error at resolution rather than a signed plan carrying a binding no
      handler could satisfy.
- [x] C-4. `--runtime` merges the entry's declared bindings into the run args,
      which already flow to `SynthesisInput.services` via the existing
      `resolve_bindings_and_sidecar` path. The merge is a **union**: the entry
      declares what the runtime needs, the flag is what the operator asked for,
      and neither may drop the other's binding.
- [x] C-5/C-6. ~~Ceiling and `--prod` pin checks on the entry.~~ Dropped with the
      reverted type. Both already exist on the run path they belong to —
      admission owns the ceiling (`admission_budget.rs`) and `--prod` already
      refuses mutable image references before any network fetch. Re-deriving
      them per catalog entry would have been the second source of truth this
      plan keeps arguing against.
- [x] C-7. Tests. Catalog side (7): no builtin entry declares a binding;
      declared bindings parse onto the detection; a malformed service or peer
      refuses at resolution and the refusal names the entry; a matched entry
      with malformed bindings is an error rather than a silent no-detection, by
      command and by project file; a genuine miss is still `None`; an entry
      without the new fields still parses. CLI side (4): a declared binding
      reaches the run args; declared and operator bindings are unioned; a
      binding both declared and passed appears once; an entry declaring nothing
      changes nothing.

### Known limits of WS-C as landed

- **No bundled runtime declares a binding.** Every entry is a language runtime
  that works with nothing bound, and inventing a default would hand every
  `--runtime python` user a service they never asked for. The mechanism is
  live; the first real declaration is a per-runtime decision.
- **Peers are carried but not yet consumed.** `Detection.peers` parses and
  reaches the CLI. Threading it into the plan's peer bindings needs the
  admission-side field from WS-A A-2 wired through the run path, which is not
  done.

### Known limits of WS-A as landed

- **Peer dialing is TCP-only.** `handle_open_tcp` routes through
  `decide_target`; `handle_open_udp` uses `decide_udp_addr` and has no peer
  branch. A UDP dial to a peer name is refused by ordinary egress policy.
  Widening it means giving the UDP path the same single-branch treatment, not
  a second branch.
- **The substitution proxy refuses peers** (A-5b), so a peer cannot be reached
  over the HTTP leg that substitutes credentials.
- **No live witness.** Every test drives the gate directly. Nothing yet boots
  two workloads and has one dial the other.

## 4b. WS-D — Docs and BDD

Definition of done for anything in this plan: the README, the website docs, and
the BDD suite reflect it. Added at the maintainer's direction on 2026-08-25.

- [x] D-1. BDD suite `features/suites/s30_service_plane/` with three feature
      files — peer addressing (8 scenarios over the real `EgressGate`), the host
      key-value store (6 over the real registry and handler), and declared
      runtime bindings (4 over the real catalog, plus one `@live` boot). Steps in
      `crates/mvm-conformance/tests/steps/service_plane.rs` drive real seams, so
      they are hermetic and gate on every PR rather than needing `MVM_BDD_LIVE`.
- [x] D-2. README: a store section under the vsock-only invariant, and a peer
      section that says plainly there is no CLI flag yet.
- [x] D-3. Website: `guides/flowmux-networking.md` gains both sections, with the
      peer half behind a `:::caution[Not yet authorable]` admonition.
- [x] D-4. **A fabricated `--peer` flag was caught before it shipped.** The first
      draft of D-3 documented `mvmctl machine run --peer <name>:<port>=<addr>:<port>`
      with a worked example, and added a row for it to
      `reference/cli-commands.md`. **No such flag exists.** Peer bindings are not
      authorable from the CLI at all — `PeerBinding` is a contract type the gate
      consumes, and nothing threads it from `mvmctl` through admission to the
      supervisor. The row was removed and both documents rewritten to say so.
      This is the exact failure `check-declared-backing` exists for, and no gate
      covers prose about CLI flags, so it would have shipped.
- [x] D-5. Peer usage re-documented now that A-9 has landed, with every
      documented invocation executed against the built binary first.

### A-9 — thread peer bindings from the CLI to the gate (DONE)

The gap D-4 exposed, now closed. `mvmctl run --peer NAME:PORT=ADDR:PORT` and
`machine run --peer ...` author a binding that reaches `EgressGate::decide_peer`.

**The plan called for a parallel channel through six layers. That was the wrong
shape.** A peer route *is* network policy — where this workload may connect —
and `NetworkPolicy` is already threaded from the CLI through the signed plan to
the endpoint that builds the gate. Carrying `peers` on the policy is one field
instead of six re-threads, and it removes the failure the plan warned about by
construction: there is no layer that can forget to pass it along.

- [x] A-9.1 `--peer NAME:PORT=ADDR:PORT` on `RunArgs`, parsed by
      `parse_peer_binding` and validated at the CLI boundary, so a malformed
      route never reaches the signed plan.
- [x] A-9.2 `NetworkPolicy` carries `peers` on both variants (`#[serde(default)]`,
      so every existing policy document still parses).
- [x] A-9.3 No new plumbing: the policy already crosses to the endpoint.
- [x] A-9.4 `build_egress_gate` attaches `policy.peers()` at the same place it
      projects the egress rules — one construction site for the whole gate.
- [x] A-9.5 The assertion whose absence allowed D-4:
      `a_peer_binding_on_the_admitted_policy_reaches_the_gate`. Three of the
      four tests in that module go red when `.with_peers(..)` is removed.
- [x] A-9.6 D-5 done: README, guide, and CLI reference document `--peer` with a
      real invocation, and **every documented invocation was executed** before
      the docs were committed.

**A second partial thread was caught by running the binary, not by the tests.**
With every unit test green, `mvmctl run --peer <malformed> --dry-run` exited 0.
`--dry-run` returns before grants resolution, and both the preflight and the
receipt resolved the policy through the two-argument
`resolve_run_network_policy`, which drops peers. So the flag parsed, the tests
passed, and the dry-run silently ignored it. Both sites now use
`resolve_run_network_policy_with_peers`. The lesson is the same one D-4 taught
from the other direction: a green unit suite says nothing about whether a user
invocation reaches the code under test.

`peers_survive_both_egress_arms` covers the related trap —
`enforced_network_policy` has a projected-grant arm and a legacy arm, and a
per-arm attachment would have dropped peers for any run that authored an egress
grant.

### A-10 — the two A-9 gaps, closed

- [x] A-10.1 **Peers persist on a machine spec.** `--peer` is on
      `machine create` and `machine start`, and `MachineSpec.peer` carries it,
      so a stored machine keeps its routes across a stop/start the way
      `allow_host` does. Without it a second start would boot peerless and the
      workload would fail to reach a dependency it reached the first time.
      `machine_config_diff` reports a changed peer set as drift, or a start
      with different routes would silently reuse the old ones. A spec written
      before the field existed loads as peerless rather than failing.
      Stored raw rather than parsed: the spec records what the operator asked
      for, and parsing happens once at launch where a refusal can be reported.
- [x] A-10.2 **The dry-run summary names the routes.** It printed
      `network: deny-all` for a policy carrying peers, which reads as "this
      workload can reach nothing" — the opposite of true for the common shape
      of a service that talks only to its own database. A `peers:` line now
      reports each `name:port -> addr:port`, separate from the egress posture
      because a peer route is not egress.

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
