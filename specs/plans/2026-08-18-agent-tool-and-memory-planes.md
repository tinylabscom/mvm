# Agent tool and memory planes

Backing: preview
Validation: none

**Status:** Design. Not implemented.
**Date:** 2026-08-18
**Implements:** ADR-045 sections 18 and 19 (agent tool calling), ADR-047 (the
agent memory plane).
**Depends on:** ADR-020 (host services broker), ADR-023 (egress substitution),
`specs/plans/2026-08-18-durable-agent-sessions.md` (session identity and the
retention ladder) — unmerged at the time of writing, living on
`docs/durable-agent-sessions` with no open pull request.

## The problem

Two gaps sit between the workflow documents and an AI agent actually running
inside an admitted microVM.

**Host-mediated tool calling has no defined surface.** ADR-045 section 8
governs what a controller's *planner* may do to the workflow graph. It says
nothing about an ordinary workload agent emitting tool calls at a model's
direction. Without a decision, a framework will reach for a guest-side client
speaking outward to a remote tool server, which is an unaudited egress path
and a namespace that mutates under a running admission.

Scope, per ADR-045 section 18: this is about tools that cross the VM boundary,
which is a handful of services. Tools running inside the guest — a shell, a
browser driver, an interpreter, a local tool server the agent talks to over
its own stdio — are deliberately out of scope and stay ungoverned, because the
NIC-less, verity-sealed microVM is what bounds them.

**Memory has no defined surface either.** The durable agent sessions design
carries the *substrate* across sandboxes — checkpoint, journal cursor,
approval head. It does not define what an agent writes down on purpose and
reads back three days later. In the absence of a definition an agent uses
whatever writable surface it can reach, and guest-authored bytes cross an
epoch boundary with no attribution, no scan, and no ceiling.

Both gaps have the same shape: a place where an LLM's output or an LLM's input
could become authority if nobody decides that it does not.

## What already exists

The mechanism for the tool plane is largely built. What is missing is the
derivation rule and the refusal to grow a second path.

| Piece | Where | State |
|---|---|---|
| `ServiceId` (`host.<name>.v<n>`) | `crates/mvm-contract/src/protocol/broker.rs:31` | Shipped |
| Plan-bound service list | `crates/mvm-contract/src/plan/execution_plan.rs:257` | Shipped |
| Binding-gated dispatch | `crates/mvm-hostd/src/broker/registry.rs:163` | Shipped |
| Handler convention | `crates/mvm-hostd/src/broker/handlers/host_{time,audit,assurance}_v1.rs` | Shipped |
| Secret fingerprint scanner | `crates/mvm-hostd/src/stream/secret_scan.rs:82` | Shipped, `pub(crate)` |
| Input gate (Preview claim 17) | `crates/mvm-hostd/src/stream/input_gate.rs` | Shipped |
| Session identity, retention ladder | `specs/plans/2026-08-18-durable-agent-sessions.md` | Design, unmerged |

The memory plane has no existing piece beyond the broker it rides on.

## Part A — The tool plane

**Where the ticked boxes live:** WS1, WS2 and WS4 are implemented in PR #2705
and WS3's gate in its own change. A ticked box here means implemented and
verified, not merged — check the PR before relying on it being on `main`.

### WS1 — Catalog derivation

- [x] **WS1 — Derive the presented catalog from the plan.** One function from
      an admitted `ExecutionPlan` to the tool descriptor set a guest may see,
      in `mvm-hostd`'s broker. No other path produces a catalog. A guest asking
      what tools it has receives the projection of its own binding.
- [x] Descriptor content — name, argument schema, human description — is
      host-held and versioned with the `ServiceId`, so what the model reads
      cannot be authored by the guest.

### WS2 — Per-tool argument policy

- [x] **WS2 — Typed argument policy per `ServiceId`.** ADR-045 section 19 is
      explicit that binding gates the tool while argument policy constrains the
      call. Today each handler validates its own arguments; a bound tool with
      an unconstrained argument is an unbound tool wearing a name.
- [x] One host-side schema per service — destination allow-lists, path scoping,
      size bounds — enforced before handler dispatch, beside the binding check
      rather than inside each handler.
- [x] Refusals audited with the service, the rejected field, and no argument
      values.

### WS3 — Host-side dynamic tool adapter

**Status: the compilation seam and the gate are in; the transport is not.**
The seam is `mvm_contract::protocol::upstream_tools::compile_namespace` — pure,
no I/O, no clock — which is where an upstream server's claims become
descriptors this host is willing to bind. The protocol client that *fetches*
those claims is deliberately still absent: it is transport behind a seam that
already refuses everything a malformed or hostile namespace can express, and
building it first would have meant testing the security properties through a
socket.

- [x] **WS3 — Compile an upstream tool namespace at admission.** Each upstream
      tool compiles to a `CapabilityId` under one `ServiceId`, and the result is
      sorted so an identical namespace always compiles to identical bytes —
      admission binds a digest, and a digest that depended on upstream ordering
      would admit differently run to run.
- [x] An upstream name this host cannot represent as a verb is refused rather
      than repaired. Lowercasing and substituting would collapse `getWeather`,
      `get_weather` and `Get Weather` onto one capability, which merges their
      authority. Duplicate verbs refuse the namespace instead of last-one-wins.
- [x] Discovery verbs answer from the plan binding — that is WS1's
      `admitted_catalog`. A namespace that gains a tool compiles to different
      bindings, so it cannot widen an admission already in flight.
- [ ] **WS3c — The transport.** Fully specified below; implementing it is
      mechanical. It is last on purpose: it is the only part with no security
      properties of its own, and putting it behind a seam that already refuses
      everything a hostile namespace can express means none of those refusals
      have to be tested through a socket.
- [x] A gate — in the `xtask check-*` family — refusing an outbound tool
      protocol client on any guest-reachable path, in the manner of
      `check-vsock-only-egress`. Without it this decision decays the first time
      a framework is vendored into a guest image.
- [x] The gate must catch a guest *originating a connection to a remote tool
      server*, and must not catch a tool server running wholly inside the
      guest over stdio or loopback — that is a supported in-guest tool, and a
      gate that greps for the protocol's name rather than for outbound
      connection setup would refuse it. A gate written the lazy way here
      breaks the common packaging of that ecosystem.

#### WS3c design — the transport, specified

**A namespace comes from operator configuration, not from discovery.** The host
reads a declared list of upstream servers; it does not go looking for them.
Discovery would make the set of things a workload might be offered depend on
the network at boot time, which is the mutable-namespace problem wearing a
different hat.

**One `ServiceHandler` per namespace.** `compile_namespace` yields the
descriptors; the handler owns the client and routes `verb` to the matching
upstream tool. It needs no new gate: `dispatch_capability` already enforces the
binding, the descriptor digest, the argument policy, the size bounds, the
timeout and replay, and it does that before the handler is reached.

**Prefer a host-side subprocess over stdio to a network client.** A subprocess
adds no network surface, no new dependency, and no destination to admit, and it
is how most of that ecosystem ships anyway. A remote server is not a second
transport — it is a *destination*, and it goes through the ordinary egress
policy like any other, which is what keeps one rule instead of two.

**Admission is fail-closed.** A namespace that cannot be fetched, cannot be
parsed, or fails `compile_namespace` refuses the admission rather than booting
a workload whose catalog advertises tools that will error on first call. A
planner that is told a tool exists and then finds it does not is worse off than
one never told: it will retry, and the retry is indistinguishable from the
enumeration the refusal path is bounding.

**Never re-fetch inside an admission.** If an upstream server dies mid-session,
its calls fail and the catalog does not change; the surface is fixed for the
admission's lifetime and a new surface requires a new admission. A handler that
re-fetched on failure would reintroduce exactly the mid-epoch mutation the
compile-once rule exists to prevent.

**Upstream text is `Observed`, in ADR-047's sense.** Names and descriptions are
authored by a third party and land directly in a model's context window. They
are bounded at compile time and they never become identifiers beyond the verb,
which is why an unrepresentable name is refused rather than repaired. When the
memory plane lands, a description quoted into a memory record carries the
`Observed` class for the same reason.

Tests worth having, none of which need a live server: a namespace that fails to
fetch refuses the admission; a namespace that compiles registers exactly its
compiled verbs and no others; a verb absent from the compiled set is `NotBound`
through the shipped path; an upstream process that dies leaves the catalog
unchanged; and a call whose upstream response exceeds the descriptor's output
bound is refused by the existing gate rather than by the handler.

### WS4 — Refusal is a signal

- [x] **WS4 — Unbound calls are planning signals, not errors.** The existing
      `NotBound` path already refuses. Add the audit entry shape and a
      structured refusal the agent runtime can hand back to the model, so an
      unbound call teaches the model its actual surface instead of surfacing as
      an opaque failure.
- [x] Repeated unbound calls to the same name are rate-bounded; a model in a
      retry loop is a denial-of-service against the broker.

## Part B — The memory plane

### WS5 — Store and record

- [ ] **WS5 — `mvm_core::config::memory_dir()` and the record type.** Follows
      the existing `checkpoints_dir()` / `snapshots_dir()` convention at
      `crates/mvm-core/src/config.rs:766`; never an inline `$HOME` join.
- [ ] Record per ADR-047 section 4: session ID, generation, admission digest,
      host monotonic `authored_at`, trust class, content digest, content.
      Provenance fields are host-stamped and rejected if guest-supplied.
- [ ] Keyed by session ID, never `VmId` or boot ID.

### WS6 — `host.memory.v1`

- [ ] **WS6 — The handler.** `crates/mvm-hostd/src/broker/handlers/
      host_memory_v1.rs`, following the three existing handlers. Verbs: append,
      query. No delete verb exists for the guest.
- [ ] Bound like any other service, so an unbound guest gets `NotBound` from
      the shipped path with no new gate.
- [ ] Trust class on append: `Observed` where the agent declares external
      input, and `Observed` for any record the agent derives from `Observed`
      input. The class does not launder by restatement.

### WS7 — Write-path scan and ceilings

- [ ] **WS7 — Reuse `SecretScanner` on the write path.** It is `pub(crate)` in
      the crate the handler lives in, so no visibility change is needed. Its
      semantics differ: the stream plane withholds on match, memory **refuses
      the write**. Wire the refusal, do not reshape the scanner.
- [ ] Fingerprints come from the per-VM substitution endpoint's resolved set,
      the same source `StreamPlane::open_input` uses. Only length, rolling
      hash, and category cross the process boundary.
- [ ] Per-record and per-session ceilings charged against the session budget of
      ADR-045 section 6.
- [ ] Document the limit where the code enforces it: a fingerprint match is a
      length-and-hash match, and encoding, derivation, and splitting defeat it.
      This raises the cost of exfiltration by recall; it does not end it.

### WS8 — Audit and retention

- [ ] **WS8 — Chain-signed write entries.** Session, generation, admission
      digest, size, trust class, content digest. No content bytes, matching the
      stream plane's payload-freedom rule.
- [ ] Append-only enforcement: no guest path mutates or removes a record.
- [ ] Host-side compaction emitting a new record that names what it summarizes,
      originals retained until retention expires.
- [ ] Retention rides the durable-sessions ladder (its WS5) rather than growing
      a second GC. Cryptographic erasure at session close stays ADR-046
      section 7.

### WS9 — Bounded recall

- [ ] **WS9 — Query with a host ceiling**, independent of what the guest asks
      for. Results carry their trust class.
- [ ] Scoped to the session. Cross-session recall is a separate capability, off
      by default, separately audited.

### WS10 — CLI and tests

- [ ] **WS10 — `mvmctl memory {ls,show,stats}`**, read-only, reading sidecars
      without a VM spawn, in the manner of `mvmctl deps inspect`.
- [ ] Tests and BDD per the Testing section.

## Forward compatibility — controller-launched child microVMs

ADR-045 section 3 gives a controller real lifecycle authority, and the
research basis models a launch as `ActionTarget::ChildMicroVm`, a peer of
`HostService` in one action vocabulary. Nothing in Part A needs redesigning to
carry that: a launch is a `CapabilityId` like any other, its catalog entry is
the same projection, and its `template` and `launch_mode` arguments are
precisely what WS2's `OneOf` constrains — with the template digest pinned the
way every descriptor digest already is.

Five things have to stay true, and they are recorded here so the next author
does not rediscover them by hitting them.

- [ ] **FC1 — Reservation is transactional; these gates are not.** Every gate
      in `dispatch_capability` is a stateless validator: check, then dispatch.
      A launch must atomically reserve across the resource dimensions and
      release on failure — reserve, dispatch, then commit or roll back. The
      argument-policy gate keeps its place ahead of the reservation, but the
      ladder has no rollback-capable slot and needs one. Putting the
      reservation inside the handler instead leaks budget on any crash between
      reserving and dispatching, with nobody holding the rollback.
- [ ] **FC2 — Launch idempotency is not replay refusal.** `consumed_invocations`
      refuses a repeated `(CapabilityId, AgentRequestId)` with `Replay`, and
      the `Idempotency` vocabulary offers `MintFresh`, `CacheRecent { ttl_ms }`
      and `DedupByCorrelation` — none of which means "the same key returns the
      same child handle". A controller retrying after a dropped reply needs the
      prior handle back, or it abandons a live child and relaunches. ADR-045
      invariant 8 is satisfied by refusing, so the invariant will not catch
      this; it appears only under retry. Needs a fourth variant, or launch
      outside that vocabulary.
- [ ] **FC3 — Launch returns a handle, not a finished child.** The capability
      means "start a child, return its handle", with results arriving on the
      mailbox plane. `CapabilityLimits.timeout_ms` is bounded, so modelling it
      as "run the child to completion" breaks as soon as a child outlives one
      call timeout.
- [ ] **FC4 — One descriptor, derived, never two authored.** The research
      basis's planning-layer `ActionDescriptor` overlaps this plan's
      enforcement-layer `CapabilityDescriptor`. Authored independently they
      drift, and then what the model is shown and what the host enforces
      disagree. Derive the planning descriptor from the enforcement one plus
      planning metadata, and decide that direction before the planning-snapshot
      phase — retrofitting it means re-cutting every descriptor digest.
- [ ] **FC5 — Fan-out is a budget, not a boolean.** See below.

### FC5 — Bounding how many children a controller may start

"May launch children" is a permission and the envelope answers it. "May launch
five hundred of them right now" is not something a boolean can express. The
envelope answers *whether*; a budget answers *how much more*, and only the
second stops a runaway. A controller with a legitimate launch permission and no
budget is a fork bomb with a signature on it.

Four limits, because each catches a failure the others miss:

- **Concurrency** — live children at once, per controller and per workflow.
  Catches fan-out.
- **Rate** — launches per window. Catches a crash-loop, which a concurrency cap
  never sees: children that die immediately keep the live count near zero while
  the host burns.
- **Cumulative** — total attempts over the workflow's life. Catches a slow
  bleed that stays under both of the above.
- **Depth** — a controller launching a controller. The bound must exist even
  while recursive delegation is deferred, because the bound is what keeps it
  deferred.

How it has to be enforced:

- [ ] **Reserve, do not check.** Check-then-launch is the bug: two controllers
      both read "under the cap", both launch, and the cap was never real. One
      authority, one atomic reservation, released on failure — the same reason
      the resource ledger is transactional rather than advisory.
- [ ] **Hierarchical.** A subtree budget, so one controller cannot spend the
      whole workflow's allowance and starve its siblings.
- [ ] **Host-side, from the signed constraint snapshot.** Never from a count
      the controller supplies or a limit it names.
- [ ] **Copy `crates/mvm-hostd/src/admission_budget.rs`'s two properties**
      rather than reinventing them. Count only *live* children, using the same
      pid-marker probe the fork path trusts, so a child that crashed without
      cleanup does not permanently lock its parent out — a safety check that
      becomes a lockout is worse than the exhaustion it prevents. And charge the
      configured maximum at admission rather than observed usage, so a child
      that has not finished starting is already counted.
- [ ] **Audit every refusal.** A controller repeatedly hitting its launch
      ceiling is a signal — a crash-loop, or a planner steered into one — and it
      should be visible without reading guest logs.
- [ ] **Make the refusal legible to the planner** (WS4). "Launch ceiling
      reached, N of M live, retry after T" lets a planner wait or re-plan; a
      bare error makes it retry immediately, which is indistinguishable from the
      attack the ceiling exists to stop.

The tests that would catch a wrong implementation, since a limit with no test
is decoration:

- [ ] Two launches racing for the last slot: exactly one is admitted. This is
      the check-then-act bug and the only test that finds it.
- [ ] A controller at its concurrency cap is refused, and the refusal is
      audited.
- [ ] A child that crash-loops trips the rate limit while the live count stays
      near zero — the case a concurrency cap alone reports as healthy.
- [ ] A child that died without cleanup stops being counted, so its parent can
      launch again rather than being locked out for the workflow's life.
- [ ] A failed launch releases its reservation; N failed launches do not shrink
      the budget by N.
- [ ] A controller cannot exceed its subtree budget by launching through a
      descendant.

## Reconciliation required

- The durable agent sessions design owns session identity, generation, and the
  retention ladder. This plan consumes them and defines neither. If WS5 here
  lands before that plan's WS1, memory has no session ID to key on, so the two
  sequence: durable-sessions WS1 first. That plan is not merged and has no open
  pull request, so this is a dependency on a document that could still move.
- Numbering was settled against the merge queue rather than against `main`:
  ADR-045 and ADR-046 land via #2691, which makes 047 the next free number on
  the `main` line. Four long-lived branches (`berg`, `cleanup-rearchitecture`,
  `release/0-17-0-prep`, `release/v0.17.0`) carry an unrelated historical
  scheme in which 045-049 name entirely different documents. That scheme never
  came back to `main` and is not a live claim on these numbers, but a future
  renumbering that merges one of those branches would collide with all three
  of these ADRs, not just this one.
- ADR-045's `Related` list cites a bare "Plan 329", a number held by three
  existing files. Left alone here; it needs the original author's intent.
- ADR-047 section 5 leans on Preview claim 17's scanner. If that claim's limits
  note changes, this plan's WS7 text changes with it — one statement of the
  limit, cited twice, not two statements that drift.

## Testing

Negative paths carry this design, so they are named individually:

- A guest without a `host.memory.v1` binding is refused by the shipped
  `NotBound` path.
- A record written in epoch N contributes nothing to the grants admitted in
  epoch N+1 — asserted against a synthesized plan, not against prose.
- An `Observed` record recalled in a later epoch is still `Observed`.
- A record derived from `Observed` input is not classified `Derived`.
- A write whose content fingerprint-matches a live substituted secret is
  refused and audited.
- A memory audit entry carries the binding and no content bytes.
- A guest cannot delete or rewrite; compaction retains originals.
- Recall is bounded by the host ceiling regardless of the guest's query.
- Cross-session recall without its capability is refused.
- A tool call to an unbound `ServiceId` is refused and audited.
- A bound tool with an out-of-policy argument is refused before dispatch.
- A tool descriptor set presented to a guest matches its plan binding exactly.
- An upstream namespace that adds a tool after admission does not widen a
  running guest's surface.

Each of these must be checked against a mutation that turns it red. A test
that passes with the enforcement removed is the failure mode this repository
has already paid for more than once.

## Out of scope

- Semantic quality of remembered content. Memory is bounded and attributable,
  not correct.
- Cross-session and cross-tenant memory sharing beyond refusing it by default.
- Embedding, ranking, and retrieval strategy. Recall here is a bounded query;
  anything smarter is a `Derived` write the agent performs itself.
- The controller planner's own tool surface, which stays under ADR-045
  section 8 until follow-up decision 9 settles whether the two share one
  derivation.
- Fleet-side memory replication and placement (`mvmd`).

## Open questions

- Whether the trust class should be a lattice rather than two values. Two
  classes applied correctly beat five applied by guess, so this starts at two
  and widens only against a case that needs it.
- Whether host compaction should be scheduled or agent-triggered. Scheduled
  compaction can summarize a record the agent was about to cite; triggered
  compaction gives the guest a lever on host work.
- Whether a memory write should be admissible while a session is hibernated.
  Nothing is running, so the answer is probably no, but a park-time flush of
  in-flight findings is the obvious counter-case.
- What a memory ceiling does when it is hit mid-task: refuse the write and let
  the agent decide, or force compaction. Refusing is honest and may strand a
  long investigation.
