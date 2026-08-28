# Plan 296 — fleet stream fan-out

**Status:** Complete. WS1–WS6 landed.

**Integration repair (2026-08-28):** `EdgeConnector` now owns the admitted
`InputRoute`, not a bare `InputSession`, so `step()` carries cleared bytes over
the guest transport and `close()` delivers the scanner tail before EOF.
`StreamPlane::subscribe` exposes the redacted reader by host-resolved VM name,
and `LaunchOutcome::admitted` hands the fleet caller the exact authority object
used for the boot rather than inviting a second admission.

`mvm` ships the mechanism; `mvmd` declares the edges and resolves the bindings.
That split is why the landed half has **no production caller in this
repository** — see "Declared dormancy" below. It is a declaration, not an
oversight.

Connect one workload's output stream to another's input stream, so a fleet can
run a workflow. `mvmd` declares the edges; `mvm` exposes the primitives and
never learns what a fleet is.

Predecessor: plan 283 built both halves — a plan-bound output subscription and a
plan-bound input grant — and reserved this slot deliberately rather than leaving
it to be retrofitted. Read plan 283's "Slice 2 — fleet fan-out" section and
ADR-035 before this document; the four decisions below were settled there.

## Why this is composition, not construction

Everything an edge needs already exists and has been reviewed:

- **Output subscription** — `connect_stream` / `serve_stream` /
  `ReaderHandle::drain_verified`, with `verify_chain_from` for the pruned or
  resumed windows an edge will normally hold.
- **Input grant** — `InputGate::open(vm, &AdmittedPlan)` → `StreamPlane::write_input`,
  default-deny, leased, secret-scanned across frame boundaries.
- **A single crossing point** — the host broker is already the only place bytes
  cross, so it is already the single authorization point.

An edge adds no transport. It binds two things that already talk to the host.

## The invariant this plan must not break

**A guest never addresses another guest.** VM B names a binding from its own
signed plan; the host resolves that binding to VM A and copies bytes between two
independent vsock channels. A and B never share a transport, never learn each
other's identity, and neither gains a NIC.

That is what keeps fleet data-sharing from becoming guest networking by the back
door. `xtask check-vsock-only-egress` and `check-uniform-vsock-egress` must stay
clean, and no edge may introduce a tap, a gateway token, or a virtio-net
reference on a workload path.

## Decisions, settled in plan 283

| # | Decision | Rationale |
|---|---|---|
| E1 | Redaction is a property of the edge, defaulting to redacted | Always-redact corrupts a pipeline whose second stage needs what the first computed; never-redact makes every edge a leak path around the single seam. The edge declares its posture in the signed plan; fidelity requires an explicit signed opt-out, and that opt-out is audited. |
| E2 | On an opt-out edge the consumer receives raw bytes; the durable transcript still stores the redacted copy, and the divergence is audited | Mirrors how `invoke` returns its caller's own bytes without weakening the artifact that outlives the run. |
| E3 | The single-writer lease stays; fan-in is a merge node | Two producers interleaving into one stdin produce corrupted records and stdin carries no framing to recover them. A workflow needing fan-in declares a merge stage, which is itself a workload the fleet can express. |
| E4 | Backpressure never stalls a producer and never silently loses | `lossy` (default) rings, evicts oldest, marks the gap and audits it. `reliable` keeps the producer unstalled but fails the edge loudly when its buffer fills. A mode named `reliable` must never quietly drop records. |
| E5 | The topology is a DAG, rejected at admission | A cycle breaks EOF propagation, so nothing downstream of itself ever closes. With lossy eviction it does not even deadlock — it degrades into a silently churning loop. And every edge hash-chains, so a cycle leaves no order in which to ask what a workload saw. The topology is declared, so validate the static graph once and refuse before anything boots. |
| E6 | A broken edge fails the workflow. It does not silently reconnect across a consumer restart | Reconnection is not free: the gate builds a fresh `SecretScanner` per session, so a secret split across the restart boundary would be scanned by two scanners with neither seeing the whole — the same hole this project refused to open at route displacement. Surviving a restart also means buffering on the producer for an unbounded interval, which breaks the bounded-memory invariant. Workflows already have a supervisor; re-running the DAG is the correct recovery, at the correct layer. The edge records its last delivered sequence in the chain-signed log so a re-run is reasoned about rather than guessed. |
| E7 | The redaction opt-out (E1) requires an explicit operator acknowledgement, distinct from the plan signature | A plan is signed on behalf of whoever launched the workload, so letting a workload's own plan opt its edge out of redaction lets a careless or compromised workload definition export raw PII to another workload with no human in the loop. Between two workloads these are different trust domains. This repository already has the right shape for it: unrestricted egress requires `MVM_ACK_UNRESTRICTED_NETWORK=1`, an operator acknowledgement never set in CI. The redaction opt-out takes the same form and is audited. |

Two consequences worth stating plainly, because they will surprise someone:

- An edge consumes the consumer's single input slot, so a workload fed by an
  edge cannot simultaneously take operator stdin. That must be a diagnosable
  admission error, not a runtime surprise.
- Iteration is not expressible. A workflow needing a loop re-invokes the DAG
  from an external orchestrator, which keeps termination and provenance intact.

## Work

- [x] **WS1 — the edge binding.** Landed. `mvm_contract::stream::edge` defines
  `StreamEdge` (binding name, `EdgeRedaction`, `EdgeBackpressure`), the plan
  carries `ExecutionPlan.stream_edges`, and `check_plan_edges` refuses a
  duplicate binding, a raw edge without `MVM_ACK_RAW_STREAM_EDGE`, and an edge
  contending with operator stdin. Both postures default to the safe side and
  are `#[serde(default)]`, so a plan written before the field existed cannot
  acquire a raw edge by omission. `stream_edges` is `skip_serializing_if`
  empty, so no existing plan's content address moved.

- [x] **WS2 — DAG validation at admission.** Landed.
  `mvm_contract::stream::topology::validate` takes resolved edges and refuses
  fan-in and cycles, returning flow order on success. Iterative DFS, because a
  fleet can trivially declare a chain deep enough to blow a recursive one.

  One consequence fell out and is worth keeping: with fan-in refused first
  (E3), every consumer has at most one in-edge, so a cycle can only ever be an
  **isolated loop** — entering one from outside necessarily gives the entry
  node two writers and is refused as fan-in instead. The tests cover the
  self-edge, the two-node cycle, a five-node cycle, a cycle in a second
  disjoint component, and a diamond that must *not* be mistaken for one.

- [x] **WS3 — the connector.** Landed as `EdgeConnector`, deliberately
  **caller-driven**: `step()` moves what is available and returns, owning no
  thread, no timer and no lifecycle. The caller is in another repository, and
  a connector that had picked those answers here would have picked them blind.
  What it does own is local: acceptance order (one pass, never reordered,
  `seq` strictly increasing across the edge's life), lease upkeep on every
  step including idle ones, and `close()` routing through `InputRoute::close`
  so the scanner's withheld tail is carried to the guest before EOF rather
  than merely returned to the caller or dropped.

  **E2 cannot be served from this reader, and that is a finding.** Redaction
  runs before hashing, so a record reaching a `ReaderHandle` has already
  crossed the seam and no raw copy survives. A `Raw` edge is therefore refused
  at construction rather than handed masked bytes under a fidelity label —
  serving it needs a pre-seam tap, which is a different design. Why it existed: Pump A's `ReaderHandle` into B's `InputSession`
  in acceptance order, honouring the lease and refreshing it. This is where
  plan 283's guarantees are easiest to lose: the gate's secret scan concatenates
  in acceptance order and does not reassemble by `seq`, and the withheld tail
  must be delivered before close. Both need a test that fails if dropped.

- [x] **WS4 — backpressure modes.** Landed, and smaller than expected because
  the ring already existed: the reader's queue is bounded and already evicts,
  so the producer cannot be stalled by a slow consumer no matter what this
  does. What the mode decides is the *reaction* to a gap the reader reports —
  `Lossy` marks it and carries on, `Reliable` fails the edge. No second
  buffer, which is one fewer place for records to go missing. Why it existed: Implement `lossy` and `reliable` per E4, and
  prove the distinction: a slow consumer on a `lossy` edge produces a marked gap;
  on a `reliable` edge it produces a loud edge failure. Neither stalls the
  producer — that invariant is inherited and must be re-verified here, not
  assumed.

- [x] **WS5 — claim work.** Landed. ADR-035 gains a section stating what an
  edge guarantees by construction (no guest addresses another, no new path out
  of a guest, the four pre-boot refusals, raw refused rather than downgraded,
  safe defaults that cannot be lost by omission, producer never stalled) and
  what it does not — chiefly that **none of those refusals has fired in
  production**, because none has a caller here. They are dormant by
  declaration, and the gate now enforces that in both directions.

  Claim 17 stays `Preview`. An edge would be the input plane's second
  production caller and the promotion question is deferred until one exists;
  promoting on a caller nobody has written would make the claim true of code
  and false of the system. Why it existed: An edge is a different authorization shape than a
  per-plan grant, so this is not claim 17 with more rows. State what an edge
  guarantees, what it does not, and witness it. Reassess whether the input plane
  can leave `Preview` once it has a second production caller.

- [x] **WS6 — docs.** Landed as `guides/fleet-stream-edges`, wired into the
  sidebar: how a consumer names a binding rather than a VM, what the two
  redaction postures mean and why `raw` needs an operator acknowledgement it
  cannot get from a plan signature, why fan-in is a merge stage, why the
  topology is a DAG, what each backpressure mode does when a consumer falls
  behind, and why a broken edge fails the workflow instead of reconnecting. It
  opens by saying the surface has no CLI driver yet, so a reader is not left
  hunting for a command that does not exist. Why it existed: How a fleet declares edges, what redaction does to data in
  flight, why fan-in is a merge node, and what happens when a consumer falls
  behind under each mode.

## Declared dormancy

`validate_topology` and `check_plan_edges` have **no caller inside `mvm`**, and
will not get one: a single-VM `mvmctl` run has no graph to validate, and this
repository has no fleet. `mvmd` is the caller.

That is the shape plan 293's WS4 exists to catch, so it is written down here
rather than discovered later. The distinction WS4 draws is between a control
that is dormant *by declaration* and one that is dormant *by accident* — this
is the former, and when WS4 lands these two belong in its allowlist with this
paragraph as the justification.

What keeps it honest meanwhile: both are pure functions with no side effects,
both are covered by their own tests, and neither claims a guarantee that
anything in `mvm` relies on. The refusals they implement are real only once
`mvmd` calls them, and no claim in ADR-001 asserts otherwise.

## Open questions

None. E6 and E7 were the two that remained; both are settled above.
