# Plan 296 — fleet stream fan-out

**Status:** Proposed.

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

Two consequences worth stating plainly, because they will surprise someone:

- An edge consumes the consumer's single input slot, so a workload fed by an
  edge cannot simultaneously take operator stdin. That must be a diagnosable
  admission error, not a runtime surprise.
- Iteration is not expressible. A workflow needing a loop re-invokes the DAG
  from an external orchestrator, which keeps termination and provenance intact.

## Work

- [ ] **WS1 — the edge binding.** A signed-plan shape by which a consumer names
  a *binding*, not a VM. The host resolves it. A consumer that names a source it
  was not granted is refused and the refusal reaches the chain-signed log.
  Includes the redaction posture (E1) and the backpressure mode (E4) as
  properties of the binding.

- [ ] **WS2 — DAG validation at admission.** Build the declared graph, reject a
  cycle before any boot, and name the offending edge. Cheap, static, fail-closed.
  Test the self-edge, the two-node cycle, and a long cycle — a validator that
  only catches `A→A` is the usual defect.

- [ ] **WS3 — the connector.** Pump A's `ReaderHandle` into B's `InputSession`
  in acceptance order, honouring the lease and refreshing it. This is where
  plan 283's guarantees are easiest to lose: the gate's secret scan concatenates
  in acceptance order and does not reassemble by `seq`, and the withheld tail
  must be delivered before close. Both need a test that fails if dropped.

- [ ] **WS4 — backpressure modes.** Implement `lossy` and `reliable` per E4, and
  prove the distinction: a slow consumer on a `lossy` edge produces a marked gap;
  on a `reliable` edge it produces a loud edge failure. Neither stalls the
  producer — that invariant is inherited and must be re-verified here, not
  assumed.

- [ ] **WS5 — claim work.** An edge is a different authorization shape than a
  per-plan grant, so this is not claim 17 with more rows. State what an edge
  guarantees, what it does not, and witness it. Reassess whether the input plane
  can leave `Preview` once it has a second production caller.

- [ ] **WS6 — docs.** How a fleet declares edges, what redaction does to data in
  flight, why fan-in is a merge node, and what happens when a consumer falls
  behind under each mode.

| E6 | A broken edge fails the workflow. It does not silently reconnect across a consumer restart | Reconnection is not free: the gate builds a fresh `SecretScanner` per session, so a secret split across the restart boundary would be scanned by two scanners with neither seeing the whole — the same hole this project refused to open at route displacement. Surviving a restart also means buffering on the producer for an unbounded interval, which breaks the bounded-memory invariant. Workflows already have a supervisor; re-running the DAG is the correct recovery, at the correct layer. The edge records its last delivered sequence in the chain-signed log so a re-run is reasoned about rather than guessed. |
| E7 | The redaction opt-out (E1) requires an explicit operator acknowledgement, distinct from the plan signature | A plan is signed on behalf of whoever launched the workload, so letting a workload's own plan opt its edge out of redaction lets a careless or compromised workload definition export raw PII to another workload with no human in the loop. Between two workloads these are different trust domains. This repository already has the right shape for it: unrestricted egress requires `MVM_ACK_UNRESTRICTED_NETWORK=1`, an operator acknowledgement never set in CI. The redaction opt-out takes the same form and is audited. |

## Open questions

None. E6 and E7 were the two that remained; both are settled above.
