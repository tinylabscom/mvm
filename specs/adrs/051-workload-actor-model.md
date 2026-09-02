# ADR-051 — The workload actor model is one vocabulary shared by spawned microVMs and durable messaging

Backing: preview
Validation: none — this is a reconciling design decision; no code implements it and no test exercises it.

**Status:** Proposed
**Date:** 2026-08-25
**Owner:** `mvm` maintainers
**Reconciles:** ADR-045 (capability-secure intelligent workflow controllers) and
ADR-046 (the secure message fabric).
**Complements:** ADR-001, ADR-014, ADR-020, ADR-031, ADR-035, ADR-042, ADR-047.
**Implemented by:** no plan yet. The vertical slice below is the first one to write.

## Context

Two proposed designs were authored a few days apart, by different passes over
the same problem, and neither references the other.

ADR-045 lets an admitted controller microVM launch admitted worker microVMs:
`launch_child`, `observe_child`, `release_child`, `ActorHandle`, lifecycle
receipts, per-child capacity reservation, and the rule that
`effective_child_authority ⊆ effective_parent_authority`. Its WS7 gives those
children "bidirectional, bounded, auditable communication".

ADR-046 makes durable local messaging the workload data plane: one
`ExclusiveInbox` per workload, E2E-encrypted with workload-owned keys,
at-least-once delivery over a deterministic SQLite-backed state machine, dedup
by idempotency key, per-route ordering, bounded queues for offline recipients,
crash redelivery, and archive-before-purge.

Read together, both describe the same thing: **addressable, supervised,
independently-failing units that communicate only by message.** That is the
actor model, with capability attenuation added. Neither document names it, so
neither can defer to the other, and the overlap has already turned into a
concrete collision:

| Type | ADR-045 WS7 | ADR-046 M1 |
|---|---|---|
| `MailboxAddress` | "add under `mvm-contract`" | "define with workload-only destination" |
| `MessageId` | "add under `mvm-contract`" | "add" |
| `MailboxEnvelope` / message envelope | defined in WS7 | defined in M1 |
| correlation / causation | `CorrelationId`, `CausationId` | "define causation/correlation fields" |
| acknowledgement | `Acknowledgement`, `DeliveryReceipt` | ACK / NACK / lease commands |
| delivery attempt | `DeliveryAttempt` | `AttemptId` |
| cursor | `MailboxCursor` | `CommitPosition`, `DeliveryToken` |

Both write those names into `mvm-contract`. Whichever lands second either
conflicts or silently forks the model.

ADR-046 already assumes the resolution — it lists itself as "consumed by the
capability-secure workflow ADR/plan after those documents are reconciled to
depend on this fabric" — but ADR-045 has no corresponding edge, and the
reconciliation exists only as one unchecked box in the fabric plan.

Separately: because the shape is the actor model, adopting a Rust actor
framework has been raised. That question is answered here rather than left to
whoever writes the first plan.

## Decision

### 1. Name the unit

A **workload actor** is one microVM together with:

- one `ExclusiveInbox` (ADR-046) — its only inbound message path;
- one `ActorHandle` (ADR-045) — the lifecycle capability its parent holds;
- one attenuated authority envelope;
- one audit lineage rooted in the signed `ExecutionPlan` it booted under.

An actor is not a new runtime object. It is the name for a workload seen
through those four bindings at once.

### 2. Four invariants

1. **One guest is one actor.** No multi-workload guest, no nested
   virtualization. Carried forward from ADR-045.
2. **Every actor is an ordinary admitted workload.** Spawning a child reuses
   plan synthesis, signing, admission, backend dispatch, secrets, network
   policy, and the audit chain unchanged. A child is not a privileged object.
3. **Authority only attenuates.** A child's capabilities, egress, secrets,
   filesystem, tools, resources, and delegation are subsets of every applicable
   parent, workflow, tenant, template, and host ceiling.
4. **Every message is durable, bounded, and audited.** No control path may
   deliver a message the fabric would refuse, and no lifecycle transition may
   escape the chain-signed log.

### 3. One vocabulary — the fabric's

ADR-046 defines the messaging contract. ADR-045 consumes it and defines no
message types of its own.

Concretely: the WS7 "add dependency-light mailbox types under `mvm-contract`"
list is **deleted** from the workflows plan. `MailboxAddress`, `MessageId`,
envelopes, correlation, causation, attempts, acknowledgement, and cursors have
exactly one definition, in `mvm_contract::fabric`.

`ActorHandle` survives, because it is not an address. It is the lifecycle
capability authorizing `observe_child` and `release_child` on one child. It
resolves to a `MailboxAddress`; it never carries a second addressing scheme, and
in particular it never carries a VM name, node address, CID, socket path, or
file descriptor — which ADR-046's route contracts already forbid.

The reciprocal edge is added to ADR-045: it depends on ADR-046, and the fabric
must reach its local mailbox milestone before the workflow layer's
communication workstream can start.

### 4. No third-party actor framework

`kameo` was evaluated as the substrate and is **rejected**. Two structural
reasons, neither of them about crate quality:

**The actors are microVMs.** They are separate kernels in separate address
spaces behind vsock, running workloads in Python, TypeScript, and other
languages. An in-process Rust actor framework addresses actors by a typed
handle to a task in the current process. It cannot name a microVM, and the
addressing model it provides is the one ADR-046 explicitly rejects.

**Supervision conflicts with determinism.** ADR-046 requires a deterministic
command log that replays exactly, because `mvmd` data-group replicas re-execute
it later. An actor framework's value is panic isolation and restart policy —
nondeterminism that would then have to be suppressed to keep replay exact. This
also disposes of the one place such a framework could plausibly have helped
locally, the fabric's resident shard workers: a shard worker owning a SQLite
connection and a deterministic state machine wants a single owned loop, not
supervised restart.

Measured against what ADR-046 actually requires — durable transactional
cursors, dedup by idempotency key, bounded encrypted queues for offline
recipients, E2E encryption the host cannot read, capability-bound sends,
host-stamped sender identity, payload-free audit events, and deterministic
replay — an in-process actor framework supplies none of them. It supplies a
bounded mailbox, which is a channel.

What is adopted is the **model**: addressable mailboxes, supervised lifecycle,
message-only communication, independent failure. Those are built on `mvm`'s own
types, under `mvm-contract`, where the capability and audit bindings can be
part of the contract rather than bolted beside it.

This decision is recorded so it is not re-litigated per plan. Revisiting it
requires new evidence about the microVM boundary or the determinism
requirement, not a preference for the ergonomics.

### 5. The vertical slice that demonstrates the model

One scenario, exercising both ADRs end to end on one host:

> A parent actor spawns one child actor, sends it one durable message, receives
> one response, and releases it. The child is destroyed and never re-enters
> warm capacity.

It is done when all four invariants have negative witnesses, not just a happy
path: a child that requests authority its parent lacks is refused; a message
that exceeds a fabric bound is refused rather than silently truncated; the
response survives a host process crash between accept and acknowledgement; and
the whole exchange appears in the chain-signed log with no payload bytes.

Both existing plans stay whole. This slice is the first increment either one
ships, and it is the increment that forces the vocabulary to be shared rather
than described as shared.

## Consequences

- ADR-045 and its plan lose their independent mailbox contract and gain a hard
  dependency on ADR-046. The workflow layer cannot start its communication
  workstream before the fabric's local mailbox milestone lands.
- `mvm-contract` gains exactly one messaging module. The runtime-free and
  `no_std + alloc` posture of the transport-free types is preserved, as ADR-046
  already requires.
- Sequencing becomes explicit: fabric contracts and state machine first, then
  child lifecycle, then the planner. The planner is the last thing built, not
  the first, and nothing depends on it.
- The kameo question is closed. Future proposals cite this ADR.
- Neither ADR is superseded. This one is deliberately small; its whole job is
  to make two documents agree and to be deleted into them if they are ever
  merged.

## Alternatives considered

**Amend ADR-045 and ADR-046 in place, with no new ADR.** Smallest diff, but the
shared model stays implicit — the next document to describe actors has nothing
to defer to, which is exactly how the current collision happened.

**Build the vertical slice first and let the vocabulary reconcile in code.**
Attractive, and correct for most of this. Rejected for the parts that cannot be
retrofitted: capability attenuation and audit-chain binding have to be in the
contract from the first commit. The rest of the model can and should be settled
by working code.

**Adopt an actor framework and shape the plans around it.** Rejected in
§4 above.
