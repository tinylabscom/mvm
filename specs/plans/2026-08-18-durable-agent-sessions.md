# Durable agent sessions — long-horizon state across disposable sandboxes

Backing: preview
Validation: none

**Status:** Design. Not implemented.
**Date:** 2026-08-18
**Depends on:** ADR-045 (capability-secure intelligent workflow controllers),
ADR-046 (secure message fabric), Plan 2167 (durable agent session contract),
Plan 2168 (unified runtime policy and human approval).

## The problem

A long-running agent task outlives the sandbox that runs it. An incident
investigation spans days. An agent that develops a feature, tests it, opens a
pull request, and follows it to production spans longer, and crosses external
systems whose credentials expire in minutes.

Three things follow, and none of them are covered today:

1. **A task that outlives its live session has no resume path.** ADR-045 §12
   defines a *private actor checkpoint* bound to a workflow and logical actor.
   ADR-046 §13 defines archive-before-purge, and is explicit that an archive
   "cannot be accepted as ... automatic session restore" — an archive is
   evidence, not resumable state. Between the live checkpoint and the sealed
   archive there is no defined third state: a task parked for three days.

2. **Waiting for a human is not a first-class park reason.** ADR-045 §12 gives
   the host monotonic idle timers, and §3 gives controllers `Pause` / `Resume`
   / `Checkpoint` / `Restore`. Plan 2168 supplies `ApprovalLedger` with
   operator keys, a 24h TTL, and replay handling. Nothing connects them, so an
   agent blocked on an operator decision holds a live VM for the duration.

3. **The memory image has no retention ladder.** `STANDBY_POOL_TTL` is 30
   minutes with a `PARKED_TTL_MULTIPLIER` of 6
   (`crates/mvm-runtime/src/standby_pool.rs:19-27`), tuned for warm-pool
   capacity rather than for a task parked overnight. Nothing GCs
   `checkpoints_dir()` (`crates/mvm-core/src/config.rs:766`) at all.

## Framing

**The durable unit is the session, not the VM.** A session is a signed,
chain-anchored sequence of *admissions*. A sandbox instance is a disposable,
bounded lease against a durable task. No sandbox carries authority between
admissions, because between admissions there is no sandbox.

This is what makes an unattended multi-day run compatible with the strongest
available authority story: nothing holds standing privilege across days
because nothing holds privilege in the gaps.

ADR-045 §12 already decides the resume semantics this rests on — restoring a
private actor checkpoint "creates a fresh boot identity, session keys,
credentials, and grants." This design supplies the lifetime, the trigger, and
the retention policy that decision needs in order to span days.

## Design

### D1 — Hibernation: a third state between live and archived

A session in `Hibernated` has released every host resource except storage. It
is not `Active` (no live sandbox, no fabric session, no leases) and not
`Closed` (not sealed, not purged, still resumable).

```text
Active ──park──> Hibernated ──resume──> Active
   │                  │
   └──close──> Closing -> Draining -> Sealing -> ArchiveCommitted -> Purging -> Closed
                      (ADR-046 §13, unchanged)
```

Hibernation is generation-fenced the same way close is. A resume of a
hibernated session opens a new generation; a late frame addressed to the prior
generation is rejected rather than delivered.

The hibernation record holds, in the session store:

```text
session ID
current generation
parent checkpoint digest        (content-addressed resume point)
journal cursor                  (AgentSessionJournal position)
approval ledger head + signature
storage tier                    (Parked | Cold)
park reason
audit-chain head
retention class + expiry
```

This is deliberately close in shape to ADR-046 §13's tombstone. A tombstone
records a session that ended; a hibernation record records one that paused.

### D2 — `CheckpointMeta` gains a session binding

```rust
pub struct SessionBinding {
    pub session_id: AgentSessionId,
    pub generation: u64,
    pub journal_cursor: u64,
    pub approval_head: CheckpointDigest,
}
```

Carried as `Option<SessionBinding>` on `CheckpointMeta`, and **inside the meta
digest**. Admitted grants already sit inside that digest
(`the_admitted_grant_is_inside_the_content_address`,
`crates/mvm-core/src/checkpoint.rs:661`), so extending it makes the resume
point content-addressed and tamper-evident by the mechanism already in place.

The payoff is that `materialize_child_from_parent`
(`crates/mvm-runtime/src/warm_snapshot.rs:39`) already refuses a missing,
unaudited, or tampered parent, with negative tests for each. Binding the
session into the digest brings hibernated resume under that same refusal
without a second verification path.

A direct (non-session) workload sets `None` and initializes nothing —
consistent with ADR-045 §13.

### D3 — Approval-wait is a park reason; a signed approval is a wake source

```rust
pub enum ParkReason {
    ApprovalWait { approval_id: ApprovalRequestId },
    Idle,
    HostShutdown,
    Operator,
    RetentionDemotion,
}
```

The reason selects the storage tier. `ApprovalWait` and `HostShutdown` go
directly to `Parked` — an operator decision has unbounded latency and must not
hold RAM. `Idle` may linger in `Idle` first.

Wake is driven by `ApprovalLedger::respond`
(`crates/mvm-contract/src/policy/approval.rs:603`) reaching a terminal
outcome. The operator signature is verified before any VM work begins, so the
transport is untrusted in both deployments: `mvmctl session approve` locally,
an `mvmd` web action remotely, one signed `ApprovalResponse` either way.

`MAX_APPROVAL_TTL_MS` is 24h. A park whose approval expires unanswered
demotes to `Cold` and records the expiry; it does not resume and does not
silently widen.

### D4 — Retention ladder

| Tier | Holds | Resume cost | Governed by |
|---|---|---|---|
| `Idle` | RAM (live paused process) | instant | `STANDBY_POOL_TTL` |
| `Parked` | disk, GB-scale memory image | restore + blob read | session retention class |
| `Cold` | KB (record + journal + meta) | boot + journal replay | session retention class |
| `Closed` | archive only | not resumable | ADR-046 §13 |

Demotion is one-way within a session generation and always downward. Promotion
happens only through resume, which opens a new generation.

Retention classes are operator-configured, with the memory image and the
session record governed **separately**: a session may retain its record for 90
days while its memory image expires in 48 hours. Losing the memory image costs
speed, never resumability — the journal remains the durable record.

This introduces the first actual GC over `checkpoints_dir()`. It must not
reap a checkpoint that any live or hibernated session names as its parent.

### D5 — Resume is re-admission, and it is incremental

```text
resume_session(session_id):
  1. load hibernation record; verify audit-chain head
  2. verify approval ledger head signature        <- cached head, not a replay
  3. evaluate PolicySet at *current* time
  4. synthesize a fresh ExecutionPlan
       - names session_id, generation+1, parent digest, approval head
       - fresh wall-clock bound, CPU scope, audit identity
       - grants = exactly the approved scope
  5. admit the plan  (claim 8 path)
  6. select cheapest valid tier: Parked -> restore | Cold -> boot + replay
  7. PostRestore: fresh VMGenID, re-register fabric identity
  8. mint short-lived credentials at the substitution endpoint
  9. chain entry: sandbox.resumed
```

Steps 1–3 must be **incremental** — two signature checks and a digest
comparison. `ApprovalLedger::from_history`
(`crates/mvm-contract/src/policy/approval.rs:532`) replays the full history,
which is correct for recovery and too expensive for the resume path. Resume
needs a signed ledger head cached in the hibernation record.

This is a hard constraint, not a preference. Plan 297 measures the warm SLO
from *plan admitted* to guest-ready (p99 ≤ 50ms warm), so admission sits just
outside the measured interval — the region where launch cost is already known
to be under pressure. Moving admission from once-per-task to once-per-resume
is only viable if each resume admission is cheap.

Step 4 also retires a documented `Preview` claim 18 limitation: today a
restored child is admission-bounded without its host-side CPU control or its
wall-clock timer being re-armed, because `hvf_child_restore_config` sets
`plan: None` (`crates/mvm-backends/src/driver/hvf_restore.rs`) — correctly, to
avoid auditing a child's kill under its parent's identity. A freshly
synthesized per-resume plan re-arms both without that misattribution.

### D6 — What a restored image may not carry

ADR-046 §14 requires that warm snapshots contain "code and initialized
buffers, never live authority, keys, nonces, sequences, assignments, leases,
messages, or sessions," and that `communication_ready` means "no restored
key/session/nonce/sequence/lease state."

So a restored memory image resumes the agent's *reasoning* state — its plan,
working set, buffers — and must have its *communication and authority* state
torn down and rebuilt. `PostRestore` already mints a fresh VMGenID
(`crates/mvm-client/src/local.rs:209`); it gains responsibility for
invalidating and re-registering fabric identity.

The guest-side quiesce verbs this needs already exist:
`GuestRequest::SleepPrep`, `CheckpointIntegrations`, `Wake`, `PostRestore`
(`crates/mvm-agentd/src/vsock/request.rs`).

### D7 — The session owns a set of members

The session record holds a **set** of sandbox lineages from the start, even
though this design admits exactly one. Multi-member sessions — ADR-045
controllers with worker microVMs — need a consistent cut across members, which
is tractable here only because ADR-046 §11 keeps all communication
host-mediated and workload microVMs have no NIC. Group quiesce belongs to a
follow-on spec that consumes the fabric.

Shaping the record for N now costs a field. Retrofitting it later means
migrating every stored session and re-cutting every digest.

## Failure modes

| Failure | Behaviour |
|---|---|
| Torn park (crash mid-capture) | Hibernation record commits last, after content verification. A record without verified content is absent, so the session stays `Active` and recovers by ordinary crash paths. |
| Parent checkpoint missing or tampered | `materialize_child_from_parent` refuses before any clone. Demote to `Cold` and replay; refuse if the journal is also unavailable. |
| Approval expires unanswered | Demote to `Cold`, record expiry, do not resume. |
| Approval arrives after generation fence | Rejected as stale; the ledger's existing stale-response handling applies. |
| Audit chain head mismatch | Refuse resume. A session whose continuity is not verifiable does not resume under its old identity. |
| Host loss with `Parked` image | Record and journal survive if replicated; memory image does not. Resume degrades to `Cold`. |
| Retention GC races a resume | GC refuses any checkpoint named as a parent by a live or hibernated session. |
| Fresh plan fails admission on resume | Session stays hibernated. Failure is recorded; no partial boot. |

Every refusal is fail-closed and matches the existing `StandbyError`
discipline, where every variant means fall back to a cold path rather than
silently proceed.

## Testing

- `CheckpointMeta` digest changes when any `SessionBinding` field changes, and
  is invariant under content insertion order (extends the existing digest
  suite in `crates/mvm-core/src/checkpoint.rs`).
- Park → resume round trip preserves journal cursor and generation; a replayed
  prior-generation frame is refused.
- Resume synthesizes a plan with a re-armed wall-clock bound and CPU scope,
  and with grants no wider than the approval head.
- Approval expiry during park demotes to `Cold` without resuming.
- A tampered parent checkpoint refuses before any clone (negative control
  mirroring `negative_tampered_parent_refuses_before_any_clone`).
- Retention GC refuses to reap a parent named by a hibernated session.
- Resume admission does not replay full approval history — asserted against
  ledger length, so the incremental requirement cannot silently regress.
- BDD scenario: park on approval-wait, resume days later under a fresh plan,
  verify the audit chain across the gap.

Mutation coverage on the refusal paths specifically: a test that passes when
the refusal is removed is not a witness.

## Reconciliation required

ADR-045, ADR-046, and the two new workflow/fabric plans reference Plan 2167
and Plan 2168 zero times, while assuming a session, journal, and approval model. Plan 2167's
`AgentSessionJournal`, Plan 2168's `ApprovalLedger`, and `PolicySet` currently
have no callers outside `mvm-contract`; the only production consumer of either
module anywhere is `AgentRequestId`, used by the broker for request
correlation. Both plans are re-exported from `mvm-client` and `mvm-sdk` as
`pub use` of the module, which is surface rather than adoption.

This design consumes those contracts rather than defining new ones. Before
implementation, the new documents should name them, so a second session and
approval model is not built alongside the first.

Numbering was reconciled while carrying these documents onto this branch:

- Both new ADRs carried `# ADR-043` as their H1, a number already held by
  `specs/adrs/043-client-interface-conformance.md`. Retitled to ADR-045 and
  ADR-046 so the titles match their filenames.
- Both new plans were number-named, which `check-plan-names` refuses, and
  their H1s claimed "Plan 329" and "Plan 338" — 329 is already held by three
  files. Renamed to date-prefixed slugs, with the bare numbers dropped from
  their titles.
- ADR-046 read "Implemented by: Plan 338", which agreed with the
  message-fabric plan title but not its filename. It now names the path.
- Left alone: ADR-045 cites "Plan 329" in its Related list, and three legacy
  files claim that number. Disambiguating it needs the author intent.

## Workstreams

- [ ] **WS1 — Session store.** `mvm-runtime/src/session/` mirroring
      `checkpoint/`, over a new `mvm_core::config::sessions_dir()`. Record,
      journal persistence, approval-ledger head caching.
- [ ] **WS2 — `SessionBinding` on `CheckpointMeta`.** Field, digest coverage,
      digest tests.
- [ ] **WS3 — Park path.** `ParkReason`, tier selection, quiesce sequence over
      the existing guest verbs, hibernation record commit ordering.
- [ ] **WS4 — Resume path.** `resume_session`, incremental ledger-head
      verification, fresh-plan synthesis, tier selection, `PostRestore`
      fabric re-registration.
- [ ] **WS5 — Retention ladder + GC.** Retention classes, one-way demotion,
      first GC over `checkpoints_dir()` with parent-reachability refusal.
- [ ] **WS6 — CLI.** `mvmctl session {open,ls,show,park,resume,approve,close}`.
- [ ] **WS7 — Chain records.** `session.opened`, `sandbox.admitted`,
      `sandbox.parked`, `approval.requested`, `approval.granted`,
      `sandbox.resumed`, `session.hibernated`, `session.closed`, wired through
      the existing `AgentApprovalEvent::audit_action` projection.
- [ ] **WS8 — Tests + BDD** per the Testing section.

## Out of scope

- Group quiesce and consistent cuts across multiple sandboxes (follow-on spec;
  the record is shaped for it).
- The agent-to-agent message fabric itself (ADR-046 and
  `specs/plans/2026-08-15-secure-message-fabric.md`).
- Fleet placement, cross-host resume, replicated session storage (`mvmd`).
- Changing archive-before-purge or cryptographic erasure (ADR-046 §7, §13).

## Open questions

- Default retention class for a hibernated session's memory image. 48h is a
  starting proposal, not a measured one; it wants disk-pressure data.
- Whether a hibernated session should hold a reservation against the host
  memory budget for its eventual resume, or re-contend on wake. Re-contending
  is simpler and can starve a long-parked task.
- Whether `Cold` resume needs a workload-declared replay-tolerance capability,
  so a workload that cannot rebuild from its journal refuses demotion rather
  than failing at hour 73.
