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
   capacity rather than for a task parked overnight. `checkpoints_dir()`
   (`crates/mvm-core/src/config.rs:766`) already has an age-based, tag-aware
   sweep (`sweep_untagged_checkpoints`, reached from `mvmctl cache prune`) —
   but it knows nothing about sessions, so a session parked past the sweep's
   age cut loses the checkpoint it resumes from with no reachability check at
   all.

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

A session in `Hibernated` is off its live sandbox identity and parked at
whichever tier D4 selects for the reason. Only the `Resident` tier keeps a
live paused process — and its memory — around, for the sake of a near-instant
resume; `Parked` and `Cold` release the process, holding progressively less: a
memory image on disk, or just the record and journal. Every tier is not
`Active` (no live sandbox identity, no fabric session, no leases) and not
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
session ID                      (built)
current generation              (built)
parent checkpoint digest        (built — content-addressed resume point)
journal cursor                  (built — AgentSessionJournal position)
approval ledger head            (built, as a digest only — see note below)
storage tier                    (built — Resident | Parked | Cold)
park reason                     (built)
audit-chain head                (not built)
retention class + expiry        (not built)
```

`specs/plans/2026-08-18-durable-session-park.md` Task 3 landed the first seven
fields on `AgentSessionRecord`, plus `park()` / `resume()` transitions and a
store-level generation fence (`specs/plans/2026-08-18-durable-session-substrate.md`
landed `parent_checkpoint` earlier). The approval field is narrower than this
section originally sketched: `approval_head` carries the `ApprovalHead` digest
alone, not a paired signature. `specs/plans/2026-08-18-session-approval-head.md`
closed part of that gap: `ApprovalLedger::head()`
(`crates/mvm-contract/src/policy/approval.rs`) content-addresses the ledger's
decision state — every record's approval id, its capability, and its terminal
state, deliberately excluding wall-clock fields and also excluding
`resource_digest`, `policy_digest`, `admission_plan_digest`, and
`authorized_operators` — and `AgentSessionStore::resume` now takes the
caller's `current_head` and refuses when it differs from the `approval_head`
`ParkInput` committed at park. What is still missing is the wiring between
the two calls: nothing in the workspace calls `ApprovalLedger::head()` to
produce the value either `ParkInput::approval_head` or `resume`'s
`current_head` carries — that caller is `resume_session`, which does not
exist, so today a caller of `park`/`resume` supplies the digest itself. And a
session parked with `approval_head: None` has nothing recorded to compare
against, so such a resume proceeds with no ledger fence at all; that is a
documented gap, not an oversight.
`audit-chain head` and `retention class + expiry` remain entirely absent; both
belong to WS5 (the retention plan) and WS7 (chain records).

This is deliberately close in shape to ADR-046 §13's tombstone. A tombstone
records a session that ended; a hibernation record records one that paused.

### D2 — `CheckpointMeta` gains a session binding

```rust
pub struct SessionBinding {
    pub session_id: AgentSessionId,
    pub generation: u64,
    pub journal_cursor: u64,
    pub approval_head: ApprovalHead,
}
```

`ApprovalHead` is a dedicated `sha256:<64-hex>` newtype, not `CheckpointDigest`
reused: an approval-ledger head and a checkpoint content-address are different
hash chains, and `CheckpointDigest` carries no conversion to any other
prefixed digest type on purpose (see its own doc comment), so the binding
needs its own type rather than borrowing one that means something else.

Carried as `Option<SessionBinding>` on `CheckpointMeta`, and **inside the meta
digest**. Admitted grants already sit inside that digest
(`the_admitted_grant_is_inside_the_content_address`,
`crates/mvm-core/src/checkpoint.rs:786`), so extending it makes the resume
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
    ApprovalWait,
    Idle,
    HostShutdown,
    Operator,
    RetentionDemotion,
}
```

Fieldless, as built (`crates/mvm-runtime/src/agent_session/mod.rs`) — not the
`ApprovalWait { approval_id: ApprovalRequestId }` this section originally
called for. The consequence: nothing on the record links a parked session to
the approval it is waiting on, so the wake path below cannot be built as
written — it needs a way to find a parked session *from* an approval id, and
that lookup does not exist yet. See WS3's remaining-work note.

The reason selects the storage tier. `ApprovalWait` and `HostShutdown` go
directly to `Parked` — an operator decision has unbounded latency and must not
hold RAM. `Idle` may linger in `Resident` first.

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
| `Resident` | RAM (live paused process) | instant | `STANDBY_POOL_TTL` |
| `Parked` | disk, GB-scale memory image | restore + blob read | session retention class |
| `Cold` | KB (record + journal + meta) | boot + journal replay | session retention class |
| `Closed` | archive only | not resumable | ADR-046 §13 |

Demotion is one-way within a session generation and always downward. Promotion
happens only through resume, which opens a new generation.

Retention classes are operator-configured, with the memory image and the
session record governed **separately**: a session may retain its record for 90
days while its memory image expires in 48 hours. Losing the memory image costs
speed, never resumability — the journal remains the durable record.

`checkpoints_dir()` already has a GC — the age-based, tag-aware
`sweep_untagged_checkpoints` reached from `mvmctl cache prune`. What is
missing is teaching it about sessions: it must not reap a checkpoint that any
live or hibernated session names as its parent.
(Delivered by `specs/plans/2026-08-18-session-retention.md`: the sweep now
consults `mvm_runtime::agent_session::pinned_checkpoints` and a manual
`mvmctl vm checkpoint rm` refuses the same way. Retention classes, expiry,
and a scheduler that calls `demote` remain undelivered — see that plan's
"Deferred to later plans" section.)

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

`specs/plans/2026-08-18-session-approval-head.md` landed the digest half of
step 2: `AgentSessionStore::resume` takes a `current_head` parameter and
refuses when it differs from the `approval_head` recorded at park, comparing
`ApprovalLedger::head()`'s SHA-256 output for equality — a digest comparison,
not the signature check this sketch names.

`specs/plans/2026-08-18-resume-session-orchestrator.md` landed
`resume_session` (`crates/mvm-hostd/src/session_resume.rs`), which covers
step 4 (fresh `ExecutionPlan` synthesis) and step 5 (admission).
`specs/plans/2026-08-19-resume-boot.md` lands the cold-tier half of step 6:
`mvmctl agent-session resume --boot` drives `resume_and_boot`, which refuses
`Parked` and `Resident` tiers by name, transitions the record, and then boots
a fresh VM from the resume point's rootfs through the shared
`start_admitted` post-admission tail. The config carries the resume point's
runtime-source policy, attaches the runtime overlay from the host cache, and
threads dm-verity roothash tokens when the checkpoint has them. Step 9's
`session.resumed` chain entry is emitted before the boot attempt, so a boot
failure leaves the chain consistent with the moved record. Steps 1
(audit-chain head), 3 (`PolicySet` evaluation at current time), 7
(`PostRestore` fabric re-registration), and 8 (credential minting) remain
design only. Nothing calls `ApprovalLedger::head()` to produce the value
either side of the step-2 comparison carries — a caller supplies both
`ParkInput::approval_head` and `resume`'s `current_head` itself today,
`resume_session` included: its `ResumeRequest::current_approval_head` is read
straight off the record the caller already holds. A session parked with
`approval_head: None` skips the comparison entirely and resumes with no
ledger fence at all; the fence's own doc comment records this as a
deliberate gap rather than a defect to close silently later.

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

That remains the design intent, and it is not yet true of the code.
`crates/mvm-hostd/src/session_resume.rs` synthesizes the per-resume plan with
`grants: None`, because `ResumePlanMaterial` — the caller-supplied workload half
of the plan — carries no grant surface to fill them from. With no `wall_clock`
grant `exec_secs_from_grants` projects to `0`, and with no `cpu` grant there is
no share for a host-side control to scope, so the freshly synthesized plan
arms neither bound: there is nothing in it to arm. Until grants reach the
synthesis input, a resumed session is unbounded in exactly the two dimensions
this paragraph describes the resume as fixing, and the `Preview` claim 18
limitation it names is not retired. The step-4 line
"grants = exactly the approved scope" is the unimplemented half.

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

Numbering was reconciled before these documents landed on main (PR #2691):

- Both new ADRs carried `# ADR-043` as their H1, a number already held by
  `specs/adrs/043-client-interface-conformance.md`. Retitled to ADR-045 and
  ADR-046 so the titles match their filenames.
- Both new plans were number-named, which `check-plan-names` refuses, and
  their H1s claimed "Plan 329" and "Plan 338" — 329 is already held by three
  files. They now carry date-prefixed slugs with the bare numbers dropped:
  `specs/plans/2026-08-18-capability-secure-intelligent-workflows.md` and
  `specs/plans/2026-08-18-secure-message-fabric.md`.
- ADR-046 read "Implemented by: Plan 338", which agreed with the
  message-fabric plan title but not its filename.
- Left alone: ADR-045 cites "Plan 329" in its Related list, and three legacy
  files claim that number. Disambiguating it needs the author intent.

## Workstreams

- [ ] **WS1 — Session store.** `mvm-runtime/src/agent_session/` mirroring
      `checkpoint/`, over a new `mvm_core::config::agent_sessions_dir()`.
      Record and store landed
      (`specs/plans/2026-08-18-durable-session-substrate.md`); journal
      persistence and approval-ledger head caching have not.
- [ ] **WS2 — `SessionBinding` on `CheckpointMeta`.** Field, digest coverage,
      digest tests.
- [ ] **WS3 — Park path.** `ParkReason`, tier selection, quiesce sequence over
      the existing guest verbs, hibernation record commit ordering.
      `ParkReason`, `select_tier`, the record's `park()`/`resume()`
      transitions, and crash-safe record commit landed
      (`specs/plans/2026-08-18-durable-session-park.md`). The quiesce
      sequence has not: `GuestRequest::SleepPrep`, `CheckpointIntegrations`,
      and `Wake` are defined in the agent protocol and have host-facing
      convenience functions in `mvm-agentd/src/vsock/api.rs`, but none of
      those functions has a caller anywhere in the workspace outside their
      own tests. Wiring park to call them is what remains. `ParkReason` shipped
      fieldless (see D3): the record does not name the approval a parked
      session is waiting on, so the `ApprovalLedger::respond`-driven wake path
      D3 describes has no way to find the parked session an incoming response
      belongs to. That lookup is unbuilt and is not tracked as anyone's task
      today.
- [ ] **WS4 — Resume path.** `resume_session`, incremental ledger-head
      verification, fresh-plan synthesis, tier selection, `PostRestore`
      fabric re-registration.
      The ledger-head half of verification landed
      (`specs/plans/2026-08-18-session-approval-head.md`):
      `ApprovalLedger::head()` content-addresses the ledger's decision state
      and `AgentSessionStore::resume` refuses when its caller-supplied
      `current_head` differs from the `approval_head` `ParkInput` committed
      at park. `specs/plans/2026-08-18-resume-session-orchestrator.md` then
      landed `resume_session` (`crates/mvm-hostd/src/session_resume.rs`, 12
      tests): load, refuse anything but `Hibernated`, resolve the resume
      point, `verify_content` it, build a `SynthesisInput` naming the session
      and the generation the resume opens (a struct literal in
      `synthesis_for_resume`, not `SynthesisInputBuilder` — mirroring
      `crate::run`'s own choice of literal over builder), and admit it
      through `mvm_hostd::plan_admission::admit_for_run`; only on success does
      it call the store's `resume` transition, so a refusal anywhere before
      that leaves the record parked and untouched. The synthesized plan
      carries `grants: None` — `ResumePlanMaterial` has no grant surface to
      fill them from, so the resumed plan re-arms neither the wall-clock
      timer nor a CPU share (see the `grants: None` paragraph under D5).
      Still open: nothing calls `ApprovalLedger::head()` to produce the value
      fed into either side of the step-2 comparison, so a caller — including
      `resume_session`, via `ResumeRequest::current_approval_head` — supplies
      it directly today by reading it off the record; there is no tier
      selection, no `PostRestore` fabric re-registration, no credential
      minting at the substitution endpoint.
      `resume_session` now has one production caller, `mvmctl agent-session
      resume` (WS6), so the steps above that it does implement do run on a
      real resume; the steps it does not implement — tier selection,
      `PostRestore`, credential minting — still do not. A session parked with
      `approval_head: None` resumes with no ledger fence at all.
- [ ] **WS5 — Retention ladder + GC.** Partially delivered by
      `specs/plans/2026-08-18-session-retention.md`: the existing
      `checkpoints_dir()` sweep (`mvmctl cache prune`) now refuses to reap a
      checkpoint any live or hibernated session names as its parent, a manual
      `mvmctl vm checkpoint rm` carries the same refusal, and
      `AgentSessionRecord::demote` gives a parked session a one-way step down
      the storage ladder. Not yet delivered: retention classes or expiry on
      the record, a scheduler that calls `demote`, or any actual movement of
      bytes between tiers — demoting only sets a field, nothing relocates a
      memory image, and nothing reads `storage_tier` to decide how to resume.
      A `Cold` session's checkpoint is still pinned by `pinned_checkpoints`
      regardless of tier, so the ladder does not yet make anything
      reclaimable — closing a session remains the only thing that frees its
      resume point.
- [x] **WS6 — CLI.** Delivered as `mvmctl agent-session
      {open,ls,show,park,resume}`
      (`crates/mvm-cli/src/commands/agent_session.rs`,
      `specs/plans/2026-08-19-session-cli-and-audit.md`). Named
      `agent-session`, not `session`: `mvmctl machine session` already means
      machine-session residency — a warm VM held across `invoke` calls — over
      a different store.
      `open` writes the initial record (Active, generation 1) and is what
      makes the other four reachable at all; before it existed no code path
      anywhere created an `AgentSessionRecord`, so `ls` printed nothing
      forever and `park`/`resume` could only refuse. `resume` is the first
      production caller of `mvm_hostd::session_resume::resume_session` — a
      caller that is both correctly constructed and, with `open` in place,
      exercisable end to end.
      `approve` and `close` are **not** delivered: there is no `close()`
      transition on the record and no approval-grant surface for a CLI to
      drive.
- [ ] **WS7 — Chain records.** Partial. `session.parked` and
      `session.resumed` are emitted by the CLI's park and resume paths
      (`AuditEmitter::emit_session_parked` / `emit_session_resumed`), each
      carrying non-colliding extras so a per-event label cannot overwrite a
      signed plan label of the same name. Still open: nothing verifies a
      session's chain as a unit the way `verify_audit_chain` walks a tenant's;
      there is no `session.closed` entry because no `close()` transition
      exists to emit one; and a chain-entry write failure downgrades to a
      warning with exit 0 (the precedent `bind_checkpoint_created` set), so a
      scripted operator cannot detect a missing entry from the exit status.
      `session.opened`, `sandbox.admitted`, `approval.requested`,
      `approval.granted` and `session.hibernated` are unwritten, and nothing
      yet routes through the `AgentApprovalEvent::audit_action` projection.

      **Event naming.** The two entries that exist are spelled `session.parked`
      and `session.resumed`, not the `sandbox.parked` / `sandbox.resumed` this
      spec first proposed. The code's spelling is the better one and the spec
      follows it: parking and resuming are transitions of a *session*, and
      `SandboxResidency` is a field of the session record rather than the
      subject of the event. A `sandbox.` prefix would also read as a sibling of
      `sandbox.admitted`, which is genuinely about one sandbox.
- [ ] **WS8 — Tests + BDD** per the Testing section.

## Out of scope

- Group quiesce and consistent cuts across multiple sandboxes (follow-on spec;
  the record is shaped for it).
- The agent-to-agent message fabric itself (ADR-046 and
  `specs/plans/2026-08-18-secure-message-fabric.md`).
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
