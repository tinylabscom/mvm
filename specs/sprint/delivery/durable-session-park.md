# Durable session park: crash-safe records + the park/resume state machine

`specs/plans/2026-08-18-durable-agent-sessions.md` D1/D3/D4 frame hibernation
as a third state between a live session and a sealed archive. This branch
delivers the state machine that transition rests on —
`specs/plans/2026-08-18-durable-session-park.md` Tasks 1–5, on top of the
filesystem store `specs/plans/2026-08-18-durable-session-substrate.md` landed
— with no VM, backend, or async surface involved.

## Delivered

- **Crash-safe record writes.** `AgentSessionStore::write` was a truncating
  write; a crash mid-write left `session.json` partial. It now goes through
  the workspace's shared `mvm_core::atomic_io::atomic_write` — the same
  helper `warm_artifacts.rs`, `vm/template/lifecycle/registry_sync.rs`, and
  `vm/name_registry.rs` already call in this crate — so a reader only ever
  observes the prior complete record or the new one, never a partial file,
  and the write is flushed and `fdatasync`ed before the rename. (An earlier
  pass on this branch added a private tmp+rename copy on the mistaken belief
  that no shared helper existed; a later correction pass deleted it in favor
  of the shared one.)
- `mvm_runtime::agent_session::{ParkReason, StorageTier, select_tier}` —
  `ParkReason` (`ApprovalWait`, `Idle`, `HostShutdown`, `Operator`,
  `RetentionDemotion`) selects a `StorageTier` (`Resident`, `Parked`,
  `Cold`): only `Idle` has a bounded, likely-soon resumption, so only `Idle`
  may stay resident; everything else — including an operator decision, whose
  latency is unbounded — parks straight to disk, and a retention demotion
  goes to `Cold`. Both enums round-trip as `snake_case` over serde.
- Four new fields on `AgentSessionRecord`: `journal_cursor` (u64),
  `approval_head` (`Option<mvm_core::checkpoint::ApprovalHead>`), `storage_tier`
  (`Option<StorageTier>`), `park_reason` (`Option<ParkReason>`). All four are
  `#[serde(default)]` (the latter three also `skip_serializing_if`), so a
  record written before this plan still loads.
- `AgentSessionRecord::park`/`resume` — pure transitions, returning the next
  record without writing it, plus `SessionTransitionError`
  (`NotActive`/`NotHibernated`/`Closed`). A park keeps the generation: it
  identifies one period of sandbox residency, and a park suspends that
  period rather than ending it. A resume increments the generation, which is
  what makes a frame addressed to the prior generation refusable afterward.
  Parking a hibernated session, resuming an active one, and any transition
  on a closed session are all refused.
- `AgentSessionStore::park`/`resume` — the store-level operations, each
  taking the caller's `expected_generation` and refusing when the on-disk
  generation has moved past it, before ever calling the record-level
  transition or writing. A refused transition leaves the stored record
  untouched.

## What the generation fence is, and is not

The fence is a check-then-act pair (load, compare, transition, write), not a
compare-and-swap. It correctly refuses a caller working from a record it
knows is stale, but two callers racing on the *same* observed generation can
both pass the check and both write — the store does not serialize that case.
The module has no call sites yet, so nothing races it today; the eventual
caller (resume admission, WS4) is responsible for serializing writes per
session.

## Deliberately not covered

- **The quiesce sequence.** `GuestRequest::SleepPrep`, `CheckpointIntegrations`,
  and `Wake` are defined in the agent's vsock protocol
  (`crates/mvm-agentd/src/vsock/request.rs`) with host-facing convenience
  functions already written (`crates/mvm-agentd/src/vsock/api.rs`:
  `request_sleep_prep`, `checkpoint_integrations`, `signal_wake`), but none
  of those functions has a caller anywhere in the workspace outside their
  own unit tests. Wiring park to call them, against a live guest, is the
  rest of WS3.
- **Resume admission (WS4).** `resume_session`, fresh `ExecutionPlan`
  synthesis via `mvm_hostd::plan_admission::admit_for_run` and
  `mvm_core::plan::synthesis::SynthesisInput`, the incremental
  approval-ledger head check, and `PostRestore` fabric re-registration.
- **Retention ladder and GC (WS5)**, including the refusal to reap a
  checkpoint any live or hibernated session names as its parent.
- **Chain records (WS7)** for `session.parked` / `session.resumed`.
- Two D1 record fields: the audit-chain head, and retention class + expiry.
  Both belong to the retention plan.
