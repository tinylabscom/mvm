# Session retention: teaching the checkpoint GC about sessions, plus one-way demotion

`specs/plans/2026-08-18-durable-agent-sessions.md` D4 names a live hazard:
`checkpoints_dir()` already has an age-based, tag-aware GC —
`sweep_untagged_checkpoints` in `crates/mvm-cli/src/commands/ops/cache.rs`,
reached from `mvmctl cache prune` — and it predates this branch. It knows
nothing about sessions, so a session parked past the sweep's age cut loses
the checkpoint it resumes from and becomes permanently unresumable: the
session record survives, pointing at nothing. This branch delivers
`specs/plans/2026-08-18-session-retention.md` Tasks 1–3: teaching that sweep
about sessions, closing the same manual door on `mvmctl vm checkpoint rm`,
and adding the one-way `demote` transition the tier ladder needs.

## Delivered

- `mvm_runtime::agent_session::pinned_checkpoints(store)` — every checkpoint
  digest a live (`Active`) or hibernated (`Hibernated`) session names as its
  `parent_checkpoint`. `Closed` sessions are excluded: a sealed session is
  not resumable, so nothing it names needs holding. `CheckpointDigest` gained
  `PartialOrd, Ord` (a newtype over `String`, so the ordering is well-defined
  and changes no behavior) so the set can be a `BTreeSet`.
- `sweep_untagged_checkpoints` takes a `pinned: &BTreeSet<CheckpointDigest>`
  parameter and skips any checkpoint whose `meta_digest` is in it, printing
  `Kept checkpoint: <id> (pinned by a parked session's resume point)` so an
  operator sees why a stale-looking entry survived. The `mvmctl cache prune`
  call site derives `pinned` from `mvm_runtime::agent_session::
pinned_checkpoints` on the live `AgentSessionStore` before sweeping.
- A join test (`pinned_checkpoints_derived_from_a_real_session_protects_its_
checkpoint` in `crates/mvm-cli/src/commands/ops/cache.rs`) that writes a real
  `AgentSessionRecord` naming a real checkpoint's `meta_digest` as its
  `parent_checkpoint`, runs it through `pinned_checkpoints`, and feeds the
  result to the sweep — closing the gap the hand-built-set test left: that
  `pinned_checkpoints` reads `record.parent_checkpoint`, the sweep compares
  against `meta.meta_digest`, and both name the same field `CheckpointStore::
by_digest` resolves at resume, not one of the other type-compatible fields
  (`CheckpointMeta.id`, `compute_content_digest()`) a wrong pairing would
  still compile against.
- `mvmctl vm checkpoint rm` — the same data-loss class through a manual
  door: it deleted by id with no pin check, so an operator could make a
  parked session permanently unresumable by hand. It now reads the
  checkpoint's `meta_digest`, checks it against the same live-or-hibernated
  pin rule via a local `session_pinning_checkpoint` helper (which also names
  the session, since the set-only `pinned_checkpoints` can't), and refuses
  with the session id in the error when pinned. `rm` has no force/yes flag,
  so the refusal is unconditional — there is nothing to honor as an
  override, and none was added. Verified non-vacuous: dropping the pin
  check and rerunning
  `cargo nextest run -p mvm-cli rm_refuses_a_checkpoint_pinned_by_a_parked_session`
  fails with `called Result::unwrap_err() on an Ok value: ()`; restoring the
  check turns it green again.
- `AgentSessionRecord::demote(now_unix)` — moves an already-`Hibernated`
  session one rung down the storage ladder (`Resident → Parked → Cold`),
  one-way and always downward. Demoting a `Cold` session refuses with
  `SessionTransitionError::AlreadyColdest` rather than succeeding silently, so
  a caller looping over sessions can tell "moved" from "already at the
  bottom" apart. An `Active` session cannot be demoted at all
  (`NotHibernated`). The generation is unchanged (demoting suspends further,
  it doesn't end a residency), and `parent_checkpoint`/`journal_cursor`/
  `approval_head` all survive the transition unchanged — the whole point of
  demoting rather than closing is that the session stays resumable, just
  more cheaply stored. `demote`'s doc now states that after a demotion the
  stored `storage_tier` is authoritative and `park_reason` (overwritten to
  `RetentionDemotion`) is a breadcrumb of how the session got there, not an
  input a caller may recompute the tier from — `select_tier` is `pub` and the
  two fields can legitimately disagree once a demotion has happened.

## Deliberately not covered

- **Retention classes or expiry** on the session record, and a scheduler
  that walks sessions calling `demote`. Nothing in the workspace calls
  `demote` outside its own tests.
- **Actually moving bytes between tiers.** `demote` records an intent — it
  sets `storage_tier` and writes nothing else. Nothing relocates or drops a
  memory image, and nothing reads `storage_tier` to decide how to resume; a
  `Resident` and a `Cold` session resume identically today.
- **The sweep is age-based, not tier-based**, and `pinned_checkpoints` holds
  a pin for every non-`Closed` session regardless of tier. A `Cold` session's
  checkpoint is exactly as pinned as a `Resident` one's, so the ladder does
  not yet make anything reclaimable — closing a session remains the only
  thing that frees its resume point.
- **CLI (WS6)** and **chain records (WS7)** — unchanged by this branch.
