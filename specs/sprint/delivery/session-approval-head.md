# Session approval head: content-addressed ledger state + a fenced resume

`specs/plans/2026-08-18-durable-agent-sessions.md` D1 names an approval-ledger
head as one of the hibernation record's fields, and D5 sketches a resume that
compares against it instead of replaying the ledger's full history. This
branch delivers the piece that made both producible —
`specs/plans/2026-08-18-session-approval-head.md` Tasks 1–3, on top of the
park state machine `specs/plans/2026-08-18-durable-session-park.md` landed —
with no VM, backend, or async surface involved.

## Delivered

- `mvm_contract::policy::approval::ApprovalLedger::head() -> [u8; 32]` —
  content-addresses the ledger's decision state: the session id, then for
  every record its approval id, its capability, and its terminal state
  (`state_tag`, written out by hand beside the existing `capability_tag` /
  `effect_tag` so a variant rename cannot silently move a recorded head).
  Deliberately excludes wall-clock fields (two ledgers that reached the same
  decisions hash alike regardless of when they were asked) and also excludes
  `resource_digest`, `policy_digest`, `admission_plan_digest`, and
  `authorized_operators` — the head names the decision, not the request that
  produced it. Mirrors the `PolicySet::digest` idiom already in the same
  file. Mutation-style tests pin each hashed field: an empty ledger is
  stable across two builds, a decision moves the head, two ledgers that made
  the same decisions at different times hash alike, and an approved versus a
  denied outcome over the same capability do not collide.
- `mvm_runtime::agent_session::ParkInput { reason, journal_cursor,
  approval_head }` — `AgentSessionStore::park` takes this in place of a bare
  `ParkReason`, so the cursor and the head commit with the transition in one
  fenced write. Before this, a caller wanting "parked at cursor N under head
  H" had to `write()` then `park()` — two writes the fence cannot
  distinguish, because a park does not change the generation.
- `AgentSessionStore::resume` gained a `current_head: Option<&ApprovalHead>`
  parameter. After the generation fence and before the transition, it
  compares `current_head` against the `approval_head` recorded at the last
  park and refuses on a mismatch, naming the session in the error. The
  refusal was verified non-vacuous: deleting the comparison turned
  `a_resume_is_refused_when_the_ledger_moved_while_parked` red before the
  check was restored.

## The two limits this slice does not close

- **A session parked with no recorded head resumes unfenced.** `park`'s
  `approval_head` is `Option`; when it is `None` there is nothing to compare
  against, so `resume` skips the check entirely and proceeds on the
  generation fence alone. `a_session_parked_without_a_head_resumes_unfenced`
  pins this as intended behavior, not a bug to file — the doc comment on the
  fence says so directly.
- **Nothing yet calls `ApprovalLedger::head()` to produce the value either
  side of the comparison carries.** Task 1 (the ledger can produce a head)
  and Task 2 (a park can commit one) are not wired to each other: every test
  in this slice constructs an `ApprovalHead` directly
  (`ApprovalHead::parse(format!("sha256:{}", ...))`) rather than reading it
  off a live ledger. The caller that would join them is `resume_session`,
  and it does not exist anywhere in the workspace — confirmed by an
  exhaustive `grep -rn resume_session . | grep -v '\.git/'`, whose nine hits
  are all prose in `specs/`, none in a `.rs` file.

## Deliberately not covered

Everything WS4 still names past the ledger-head comparison:

- **`resume_session` itself.** No implementation anywhere in the workspace.
- **A `SynthesisInput` for a resume, built through
  `SynthesisInputBuilder`.** `SynthesisInputBuilder` exists
  (`crates/mvm-core/src/plan/synthesis.rs`) but has no caller under
  `agent_session`, `mvm-hostd`, or `mvm-cli` that constructs a resume plan
  from it.
- **A call into `mvm_hostd::plan_admission::admit_for_run` from the resume
  path.** `admit_for_run` has 88 references in the tree, all of them the
  existing `mvmctl run` / pool / stream-input-plane admission surface;
  `crates/mvm-runtime/src/agent_session/mod.rs` calls it zero times.
  `AdmittedPlan` has only private fields and a test pinning it as
  unfabricable outside `plan_admission`, so a resume has to go through this
  call rather than construct its own plan by hand.
- **`PostRestore` fabric re-registration** and the quiesce sequence.
- **Retention ladder and GC (WS5).**
- **Chain records (WS7)** for `session.parked` / `session.resumed`.
- **A durability witness for `atomic_write`** in `mvm-core` — no test
  anywhere asserts the temp is consumed or that `sync_data` is reached.
