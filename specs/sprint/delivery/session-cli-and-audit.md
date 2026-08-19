# Session CLI and chain records: the operator surface for durable agent sessions

`specs/plans/2026-08-18-durable-agent-sessions.md` WS6 and WS7, delivered
together because the chain entry belongs in the same code path the CLI drives —
doing them apart would have touched park and resume twice. Implementation plan:
`specs/plans/2026-08-19-session-cli-and-audit.md`.

Everything before this branch was library: a record type, a store, park and
resume transitions, and `resume_session`. None of it was reachable from a
terminal, and one piece of it was not reachable at all.

## Delivered

- **`mvmctl agent-session`** (`crates/mvm-cli/src/commands/agent_session.rs`),
  a new top-level verb with five subcommands. Named `agent-session` and not
  `session` because `mvmctl machine session` already means machine-session
  residency — a warm VM held across `invoke` calls, over a different store —
  and the types settled the collision first by taking the `AgentSession`
  prefix.
- **`open <id> [--resume-point <sha256:...>] [--member <name>]...`** — writes
  the initial record: `SandboxResidency::Active`, generation 1, no park fields.
  This is the piece nothing else supplied. Before it, `agent_sessions_dir` had
  six references workspace-wide (its definition, its test, two doc comments and
  `AgentSessionStore::open`) and the only production writers of the store were
  `park` and `resume`, both of which need a record that already exists. On a
  real host `ls` therefore printed `(no agent sessions)` forever, `park` and
  `resume` always errored, and both chain emitters were unreachable.
  - The id is parsed through `AgentSessionId::parse` at the boundary, so a
    malformed one is refused before it can be joined into a store path.
  - An existing session refuses rather than being overwritten. An overwrite
    would reset a live session to generation 1 and drop its `parent_checkpoint`
    — the one thing a parked session cannot be brought back without.
  - `--resume-point` goes through `CheckpointDigest::parse`, so a malformed
    digest refuses before any write. A session with no resume point is legal;
    `resume` refuses it later, which is the right place for that refusal.
  - `--member` is repeatable and matters: the park entry chains under
    `members[0]`'s persisted plan, so a session opened with none takes the
    warn-instead-of-record path. `open` says so at open time rather than
    letting the operator discover it at park time.
- **`ls [--json]` / `show <id> [--json]`** — the read-only half. `show` on an
  absent session is an error naming the id, not an empty success, and it says
  in as many words when no approval head was recorded, because such a session
  resumes unfenced.
- **`park <id> --reason <reason> [--journal-cursor] [--approval-head]`** —
  drives `AgentSessionStore::park` and then emits a `session.parked`
  chain-signed entry under the member sandbox's admitted plan. `--reason` maps
  onto `ParkReason` through an explicit match; an unknown value refuses naming
  the accepted set, because falling through to a default would pick a storage
  tier nobody asked for.
- **`resume <id> --backend --image --image-sha256 --cpus --mem-mib [...]`** —
  the first production caller of
  `mvm_hostd::session_resume::resume_session`, emitting `session.resumed` on
  success. With `open` in place that caller is not only correctly constructed
  but exercisable: a session can be opened, parked and resumed in one sitting,
  which was not true of any earlier arrangement of this code.
- **`AgentSessionStore::exists`** (`crates/mvm-runtime/src/agent_session/`) —
  a presence probe deliberately distinct from `load().is_ok()`. A record that
  is on disk but unparseable reads as present, so the create path treats a
  corrupt record as a reason to refuse rather than a reason to overwrite.
- **`session.` audit events classify as `Lifecycle`**
  (`crates/mvm-client/src/audit/event.rs`), alongside `checkpoint.`, instead
  of falling through to `AuditEventKind::Other`. Classification only —
  `sync_policy_for` already defaulted to `Barrier`, so durability was never
  affected.
- **The CLI reference** gains a `## Durable Agent Sessions` section
  (`public/src/content/docs/reference/cli-commands.md`) with a row per
  subcommand. `xtask check-cli-help-matches-docs` requires a row for every
  non-hidden top-level verb and was red on this branch until it landed.

## The label-override hazard, and a guard that watches all of it

`mvm_hostd::supervisor::audit::for_plan` does `labels.extend(extras)`, so a
per-event extra **overrides** a plan label of the same key. The resume plan
carries `session_id` and `session_generation` as signed labels, so an emitter
reusing either name would replace what was admitted with what the emitter
believed, and the entry would then attribute the action to a guess.

Both emitters use distinct keys (`parked_session`, `parked_at_generation`,
`park_reason`, `park_storage_tier`; `resumed_session`,
`resumed_at_generation`, `resumed_plan_id`). The test that holds them there no
longer compares against a copied list of two names — it derives the forbidden
set from `synthesis_for_resume(record, material).audit_labels`, the labels the
resume path actually builds. The copied list was watching half the surface:
that synthesis also emits `session_parent_checkpoint` and
`session_approval_head`, and an extra named either would have collided
uncaught. Verified non-vacuous by renaming one park extra to
`session_parent_checkpoint` and one resume extra to `session_approval_head`
and confirming both tests go red, naming the colliding key, before restoring.

## Deliberately not covered

- **A `close()` transition.** `SandboxResidency::Closed` still has no
  producer, so no `session.closed` entry can be emitted and a session's resume
  point is never released by the retention pin. `open`'s counterpart is
  missing, which is why WS6's `close` subcommand is not delivered either.
- **Verifying a session's chain as a unit.** Entries are written; nothing
  walks a session's entries end to end the way `verify_audit_chain` walks a
  tenant's.
- **A chain-entry failure is a warning, not a failure.** Both park and resume
  report the transition as done with exit 0 when the entry cannot be written,
  following `bind_checkpoint_created`'s precedent: the store write already
  succeeded, and failing afterwards would tell an operator the park did not
  happen when it did. The cost is that a scripted operator cannot detect a
  missing entry from the exit status.
- **Refusal entries.** A refused resume emits nothing. `admit_for_run` emits
  nothing itself, and a refusal entry written only by the CLI would record
  something no non-CLI caller would ever produce.
- **`--approval-head` on `resume` has no production source.** Nothing in the
  workspace calls `ApprovalLedger::head()`, so an operator's only source for
  the value is `agent-session show` — which prints the record's own recorded
  head, and passing that back compares it against itself and fences nothing.
  The flag is correct and the fence works; what is missing is a live reading
  of the ledger to compare against.
- **`ResumePlanMaterial` is taken as operator flags** — backend, image, rootfs
  and kernel sha, cpus, memory. The session record deliberately holds none of
  it: an image, a kernel and a sandbox size each change on their own schedule,
  and recording them would make the record a second copy of the plan. Deriving
  them from the resume point's supervisor config is a later step; flags keep
  the seam visible rather than guessing.
- **Booting a resumed session.** A resume stops at an admitted plan. Tier
  selection, memory-image restore, `PostRestore` fabric re-registration and
  credential minting are all absent, and the command says so on completion
  rather than letting silence imply a boot.

## Tests

28 tests in `commands::agent_session::tests` and 2 more in
`commands::tests` for `open`'s argument parsing, plus one in
`mvm_runtime::agent_session` for `exists` and two classification cases in
`mvm_client::audit::event`. The one that matters most is
`open_then_park_then_show_walks_one_session_end_to_end`: it opens a session,
asserts `ls` now sees it, parks it through the real transition, and asserts
what `show` renders off the record the store holds afterwards — so the verb is
witnessed as a usable whole rather than as five independent subcommands that
each happen to compile.
