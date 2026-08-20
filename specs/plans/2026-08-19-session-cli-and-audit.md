# Session CLI and Chain Records Implementation Plan

Backing: preview
Validation: none

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give durable agent sessions an operator surface, and make park and
resume leave chain-signed evidence. This is WS6 and WS7 together, because the
chain entry belongs in the same code path the CLI drives — doing them apart
would touch park and resume twice.

**Architecture:** A new top-level `mvmctl agent-session` verb with `open`, `ls`,
`show`, `park`, and `resume`. (`open` was not in this plan as written; review of
Tasks 1-3 found the verb had no reachable production input without it — nothing
in the workspace created an `AgentSessionRecord` — so it landed alongside Task
4.) It is **not** called `session`: `mvmctl machine session`
already exists for machine sessions — warm-VM residency, idle timeouts, attach —
which is a different concept, and the types already settled this collision by
taking the `AgentSession*` prefix. `resume` gives
`mvm_hostd::session_resume::resume_session` its first production caller, which
is the largest disclosed gap in the work so far.

**Tech Stack:** Rust, `clap`, `anyhow`, `tempfile`, `cargo nextest`.

**Spec:** `specs/plans/2026-08-18-durable-agent-sessions.md` WS6 and WS7.

## Global Constraints

- **In every shell, including the one you commit from, put
  `export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target`
  in the SAME command as the cargo or git invocation.** The Bash tool does not
  persist exports. Do not point it elsewhere — the shared default is corrupted
  by other concurrent sessions. The machine is near-full on disk; an ENOSPC is a
  host condition from other worktrees, so wait and retry rather than deleting
  anything outside this worktree.
- Use `~/.cargo/bin/cargo`, never Homebrew's rustc.
- `#[allow(clippy::too_many_arguments)]` is banned; use a params struct.
- No plan, PR, or ADR references in code comments — CI-gated.
- Let the pre-commit hook run (~1 min workspace clippy); a guard blocks skipping.
- Gate before each commit: `cargo fmt --all -- --check`, then
  `cargo nextest run -p mvm-runtime -p mvm-hostd -p mvm-cli`, then
  `cargo clippy --workspace --all-targets -- -D warnings`.

## The label-override hazard, which Task 3 must not trip

`mvm_hostd::supervisor::audit::for_plan` does `labels.extend(extras)`
(`crates/mvm-hostd/src/supervisor/audit.rs:41`), so a per-event extra
**overrides** a plan label of the same key. The resume plan already carries
`session_id` and `session_generation` as signed plan labels. If an emitter
passes either as an extra, the signed plan's value is silently replaced by
whatever the emitter believed — and the entry would then attribute the action to
the emitter's guess rather than to what was admitted. Emitters here must use
distinct extra keys and let the plan labels stand.

## A search discipline this work has violated four times

Before writing that something does not exist, verify **exhaustively** — `| wc -l`
first, or read the whole result. Do NOT truncate a search establishing absence
through `head`. Four false "nothing does X" claims have reached committed
documents on this line of work that way. Cite the command behind each absence
claim in your report.

## Interfaces produced by this plan

```rust
// mvm_cli::commands::agent_session
pub struct Args { /* clap: ls | show | park | resume */ }
pub fn run(cli: &Cli, args: Args, cfg: &Config) -> anyhow::Result<()>;
```

---

### Task 1: `agent-session ls` and `show`

Read-only. Introduces the verb, its module, and its dispatch wiring.

**Files:**
- Create: `crates/mvm-cli/src/commands/agent_session.rs`
- Modify: `crates/mvm-cli/src/commands/mod.rs` (a `Commands` variant, placed by
  the file's existing convention — read it before inserting)
- Modify: `crates/mvm-cli/src/commands/dispatch.rs` (the match arm)
- Test: `crates/mvm-cli/src/commands/tests.rs` for argument parsing, plus inline
  tests in the new module for the rendering helpers

**Interfaces:**
- Consumes: `mvm_runtime::agent_session::{AgentSessionStore, AgentSessionRecord}`.
- Produces: the `agent-session` verb.

**Mirror, do not invent:** read `crates/mvm-cli/src/commands/trust.rs` (a
sibling top-level verb with subcommands) for module shape, and
`crates/mvm-cli/src/commands/pool.rs` for how a verb reaches a store. Follow
the repo's existing output conventions — check whether sibling verbs support
`--json` and match that choice rather than inventing a format.

- [x] **Step 1: Write the failing tests**

Argument parsing, in `commands/tests.rs` alongside the existing verb-parsing
tests (read a few first and match their style):

```rust
    #[test]
    fn agent_session_ls_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "agent-session", "ls"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::AgentSession(_))));
    }

    #[test]
    fn agent_session_show_requires_an_id() {
        assert!(Cli::try_parse_from(["mvmctl", "agent-session", "show"]).is_err());
        assert!(Cli::try_parse_from(["mvmctl", "agent-session", "show", "sess-alpha"]).is_ok());
    }

    #[test]
    fn agent_session_verb_is_not_named_session() {
        // `mvmctl machine session` already means machine-session residency.
        // A bare `session` verb would collide with it in the operator's head.
        assert!(Cli::try_parse_from(["mvmctl", "session", "ls"]).is_err());
    }
```

And a rendering test in the new module: given a record in each residency state,
the summary line names the state and, when parked, the reason and tier. Assert
on the rendered string so a format change is visible.

- [x] **Step 2: Run tests to verify they fail**

`export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target && ~/.cargo/bin/cargo nextest run -p mvm-cli agent_session`

Expected: FAIL to compile — no `Commands::AgentSession`.

- [x] **Step 3: Write the implementation**

`ls` lists every record from `AgentSessionStore::open()`, sorted as the store
returns them. `show <id>` prints one record's full state: residency, generation,
storage tier, park reason, journal cursor, resume point, and whether an approval
head is recorded. An absent session is an error naming the id, not an empty
success.

Do not print the approval head's value as if it were a secret — it is a digest
and safe to show — but do say when it is absent, because a session parked
without one resumes unfenced and an operator should be able to see that.

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-cli/src/commands/agent_session.rs crates/mvm-cli/src/commands/mod.rs crates/mvm-cli/src/commands/dispatch.rs crates/mvm-cli/src/commands/tests.rs
git commit -m "feat(cli): add agent-session ls and show"
```

---

### Task 2: `agent-session park`, with a `session.parked` chain entry

**Files:**
- Modify: `crates/mvm-cli/src/commands/agent_session.rs`
- Test: inline

**Interfaces:**
- Consumes: `AgentSessionStore::park`, `ParkInput`, `ParkReason`;
  `mvm_hostd::audit::emitter::AuditEmitter`.
- Produces: the `park` subcommand.

**Read first:** `crates/mvm-cli/src/commands/pool.rs:471` for how a CLI verb
builds an `AuditEmitter` from a resolved signer. Follow it; do not invent a
second way to get a signer.

**The entry:** emit `session.parked` after the park succeeds, carrying the
session id, the generation it parked at, the reason, and the tier — as **extras
whose keys do not collide with the resume plan's `session_id` /
`session_generation` labels**. Use distinct keys and say in a comment why they
are distinct. Emit only after the store write succeeds: an entry for a park that
did not happen is worse than a missing one.

- [x] **Step 1: Write the failing tests**

```rust
    #[test]
    fn park_requires_a_reason() {
        assert!(Cli::try_parse_from(["mvmctl", "agent-session", "park", "sess-a"]).is_err());
        assert!(Cli::try_parse_from(
            ["mvmctl", "agent-session", "park", "sess-a", "--reason", "approval-wait"]
        ).is_ok());
    }

    #[test]
    fn the_park_entry_keys_do_not_collide_with_the_plan_labels() {
        // for_plan extends plan labels with extras, so an extra sharing a key
        // silently replaces the signed plan's value. The resume plan carries
        // session_id and session_generation; a park entry must not shadow them.
        let extras = park_audit_extras(/* build from a parked record */);
        let keys: Vec<&str> = extras.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"session_id"));
        assert!(!keys.contains(&"session_generation"));
        assert!(!keys.is_empty(), "the entry must carry something");
    }
```

Factor the extras into a small pure function (`park_audit_extras`) so this is
testable without a signer or a filesystem. That factoring is the point of the
test, not incidental to it.

Also test that an unparseable `--reason` is refused rather than defaulting.

- [x] **Step 2: Run tests to verify they fail**

- [x] **Step 3: Write the implementation**

Map `--reason` onto `ParkReason` with an explicit match — no
stringly-typed fallthrough, and an unknown value is an error naming the accepted
set. The `--journal-cursor` flag defaults to 0; `--approval-head` is optional
and parsed through `ApprovalHead::parse` so a malformed value is refused at the
boundary.

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Verify the no-collision guard is not vacuous**

Temporarily rename one extras key to `session_id`, confirm the collision test
goes RED, restore. Report that RED with command and output. If it does not go
red, say so and stop rather than reporting one you did not observe.

- [x] **Step 6: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-cli/src/commands/agent_session.rs
git commit -m "feat(cli): add agent-session park with a chain-signed entry"
```

---

### Task 3: `agent-session resume`, with a `session.resumed` chain entry

This is the one that matters: `resume_session` has had no production caller.

**Files:**
- Modify: `crates/mvm-cli/src/commands/agent_session.rs`
- Test: inline

**Interfaces:**
- Consumes: `mvm_hostd::session_resume::{resume_session, ResumeRequest,
  ResumePlanMaterial}`, `AgentSessionStore`, `CheckpointStore`, `AuditEmitter`.
- Produces: the `resume` subcommand.

**The material problem, stated honestly:** `resume_session` needs a
`ResumePlanMaterial` — backend, image name and sha, kernel sha, cpus, mem —
which the session record deliberately does not carry. The CLI must get them
from somewhere. For this slice, take them as flags. That is clunky for an
operator and it is the right first step anyway: it makes the seam visible rather
than guessing, and a later slice can derive them from the resume point's
supervisor config. Say so in the flag help text.

- [x] **Step 1: Write the failing tests**

Parsing tests for the required flags, plus:

```rust
    #[test]
    fn resume_refuses_a_session_that_is_not_parked() {
        // Drive the real code path against a temp store: an Active session
        // must be refused before any checkpoint or signer work.
    }

    #[test]
    fn the_resume_entry_keys_do_not_collide_with_the_plan_labels() {
        // Same hazard as the park entry, same shape of assertion, against
        // resume_audit_extras.
    }
```

The refusal test needs a temp `AgentSessionStore` and `CheckpointStore`; read
the tests in `crates/mvm-hostd/src/session_resume.rs` for the fixture shape and
reuse the approach rather than inventing one. If those fixtures are
`#[cfg(test)]` and unreachable across the crate boundary, say so in your report
and build the smallest local equivalent.

- [x] **Step 2: Run tests to verify they fail**

- [x] **Step 3: Write the implementation**

Wire the subcommand to `resume_session`. Emit `session.resumed` **only after**
it returns `Ok`, carrying the session id, the generation the resume opened, and
the admitted plan's id — again as non-colliding extras.

A refused resume must not emit a success entry. Whether it emits a refusal entry
is a real question: this plan does **not** add one, because
`admit_for_run` emits nothing itself and a refusal entry from the CLI would be
the only record of a refusal that a non-CLI caller would never produce.
Record that as a limit rather than half-building it.

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Run the full gate**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all -- --check
~/.cargo/bin/cargo nextest run -p mvm-runtime -p mvm-hostd -p mvm-cli
~/.cargo/bin/cargo clippy --workspace --all-targets -- -D warnings
```

- [x] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands/agent_session.rs
git commit -m "feat(cli): add agent-session resume, the first caller of resume_session"
```

---

### Task 4: Docs, CLI reference, and delivery record

**Files:**
- Modify: `specs/plans/2026-08-18-durable-agent-sessions.md` (WS6, WS7 state)
- Modify: `specs/REFACTOR-STATUS.md`
- Modify: `public/src/content/docs/reference/cli-commands.md`
- Create: `specs/sprint/delivery/session-cli-and-audit.md`
- Modify: this plan's checkboxes

- [x] **Step 1: Document the verb in the CLI reference**

`public/src/content/docs/reference/cli-commands.md` is described in CLAUDE.md as
the complete CLI reference. Add `agent-session` and its five subcommands,
matching the file's existing entry format. Say plainly that `resume` requires
the workload material as flags and why. `xtask check-cli-help-matches-docs`
requires a row for every non-hidden top-level verb, so this gate is red until
the section lands.

- [x] **Step 2: Update WS6 and WS7 state**

WS6 is delivered for `open`/`ls`/`show`/`park`/`resume`, and `resume_session`
now has a caller that is both correctly constructed *and* exercisable — the
second half of which was not true before `open`. WS7 is **partial**: park and
resume emit entries, but nothing verifies a session's chain as a unit, there is
no `session.closed` entry because nothing can close a session (no `close()`
transition exists), and a chain-entry failure downgrades to a warning with exit
0, so a scripted operator cannot detect a missing entry. Be accurate; do not
tick WS7.

The design spec spells the events `sandbox.parked` / `sandbox.resumed`; the code
emits `session.parked` / `session.resumed`. Update the spec to match the code —
these are session transitions, and `SandboxResidency` is a field of a session
record rather than the subject of the event.

- [x] **Step 3: Update `specs/REFACTOR-STATUS.md`** and its "Last updated".

- [x] **Step 4: Write `specs/sprint/delivery/session-cli-and-audit.md`**,
style-matching that directory. Do NOT append to `specs/SPRINT.md` —
`xtask check-sprint-append` fails if its delivery section grows.

- [x] **Step 5: Tick this plan's checkboxes and run the doc gates**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo run -p xtask -- check-plan-names
~/.cargo/bin/cargo run -p xtask -- check-declared-backing
~/.cargo/bin/cargo run -p xtask -- check-sprint-append
~/.cargo/bin/cargo run -p xtask -- check-no-spec-refs-in-comments
```

These spec files carry `Backing: preview`, which bars a short list of assertive
verbs matched as whole words — quoting one in prose trips the gate. The gate
names the word it found.

- [x] **Step 6: Commit**

```bash
git add specs/ public/
git commit -m "docs: record the session CLI and chain-record slice"
```

---

## Deferred to later plans

- **A `close()` transition.** `SandboxResidency::Closed` still has no producer,
  so `session.closed` cannot be emitted and a session's resume point is never
  released by the retention pin. This is also why WS6's `close` subcommand is
  not delivered: there is nothing for it to call. `open` landed as part of this
  plan after review found the verb had no reachable production input at all —
  no code path anywhere created an `AgentSessionRecord`, so every other
  subcommand could only refuse.
- **A live source for `--approval-head` on `resume`.** Nothing in the workspace
  calls `ApprovalLedger::head()`, so an operator's only source for the value is
  `agent-session show` — which prints the head recorded on the record itself.
  Passing that back compares it against itself and fences nothing. The flag and
  the store's fence are both correct; what is missing is a reading of the
  ledger's current state to compare the recorded head against.
- **Verifying a session's chain as a unit.** Entries are emitted; nothing walks
  a session's entries end to end the way `verify_audit_chain` walks a tenant's.
- **A chain-entry failure is observable only as a warning.** Both park and
  resume exit 0 when the entry cannot be written, following
  `bind_checkpoint_created`'s precedent, so a scripted operator cannot detect a
  missing entry from the exit status.
- **Refusal entries.** A refused resume emits nothing.
- **Deriving `ResumePlanMaterial` from the resume point** rather than taking it
  as operator flags.
- **Booting a resumed session** — tier selection, memory-image restore,
  `PostRestore`, credential minting.
