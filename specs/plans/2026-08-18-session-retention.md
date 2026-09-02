# Session Retention Implementation Plan

Backing: preview
Validation: none

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the existing checkpoint sweep from deleting a parked session's
resume point, and give a parked session a way down the storage ladder.

**Architecture:** There is already a checkpoint GC —
`sweep_untagged_checkpoints` in `crates/mvm-cli/src/commands/ops/cache.rs`,
reached from `mvmctl cache prune`. It removes untagged checkpoints past a max
age and pins tagged ones. That is a live hazard for the durable-session work on
this branch: a session parked for days names an untagged `parent_checkpoint`, so
the sweep would delete the very checkpoint the session resumes from and make it
permanently unresumable. This plan teaches the existing sweep about sessions
rather than building a second GC, then adds the one-way demotion the tier ladder
needs.

**Tech Stack:** Rust, `anyhow`, `tempfile`, `cargo nextest`.

**Spec:** `specs/plans/2026-08-18-durable-agent-sessions.md` D4 (retention
ladder, "GC refuses any checkpoint named as a parent by a live or hibernated
session") and D1.

## Global Constraints

- **In every shell, including the one you commit from, put
  `export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target`
  in the SAME command as the cargo or git invocation.** The Bash tool does not
  persist exports. Do not point it elsewhere — the shared default is corrupted
  by other concurrent sessions.
- Use `~/.cargo/bin/cargo`, never Homebrew's rustc.
- `#[allow(clippy::too_many_arguments)]` is banned; use a params struct.
- No plan, PR, or ADR references in code comments — CI-gated.
- On-disk types keep `#[serde(deny_unknown_fields)]`; new fields additive with
  `#[serde(default)]`.
- Let the pre-commit hook run; a guard blocks skipping it. It runs workspace
  clippy and takes about a minute.
- Gate before each commit: `cargo fmt --all -- --check`, then
  `cargo nextest run -p mvm-core -p mvm-runtime -p mvm-cli`, then
  `cargo clippy --workspace --all-targets -- -D warnings`.

## A search discipline this branch has now violated four times

Before writing that something does not exist, verify **exhaustively** — pipe to
`| wc -l` first, or read the whole result. Do NOT truncate a search that
records absence through `head`. Four false "nothing does X" claims have
reached committed documents on this branch that way, including the claim that
nothing GCs checkpoints — which is what this plan exists to correct. Cite the
command behind each absence claim in your report.

## Interfaces produced by this plan

```rust
// mvm_runtime::agent_session
/// Every checkpoint digest a live or hibernated session names as its resume
/// point. A GC consults this before reaping.
pub fn pinned_checkpoints(store: &AgentSessionStore)
    -> anyhow::Result<std::collections::BTreeSet<CheckpointDigest>>;

impl AgentSessionRecord {
    /// Move an already-parked session one rung down the ladder.
    pub fn demote(&self, now_unix: u64) -> Result<Self, SessionTransitionError>;
}

// mvm_cli::commands::ops::cache  (signature change)
pub(super) fn sweep_untagged_checkpoints(
    store: &CheckpointStore,
    pinned: &BTreeSet<CheckpointDigest>,
    now_unix: u64,
    max_age_secs: u64,
) -> anyhow::Result<usize>;
```

---

### Task 1: The sweep must not reap a session's resume point

**Files:**
- Modify: `crates/mvm-runtime/src/agent_session/mod.rs` (add `pinned_checkpoints`)
- Modify: `crates/mvm-cli/src/commands/ops/cache.rs` (`sweep_untagged_checkpoints`
  ~L824 and its caller)
- Test: inline `mod tests` in both files

**Interfaces:**
- Consumes: `AgentSessionStore`, `CheckpointDigest`.
- Produces: `pinned_checkpoints`; a new `pinned` parameter on the sweep.

**Read first:** `sweep_untagged_checkpoints` and the call site that reaches it
from `mvmctl cache prune`. Follow the file's existing reporting style — it
prints what it removes so an operator sees it. A skipped-because-pinned
checkpoint should be visible too, not silently retained.

**Which sessions pin:** `Active` and `Hibernated` both. An `Active` session's
sandbox is running but its resume point is still what a later park would rest
on; a `Hibernated` session's is the thing it resumes from. `Closed` does not
pin — a closed session is sealed and not resumable, so its resume point is free.

- [x] **Step 1: Write the failing tests**

In `agent_session/mod.rs`:

```rust
    #[test]
    fn pinned_checkpoints_covers_active_and_hibernated_but_not_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());

        let mut live = record("sess-live");
        live.parent_checkpoint = Some(digest_of("11"));
        store.write(&live).unwrap();

        let mut parked = record("sess-parked");
        parked.parent_checkpoint = Some(digest_of("22"));
        parked.state = SandboxResidency::Hibernated;
        store.write(&parked).unwrap();

        let mut closed = record("sess-closed");
        closed.parent_checkpoint = Some(digest_of("33"));
        closed.state = SandboxResidency::Closed;
        store.write(&closed).unwrap();

        let pinned = pinned_checkpoints(&store).unwrap();
        assert!(pinned.contains(&digest_of("11")));
        assert!(pinned.contains(&digest_of("22")));
        assert!(
            !pinned.contains(&digest_of("33")),
            "a closed session is not resumable, so it pins nothing"
        );
    }

    #[test]
    fn a_session_with_no_resume_point_pins_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        store.write(&record("sess-alpha")).unwrap();
        assert!(pinned_checkpoints(&store).unwrap().is_empty());
    }
```

Write a `digest_of(byte)` helper if the module lacks one, mirroring the existing
`head_of`.

In `ops/cache.rs`, add a test asserting the sweep leaves a pinned checkpoint
alone even when it is untagged and past the age cut, and still reaps an
unpinned one in the same run. Read the file's existing checkpoint-sweep tests
first and follow their fixture style.

- [x] **Step 2: Run tests to verify they fail**

`export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target && ~/.cargo/bin/cargo nextest run -p mvm-runtime pinned_checkpoints`

Expected: FAIL to compile — no `pinned_checkpoints`.

- [x] **Step 3: Write the implementation**

```rust
/// Every checkpoint a live or hibernated session names as its resume point.
///
/// A garbage collector consults this before reaping. Without it, a session
/// parked for longer than the sweep's age cut loses the checkpoint it resumes
/// from and becomes permanently unresumable — the record survives and points at
/// nothing. `Closed` sessions are excluded deliberately: a sealed session is not
/// resumable, so nothing it names needs holding.
pub fn pinned_checkpoints(
    store: &AgentSessionStore,
) -> Result<std::collections::BTreeSet<mvm_core::checkpoint::CheckpointDigest>> {
    let mut pinned = std::collections::BTreeSet::new();
    for record in store.list()? {
        if matches!(record.state, SandboxResidency::Closed) {
            continue;
        }
        if let Some(digest) = record.parent_checkpoint {
            pinned.insert(digest);
        }
    }
    Ok(pinned)
}
```

`CheckpointDigest` needs `Ord` for `BTreeSet`. Check whether it derives it; if
not, add `PartialOrd, Ord` to its derive list — it is a newtype over `String`,
so the ordering is well-defined and adding it changes no behaviour. Say in your
report which you did.

Then add the `pinned` parameter to `sweep_untagged_checkpoints`, skip any
checkpoint whose `meta_digest` is in the set, and thread the set from the call
site via `mvm_runtime::agent_session::pinned_checkpoints`. Report a skipped
checkpoint in the file's existing style so the operator sees why a stale entry
stayed.

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Verify the guard is not vacuous**

Temporarily drop the `pinned` check from the sweep, confirm the cache test goes
RED, then restore. Report that RED with command and output. If it does not go
red, say so and stop rather than reporting one you did not observe.

- [x] **Step 6: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-runtime/src/agent_session/mod.rs crates/mvm-cli/src/commands/ops/cache.rs crates/mvm-core/src/checkpoint.rs
git commit -m "fix(cli): stop the checkpoint sweep reaping a parked session's resume point"
```

---

### Task 2: One-way demotion down the storage ladder

**Files:**
- Modify: `crates/mvm-runtime/src/agent_session/mod.rs`
- Test: inline `mod tests`

**Interfaces:**
- Consumes: `StorageTier`, `SandboxResidency`, `SessionTransitionError`.
- Produces: `AgentSessionRecord::demote`.

**Why:** `ParkReason::RetentionDemotion` documents itself as demoting "an
already-parked session further down the ladder", but `park()` refuses a session
that is already `Hibernated`, so the only transition that consumes a
`ParkReason` cannot apply that one. The variant is currently unreachable through
the state machine that owns it. `demote` is the missing transition.

**The rule:** demotion is one-way and always downward —
`Resident` → `Parked` → `Cold`. Demoting a `Cold` session is a no-op error
rather than a silent success, so a caller looping over sessions can tell the
difference between "moved" and "already at the bottom". A session that is not
`Hibernated` cannot be demoted at all.

- [x] **Step 1: Write the failing tests**

```rust
    #[test]
    fn demotion_walks_one_rung_down_the_ladder() {
        let resident = record("sess-alpha")
            .park(&ParkInput { reason: ParkReason::Idle, journal_cursor: 0, approval_head: None }, 100)
            .unwrap();
        assert_eq!(resident.storage_tier, Some(StorageTier::Resident));

        let parked = resident.demote(200).unwrap();
        assert_eq!(parked.storage_tier, Some(StorageTier::Parked));
        assert_eq!(parked.park_reason, Some(ParkReason::RetentionDemotion));
        assert_eq!(parked.generation, resident.generation, "demotion is not a new residency");

        let cold = parked.demote(300).unwrap();
        assert_eq!(cold.storage_tier, Some(StorageTier::Cold));
    }

    #[test]
    fn a_cold_session_cannot_be_demoted_further() {
        let cold = record("sess-alpha")
            .park(&ParkInput { reason: ParkReason::RetentionDemotion, journal_cursor: 0, approval_head: None }, 100)
            .unwrap();
        assert_eq!(cold.storage_tier, Some(StorageTier::Cold));
        assert!(matches!(cold.demote(200), Err(SessionTransitionError::AlreadyColdest)));
    }

    #[test]
    fn an_active_session_cannot_be_demoted() {
        assert!(matches!(
            record("sess-alpha").demote(200),
            Err(SessionTransitionError::NotHibernated)
        ));
    }

    #[test]
    fn demotion_preserves_the_resume_point_and_the_cursor() {
        // The whole point of demoting rather than closing is that the session
        // stays resumable, just more cheaply stored.
        let mut rec = record("sess-alpha");
        rec.parent_checkpoint = Some(digest_of("11"));
        let parked = rec
            .park(&ParkInput { reason: ParkReason::Idle, journal_cursor: 42, approval_head: None }, 100)
            .unwrap();
        let cold = parked.demote(200).unwrap().demote(300);
        let cold = cold.unwrap_or_else(|_| parked.demote(200).unwrap());
        assert_eq!(cold.journal_cursor, 42);
        assert_eq!(cold.parent_checkpoint, Some(digest_of("11")));
    }
```

The last test's double-demote is awkward as written — simplify it to whatever
reaches `Cold` cleanly given your implementation, keeping the property it
asserts.

- [x] **Step 2: Run tests to verify they fail**

- [x] **Step 3: Write the implementation**

Add an `AlreadyColdest` variant to `SessionTransitionError`, then:

```rust
    /// Move an already-parked session one rung down the storage ladder.
    ///
    /// One-way and always downward: `Resident` releases RAM to disk, `Parked`
    /// releases the memory image and leaves the record and journal. The
    /// generation is unchanged — demoting does not end a residency, it makes
    /// the same suspended one cheaper to hold. The resume point and journal
    /// cursor are preserved, because a demoted session is still resumable; only
    /// the cost of holding it changed.
    pub fn demote(&self, now_unix: u64) -> Result<Self, SessionTransitionError> {
        match self.state {
            SandboxResidency::Closed => return Err(SessionTransitionError::Closed),
            SandboxResidency::Active => return Err(SessionTransitionError::NotHibernated),
            SandboxResidency::Hibernated => {}
        }
        let next = match self.storage_tier {
            Some(StorageTier::Resident) => StorageTier::Parked,
            Some(StorageTier::Parked) => StorageTier::Cold,
            Some(StorageTier::Cold) => return Err(SessionTransitionError::AlreadyColdest),
            None => return Err(SessionTransitionError::NotHibernated),
        };
        Ok(Self {
            storage_tier: Some(next),
            park_reason: Some(ParkReason::RetentionDemotion),
            updated_unix: now_unix,
            ..self.clone()
        })
    }
```

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-runtime/src/agent_session/mod.rs
git commit -m "feat(runtime): add one-way demotion down the session storage ladder"
```

---

### Task 3: Specs and delivery record

**Files:**
- Modify: `specs/plans/2026-08-18-durable-agent-sessions.md` (D4, WS5 state)
- Modify: `specs/REFACTOR-STATUS.md`
- Create: `specs/sprint/delivery/session-retention.md`
- Modify: this plan's checkboxes

- [x] **Step 1: Correct D4 and the record of what GCs checkpoints**

D4 and the earlier delivery records say nothing GCs `checkpoints_dir()`. That
is false and was false when written: `sweep_untagged_checkpoints` in
`crates/mvm-cli/src/commands/ops/cache.rs` has removed untagged checkpoints past
a max age all along, reached from `mvmctl cache prune`. Correct every place that
claim appears — search exhaustively for it rather than fixing the first hit — and
say what this plan changed: the sweep now consults the sessions that pin a
resume point.

- [x] **Step 2: Update WS5's state, naming what remains**

This plan delivers the GC refusal and the demotion transition. It does NOT
deliver: retention classes or expiry on the record, a scheduler that calls
`demote`, or any actual movement of bytes between tiers — demoting sets a field,
nothing relocates a memory image. Say so; do not tick WS5.

- [x] **Step 3: Update `specs/REFACTOR-STATUS.md`** and its "Last updated".

- [x] **Step 4: Write `specs/sprint/delivery/session-retention.md`**,
style-matching that directory. Do NOT append to `specs/SPRINT.md`.

- [x] **Step 5: Tick this plan's checkboxes and run the doc gates**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo run -p xtask -- check-plan-names
~/.cargo/bin/cargo run -p xtask -- check-declared-backing
~/.cargo/bin/cargo run -p xtask -- check-sprint-append
~/.cargo/bin/cargo run -p xtask -- check-no-spec-refs-in-comments
```

These files carry `Backing: preview`, which bars a short list of assertive verbs
matched as whole words — quoting one trips the gate. The gate names the word.

- [x] **Step 6: Commit**

```bash
git add specs/
git commit -m "docs: record the session retention slice"
```

---

## Deferred to later plans

- **Retention classes and expiry** on the session record, and a scheduler that
  walks sessions calling `demote`.
- **Actually moving bytes between tiers.** `demote` records an intent; nothing
  relocates or drops a memory image, and nothing reads `storage_tier` to decide
  how to resume.
- **The sweep is age-based, not tier-based.** A `Cold` session's checkpoint is
  still pinned by `pinned_checkpoints`, so the ladder does not yet make anything
  reclaimable — closing a session is the only thing that frees its resume point.
- **CLI (WS6)** and **chain records (WS7)**.
