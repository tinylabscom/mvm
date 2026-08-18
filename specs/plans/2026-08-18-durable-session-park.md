# Durable Session Park State Machine Implementation Plan

Backing: preview
Validation: none

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a durable agent session parkable and resumable as a *state
machine* — durable on disk, fenced against stale writers, and refusing
transitions that would corrupt a session's identity — without yet touching a VM.

**Architecture:** Extends `mvm_runtime::agent_session`, built by the substrate
plan. The record gains the D1 fields it was missing (`journal_cursor`,
`approval_head`, `tier`, `park_reason`), plus `park()` / `resume()` transitions.
A park keeps the generation; a *resume* opens generation+1, which is what fences
a late frame addressed to the prior generation. Store-level operations
compare-and-swap on the generation, so a caller holding a stale record cannot
clobber a newer one. Every task here is unit-testable with no VM, no backend,
and no async.

**Tech Stack:** Rust, `serde` / `serde_json`, `anyhow`, `thiserror`, `tempfile`,
`cargo nextest`.

**Spec:** `specs/plans/2026-08-18-durable-agent-sessions.md` (D1, D3, D4 tier
selection). The substrate it builds on is
`specs/plans/2026-08-18-durable-session-substrate.md`.

## Global Constraints

- **In every shell, including the one you commit from, export
  `CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target`.**
  The Bash tool does not persist exports across calls, so put it in the SAME
  command as the cargo or git invocation. Do not unset it, point it elsewhere,
  or create a fresh one — the shared default is corrupted by other concurrent
  sessions and cost a previous implementer over an hour.
- Use `~/.cargo/bin/cargo`, never Homebrew's rustc.
- Every `~/.mvm` path goes through a `mvm_core::config` helper.
- `#[allow(clippy::too_many_arguments)]` is banned. Use a struct + builder.
- No plan, PR, or ADR references in code comments — gated by
  `xtask check-no-spec-refs-in-comments`. Explain reasoning directly instead.
- Every on-disk type carries `#[serde(deny_unknown_fields)]`.
- New fields are additive with `#[serde(default)]`; no schema-version bump.
- Bypassing the pre-commit hook is blocked by a guard. Let the hook run.
- Gate before each commit: `cargo fmt --all -- --check`, then
  `cargo nextest run -p mvm-core -p mvm-runtime`, then
  `cargo clippy --workspace --all-targets -- -D warnings`.

## Interfaces produced by this plan

Later plans (resume admission, retention GC, CLI) consume exactly these:

```rust
// mvm_runtime::agent_session
pub enum ParkReason { ApprovalWait, Idle, HostShutdown, Operator, RetentionDemotion }
pub enum StorageTier { Resident, Parked, Cold }

pub fn select_tier(reason: ParkReason) -> StorageTier;

pub struct AgentSessionRecord {
    // ... existing fields ...
    pub journal_cursor: u64,
    pub approval_head: Option<mvm_core::checkpoint::ApprovalHead>,
    pub tier: Option<StorageTier>,
    pub park_reason: Option<ParkReason>,
}

impl AgentSessionRecord {
    pub fn park(&self, reason: ParkReason, now_unix: u64) -> Result<Self, SessionTransitionError>;
    pub fn resume(&self, now_unix: u64) -> Result<Self, SessionTransitionError>;
}

pub enum SessionTransitionError { NotActive, NotHibernated, Closed }

impl AgentSessionStore {
    pub fn park(&self, id: &AgentSessionId, expected_generation: u64,
                reason: ParkReason, now_unix: u64) -> Result<AgentSessionRecord>;
    pub fn resume(&self, id: &AgentSessionId, expected_generation: u64,
                  now_unix: u64) -> Result<AgentSessionRecord>;
}
```

---

### Task 1: Make the record write crash-safe

The store currently truncates `session.json` in place, so a crash mid-write
destroys the prior good record. The design leans on the record being the thing
that survives a memory image, so this must land before anything parks.

**Files:**
- Modify: `crates/mvm-runtime/src/agent_session/mod.rs` (`write`, ~L96)
- Test: same file, inline `mod tests`

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature change — `write` keeps `(&self, &AgentSessionRecord) -> Result<()>`.

**Note on reuse:** this repo has no shared atomic-write helper; the tmp+rename
pattern is inlined at eleven-plus sites (see `crates/mvm-client/src/volume/lifecycle.rs`).
Keep this copy **private to this module** rather than adding a twelfth public
one, and do not refactor the other sites — that is a separate change.

- [x] **Step 1: Write the failing test**

```rust
    #[test]
    fn a_write_leaves_no_partial_record_when_a_stale_temp_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();

        // Simulate a crashed prior write: a leftover temp beside the record.
        let dir = tmp.path().join("sess-alpha");
        std::fs::write(dir.join("session.json.tmp"), b"{ truncated").unwrap();

        // A subsequent write must still succeed and must leave the record
        // readable, not the debris.
        let mut next = rec.clone();
        next.generation = 2;
        store.write(&next).unwrap();
        assert_eq!(store.load(&rec.session_id).unwrap().generation, 2);
    }

    #[test]
    fn the_record_is_never_observed_truncated_mid_write() {
        // Writing over an existing record must be atomic from a reader's view:
        // the destination is only ever the old complete record or the new one.
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        let path = tmp.path().join("sess-alpha").join("session.json");
        let before = std::fs::read(&path).unwrap();

        let mut next = rec.clone();
        next.generation = 7;
        store.write(&next).unwrap();
        let after = std::fs::read(&path).unwrap();

        assert_ne!(before, after);
        // Both are complete records, not partial JSON.
        serde_json::from_slice::<AgentSessionRecord>(&before).unwrap();
        serde_json::from_slice::<AgentSessionRecord>(&after).unwrap();
    }
```

- [x] **Step 2: Run tests to verify they fail**

Run: `export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target && ~/.cargo/bin/cargo nextest run -p mvm-runtime agent_session`

Expected: `a_write_leaves_no_partial_record_when_a_stale_temp_exists` FAILS
once the temp path is in use. If either test passes before your change, say so
plainly in your report rather than claiming a RED you did not observe — a single
`fs::write` of a small buffer is often atomic in practice. Both tests exist to
pin the property, not to prove the old code broken.

- [x] **Step 3: Write the implementation**

Replace the body of `write` with a tmp+rename, and add the private helper:

```rust
    /// Write a record, replacing any prior one for the same session.
    ///
    /// Writes to a temp beside the destination and renames over it, so a crash
    /// mid-write leaves the previous complete record rather than a truncated
    /// one. The record is what a session's durability rests on — a memory image
    /// may be reaped, but losing the record loses the session.
    pub fn write(&self, record: &AgentSessionRecord) -> Result<()> {
        let path = self.record_path(&record.session_id);
        let dir = path
            .parent()
            .expect("record path always has a parent directory");
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create session dir {}", dir.display()))?;
        let json = serde_json::to_vec_pretty(record).context("serialize session record")?;
        write_then_rename(&path, &json)
    }
```

```rust
/// Write `bytes` to `path` via a temp in the same directory, then rename.
///
/// Kept private to this module deliberately. The same pattern is inlined at
/// many other call sites in this workspace; consolidating them is worth doing
/// but is not this module's job, and adding another public copy would make the
/// eventual consolidation harder rather than easier.
fn write_then_rename(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)
        .with_context(|| format!("write session record temp {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename session record into {}", path.display()))?;
    Ok(())
}
```

- [x] **Step 4: Run tests to verify they pass**

Run the same nextest command. Expected: PASS, plus the six pre-existing
`agent_session` tests still green.

- [x] **Step 5: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-runtime/src/agent_session/mod.rs
git commit -m "fix(runtime): write the session record atomically"
```

---

### Task 2: `ParkReason`, `StorageTier`, and the tier-selection policy

**Files:**
- Modify: `crates/mvm-runtime/src/agent_session/mod.rs`
- Test: same file, inline `mod tests`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `ParkReason`, `StorageTier`, `select_tier`.

- [x] **Step 1: Write the failing tests**

```rust
    #[test]
    fn an_unbounded_wait_parks_straight_to_disk() {
        // An operator decision and a host shutdown both have unbounded or
        // externally-determined latency, so neither may hold RAM.
        assert_eq!(select_tier(ParkReason::ApprovalWait), StorageTier::Parked);
        assert_eq!(select_tier(ParkReason::HostShutdown), StorageTier::Parked);
        assert_eq!(select_tier(ParkReason::Operator), StorageTier::Parked);
    }

    #[test]
    fn an_idle_session_may_linger_resident() {
        // Idle is the one reason with a bounded, cheap resumption: the sandbox
        // may still be wanted shortly, so it stays resident until a TTL demotes
        // it.
        assert_eq!(select_tier(ParkReason::Idle), StorageTier::Resident);
    }

    #[test]
    fn a_retention_demotion_goes_cold() {
        assert_eq!(select_tier(ParkReason::RetentionDemotion), StorageTier::Cold);
    }

    #[test]
    fn park_reason_and_tier_round_trip_as_snake_case() {
        let json = serde_json::to_string(&ParkReason::ApprovalWait).unwrap();
        assert_eq!(json, "\"approval_wait\"");
        assert_eq!(
            serde_json::from_str::<ParkReason>(&json).unwrap(),
            ParkReason::ApprovalWait
        );
        let tier = serde_json::to_string(&StorageTier::Parked).unwrap();
        assert_eq!(tier, "\"parked\"");
        assert_eq!(
            serde_json::from_str::<StorageTier>(&tier).unwrap(),
            StorageTier::Parked
        );
    }
```

- [x] **Step 2: Run tests to verify they fail**

Expected: FAIL to compile — `cannot find type 'ParkReason' in this scope`.

- [x] **Step 3: Write the implementation**

```rust
/// Why a sandbox was parked. The reason is not decoration: it selects the
/// storage tier, because what a park costs while it waits depends entirely on
/// how long the wait might be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParkReason {
    /// Blocked on a human decision. Latency is unbounded — the operator may be
    /// asleep — so this must never hold RAM.
    ApprovalWait,
    /// No work for a while. Resumption is likely and soon, so this is the one
    /// reason that may stay resident.
    Idle,
    /// The host is going down. The sandbox cannot survive it either way, so the
    /// memory image goes to disk.
    HostShutdown,
    /// An operator parked it explicitly.
    Operator,
    /// A retention policy demoted an already-parked session further down the
    /// ladder.
    RetentionDemotion,
}

/// Where a parked session's state lives, and therefore what it costs to hold
/// and what it costs to resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageTier {
    /// Live paused process; memory resident. Fastest to resume, and the only
    /// tier that consumes RAM while it waits.
    Resident,
    /// Memory image on disk, no process. Costs disk, resumes by restore.
    Parked,
    /// Record and journal only. Costs almost nothing; resumes by a fresh boot
    /// and a journal replay.
    Cold,
}

/// Pick the tier a park should land in.
///
/// The rule is about the wait's shape rather than its cause: a wait whose
/// length the host cannot predict must not hold the scarcest resource. Only
/// `Idle` has a bounded, likely-soon resumption, so only `Idle` stays resident.
#[must_use]
pub fn select_tier(reason: ParkReason) -> StorageTier {
    match reason {
        ParkReason::Idle => StorageTier::Resident,
        ParkReason::ApprovalWait | ParkReason::HostShutdown | ParkReason::Operator => {
            StorageTier::Parked
        }
        ParkReason::RetentionDemotion => StorageTier::Cold,
    }
}
```

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-runtime/src/agent_session/mod.rs
git commit -m "feat(runtime): add park reasons and the storage-tier policy"
```

---

### Task 3: Record fields and the park/resume transitions

**Files:**
- Modify: `crates/mvm-runtime/src/agent_session/mod.rs`
- Test: same file, inline `mod tests`

**Interfaces:**
- Consumes: `ParkReason`, `StorageTier`, `select_tier` (Task 2);
  `mvm_core::checkpoint::ApprovalHead` (already exists).
- Produces: the four new record fields, `park()`, `resume()`,
  `SessionTransitionError`.

**Generation rule, which the tests pin:** a park does NOT change the
generation; a resume increments it. A generation identifies one period of
sandbox residency, so parking — which suspends such a period rather than ending
it — leaves it alone, and resuming opens a new one. That is what makes a frame
addressed to the prior generation refusable after a resume.

- [x] **Step 1: Write the failing tests**

```rust
    #[test]
    fn parking_keeps_the_generation_and_records_why() {
        let rec = record("sess-alpha");
        assert_eq!(rec.generation, 1);
        let parked = rec.park(ParkReason::ApprovalWait, 1_755_000_100).unwrap();
        assert_eq!(parked.state, SandboxResidency::Hibernated);
        assert_eq!(parked.generation, 1, "a park suspends a residency, it does not end one");
        assert_eq!(parked.park_reason, Some(ParkReason::ApprovalWait));
        assert_eq!(parked.tier, Some(StorageTier::Parked));
        assert_eq!(parked.updated_unix, 1_755_000_100);
    }

    #[test]
    fn resuming_opens_a_new_generation_and_clears_the_park() {
        let parked = record("sess-alpha")
            .park(ParkReason::ApprovalWait, 1_755_000_100)
            .unwrap();
        let live = parked.resume(1_755_000_200).unwrap();
        assert_eq!(live.state, SandboxResidency::Active);
        assert_eq!(live.generation, 2, "a resume opens a new residency");
        assert_eq!(live.park_reason, None);
        assert_eq!(live.tier, None);
        assert_eq!(live.updated_unix, 1_755_000_200);
    }

    #[test]
    fn a_session_cannot_be_parked_twice() {
        let parked = record("sess-alpha").park(ParkReason::Idle, 1).unwrap();
        assert!(matches!(
            parked.park(ParkReason::Idle, 2),
            Err(SessionTransitionError::NotActive)
        ));
    }

    #[test]
    fn an_active_session_cannot_be_resumed() {
        assert!(matches!(
            record("sess-alpha").resume(2),
            Err(SessionTransitionError::NotHibernated)
        ));
    }

    #[test]
    fn a_closed_session_neither_parks_nor_resumes() {
        let mut closed = record("sess-alpha");
        closed.state = SandboxResidency::Closed;
        assert!(matches!(
            closed.park(ParkReason::Idle, 2),
            Err(SessionTransitionError::Closed)
        ));
        assert!(matches!(
            closed.resume(2),
            Err(SessionTransitionError::Closed)
        ));
    }

    #[test]
    fn the_new_fields_round_trip_and_default_when_absent() {
        let mut rec = record("sess-alpha");
        rec.journal_cursor = 118;
        rec.approval_head = Some(
            mvm_core::checkpoint::ApprovalHead::parse(format!("sha256:{}", "ab".repeat(32)))
                .unwrap(),
        );
        let json = serde_json::to_string(&rec).unwrap();
        assert_eq!(serde_json::from_str::<AgentSessionRecord>(&json).unwrap(), rec);

        // A record written before these fields existed still loads.
        let old = r#"{"session_id":"sess-old","generation":1,"state":"active","created_unix":1,"updated_unix":1}"#;
        let parsed: AgentSessionRecord = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.journal_cursor, 0);
        assert_eq!(parsed.approval_head, None);
        assert_eq!(parsed.tier, None);
        assert_eq!(parsed.park_reason, None);
    }
```

- [x] **Step 2: Run tests to verify they fail**

Expected: FAIL to compile — no `park` method, no `journal_cursor` field.

- [x] **Step 3: Write the implementation**

Add to `AgentSessionRecord`, after `parent_checkpoint`:

```rust
    /// Session-journal position this record is consistent with. A resume that
    /// replayed from an earlier cursor would re-run work the session already
    /// committed.
    #[serde(default)]
    pub journal_cursor: u64,
    /// Approval-ledger head the session was last admitted under. A resume
    /// bounds its fresh grants against this rather than against whatever the
    /// ledger holds later, so a park cannot silently widen what the session may
    /// do while it waits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_head: Option<mvm_core::checkpoint::ApprovalHead>,
    /// Where the parked state lives. `None` while the session is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<StorageTier>,
    /// Why the session was parked. `None` while the session is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub park_reason: Option<ParkReason>,
```

Add the transitions and the error:

```rust
/// Why a park or resume was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionTransitionError {
    #[error("session is not active, so it cannot be parked")]
    NotActive,
    #[error("session is not hibernated, so it cannot be resumed")]
    NotHibernated,
    #[error("session is closed")]
    Closed,
}

impl AgentSessionRecord {
    /// Suspend a residency. Returns the parked record; does not write it.
    ///
    /// The generation is deliberately unchanged: it identifies one period of
    /// sandbox residency, and a park suspends that period rather than ending
    /// it. `resume` is what opens the next one.
    pub fn park(
        &self,
        reason: ParkReason,
        now_unix: u64,
    ) -> Result<Self, SessionTransitionError> {
        match self.state {
            SandboxResidency::Closed => return Err(SessionTransitionError::Closed),
            SandboxResidency::Hibernated => return Err(SessionTransitionError::NotActive),
            SandboxResidency::Active => {}
        }
        Ok(Self {
            state: SandboxResidency::Hibernated,
            tier: Some(select_tier(reason)),
            park_reason: Some(reason),
            updated_unix: now_unix,
            ..self.clone()
        })
    }

    /// Open a new residency. Returns the resumed record; does not write it.
    ///
    /// Incrementing the generation is what lets a late frame addressed to the
    /// prior residency be refused rather than delivered into its successor.
    pub fn resume(&self, now_unix: u64) -> Result<Self, SessionTransitionError> {
        match self.state {
            SandboxResidency::Closed => return Err(SessionTransitionError::Closed),
            SandboxResidency::Active => return Err(SessionTransitionError::NotHibernated),
            SandboxResidency::Hibernated => {}
        }
        Ok(Self {
            state: SandboxResidency::Active,
            generation: self.generation + 1,
            tier: None,
            park_reason: None,
            updated_unix: now_unix,
            ..self.clone()
        })
    }
}
```

If `thiserror` is not already a dependency of `mvm-runtime`, check before adding
it — it is used widely in this workspace and is very likely present.

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-runtime/src/agent_session/mod.rs
git commit -m "feat(runtime): add park and resume transitions to the session record"
```

---

### Task 4: Store-level park/resume with a generation fence

**Files:**
- Modify: `crates/mvm-runtime/src/agent_session/mod.rs`
- Test: same file, inline `mod tests`

**Interfaces:**
- Consumes: everything from Tasks 1-3.
- Produces: `AgentSessionStore::park`, `AgentSessionStore::resume`.

**Why a fence:** two callers can hold the same record. Without a
compare-and-swap on the generation, a caller holding a record from before a
resume would park the session it thinks it has and silently discard the newer
residency. The store refuses when the on-disk generation is not the one the
caller expected.

- [x] **Step 1: Write the failing tests**

```rust
    #[test]
    fn store_park_persists_the_transition() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();

        let parked = store
            .park(&rec.session_id, 1, ParkReason::ApprovalWait, 1_755_000_100)
            .unwrap();
        assert_eq!(parked.state, SandboxResidency::Hibernated);
        assert_eq!(
            store.load(&rec.session_id).unwrap().park_reason,
            Some(ParkReason::ApprovalWait)
        );
    }

    #[test]
    fn store_resume_persists_and_bumps_the_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store
            .park(&rec.session_id, 1, ParkReason::Idle, 1_755_000_100)
            .unwrap();

        let live = store.resume(&rec.session_id, 1, 1_755_000_200).unwrap();
        assert_eq!(live.generation, 2);
        assert_eq!(store.load(&rec.session_id).unwrap().generation, 2);
    }

    #[test]
    fn a_stale_generation_cannot_park_a_session_that_moved_on() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store.park(&rec.session_id, 1, ParkReason::Idle, 100).unwrap();
        store.resume(&rec.session_id, 1, 200).unwrap(); // now generation 2

        // A caller still holding generation 1 must not be able to park it.
        let err = store
            .park(&rec.session_id, 1, ParkReason::Operator, 300)
            .unwrap_err()
            .to_string();
        assert!(err.contains("generation"), "unexpected error: {err}");
        assert_eq!(
            store.load(&rec.session_id).unwrap().state,
            SandboxResidency::Active,
            "the stale park must not have taken effect"
        );
    }

    #[test]
    fn a_refused_transition_leaves_the_stored_record_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();

        // Resuming an active session is refused; the record must be unchanged.
        assert!(store.resume(&rec.session_id, 1, 400).is_err());
        let after = store.load(&rec.session_id).unwrap();
        assert_eq!(after.state, SandboxResidency::Active);
        assert_eq!(after.generation, 1);
        assert_eq!(after.updated_unix, rec.updated_unix);
    }
```

- [x] **Step 2: Run tests to verify they fail**

Expected: FAIL to compile — no `park` method on `AgentSessionStore`.

- [x] **Step 3: Write the implementation**

```rust
impl AgentSessionStore {
    /// Park a session, refusing if it has moved past `expected_generation`.
    ///
    /// The fence matters because two callers can hold the same record: without
    /// it, a caller holding a pre-resume record would park the residency it
    /// thinks is current and silently discard the newer one. The record is
    /// written only after the transition is accepted, so a refused park leaves
    /// what is on disk untouched.
    pub fn park(
        &self,
        id: &AgentSessionId,
        expected_generation: u64,
        reason: ParkReason,
        now_unix: u64,
    ) -> Result<AgentSessionRecord> {
        let current = self.load(id)?;
        fence(&current, expected_generation)?;
        let parked = current.park(reason, now_unix)?;
        self.write(&parked)?;
        Ok(parked)
    }

    /// Resume a session, refusing if it has moved past `expected_generation`.
    pub fn resume(
        &self,
        id: &AgentSessionId,
        expected_generation: u64,
        now_unix: u64,
    ) -> Result<AgentSessionRecord> {
        let current = self.load(id)?;
        fence(&current, expected_generation)?;
        let live = current.resume(now_unix)?;
        self.write(&live)?;
        Ok(live)
    }
}

/// Refuse an operation whose caller is working from a superseded record.
fn fence(current: &AgentSessionRecord, expected: u64) -> Result<()> {
    if current.generation != expected {
        anyhow::bail!(
            "session {} is at generation {}, not the expected {}",
            current.session_id.as_str(),
            current.generation,
            expected
        );
    }
    Ok(())
}
```

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Run the full gate**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all -- --check
~/.cargo/bin/cargo nextest run -p mvm-core -p mvm-runtime
~/.cargo/bin/cargo clippy --workspace --all-targets -- -D warnings
```

- [x] **Step 6: Commit**

```bash
git add crates/mvm-runtime/src/agent_session/mod.rs
git commit -m "feat(runtime): fence store-level session park and resume on the generation"
```

---

### Task 5: Update the specs and the delivery record

**Files:**
- Modify: `specs/plans/2026-08-18-durable-agent-sessions.md` (D1 record shape,
  WS3 checkbox state)
- Modify: `specs/REFACTOR-STATUS.md` (this plan's entry, "Last updated")
- Create: `specs/sprint/delivery/durable-session-park.md`
- Modify: this plan's checkboxes

**Interfaces:** none.

- [x] **Step 1: Update the design spec's D1 record shape**

D1 lists nine fields for the hibernation record. After this plan the record
carries: session ID, generation, parent checkpoint digest, journal cursor,
approval head, storage tier, park reason. Still absent: audit-chain head, and
retention class + expiry (both belong to the retention plan). Update D1 to say
which are built and which remain, accurately — do not tick what is not done.

- [x] **Step 2: Update WS3's checkbox state in the design spec**

WS3 reads "Park path. `ParkReason`, tier selection, quiesce sequence over the
existing guest verbs, hibernation record commit ordering." This plan delivers
`ParkReason`, tier selection, and the transition/fence machinery. It does NOT
deliver the quiesce sequence over the guest verbs — `SleepPrep`,
`CheckpointIntegrations`, and `Wake` still have no host-side caller anywhere in
the workspace. Mark WS3 partially complete with a note naming exactly what
remains, rather than ticking it.

- [x] **Step 3: Update `specs/REFACTOR-STATUS.md`**

Add or extend this plan's entry and bump "Last updated" to the current date.
Match the format of the neighbouring in-flight plan entries.

- [x] **Step 4: Write the delivery record**

Create `specs/sprint/delivery/durable-session-park.md` recording what this slice
delivered, in the style of the existing files in that directory. Do NOT append
to `specs/SPRINT.md` — `xtask check-sprint-append` fails if its delivery section
grows.

- [x] **Step 5: Tick this plan's checkboxes and run the doc gates**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo run -p xtask -- check-plan-names
~/.cargo/bin/cargo run -p xtask -- check-declared-backing
~/.cargo/bin/cargo run -p xtask -- check-sprint-append
~/.cargo/bin/cargo run -p xtask -- check-no-spec-refs-in-comments
```

Both spec files carry `Backing: preview`, which bars a short list of assertive
verbs. Do not reach for words that assert a property was demonstrated; write
what the code does instead. If the gate refuses, it names the exact word it
found, and `xtask/src/check_declared_backing.rs` holds the list — note that
merely quoting one of those words in prose trips the gate too, which is a trap
worth knowing before you write the delivery record.

- [x] **Step 6: Commit**

```bash
git add specs/
git commit -m "docs: record the park state machine slice"
```

---

## Deferred to later plans

Named so their absence is not read as an oversight:

- **The quiesce sequence.** `GuestRequest::SleepPrep`, `CheckpointIntegrations`,
  and `Wake` are defined in the agent's protocol but have no host-side caller
  anywhere in the workspace. Wiring them is the rest of WS3 and needs a live
  guest to test against.
- **Resume admission (WS4).** `resume_session` synthesizing a fresh
  `ExecutionPlan` via `mvm_hostd::plan_admission::admit_for_run` and
  `mvm_core::plan::synthesis::SynthesisInput`, the incremental approval-ledger
  head check, and `PostRestore` fabric re-registration.
- **Retention ladder and GC (WS5)**, including the refusal to reap a checkpoint
  any live or hibernated session names as its parent.
- **Chain records (WS7)** for `session.parked` / `session.resumed`.
