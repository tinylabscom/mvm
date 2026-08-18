# Session Approval Head Implementation Plan

Backing: preview
Validation: none

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the approval ledger a content-addressed head, commit that head
into a session's park record in one write, and refuse a resume whose ledger has
moved since the park.

**Architecture:** `SessionBinding.approval_head` and
`AgentSessionRecord.approval_head` are both typed `ApprovalHead` today, and
nothing can produce one — `ApprovalLedger` exposes no head across its seventeen
public functions. This plan adds `ApprovalLedger::head() -> [u8; 32]`, mirroring
the digest idiom `PolicySet::digest` already uses in the same file, which
`ApprovalHead::from_bytes` then bridges. Park gains a params struct so the head
and the journal cursor commit with the transition rather than in a second
unfenced write. Resume gains a fence against the head. No VM, no async.

**Tech Stack:** Rust, `sha2` (already a `mvm-contract` dependency, no_std),
`serde`, `anyhow`, `thiserror`, `cargo nextest`.

**Spec:** `specs/plans/2026-08-18-durable-agent-sessions.md` (D1's approval-head
field, D5's "resume bounds its fresh grants against that head"). Builds on
`specs/plans/2026-08-18-durable-session-park.md`.

## Global Constraints

- **In every shell, including the one you commit from, put
  `export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target`
  in the SAME command as the cargo or git invocation.** The Bash tool does not
  persist exports. Do not point it elsewhere or make a fresh one — the shared
  default is corrupted by other concurrent sessions and costs an hour of cold
  rebuilds.
- Use `~/.cargo/bin/cargo`, never Homebrew's rustc.
- `mvm-contract` is `#![no_std]` + alloc and `forbid(unsafe_code)`, and must
  keep building for `wasm32-unknown-unknown`. Nothing you add there may pull in
  `std`. `sha2` is already a dependency with `default-features = false`.
- `#[allow(clippy::too_many_arguments)]` is banned. Use a struct + builder —
  which is exactly why Task 2 introduces a params struct rather than a fifth
  positional argument.
- No plan, PR, or ADR references in code comments — gated by
  `xtask check-no-spec-refs-in-comments`. Explain reasoning directly.
- Every on-disk type keeps `#[serde(deny_unknown_fields)]`; new fields additive
  with `#[serde(default)]`.
- Bypassing the pre-commit hook is blocked by a guard. Let it run.
- Gate before each commit: `cargo fmt --all -- --check`, then
  `cargo nextest run -p mvm-contract -p mvm-core -p mvm-runtime`, then
  `cargo clippy --workspace --all-targets -- -D warnings`.

## Interfaces produced by this plan

```rust
// mvm_contract::policy::approval
impl ApprovalLedger {
    pub fn head(&self) -> [u8; 32];
}

// mvm_runtime::agent_session
pub struct ParkInput {
    pub reason: ParkReason,
    pub journal_cursor: u64,
    pub approval_head: Option<mvm_core::checkpoint::ApprovalHead>,
}

impl AgentSessionStore {
    pub fn park(&self, id: &AgentSessionId, expected_generation: u64,
                input: ParkInput, now_unix: u64) -> Result<AgentSessionRecord>;
    pub fn resume(&self, id: &AgentSessionId, expected_generation: u64,
                  current_head: Option<&mvm_core::checkpoint::ApprovalHead>,
                  now_unix: u64) -> Result<AgentSessionRecord>;
}
```

---

### Task 1: `ApprovalLedger::head()`

**Files:**
- Modify: `crates/mvm-contract/src/policy/approval.rs` (add to `impl ApprovalLedger`, near `state` ~L690)
- Test: same file, inline `mod tests`

**Interfaces:**
- Consumes: nothing.
- Produces: `ApprovalLedger::head() -> [u8; 32]`.

**Mirror, do not invent.** `PolicySet::digest` at `approval.rs:179` sets the
idiom for this file: a `Sha256` over tagged, fixed-width, order-dependent
fields. Follow it. Two helpers already exist for exactly this — `capability_tag`
(~L830) and `effect_tag` (~L842); write a `state_tag` beside them in the same
shape rather than hashing an enum's `Debug` or its serde name, because a
rename of a variant must not move the digest.

**What the head must cover, and why:** the head names the ledger's decision
state, so a resume can tell that the ledger moved under it. It must cover every
record's approval id, its capability, and its terminal state. It must NOT cover
wall-clock fields such as expiry timestamps: two ledgers that made the same
decisions must hash alike regardless of when they were asked, or a resume would
refuse itself for the passage of time alone.

- [x] **Step 1: Write the failing tests**

Add inside the existing `mod tests` in `crates/mvm-contract/src/policy/approval.rs`. Read the existing tests first to reuse their fixture helpers for building a ledger, requesting, and responding — do not invent a second fixture style.

```rust
    #[test]
    fn an_empty_ledger_has_a_stable_head() {
        let a = ApprovalLedger::new(AgentSessionId::parse("sess-a").unwrap());
        let b = ApprovalLedger::new(AgentSessionId::parse("sess-a").unwrap());
        assert_eq!(a.head(), b.head());
    }

    #[test]
    fn a_decision_moves_the_head() {
        // Build a ledger with one pending request, snapshot the head, then
        // answer it. The head must move: a resume bounds its grants against
        // the head, so an answered request that hashed the same as a pending
        // one would let a resume proceed under a decision it never saw.
        // Use whatever fixture the surrounding tests use to request+respond.
    }

    #[test]
    fn the_head_ignores_when_a_decision_was_made() {
        // Two ledgers that reached the same decisions must hash alike even if
        // their requests carried different created/expiry timestamps —
        // otherwise a resume would refuse itself for the passage of time.
    }

    #[test]
    fn two_different_decisions_do_not_collide() {
        // An approved request and a denied one over the same capability must
        // produce different heads.
    }
```

The three tests above are described rather than written out because they depend
on the fixture helpers already in that module. Read those helpers, then write
each test to the description. If no suitable helper exists, say so in your
report and write the smallest one that serves all four tests.

- [x] **Step 2: Run tests to verify they fail**

Run: `export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target && ~/.cargo/bin/cargo nextest run -p mvm-contract head`
Expected: FAIL — `no method named 'head' found for struct ApprovalLedger`.

- [x] **Step 3: Write the implementation**

```rust
    /// Content-address the ledger's decision state.
    ///
    /// A session records this at park time and a resume compares against it, so
    /// what it covers is what a resume treats as "the ledger has not moved":
    /// every record's identity, the capability it was asked about, and the
    /// state it reached. Timestamps are deliberately excluded — two ledgers
    /// that made the same decisions hash alike however long ago they were
    /// asked, so a session cannot refuse itself for the passage of time.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.session_id.as_str().as_bytes());
        hasher.update([0u8]); // terminator: ids cannot run together
        for record in &self.records {
            hasher.update(record.request.approval_id.as_str().as_bytes());
            hasher.update([0u8]);
            hasher.update([capability_tag(record.request.capability)]);
            hasher.update([state_tag(record.state)]);
        }
        hasher.finalize().into()
    }
```

Adjust the field paths to whatever `ApprovalRequest` actually names them — read
the struct rather than trusting this sketch, and say in your report what you had
to change.

Add beside `capability_tag` / `effect_tag`:

```rust
/// Stable tag per approval state. Written out rather than derived so renaming a
/// variant cannot silently move every recorded head.
fn state_tag(state: ApprovalState) -> u8 {
    match state {
        ApprovalState::Pending => 0,
        ApprovalState::Approved => 1,
        ApprovalState::Denied => 2,
        ApprovalState::Expired => 3,
        ApprovalState::Canceled => 4,
    }
}
```

- [x] **Step 4: Run tests to verify they pass**

Also confirm the no_std build still works:
`export CARGO_TARGET_DIR=... && ~/.cargo/bin/cargo check -p mvm-contract --target wasm32-unknown-unknown --no-default-features`
If that target is not installed, say so in your report rather than skipping silently.

- [x] **Step 5: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-contract/src/policy/approval.rs
git commit -m "feat(contract): content-address the approval ledger's decision state"
```

---

### Task 2: `ParkInput` — commit the head and cursor with the transition

**Files:**
- Modify: `crates/mvm-runtime/src/agent_session/mod.rs`
- Test: same file, inline `mod tests`

**Interfaces:**
- Consumes: `ApprovalHead` (already exists in `mvm-core`).
- Produces: `ParkInput`; `AgentSessionStore::park` takes it in place of `reason`.

**Why:** `park` currently takes only a reason, so a caller that wants "parked at
cursor N under head H" must `write()` then `park()` — two writes, and the fence
cannot tell them apart because a park does not change the generation. One
params struct makes it a single fenced commit, and keeps `park` from growing a
fourth and fifth positional argument.

- [x] **Step 1: Write the failing tests**

```rust
    #[test]
    fn park_commits_the_cursor_and_head_with_the_transition() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();

        let head = mvm_core::checkpoint::ApprovalHead::parse(
            format!("sha256:{}", "ab".repeat(32)),
        )
        .unwrap();
        let parked = store
            .park(
                &rec.session_id,
                1,
                ParkInput {
                    reason: ParkReason::ApprovalWait,
                    journal_cursor: 42,
                    approval_head: Some(head.clone()),
                },
                1_755_000_100,
            )
            .unwrap();

        assert_eq!(parked.journal_cursor, 42);
        assert_eq!(parked.approval_head, Some(head.clone()));

        // One write, not two: the values are on disk after the single call.
        let on_disk = store.load(&rec.session_id).unwrap();
        assert_eq!(on_disk.journal_cursor, 42);
        assert_eq!(on_disk.approval_head, Some(head));
        assert_eq!(on_disk.state, SandboxResidency::Hibernated);
    }

    #[test]
    fn a_refused_park_commits_neither_the_cursor_nor_the_head() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store
            .park(&rec.session_id, 1, ParkInput { reason: ParkReason::Idle, journal_cursor: 7, approval_head: None }, 100)
            .unwrap();

        // Already hibernated: a second park is refused, and must not advance
        // the cursor it was called with.
        assert!(store
            .park(&rec.session_id, 1, ParkInput { reason: ParkReason::Idle, journal_cursor: 99, approval_head: None }, 200)
            .is_err());
        assert_eq!(store.load(&rec.session_id).unwrap().journal_cursor, 7);
    }
```

- [x] **Step 2: Run tests to verify they fail**

Expected: FAIL to compile — `cannot find struct ParkInput`.

- [x] **Step 3: Write the implementation**

```rust
/// What a park commits alongside the state transition.
///
/// Grouped into a struct rather than added as further positional arguments so
/// the values land in the same fenced write as the transition. A caller that
/// had to `write()` then `park()` would take two writes with no fence between
/// them — a park does not change the generation, so the fence cannot tell the
/// two calls apart.
#[derive(Debug, Clone)]
pub struct ParkInput {
    pub reason: ParkReason,
    /// Journal position the park is consistent with.
    pub journal_cursor: u64,
    /// Approval-ledger head the session was last admitted under, if it has one.
    pub approval_head: Option<mvm_core::checkpoint::ApprovalHead>,
}
```

Change `AgentSessionRecord::park` to take `&ParkInput` instead of a bare
`ParkReason`, setting `journal_cursor` and `approval_head` from it alongside the
existing fields. Change `AgentSessionStore::park`'s third parameter to
`ParkInput`. Update every existing call site and test — several tests currently
pass a bare `ParkReason`.

- [x] **Step 4: Run tests to verify they pass**

Run the full `agent_session` module; every pre-existing park test must be
updated and still green.

- [x] **Step 5: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-runtime/src/agent_session/mod.rs
git commit -m "feat(runtime): commit the journal cursor and approval head with a park"
```

---

### Task 3: Fence a resume against a moved approval ledger

**Files:**
- Modify: `crates/mvm-runtime/src/agent_session/mod.rs`
- Test: same file, inline `mod tests`

**Interfaces:**
- Consumes: `ParkInput` (Task 2).
- Produces: `AgentSessionStore::resume` gains a `current_head` parameter.

**The rule, and its limit:** a resume compares the caller's current ledger head
against the one recorded at park. A difference means the ledger moved while the
session was parked, so the grants the session would resume under are not the
ones it was admitted for — refuse, and let the caller re-admit deliberately.
A session parked with no head (`None`) has nothing to compare, so it resumes
without this check; that is a real gap and the doc comment must say so rather
than implying every resume is fenced.

- [x] **Step 1: Write the failing tests**

```rust
    fn head_of(byte: &str) -> mvm_core::checkpoint::ApprovalHead {
        mvm_core::checkpoint::ApprovalHead::parse(format!("sha256:{}", byte.repeat(32))).unwrap()
    }

    #[test]
    fn a_resume_under_the_recorded_head_is_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        let head = head_of("ab");
        store
            .park(&rec.session_id, 1, ParkInput { reason: ParkReason::ApprovalWait, journal_cursor: 5, approval_head: Some(head.clone()) }, 100)
            .unwrap();

        let live = store.resume(&rec.session_id, 1, Some(&head), 200).unwrap();
        assert_eq!(live.generation, 2);
        assert_eq!(live.journal_cursor, 5, "the cursor survives the resume");
    }

    #[test]
    fn a_resume_is_refused_when_the_ledger_moved_while_parked() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store
            .park(&rec.session_id, 1, ParkInput { reason: ParkReason::ApprovalWait, journal_cursor: 5, approval_head: Some(head_of("ab")) }, 100)
            .unwrap();

        let err = store
            .resume(&rec.session_id, 1, Some(&head_of("cd")), 200)
            .unwrap_err()
            .to_string();
        assert!(err.contains("approval"), "unexpected error: {err}");
        assert_eq!(
            store.load(&rec.session_id).unwrap().state,
            SandboxResidency::Hibernated,
            "a refused resume must leave the session parked"
        );
    }

    #[test]
    fn a_session_parked_without_a_head_resumes_unfenced() {
        // Documents the gap deliberately: nothing was recorded to compare
        // against, so this resume is not fenced on approvals.
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store
            .park(&rec.session_id, 1, ParkInput { reason: ParkReason::Idle, journal_cursor: 0, approval_head: None }, 100)
            .unwrap();
        assert!(store.resume(&rec.session_id, 1, Some(&head_of("cd")), 200).is_ok());
    }
```

- [x] **Step 2: Run tests to verify they fail**

Expected: FAIL to compile — `resume` takes three arguments, not four.

- [x] **Step 3: Write the implementation**

Add the `current_head` parameter to `AgentSessionStore::resume`, and after the
generation fence and before the transition:

```rust
        // Refuse when the ledger moved while the session was parked: the grants
        // it would resume under are not the ones it was admitted for, and the
        // caller should re-admit deliberately rather than inherit silently.
        //
        // A session parked with no recorded head is not fenced here — there is
        // nothing to compare against. That is a real gap, not an oversight:
        // whoever records a head at park time closes it, and until then such a
        // session resumes on the generation fence alone.
        if let Some(recorded) = current.approval_head.as_ref() {
            match current_head {
                Some(now) if now == recorded => {}
                _ => anyhow::bail!(
                    "session {} was parked under a different approval head; re-admit before resuming",
                    current.session_id.as_str()
                ),
            }
        }
```

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Verify the fence is not vacuous**

Temporarily delete the `if let` block, confirm
`a_resume_is_refused_when_the_ledger_moved_while_parked` goes RED, then restore.
Report the RED with its command and output. If you do not see a red, say so and
stop rather than reporting one you did not observe.

- [x] **Step 6: Run the full gate and commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all -- --check
~/.cargo/bin/cargo nextest run -p mvm-contract -p mvm-core -p mvm-runtime
~/.cargo/bin/cargo clippy --workspace --all-targets -- -D warnings
git add crates/mvm-runtime/src/agent_session/mod.rs
git commit -m "feat(runtime): refuse a resume whose approval ledger moved while parked"
```

---

### Task 4: Update the specs and the delivery record

**Files:**
- Modify: `specs/plans/2026-08-18-durable-agent-sessions.md` (D1 field list, D5, WS4 state)
- Modify: `specs/REFACTOR-STATUS.md`
- Create: `specs/sprint/delivery/session-approval-head.md`
- Modify: this plan's checkboxes

- [x] **Step 1: Update D1 and D5 accurately**

D1's approval-head field can now be produced and is committed at park. D5's
"incremental ledger-head verification" is partly real: the comparison exists,
but there is still no `resume_session` orchestrator, no fresh `ExecutionPlan`
synthesis, and no `PostRestore` re-registration. Say which is which. Record the
limit that a session parked with no head resumes unfenced.

- [x] **Step 2: Mark WS4 partially complete, naming what remains**

Do not tick WS4. It remains: `resume_session` itself, building a
`SynthesisInput` through `SynthesisInputBuilder`, calling
`mvm_hostd::plan_admission::admit_for_run`, and `PostRestore` fabric
re-registration. Verify each of those absences with your own exhaustive search
before writing it down — do not pipe a search establishing absence through
`head`, because that is exactly how two false claims reached earlier documents
on this branch.

- [x] **Step 3: Update `specs/REFACTOR-STATUS.md`** and bump "Last updated".

- [x] **Step 4: Write `specs/sprint/delivery/session-approval-head.md`**

Style-match the existing files in that directory. Do NOT append to
`specs/SPRINT.md` — `xtask check-sprint-append` fails if its delivery section
grows.

- [x] **Step 5: Tick this plan's checkboxes and run the doc gates**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo run -p xtask -- check-plan-names
~/.cargo/bin/cargo run -p xtask -- check-declared-backing
~/.cargo/bin/cargo run -p xtask -- check-sprint-append
~/.cargo/bin/cargo run -p xtask -- check-no-spec-refs-in-comments
```

These spec files carry `Backing: preview`, which bars a short list of assertive
verbs matched as whole words — quoting one in prose trips the gate too. Write
about what the code does. If the gate refuses, it names the word it found.

- [x] **Step 6: Commit**

```bash
git add specs/
git commit -m "docs: record the approval-head slice"
```

---

## Deferred to later plans

- **`resume_session` orchestration**: verifying parent lineage through
  `CheckpointStore::by_digest`, building a `SynthesisInput` via
  `SynthesisInputBuilder`, and admitting through
  `mvm_hostd::plan_admission::admit_for_run`. Note that `AdmittedPlan` has only
  private fields and a test that pins it as unfabricable outside
  `plan_admission` — a resume must go through admission, not around it.
- **`PostRestore` fabric re-registration** and the quiesce sequence.
- **Retention ladder and GC (WS5).**
- **Chain records (WS7)** for `session.parked` / `session.resumed`.
- **A durability witness for `atomic_write`** in `mvm-core` — no test anywhere
  asserts the temp is consumed or that `sync_data` is reached.
