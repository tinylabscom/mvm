# Durable Session Substrate Implementation Plan

Backing: preview
Validation: none

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a checkpoint content-address the durable agent session it belongs
to, and give sessions a filesystem store, so a resume point can be verified as
belonging to a specific session at a specific journal position.

**Architecture:** `SessionBinding` is a new optional field on `CheckpointMeta`,
folded into the existing `meta_digest` derivation the same way `grants` already
is. A new `AgentSessionStore` in `mvm-runtime/src/agent_session/` mirrors the
existing `CheckpointStore`, rooted at a new
`mvm_core::config::agent_sessions_dir()`. No VM, no backend, and no async are
involved — every task here is unit-testable.

**Tech Stack:** Rust, `serde` / `serde_json`, `sha2`, `hex`, `anyhow`,
`tempfile`, `cargo nextest`.

**Spec:** `specs/plans/2026-08-18-durable-agent-sessions.md` (sections D1, D2, D4).

## Global Constraints

- Toolchain: use `~/.cargo/bin/cargo`, never Homebrew's rustc.
- Every `~/.mvm` path goes through a `mvm_core::config` helper. Never build one
  inline from `$HOME`; that ignores `MVM_HOME` and breaks worktree isolation.
- `#[allow(clippy::too_many_arguments)]` is banned. Use a struct + builder.
- No plan, PR, or ADR references in code comments — CI-gated by
  `xtask check-no-spec-refs`.
- Every host↔guest and on-disk type carries `#[serde(deny_unknown_fields)]`.
- New fields are additive with `#[serde(default)]`; no schema-version bump.
- Tests that touch `MVM_HOME` must use `TestEnv` for isolation
  (`xtask check-test-home-isolation` gates this).
- Gate command before any commit: `cargo fmt --all -- --check`, then
  `cargo nextest run -p <crate>`, then `cargo clippy --workspace -- -D warnings`.

## Interfaces produced by this plan

Later plans (park, resume, retention) consume exactly these:

```rust
// mvm_core::config
pub fn agent_sessions_dir() -> std::path::PathBuf;

// mvm_core::checkpoint
pub struct ApprovalHead(/* sha256:<64-hex>, dedicated newtype — not CheckpointDigest */);
pub struct SessionBinding {
    pub session_id: mvm_contract::protocol::agent_session::AgentSessionId,
    pub generation: u64,
    pub journal_cursor: u64,
    pub approval_head: ApprovalHead,
}
impl CheckpointMetaBuilder {
    pub fn session(self, binding: Option<SessionBinding>) -> Self;
}
// CheckpointMeta gains: pub session: Option<SessionBinding>

// mvm_runtime::agent_session
pub enum SandboxResidency { Active, Hibernated, Closed }
pub struct AgentSessionRecord {
    pub session_id: AgentSessionId,
    pub generation: u64,
    pub state: SandboxResidency,
    pub members: Vec<String>,
    // Content-addressed, not a mutable checkpoint name — see field doc.
    pub parent_checkpoint: Option<mvm_core::checkpoint::CheckpointDigest>,
    pub created_unix: u64,
    pub updated_unix: u64,
}
pub struct AgentSessionStore { /* ... */ }
impl AgentSessionStore {
    pub fn open() -> Self;
    pub fn at(root: impl Into<std::path::PathBuf>) -> Self;
    pub fn root(&self) -> &std::path::Path;
    pub fn write(&self, record: &AgentSessionRecord) -> anyhow::Result<()>;
    pub fn load(&self, id: &AgentSessionId) -> anyhow::Result<AgentSessionRecord>;
    pub fn list(&self) -> anyhow::Result<Vec<AgentSessionRecord>>;
}
```

> **Naming note.** The task bodies below are the text these tasks were
> dispatched from, and they predate the rename that landed in the same branch
> (`sessions_dir` -> `agent_sessions_dir`, module `session` -> `agent_session`,
> `SessionRecord`/`SessionState`/`SessionStore` -> `AgentSessionRecord`/
> `SandboxResidency`/`AgentSessionStore`, and `open()` losing its `Result`).
> They are left as dispatched rather than rewritten, so this document records
> what was actually asked for. Where they disagree with the interface block
> above, the interface block is the one later plans consume.

---

### Task 1: `sessions_dir()` config helper

**Files:**
- Modify: `crates/mvm-core/src/config.rs` (add beside `checkpoints_dir`, ~L766)
- Test: `crates/mvm-core/src/config.rs` (inline `mod tests`, beside
  `checkpoints_dir_is_under_data_dir` ~L1454)

**Interfaces:**
- Consumes: nothing.
- Produces: `mvm_core::config::sessions_dir() -> PathBuf`.

- [x] **Step 1: Write the failing test**

Add to the existing `mod tests` in `crates/mvm-core/src/config.rs`, directly
after `checkpoints_dir_is_under_data_dir`:

```rust
    #[test]
    fn sessions_dir_is_under_data_dir() {
        let mut env = TestEnv::new();
        let temp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", temp.path());
        let dir = sessions_dir();
        assert_eq!(dir, temp.path().join("sessions"));
        env.remove("MVM_HOME");
    }
```

- [x] **Step 2: Run test to verify it fails**

Run: `~/.cargo/bin/cargo nextest run -p mvm-core sessions_dir_is_under_data_dir`
Expected: FAIL — `cannot find function 'sessions_dir' in this scope`.

- [x] **Step 3: Write minimal implementation**

Add to `crates/mvm-core/src/config.rs` immediately after `checkpoints_dir`:

```rust
/// Durable agent-session store: `<mvm_home>/sessions/`. Each session is a
/// subdirectory `<id>/` holding `session.json` plus its journal. Sibling to
/// [`checkpoints_dir`]: a session names checkpoints as its resume points, and
/// the two are reaped under different retention because one is kilobytes and
/// the other is gigabytes.
pub fn sessions_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("sessions")
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `~/.cargo/bin/cargo nextest run -p mvm-core sessions_dir_is_under_data_dir`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions
~/.cargo/bin/cargo fmt --all
git add crates/mvm-core/src/config.rs
git commit -m "feat(core): add sessions_dir config helper"
```

---

### Task 2: `SessionBinding` type

**Files:**
- Modify: `crates/mvm-core/src/checkpoint.rs` (add above `CheckpointMeta`, ~L207)
- Test: `crates/mvm-core/src/checkpoint.rs` (inline `mod tests`, ~L504)

**Interfaces:**
- Consumes: `AgentSessionId` from `mvm_contract::protocol::agent_session`
  (reachable: `mvm-core` enables `mvm-contract`'s `protocol` feature, and
  `policy`/`protocol` modules both ride that feature).
- Produces: `mvm_core::checkpoint::SessionBinding`.

- [x] **Step 1: Write the failing test**

Add inside the existing `mod tests` in `crates/mvm-core/src/checkpoint.rs`:

```rust
    fn test_binding() -> SessionBinding {
        SessionBinding {
            session_id: mvm_contract::protocol::agent_session::AgentSessionId::parse(
                "sess-incident-42",
            )
            .unwrap(),
            generation: 3,
            journal_cursor: 118,
            approval_head: CheckpointDigest::parse(format!("sha256:{}", "cd".repeat(32)))
                .unwrap(),
        }
    }

    #[test]
    fn session_binding_roundtrips_and_denies_unknown() {
        let binding = test_binding();
        let json = serde_json::to_string(&binding).unwrap();
        let back: SessionBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);

        let with_extra = json.replace('{', "{\"surprise\":1,");
        assert!(serde_json::from_str::<SessionBinding>(&with_extra).is_err());
    }
```

- [x] **Step 2: Run test to verify it fails**

Run: `~/.cargo/bin/cargo nextest run -p mvm-core session_binding_roundtrips`
Expected: FAIL — `cannot find type 'SessionBinding' in this scope`.

- [x] **Step 3: Write minimal implementation**

Add to `crates/mvm-core/src/checkpoint.rs` immediately above `CheckpointMeta`:

```rust
/// The durable agent session a checkpoint is a resume point for.
///
/// `generation` fences a resume: reopening a parked session increments it, so a
/// frame addressed to an earlier generation is refused rather than delivered
/// into a successor. `journal_cursor` is the session-journal position the
/// capture is consistent with, and `approval_head` names the approval-ledger
/// state the capture was admitted under — a resume bounds its fresh grants
/// against that head rather than against whatever the ledger holds later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBinding {
    pub session_id: mvm_contract::protocol::agent_session::AgentSessionId,
    pub generation: u64,
    pub journal_cursor: u64,
    pub approval_head: CheckpointDigest,
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `~/.cargo/bin/cargo nextest run -p mvm-core session_binding_roundtrips`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
~/.cargo/bin/cargo fmt --all
git add crates/mvm-core/src/checkpoint.rs
git commit -m "feat(core): add SessionBinding checkpoint type"
```

---

### Task 3: Fold `SessionBinding` into the checkpoint content-address

This is the load-bearing task. The field must reach four places or the digest
and the record disagree.

**Files:**
- Modify: `crates/mvm-core/src/checkpoint.rs` — `CheckpointMeta` struct (~L221),
  `CheckpointMeta::builder` (~L254), `compute_meta_digest` (~L281),
  `CheckpointDigestInput` (~L344), `CheckpointMetaBuilder` struct (~L403),
  `CheckpointMetaBuilder::build` (~L464)
- Test: `crates/mvm-core/src/checkpoint.rs` (inline `mod tests`)

**Interfaces:**
- Consumes: `SessionBinding` from Task 2.
- Produces: `CheckpointMeta.session`, `CheckpointMetaBuilder::session()`.

**Critical detail — why `skip_serializing_if` is mandatory in the digest
input:** `grants` carries
`#[serde(skip_serializing_if = "Option::is_none")]` inside
`CheckpointDigestInput` so that a record sealed before the field existed hashes
byte-identically to how it hashed then. Without it, every checkpoint on disk
recomputes to a different digest and `verify_lineage` reports `meta_digest
drift` — i.e. reports *tamper* on records nobody touched. `session` needs the
same attribute for the same reason. The `meta_digest_excludes_audit_ref` and
`meta_digest_covers_every_load_bearing_field` tests already in the file are the
guardrails; Step 1 extends them.

- [x] **Step 1: Write the failing tests**

Add inside `mod tests` in `crates/mvm-core/src/checkpoint.rs`:

```rust
    #[test]
    fn meta_digest_changes_when_the_session_binding_changes() {
        let base = CheckpointMeta::builder(
            CheckpointId::new("cp-1"),
            CheckpointClass::VmFull,
            "vm-1",
        )
        .session(Some(test_binding()))
        .build();

        let mut other_binding = test_binding();
        other_binding.generation += 1;
        let bumped = CheckpointMeta::builder(
            CheckpointId::new("cp-1"),
            CheckpointClass::VmFull,
            "vm-1",
        )
        .session(Some(other_binding))
        .build();

        assert_ne!(base.meta_digest, bumped.meta_digest);
        assert_eq!(base.meta_digest, base.compute_meta_digest());
        assert_eq!(bumped.meta_digest, bumped.compute_meta_digest());
    }

    #[test]
    fn a_sessionless_checkpoint_hashes_as_it_did_before_the_field_existed() {
        // A record that binds no session must be byte-identical in the digest
        // input to one built before `session` was added, or every checkpoint on
        // disk reads as tampered.
        let sessionless = CheckpointMeta::builder(
            CheckpointId::new("cp-1"),
            CheckpointClass::VmFull,
            "vm-1",
        )
        .build();
        assert!(sessionless.session.is_none());
        assert_eq!(sessionless.meta_digest, sessionless.compute_meta_digest());

        let input = CheckpointDigestInput {
            id: &sessionless.id,
            class: sessionless.class,
            vm_name: &sessionless.vm_name,
            tag: &sessionless.tag,
            parent: &sessionless.parent,
            created_unix: sessionless.created_unix,
            content: sorted_content(&sessionless.content),
            supervisor_config_digest: &sessionless.supervisor_config_digest,
            runtime_source_policy: &sessionless.runtime_source_policy,
            runtime_overlay_version: &sessionless.runtime_overlay_version,
            snapshot_id: &sessionless.snapshot_id,
            grants: &sessionless.grants,
            session: &None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(
            !json.contains("session"),
            "an absent session must not appear in the digest input: {json}"
        );
    }

    #[test]
    fn session_binding_survives_meta_json_roundtrip() {
        let meta = CheckpointMeta::builder(
            CheckpointId::new("cp-1"),
            CheckpointClass::VmFull,
            "vm-1",
        )
        .session(Some(test_binding()))
        .build();
        let json = serde_json::to_string(&meta).unwrap();
        let back: CheckpointMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
        assert_eq!(back.session.unwrap().journal_cursor, 118);
    }
```

- [x] **Step 2: Run tests to verify they fail**

Run: `~/.cargo/bin/cargo nextest run -p mvm-core session`
Expected: FAIL — `no method named 'session' found for struct CheckpointMetaBuilder`
and `struct CheckpointDigestInput has no field named 'session'`.

- [x] **Step 3: Write the implementation — all six sites**

3a. `CheckpointMeta` struct, after the `grants` field:

```rust
    /// The durable agent session this checkpoint is a resume point for, when
    /// it has one. Load-bearing so a resume cannot be redirected to a
    /// different session or replayed at an earlier journal position: the
    /// digest covers this field and the signed chain covers the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionBinding>,
```

3b. `CheckpointMeta::builder`, in the returned `CheckpointMetaBuilder` literal,
after `grants: None,`:

```rust
            session: None,
```

3c. `compute_meta_digest`, in the `CheckpointDigestInput` literal, after
`grants: &self.grants,`:

```rust
            session: &self.session,
```

3d. `CheckpointDigestInput` struct, after the `grants` field:

```rust
    /// Skipped when absent for the same reason `grants` is: a record sealed
    /// before this field existed must hash exactly as it did then, or lineage
    /// verification reports drift on a record nobody edited.
    #[serde(skip_serializing_if = "Option::is_none")]
    session: &'a Option<SessionBinding>,
```

3e. `CheckpointMetaBuilder` struct, after its `grants` field:

```rust
    session: Option<SessionBinding>,
```

and its setter, beside the existing `grants` setter:

```rust
    pub fn session(mut self, binding: Option<SessionBinding>) -> Self {
        self.session = binding;
        self
    }
```

3f. `CheckpointMetaBuilder::build` — add `session: &self.session,` to the
`CheckpointDigestInput` literal, and `session: self.session,` to the
`CheckpointMeta` literal.

- [x] **Step 4: Run tests to verify they pass**

Run: `~/.cargo/bin/cargo nextest run -p mvm-core checkpoint`
Expected: PASS, including the pre-existing digest suite
(`meta_digest_covers_every_load_bearing_field`,
`meta_digest_invariant_under_content_insertion_order`,
`old_shape_meta_without_meta_digest_fails_to_parse`).

If `meta_digest_covers_every_load_bearing_field` fails, it enumerates fields
via a local `struct Fields`; add `session` to that enumeration rather than
weakening the assertion.

- [x] **Step 5: Verify no other construction site broke**

Run: `~/.cargo/bin/cargo check --workspace --all-targets`
Expected: PASS. `CheckpointMeta` is constructed through the builder, so adding
a field should not break callers; a struct-literal construction anywhere will
surface here as a missing-field error and must be fixed by adding
`session: None`.

- [x] **Step 6: Commit**

```bash
~/.cargo/bin/cargo fmt --all
git add crates/mvm-core/src/checkpoint.rs
git commit -m "feat(core): content-address the session binding on a checkpoint"
```

---

### Task 4: `SessionStore`

**Files:**
- Create: `crates/mvm-runtime/src/session/mod.rs`
- Modify: `crates/mvm-runtime/src/lib.rs` (add `pub mod session;` beside the
  existing `pub mod checkpoint;`)
- Test: `crates/mvm-runtime/src/session/mod.rs` (inline `mod tests`)

**Interfaces:**
- Consumes: `sessions_dir()` (Task 1), `SessionBinding` (Task 2),
  `AgentSessionId`, `CheckpointId`.
- Produces: `mvm_runtime::session::{SessionRecord, SessionState, SessionStore}`.

- [x] **Step 1: Write the failing tests**

Create `crates/mvm-runtime/src/session/mod.rs` containing only this test module
for now (the implementation lands in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::agent_session::AgentSessionId;

    fn record(id: &str) -> SessionRecord {
        SessionRecord {
            session_id: AgentSessionId::parse(id).unwrap(),
            generation: 1,
            state: SessionState::Active,
            members: vec!["vm-alpha".to_string()],
            parent_checkpoint: None,
            created_unix: 1_755_000_000,
            updated_unix: 1_755_000_000,
        }
    }

    #[test]
    fn a_written_record_loads_back_identically() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        assert_eq!(store.load(&rec.session_id).unwrap(), rec);
    }

    #[test]
    fn loading_an_absent_session_is_an_error_not_a_default() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SessionStore::at(tmp.path());
        let missing = AgentSessionId::parse("sess-nope").unwrap();
        assert!(store.load(&missing).is_err());
    }

    #[test]
    fn list_returns_every_written_record_sorted_by_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SessionStore::at(tmp.path());
        store.write(&record("sess-beta")).unwrap();
        store.write(&record("sess-alpha")).unwrap();
        let ids: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|r| r.session_id.as_str().to_string())
            .collect();
        assert_eq!(ids, vec!["sess-alpha", "sess-beta"]);
    }

    #[test]
    fn a_record_with_an_unknown_field_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        let path = tmp.path().join("sess-alpha").join("session.json");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace('{', "{\"surprise\":1,")).unwrap();
        assert!(store.load(&rec.session_id).is_err());
    }
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `~/.cargo/bin/cargo nextest run -p mvm-runtime session`
Expected: FAIL to compile — `cannot find type 'SessionRecord'`.

- [x] **Step 3: Write the implementation**

Prepend to `crates/mvm-runtime/src/session/mod.rs`, above the test module:

```rust
//! Filesystem-backed store for durable agent sessions.
//!
//! Mirrors `crate::checkpoint::CheckpointStore`: a directory per session under
//! `mvm_core::config::sessions_dir()`, each holding `session.json`. Kept
//! separate from the checkpoint store because the two are reaped under
//! different retention — a session record is kilobytes and outlives the
//! gigabyte-scale memory image it names.

use anyhow::{Context, Result};
use mvm_contract::protocol::agent_session::AgentSessionId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const RECORD_FILE: &str = "session.json";

/// Lifecycle state of a durable session. Distinct from the agent-session
/// contract's own lifecycle: this tracks whether a sandbox is resident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// A sandbox is live and admitted.
    Active,
    /// No sandbox is resident; the session is resumable from its parent
    /// checkpoint or by replaying its journal.
    Hibernated,
    /// Sealed and archived. Not resumable.
    Closed,
}

/// Durable record for one agent session.
///
/// `members` holds a set of sandbox lineages rather than a single name, so a
/// controller session with worker microVMs needs no migration of stored
/// records later. This store admits one member today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub session_id: AgentSessionId,
    pub generation: u64,
    pub state: SessionState,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_checkpoint: Option<mvm_core::checkpoint::CheckpointId>,
    pub created_unix: u64,
    pub updated_unix: u64,
}

/// Filesystem-backed registry over `config::sessions_dir()` (or any root, for
/// tests).
pub struct SessionStore {
    root: PathBuf,
}

impl SessionStore {
    /// Open the host-wide store.
    pub fn open() -> Result<Self> {
        Ok(Self::at(mvm_core::config::sessions_dir()))
    }

    /// Open a store rooted anywhere. Tests use this; production uses `open`.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn record_path(&self, id: &AgentSessionId) -> PathBuf {
        // `AgentSessionId::parse` already refuses `/`, `..`, and leading or
        // trailing dots, so the id cannot escape the root.
        self.root.join(id.as_str()).join(RECORD_FILE)
    }

    /// Write a record, replacing any prior one for the same session.
    pub fn write(&self, record: &SessionRecord) -> Result<()> {
        let path = self.record_path(&record.session_id);
        let dir = path
            .parent()
            .expect("record path always has a parent directory");
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create session dir {}", dir.display()))?;
        let json = serde_json::to_vec_pretty(record).context("serialize session record")?;
        std::fs::write(&path, json)
            .with_context(|| format!("write session record {}", path.display()))?;
        Ok(())
    }

    /// Load one record. An absent or malformed record is an error, never a
    /// default: a session we cannot read is not a session we may resume.
    pub fn load(&self, id: &AgentSessionId) -> Result<SessionRecord> {
        let path = self.record_path(id);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read session record {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parse session record {}", path.display()))
    }

    /// Every readable record, sorted by session id for a stable listing.
    pub fn list(&self) -> Result<Vec<SessionRecord>> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(err) => {
                return Err(err).with_context(|| format!("read {}", self.root.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("read {}", self.root.display()))?;
            let path = entry.path().join(RECORD_FILE);
            if !path.is_file() {
                continue;
            }
            let bytes = std::fs::read(&path)
                .with_context(|| format!("read session record {}", path.display()))?;
            let record: SessionRecord = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse session record {}", path.display()))?;
            out.push(record);
        }
        out.sort_by(|a, b| a.session_id.as_str().cmp(b.session_id.as_str()));
        Ok(out)
    }
}
```

Then add to `crates/mvm-runtime/src/lib.rs`, beside the existing
`pub mod checkpoint;`:

```rust
pub mod session;
```

- [x] **Step 4: Run tests to verify they pass**

Run: `~/.cargo/bin/cargo nextest run -p mvm-runtime session`
Expected: PASS, all four tests.

- [x] **Step 5: Run the gate before committing**

```bash
~/.cargo/bin/cargo fmt --all -- --check
~/.cargo/bin/cargo nextest run -p mvm-core -p mvm-runtime
~/.cargo/bin/cargo clippy --workspace -- -D warnings
```

Expected: all three clean. If `tempfile` is not already a dev-dependency of
`mvm-runtime`, add it under `[dev-dependencies]` using `workspace = true`.

- [x] **Step 6: Commit**

```bash
~/.cargo/bin/cargo fmt --all
git add crates/mvm-runtime/src/session/ crates/mvm-runtime/src/lib.rs crates/mvm-runtime/Cargo.toml
git commit -m "feat(runtime): add filesystem-backed durable session store"
```

---

### Task 5: Fork must not inherit the parent's session binding

Added after Task 4 landed, once `fork_checkpoint` and `fork_vm_full`
(`crates/mvm-runtime/src/checkpoint/mod.rs`) were read against the new
`session` field: both build the child's `CheckpointMeta` from the parent's
other fields but left `session` untouched, so the builder's `None` default
made the omission look accidental rather than deliberate — a forked child
would need to explicitly *not* carry the binding forward, not fall into it by
omission.

**Files:**
- Modify: `crates/mvm-runtime/src/checkpoint/mod.rs` — `fork_checkpoint`,
  `fork_vm_full`.
- Test: same file, inline `mod tests`.

**Interfaces:**
- Consumes: `SessionBinding` (Task 2/3).
- Produces: no new public surface; pins existing behavior.

- [x] **Step 1: Write the failing tests**

`fork_checkpoint_does_not_inherit_the_parent_session` and
`fork_vm_full_does_not_inherit_the_parent_session` bind a parent checkpoint to
a session, fork it, and assert the child's `session` is `None`.

- [x] **Step 2: Confirm the tests pass for the right reason**

Mutating either fork path to `.session(parent.session.clone())` makes its
matching test fail — the tests were run against that mutation to confirm they
are not vacuously true.

- [x] **Step 3: Add explicit `.session(None)` at both call sites**

A fork starts a new sandbox lineage; a resume continues the same session at
`generation + 1`. Carrying the parent's binding into a fork would have the
child claim to be the same session, at the same generation and journal
cursor, as a parent checkpoint that may still be backing a running sandbox —
two live identities asserting one session.

- [x] **Step 4: Run the gate before committing**

`cargo fmt --all -- --check`, `cargo nextest run -p mvm-runtime`, `cargo
clippy --workspace -- -D warnings` — all clean.

- [x] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/checkpoint/mod.rs
git commit -m "fix(runtime): forks must not inherit the parent's session binding"
```

---

## Deferred to later plans

These are spec sections this plan does not implement, listed so nobody reads
their absence as an oversight:

- D3 park path, `ParkReason`, quiesce sequencing (spec WS3).
- D5 `resume_session`, incremental ledger-head verification, fresh-plan
  synthesis (spec WS4).
- D4 retention ladder enforcement and teaching the existing `checkpoints_dir()`
  sweep about sessions (spec WS5; the sweep itself, `sweep_untagged_checkpoints`
  in `crates/mvm-cli/src/commands/ops/cache.rs`, predates this branch — it is
  not new). Task 2's `SessionBinding` and Task 4's `parent_checkpoint` are
  what a later GC reads to refuse reaping a referenced checkpoint. Delivered
  by `specs/plans/2026-08-18-session-retention.md`, which also adds the
  one-way `demote` transition; retention classes, expiry, and a scheduler
  that calls `demote` remain undelivered.
- CLI surface (spec WS6), chain records (spec WS7), BDD scenarios (spec WS8).
