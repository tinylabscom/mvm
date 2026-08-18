//! Filesystem-backed store for durable agent sessions.
//!
//! Mirrors `crate::checkpoint::CheckpointStore`: a directory per session under
//! `mvm_core::config::agent_sessions_dir()`, each holding `session.json`. Kept
//! separate from the checkpoint store because the two are reaped under
//! different retention — a session record is kilobytes and outlives the
//! gigabyte-scale memory image it names.
//!
//! Distinct from `mvm_core::domain::session`, which models an unrelated
//! concept: a warm VM kept resident across `mvmctl invoke` calls, backed by
//! its own `<mvm_runtime_dir>/sessions/` directory. The two share no code and
//! deliberately no name — this module's public types carry the
//! `AgentSession` prefix already established by `mvm-contract`
//! (`AgentSessionId`, `AgentSessionJournal`, `AgentSessionState`).

use anyhow::{Context, Result};
use mvm_contract::protocol::agent_session::AgentSessionId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const RECORD_FILE: &str = "session.json";

/// Whether a sandbox is resident for a durable agent session.
///
/// Distinct from both `mvm_contract::protocol::agent_session::AgentSessionState`
/// (the agent session's own lifecycle) and `mvm_core::domain::session::SessionState`
/// (the unrelated warm-VM-across-`invoke` session): this tracks only whether a
/// sandbox is currently booted for the durable session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxResidency {
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
pub struct AgentSessionRecord {
    pub session_id: AgentSessionId,
    pub generation: u64,
    pub state: SandboxResidency,
    #[serde(default)]
    pub members: Vec<String>,
    /// Content-addressed resume point, not a mutable checkpoint name — the
    /// same rule `CheckpointMeta.parent`'s doc states: a hash-link lets a
    /// descendant detect any post-seal edit of the checkpoint it resumes
    /// from, where a name would not. Typing this `CheckpointDigest` rather
    /// than `CheckpointId` also gets deserialize-time shape validation for
    /// free (`sha256:<64-hex>`), where `CheckpointId` derives plain
    /// `Deserialize` and would let any unvalidated string off disk be joined
    /// into a store root. `CheckpointStore::by_digest` resolves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_checkpoint: Option<mvm_core::checkpoint::CheckpointDigest>,
    pub created_unix: u64,
    pub updated_unix: u64,
}

/// Filesystem-backed registry over `config::agent_sessions_dir()` (or any
/// root, for tests).
pub struct AgentSessionStore {
    root: PathBuf,
}

impl AgentSessionStore {
    /// Open the host-wide store.
    pub fn open() -> Self {
        Self::at(mvm_core::config::agent_sessions_dir())
    }

    /// Open a store rooted anywhere. Tests use this; production uses `open`.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
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
    pub fn write(&self, record: &AgentSessionRecord) -> Result<()> {
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
    pub fn load(&self, id: &AgentSessionId) -> Result<AgentSessionRecord> {
        let path = self.record_path(id);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read session record {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parse session record {}", path.display()))
    }

    /// Every record that parses cleanly, sorted by session id for a stable
    /// listing. A read or IO error on the store root itself is returned, but
    /// the first record that fails to parse aborts the whole listing rather
    /// than being skipped — mirrors `CheckpointStore::list`.
    pub fn list(&self) -> Result<Vec<AgentSessionRecord>> {
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
            let record: AgentSessionRecord = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse session record {}", path.display()))?;
            out.push(record);
        }
        out.sort_by(|a, b| a.session_id.as_str().cmp(b.session_id.as_str()));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::agent_session::AgentSessionId;

    fn record(id: &str) -> AgentSessionRecord {
        AgentSessionRecord {
            session_id: AgentSessionId::parse(id).unwrap(),
            generation: 1,
            state: SandboxResidency::Active,
            members: vec!["vm-alpha".to_string()],
            parent_checkpoint: None,
            created_unix: 1_755_000_000,
            updated_unix: 1_755_000_000,
        }
    }

    #[test]
    fn a_written_record_loads_back_identically() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        assert_eq!(store.load(&rec.session_id).unwrap(), rec);
    }

    #[test]
    fn loading_an_absent_session_is_an_error_not_a_default() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let missing = AgentSessionId::parse("sess-nope").unwrap();
        assert!(store.load(&missing).is_err());
    }

    #[test]
    fn list_returns_every_written_record_sorted_by_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
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
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        let path = tmp.path().join("sess-alpha").join("session.json");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace('{', "{\"surprise\":1,")).unwrap();
        assert!(store.load(&rec.session_id).is_err());
    }

    #[test]
    fn list_on_a_missing_root_returns_an_empty_vec_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("does-not-exist-yet");
        let store = AgentSessionStore::at(&root);
        assert_eq!(store.list().unwrap(), Vec::new());
    }

    #[test]
    fn list_skips_a_stray_file_sitting_in_the_store_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        store.write(&record("sess-alpha")).unwrap();
        // A plain file (not a session directory) at the store root should be
        // skipped by the `is_file()` guard rather than tripping `list()`.
        std::fs::write(tmp.path().join("stray.txt"), b"not a session").unwrap();
        let ids: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|r| r.session_id.as_str().to_string())
            .collect();
        assert_eq!(ids, vec!["sess-alpha"]);
    }

    #[test]
    fn a_record_with_a_malformed_parent_checkpoint_digest_fails_to_deserialize() {
        // `CheckpointDigest` is `#[serde(try_from = "String")]` and validates
        // the `sha256:<64-hex>` shape at deserialize time. A `CheckpointId`
        // field would have let any string off disk through unchecked.
        let rec = record("sess-alpha");
        let mut value = serde_json::to_value(&rec).unwrap();
        value["parent_checkpoint"] = serde_json::json!("not-a-checkpoint-digest");
        let json = serde_json::to_string(&value).unwrap();
        assert!(serde_json::from_str::<AgentSessionRecord>(&json).is_err());
    }
}
