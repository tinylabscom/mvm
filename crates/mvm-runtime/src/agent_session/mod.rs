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
    pub storage_tier: Option<StorageTier>,
    /// Why the session was parked. `None` while the session is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub park_reason: Option<ParkReason>,
}

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
    pub fn park(&self, reason: ParkReason, now_unix: u64) -> Result<Self, SessionTransitionError> {
        match self.state {
            SandboxResidency::Closed => return Err(SessionTransitionError::Closed),
            SandboxResidency::Hibernated => return Err(SessionTransitionError::NotActive),
            SandboxResidency::Active => {}
        }
        Ok(Self {
            state: SandboxResidency::Hibernated,
            storage_tier: Some(select_tier(reason)),
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
            storage_tier: None,
            park_reason: None,
            updated_unix: now_unix,
            ..self.clone()
        })
    }
}

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
    ///
    /// Goes through the workspace's shared `mvm_core::atomic_io::atomic_write`
    /// — the same helper `warm_artifacts.rs`, `vm/template/lifecycle/registry_sync.rs`,
    /// and `vm/name_registry.rs` already use — rather than a private copy: it
    /// writes to a fresh per-call temp file (so two concurrent writers of the
    /// same session never share one temp path and clobber each other), then
    /// flushes and `fdatasync`s before renaming into place, so a crash mid-write
    /// leaves the previous complete record rather than a truncated one. The
    /// record is what a session's durability rests on — a memory image may be
    /// reaped, but losing the record loses the session.
    pub fn write(&self, record: &AgentSessionRecord) -> Result<()> {
        let path = self.record_path(&record.session_id);
        let json = serde_json::to_vec_pretty(record).context("serialize session record")?;
        mvm_core::atomic_io::atomic_write(&path, &json)
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

    /// Park a session, refusing if it has moved past `expected_generation`.
    ///
    /// What the fence does: refuses the park when the on-disk record is no
    /// longer at the generation the caller expected — i.e. the caller is
    /// working from a record some other transition has since superseded.
    /// That's a real check with a real effect: it is what stops a caller
    /// holding a pre-resume record from parking the residency it thinks is
    /// current and silently discarding the newer one, and the record is
    /// written only after the transition is accepted, so a refused park
    /// leaves what is on disk untouched.
    ///
    /// What it does not do: this is a check-then-act pair (`load` then
    /// `write`), not a compare-and-swap. Two callers that both `load` the
    /// same on-disk generation will both pass the fence, and whichever
    /// `write` lands second wins with no error to either caller — the fence
    /// serializes against a transition that already happened, not against
    /// one racing it right now.
    ///
    /// What that implies: a caller that can be invoked concurrently for the
    /// same session must serialize its own calls into this method per
    /// session id, or this module needs real file locking before such a
    /// caller is wired in. Nothing in this module does that serialization
    /// today.
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
    ///
    /// Same fence, same limit as `park`: it refuses a caller working from a
    /// superseded record, but the load-then-write pair is not a
    /// compare-and-swap, so it does not serialize two callers racing on the
    /// same on-disk generation. See `park`'s doc for the full explanation.
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
            journal_cursor: 0,
            approval_head: None,
            storage_tier: None,
            park_reason: None,
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
    fn parking_keeps_the_generation_and_records_why() {
        let rec = record("sess-alpha");
        assert_eq!(rec.generation, 1);
        let parked = rec.park(ParkReason::ApprovalWait, 1_755_000_100).unwrap();
        assert_eq!(parked.state, SandboxResidency::Hibernated);
        assert_eq!(
            parked.generation, 1,
            "a park suspends a residency, it does not end one"
        );
        assert_eq!(parked.park_reason, Some(ParkReason::ApprovalWait));
        assert_eq!(parked.storage_tier, Some(StorageTier::Parked));
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
        assert_eq!(live.storage_tier, None);
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
        assert_eq!(
            serde_json::from_str::<AgentSessionRecord>(&json).unwrap(),
            rec
        );

        // A record written before these fields existed still loads.
        let old = r#"{"session_id":"sess-old","generation":1,"state":"active","created_unix":1,"updated_unix":1}"#;
        let parsed: AgentSessionRecord = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.journal_cursor, 0);
        assert_eq!(parsed.approval_head, None);
        assert_eq!(parsed.storage_tier, None);
        assert_eq!(parsed.park_reason, None);
    }

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
        assert_eq!(
            select_tier(ParkReason::RetentionDemotion),
            StorageTier::Cold
        );
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
        store
            .park(&rec.session_id, 1, ParkReason::Idle, 100)
            .unwrap();
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

    #[test]
    fn a_write_succeeds_and_loads_correctly_despite_stale_temp_debris() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();

        // Simulate debris from an unrelated crashed writer: a leftover
        // fixed-name temp file beside the record. The shared atomic-write
        // helper names its own per-call temp file via `tempfile`, so this
        // file is never the one a write touches — this only proves that
        // stray debris sitting in the session directory does not stop a
        // later write from succeeding and loading back the right record.
        let dir = tmp.path().join("sess-alpha");
        std::fs::write(dir.join("session.json.tmp"), b"{ truncated").unwrap();

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

    #[test]
    fn park_then_resume_carries_the_resume_point_through_unchanged() {
        // A fixture with every resume-critical field non-default: an empty
        // `parent_checkpoint`/`journal_cursor`/`approval_head` would let a
        // transition that dropped one of them pass the rest of the suite
        // silently. `park` only touches `state`/`storage_tier`/`park_reason`/
        // `updated_unix`, and `resume` only touches `state`/`generation`/
        // `storage_tier`/`park_reason`/`updated_unix` — neither transition has
        // any business rewriting the resume point itself.
        let mut rec = record("sess-alpha");
        rec.parent_checkpoint = Some(
            mvm_core::checkpoint::CheckpointDigest::parse(format!("sha256:{}", "cd".repeat(32)))
                .unwrap(),
        );
        rec.journal_cursor = 42;
        rec.approval_head = Some(
            mvm_core::checkpoint::ApprovalHead::parse(format!("sha256:{}", "ab".repeat(32)))
                .unwrap(),
        );

        let parked = rec.park(ParkReason::ApprovalWait, 100).unwrap();
        assert_eq!(parked.parent_checkpoint, rec.parent_checkpoint);
        assert_eq!(parked.journal_cursor, rec.journal_cursor);
        assert_eq!(parked.approval_head, rec.approval_head);

        let resumed = parked.resume(200).unwrap();
        assert_eq!(resumed.parent_checkpoint, rec.parent_checkpoint);
        assert_eq!(resumed.journal_cursor, rec.journal_cursor);
        assert_eq!(resumed.approval_head, rec.approval_head);
    }
}
