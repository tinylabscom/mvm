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

/// Why a park, resume, or demote was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionTransitionError {
    #[error("session is not active, so it cannot be parked")]
    NotActive,
    #[error("session is not hibernated, so it cannot be resumed or demoted")]
    NotHibernated,
    #[error("session is closed")]
    Closed,
    #[error("session is already at the coldest storage tier")]
    AlreadyColdest,
}

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

impl AgentSessionRecord {
    /// Suspend a residency. Returns the parked record; does not write it.
    ///
    /// The generation is deliberately unchanged: it identifies one period of
    /// sandbox residency, and a park suspends that period rather than ending
    /// it. `resume` is what opens the next one.
    pub fn park(&self, input: &ParkInput, now_unix: u64) -> Result<Self, SessionTransitionError> {
        match self.state {
            SandboxResidency::Closed => return Err(SessionTransitionError::Closed),
            SandboxResidency::Hibernated => return Err(SessionTransitionError::NotActive),
            SandboxResidency::Active => {}
        }
        Ok(Self {
            state: SandboxResidency::Hibernated,
            storage_tier: Some(select_tier(input.reason)),
            park_reason: Some(input.reason),
            journal_cursor: input.journal_cursor,
            approval_head: input.approval_head.clone(),
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

    /// Move an already-parked session one rung down the storage ladder.
    ///
    /// One-way and always downward: `Resident` releases RAM to disk, `Parked`
    /// releases the memory image and leaves the record and journal. The
    /// generation is unchanged — demoting does not end a residency, it makes
    /// the same suspended one cheaper to hold. The resume point and journal
    /// cursor are preserved, because a demoted session is still resumable; only
    /// the cost of holding it changed.
    ///
    /// This overwrites `park_reason` with `RetentionDemotion`, discarding
    /// whatever reason the session was originally parked under, so after a
    /// demotion `storage_tier` and `park_reason` can disagree with each other
    /// under `select_tier`'s mapping. The stored `storage_tier` is what is
    /// authoritative from that point on; `park_reason` is a breadcrumb of how
    /// the session got there, not an input to recompute the tier from.
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

    /// Whether a record file is present for `id`.
    ///
    /// Deliberately not `load(id).is_ok()`: a record that is on disk but
    /// unparseable must still read as present. A caller that probes before
    /// creating a session would otherwise treat a corrupt record as an absent
    /// one and overwrite it, and the record is the only thing a parked
    /// session's resume point can be recovered from.
    pub fn exists(&self, id: &AgentSessionId) -> bool {
        self.record_path(id).is_file()
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
        input: ParkInput,
        now_unix: u64,
    ) -> Result<AgentSessionRecord> {
        let current = self.load(id)?;
        fence(&current, expected_generation)?;
        let parked = current.park(&input, now_unix)?;
        self.write(&parked)?;
        Ok(parked)
    }

    /// Resume a session, refusing if it has moved past `expected_generation`.
    ///
    /// Same fence, same limit as `park`: it refuses a caller working from a
    /// superseded record, but the load-then-write pair is not a
    /// compare-and-swap, so it does not serialize two callers racing on the
    /// same on-disk generation. See `park`'s doc for the full explanation.
    ///
    /// `current_head` is also compared against the head recorded at park
    /// time: a difference means the approval ledger moved while the session
    /// was parked, so the grants this resume would run under are not the
    /// ones it was admitted for, and it is refused rather than silently
    /// inherited. A session parked with no recorded head (`None`) is not
    /// fenced by this check — there is nothing to compare against. That is a
    /// real gap, not an oversight: whoever records a head at park time closes
    /// it, and until then such a session resumes on the generation fence
    /// alone.
    pub fn resume(
        &self,
        id: &AgentSessionId,
        expected_generation: u64,
        current_head: Option<&mvm_core::checkpoint::ApprovalHead>,
        now_unix: u64,
    ) -> Result<AgentSessionRecord> {
        let current = self.load(id)?;
        fence(&current, expected_generation)?;
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

/// Whether `record`'s resume point must survive garbage collection.
///
/// This is the one place that decides the rule: a live or hibernated session
/// can still resume from its `parent_checkpoint`, so that checkpoint must be
/// held. A `Closed` session is sealed and not resumable, so nothing it names
/// needs holding. Both `pinned_checkpoints` (the automated sweep's set) and
/// `pinning_session` (the manual-deletion door's session lookup) project from
/// this predicate rather than re-deriving it.
pub fn pins_resume_point(record: &AgentSessionRecord) -> bool {
    !matches!(record.state, SandboxResidency::Closed)
}

/// Every checkpoint a live or hibernated session names as its resume point.
///
/// A garbage collector consults this before reaping. Without it, a session
/// parked for longer than the sweep's age cut loses the checkpoint it resumes
/// from and becomes permanently unresumable — the record survives and points at
/// nothing.
pub fn pinned_checkpoints(
    store: &AgentSessionStore,
) -> Result<std::collections::BTreeSet<mvm_core::checkpoint::CheckpointDigest>> {
    let mut pinned = std::collections::BTreeSet::new();
    for record in store.list()? {
        if !pins_resume_point(&record) {
            continue;
        }
        if let Some(digest) = record.parent_checkpoint {
            pinned.insert(digest);
        }
    }
    Ok(pinned)
}

/// The live or hibernated session whose resume point is `digest`, if any.
///
/// Applies the same `pins_resume_point` rule `pinned_checkpoints` sweeps
/// with, but returns the session identity rather than folding it into a set:
/// a manual deletion refusal needs to name the session holding the pin,
/// which the set-only helper can't.
pub fn pinning_session(
    store: &AgentSessionStore,
    digest: &mvm_core::checkpoint::CheckpointDigest,
) -> Result<Option<AgentSessionId>> {
    for record in store.list()? {
        if !pins_resume_point(&record) {
            continue;
        }
        if record.parent_checkpoint.as_ref() == Some(digest) {
            return Ok(Some(record.session_id));
        }
    }
    Ok(None)
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

    /// A minimal park input for tests that only care about the reason.
    fn park_input(reason: ParkReason) -> ParkInput {
        ParkInput {
            reason,
            journal_cursor: 0,
            approval_head: None,
        }
    }

    #[test]
    fn exists_reports_a_present_record_even_when_it_will_not_parse() {
        // The distinction the method exists for: a caller creating a session
        // probes `exists` and must be told "present" for a corrupt record, or
        // it would overwrite the only copy of a parked session's resume point.
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        assert!(!store.exists(&rec.session_id));
        store.write(&rec).unwrap();
        assert!(store.exists(&rec.session_id));

        std::fs::write(
            tmp.path().join("sess-alpha").join(RECORD_FILE),
            b"{ not json",
        )
        .unwrap();
        assert!(
            store.load(&rec.session_id).is_err(),
            "the record no longer parses"
        );
        assert!(
            store.exists(&rec.session_id),
            "an unparseable record is still a record"
        );
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
        let parked = rec
            .park(&park_input(ParkReason::ApprovalWait), 1_755_000_100)
            .unwrap();
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
            .park(&park_input(ParkReason::ApprovalWait), 1_755_000_100)
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
        let parked = record("sess-alpha")
            .park(&park_input(ParkReason::Idle), 1)
            .unwrap();
        assert!(matches!(
            parked.park(&park_input(ParkReason::Idle), 2),
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
            closed.park(&park_input(ParkReason::Idle), 2),
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
    fn park_commits_the_cursor_and_head_with_the_transition() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();

        let head = mvm_core::checkpoint::ApprovalHead::parse(format!("sha256:{}", "ab".repeat(32)))
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
            .park(
                &rec.session_id,
                1,
                ParkInput {
                    reason: ParkReason::Idle,
                    journal_cursor: 7,
                    approval_head: None,
                },
                100,
            )
            .unwrap();

        // Already hibernated: a second park is refused, and must not advance
        // the cursor it was called with.
        assert!(
            store
                .park(
                    &rec.session_id,
                    1,
                    ParkInput {
                        reason: ParkReason::Idle,
                        journal_cursor: 99,
                        approval_head: None,
                    },
                    200,
                )
                .is_err()
        );
        assert_eq!(store.load(&rec.session_id).unwrap().journal_cursor, 7);
    }

    #[test]
    fn store_park_persists_the_transition() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();

        let parked = store
            .park(
                &rec.session_id,
                1,
                park_input(ParkReason::ApprovalWait),
                1_755_000_100,
            )
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
            .park(
                &rec.session_id,
                1,
                park_input(ParkReason::Idle),
                1_755_000_100,
            )
            .unwrap();

        let live = store
            .resume(&rec.session_id, 1, None, 1_755_000_200)
            .unwrap();
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
            .park(&rec.session_id, 1, park_input(ParkReason::Idle), 100)
            .unwrap();
        store.resume(&rec.session_id, 1, None, 200).unwrap(); // now generation 2

        // A caller still holding generation 1 must not be able to park it.
        let err = store
            .park(&rec.session_id, 1, park_input(ParkReason::Operator), 300)
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
        assert!(store.resume(&rec.session_id, 1, None, 400).is_err());
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
        // `parent_checkpoint` is untouched by both transitions — it isn't
        // part of `ParkInput` — so an empty fixture value would let a
        // transition that dropped it pass silently; it must come through
        // `park` and `resume` via `..self.clone()` unchanged.
        //
        // `journal_cursor` and `approval_head`, by contrast, are exactly
        // what `park` sets from its `ParkInput`. Deliberately giving `park`
        // values that differ from what the record already carries (rather
        // than feeding it the record's own fields back) keeps the
        // assertions below from comparing a value to itself by
        // construction: they pin what `park` actually committed, and then
        // that `resume` does not touch what `park` just committed.
        let mut rec = record("sess-alpha");
        rec.parent_checkpoint = Some(
            mvm_core::checkpoint::CheckpointDigest::parse(format!("sha256:{}", "cd".repeat(32)))
                .unwrap(),
        );
        rec.journal_cursor = 1;
        rec.approval_head = Some(head_of("11"));

        let park_input = ParkInput {
            reason: ParkReason::ApprovalWait,
            journal_cursor: 42,
            approval_head: Some(head_of("ab")),
        };
        let parked = rec.park(&park_input, 100).unwrap();
        assert_eq!(parked.parent_checkpoint, rec.parent_checkpoint);
        assert_eq!(parked.journal_cursor, park_input.journal_cursor);
        assert_eq!(parked.approval_head, park_input.approval_head);

        let resumed = parked.resume(200).unwrap();
        assert_eq!(resumed.parent_checkpoint, rec.parent_checkpoint);
        assert_eq!(resumed.journal_cursor, park_input.journal_cursor);
        assert_eq!(resumed.approval_head, park_input.approval_head);
    }

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
            .park(
                &rec.session_id,
                1,
                ParkInput {
                    reason: ParkReason::ApprovalWait,
                    journal_cursor: 5,
                    approval_head: Some(head.clone()),
                },
                100,
            )
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
            .park(
                &rec.session_id,
                1,
                ParkInput {
                    reason: ParkReason::ApprovalWait,
                    journal_cursor: 5,
                    approval_head: Some(head_of("ab")),
                },
                100,
            )
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
            .park(
                &rec.session_id,
                1,
                ParkInput {
                    reason: ParkReason::Idle,
                    journal_cursor: 0,
                    approval_head: None,
                },
                100,
            )
            .unwrap();
        assert!(
            store
                .resume(&rec.session_id, 1, Some(&head_of("cd")), 200)
                .is_ok()
        );
    }

    fn digest_of(byte: &str) -> mvm_core::checkpoint::CheckpointDigest {
        mvm_core::checkpoint::CheckpointDigest::parse(format!("sha256:{}", byte.repeat(32)))
            .unwrap()
    }

    #[test]
    fn pins_resume_point_holds_for_active_and_hibernated_but_not_closed() {
        let mut active = record("sess-active");
        active.state = SandboxResidency::Active;
        assert!(pins_resume_point(&active));

        let mut hibernated = record("sess-hibernated");
        hibernated.state = SandboxResidency::Hibernated;
        assert!(pins_resume_point(&hibernated));

        let mut closed = record("sess-closed");
        closed.state = SandboxResidency::Closed;
        assert!(!pins_resume_point(&closed));
    }

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

    #[test]
    fn demotion_walks_one_rung_down_the_ladder() {
        let resident = record("sess-alpha")
            .park(&park_input(ParkReason::Idle), 100)
            .unwrap();
        assert_eq!(resident.storage_tier, Some(StorageTier::Resident));

        let parked = resident.demote(200).unwrap();
        assert_eq!(parked.storage_tier, Some(StorageTier::Parked));
        assert_eq!(parked.park_reason, Some(ParkReason::RetentionDemotion));
        assert_eq!(
            parked.generation, resident.generation,
            "demotion is not a new residency"
        );

        let cold = parked.demote(300).unwrap();
        assert_eq!(cold.storage_tier, Some(StorageTier::Cold));
    }

    #[test]
    fn a_cold_session_cannot_be_demoted_further() {
        let cold = record("sess-alpha")
            .park(&park_input(ParkReason::RetentionDemotion), 100)
            .unwrap();
        assert_eq!(cold.storage_tier, Some(StorageTier::Cold));
        assert!(matches!(
            cold.demote(200),
            Err(SessionTransitionError::AlreadyColdest)
        ));
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
        // stays resumable, just more cheaply stored. Two demotes (Resident ->
        // Parked -> Cold) reach the bottom of the ladder cleanly, so there is
        // no need for a fallback branch to get there.
        //
        // approval_head is asserted here too: it is the resume fence's input,
        // and the fence only applies when it is `Some`. A refactor that
        // dropped the field through `demote` would not fail loudly — it would
        // silently stop fencing — so this must not leave it `None`.
        let mut rec = record("sess-alpha");
        rec.parent_checkpoint = Some(digest_of("11"));
        let head = head_of("ab");
        let parked = rec
            .park(
                &ParkInput {
                    reason: ParkReason::Idle,
                    journal_cursor: 42,
                    approval_head: Some(head.clone()),
                },
                100,
            )
            .unwrap();
        let cold = parked.demote(200).unwrap().demote(300).unwrap();
        assert_eq!(cold.journal_cursor, 42);
        assert_eq!(cold.parent_checkpoint, Some(digest_of("11")));
        assert_eq!(cold.approval_head, Some(head));
    }
}
