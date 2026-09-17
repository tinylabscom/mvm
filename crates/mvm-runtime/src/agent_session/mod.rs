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
use mvm_core::session_transition::{SessionTransitionDigest, TransitionIdentity, TransitionKind};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    /// Unix second until which the host promises to keep this parked session
    /// resumable. Set by park, only ever moved later by renew, and cleared by
    /// resume. `None` while the session is active.
    ///
    /// A promise, not an enforcement: nothing reclaims a session when its
    /// deadline passes, because no demotion today releases what the lower tier
    /// claims to. What the deadline does decide is that an expired session can
    /// no longer be renewed, and that listings say it is expired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_until_unix: Option<u64>,
    /// The transition this record last took, kept so a caller whose response
    /// was lost can retry it and be told it already happened. `None` for a
    /// record no transition has touched since it was opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition: Option<RecordedTransition>,
}

/// The identity and reproducible outcome of the last transition a record took.
///
/// Only the last one: a retry of anything older is refused as superseded,
/// because the record has since moved on and cannot say what that earlier call
/// returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedTransition {
    pub identity: TransitionIdentity,
    /// `identity`'s content address, stored so a retry compares one digest
    /// rather than re-deriving what the recorded call hashed.
    pub digest: SessionTransitionDigest,
    /// The plan a resume was admitted under. A replayed resume reports this
    /// rather than admitting a second plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_plan_id: Option<String>,
}

impl RecordedTransition {
    #[must_use]
    pub fn new(identity: TransitionIdentity, admitted_plan_id: Option<String>) -> Self {
        Self {
            digest: identity.digest(),
            identity,
            admitted_plan_id,
        }
    }
}

/// Which generation a transition is fenced against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationFence {
    /// The caller read the session at this generation. The transition refuses
    /// if the record has moved on, and an exact retry of a transition that
    /// already applied is answered as a replay.
    Observed(u64),
    /// Read the generation at call time. Nothing the caller held can be stale,
    /// so nothing is fenced — and a retry cannot be recognised as one, because
    /// the generation it would compare is whatever the record says now.
    ReadCurrent,
}

impl GenerationFence {
    /// The generation this fence evaluates a transition against.
    #[must_use]
    pub fn resolve(self, current: &AgentSessionRecord) -> u64 {
        match self {
            Self::Observed(generation) => generation,
            Self::ReadCurrent => current.generation,
        }
    }

    #[must_use]
    pub fn is_observed(self) -> bool {
        matches!(self, Self::Observed(_))
    }
}

/// A transition identity together with whether a retry of it may be answered
/// as a replay.
///
/// `replayable` is false whenever any state the identity records as observed
/// was read at call time instead of supplied by the caller: such an identity
/// describes the record as it is now, so it would match a transition the
/// caller never made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionClaim {
    pub identity: TransitionIdentity,
    pub replayable: bool,
}

/// What a store transition did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionResult {
    /// The transition applied and this record was written.
    Applied(AgentSessionRecord),
    /// An identical transition had already applied. Nothing was written; this
    /// is the record as that transition left it.
    Replayed(AgentSessionRecord),
}

impl TransitionResult {
    #[must_use]
    pub fn record(&self) -> &AgentSessionRecord {
        match self {
            Self::Applied(record) | Self::Replayed(record) => record,
        }
    }

    #[must_use]
    pub fn into_record(self) -> AgentSessionRecord {
        match self {
            Self::Applied(record) | Self::Replayed(record) => record,
        }
    }

    #[must_use]
    pub fn is_replay(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }
}

/// How a retry relates to the transition the record last took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryVerdict {
    /// Not a retry of anything recorded: evaluate it as a new transition.
    Apply,
    /// The recorded transition, again. Answer with its outcome; write nothing.
    Replay,
}

/// Why a transition was refused as conflicting with the record's history.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionConflict {
    /// The same step was already taken with a different request.
    #[error(
        "session {session}: a {kind} from generation {generation} was already applied with \
         different inputs ({differences}); refusing to apply a second one"
    )]
    ChangedRequest {
        session: String,
        kind: TransitionKind,
        generation: u64,
        differences: String,
    },
    /// State the caller conditioned on has since changed.
    #[error("session {session}'s {name} is {current}, not the expected {expected}{last}")]
    ObservedStateMoved {
        session: String,
        name: &'static str,
        current: String,
        expected: String,
        /// Rendered description of the transition that moved it, or empty.
        last: String,
    },
    /// The record has moved past the generation the caller observed.
    #[error("session {session} is at generation {current}, not the expected {expected}{last}")]
    Superseded {
        session: String,
        current: u64,
        expected: u64,
        /// Rendered description of the transition that moved it, or empty.
        last: String,
    },
}

/// Decide whether `claim` replays, conflicts with, or is new to `current`.
///
/// Order matters. A replay is recognised before the generation fence, because a
/// resume that applied has already moved the generation the caller observed —
/// the fence alone would refuse exactly the retry this exists to answer. A
/// changed request for the same step is named before the generic fence refusal
/// so the operator is told which input differs rather than only that the
/// session moved.
pub fn classify_retry(
    current: &AgentSessionRecord,
    claim: &TransitionClaim,
) -> Result<RetryVerdict, TransitionConflict> {
    let retried = &claim.identity;
    if claim.replayable
        && let Some(recorded) = current.last_transition.as_ref()
    {
        if recorded.digest == retried.digest() {
            return Ok(RetryVerdict::Replay);
        }
        if recorded.identity.occupies_same_slot(retried) {
            let differences = recorded
                .identity
                .differences(retried)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(TransitionConflict::ChangedRequest {
                session: current.session_id.as_str().to_string(),
                kind: retried.kind,
                generation: retried.observed_generation,
                differences,
            });
        }
    }
    if current.generation != retried.observed_generation {
        return Err(TransitionConflict::Superseded {
            session: current.session_id.as_str().to_string(),
            current: current.generation,
            expected: retried.observed_generation,
            last: describe_last_transition(current),
        });
    }
    Ok(RetryVerdict::Apply)
}

/// `"; its last transition was a <kind> from generation <n>"`, or empty.
fn describe_last_transition(current: &AgentSessionRecord) -> String {
    current
        .last_transition
        .as_ref()
        .map(|last| {
            format!(
                "; its last transition was a {} from generation {}",
                last.identity.kind, last.identity.observed_generation
            )
        })
        .unwrap_or_default()
}

/// The identity of parking `session` at `generation` with `input`.
///
/// Every field of [`ParkInput`] is covered, because each one changes what the
/// park writes. The reason is hashed in its stored spelling so the identity
/// does not depend on how a CLI chose to spell it.
#[must_use]
pub fn park_identity(
    session: &AgentSessionId,
    generation: u64,
    input: &ParkInput,
) -> TransitionIdentity {
    TransitionIdentity::new(TransitionKind::Park, session.as_str(), generation)
        .input("reason", park_reason_key(input.reason))
        .input("journal_cursor", input.journal_cursor)
        .optional_input(
            "approval_head",
            input.approval_head.as_ref().map(ToString::to_string),
        )
        .input("retain_for_secs", input.retention_secs())
}

/// Name of the observed deadline in a renewal's identity.
const OBSERVED_DEADLINE: &str = "retain_until_unix";

/// The identity of renewing `current` as `request` asks.
///
/// The deadline the caller observed is part of it, as observed state rather
/// than as an input: two renewals from different deadlines are successive
/// steps, while two from the same deadline asking for different extensions
/// compete for one step.
#[must_use]
pub fn renew_claim(current: &AgentSessionRecord, request: &RenewRequest) -> TransitionClaim {
    let observed_deadline = request.expected_deadline_unix.or(current.retain_until_unix);
    TransitionClaim {
        identity: TransitionIdentity::new(
            TransitionKind::Renew,
            current.session_id.as_str(),
            request.generation.resolve(current),
        )
        .observing(
            OBSERVED_DEADLINE,
            observed_deadline.map(|deadline| deadline.to_string()),
        )
        .input("extend_for_secs", request.extend_for_secs),
        replayable: request.generation.is_observed() && request.expected_deadline_unix.is_some(),
    }
}

/// The serde spelling of a park reason, which is also what a record stores.
fn park_reason_key(reason: ParkReason) -> &'static str {
    match reason {
        ParkReason::ApprovalWait => "approval_wait",
        ParkReason::Idle => "idle",
        ParkReason::HostShutdown => "host_shutdown",
        ParkReason::Operator => "operator",
        ParkReason::RetentionDemotion => "retention_demotion",
    }
}

/// Refuse a state-machine rejection, naming the last transition when there is
/// one: "not active" alone does not tell a retrying caller that the session is
/// hibernated because of a transition it did not make.
fn refused(current: &AgentSessionRecord, error: SessionTransitionError) -> anyhow::Error {
    anyhow::anyhow!(
        "session {}: {error}{}",
        current.session_id.as_str(),
        describe_last_transition(current)
    )
}

/// What a store resume commits besides the state transition.
///
/// A params struct because the identity, the head and the admitted plan are all
/// inputs the orchestrator computed, and a positional call could pass the
/// record's own head back where the current one belongs.
#[derive(Debug, Clone, Copy)]
pub struct ResumeTransition<'a> {
    /// The resume's identity, built by the caller that holds the plan material.
    pub claim: &'a TransitionClaim,
    /// The approval ledger's head now, compared against the one recorded at park.
    pub current_head: Option<&'a mvm_core::checkpoint::ApprovalHead>,
    /// The plan the resume was admitted under, recorded so a replay can report
    /// it without admitting another.
    pub admitted_plan_id: Option<&'a str>,
    pub now_unix: u64,
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
    #[error("session records no retention deadline to renew")]
    NoDeadline,
    #[error(
        "session's retention deadline passed at unix {deadline_unix}; it is already past its \
         promise, so it cannot be renewed"
    )]
    Expired { deadline_unix: u64 },
    #[error(
        "renewing to unix {requested_unix} would end before the current deadline of unix \
         {deadline_unix}; a renewal can only extend"
    )]
    WouldShorten {
        deadline_unix: u64,
        requested_unix: u64,
    },
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
    /// How long the host promises to keep the parked session resumable, in
    /// seconds. `None` takes [`default_retention`] for the reason.
    pub retain_for_secs: Option<u64>,
}

impl ParkInput {
    /// The retention this park promises: the explicit one, or the reason's
    /// default.
    #[must_use]
    pub fn retention_secs(&self) -> u64 {
        self.retain_for_secs
            .unwrap_or_else(|| default_retention(self.reason).as_secs())
    }
}

/// Retention for a park waiting on an approval: as long as an approval can
/// live. Holding the session past the point its approval must have expired
/// promises a wake that cannot come.
pub const APPROVAL_WAIT_RETENTION: Duration =
    Duration::from_millis(mvm_contract::policy::approval::MAX_APPROVAL_TTL_MS);

/// Retention for an idle park: the standby TTL. An idle session is the one
/// that may stay resident, and a resident sandbox is reaped on that clock.
pub const IDLE_RETENTION: Duration = crate::standby_pool::STANDBY_POOL_TTL;

/// Retention for a park forced by host shutdown. A starting proposal, not a
/// measured one: long enough to span a maintenance window and a weekend
/// morning, short enough that a memory image does not sit on disk forgotten.
pub const HOST_SHUTDOWN_RETENTION: Duration = Duration::from_secs(48 * 60 * 60);

/// Retention for an operator's explicit park. Same starting proposal as a
/// host shutdown; an operator who wants longer says so with `retain_for_secs`.
pub const OPERATOR_RETENTION: Duration = Duration::from_secs(48 * 60 * 60);

/// Retention for a session already demoted to the record-and-journal tier,
/// which costs kilobytes to hold.
pub const RETENTION_DEMOTION_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The retention a park promises when the caller names none.
#[must_use]
pub fn default_retention(reason: ParkReason) -> Duration {
    match reason {
        ParkReason::ApprovalWait => APPROVAL_WAIT_RETENTION,
        ParkReason::Idle => IDLE_RETENTION,
        ParkReason::HostShutdown => HOST_SHUTDOWN_RETENTION,
        ParkReason::Operator => OPERATOR_RETENTION,
        ParkReason::RetentionDemotion => RETENTION_DEMOTION_RETENTION,
    }
}

/// Whether a parked session's retention promise still holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RetentionStatus {
    /// The deadline is in the future.
    Alive {
        until_unix: u64,
        remaining_secs: u64,
    },
    /// The deadline has passed. The session has not been reclaimed — nothing
    /// reclaims one — but it can no longer be renewed.
    Expired {
        until_unix: u64,
        expired_for_secs: u64,
    },
}

/// What a store renewal is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewRequest {
    pub generation: GenerationFence,
    /// The deadline the caller read. Successive renewals of one parked session
    /// share a generation, so this is what tells a retry of one renewal from
    /// the next renewal. `None` reads the deadline at call time, which fences
    /// nothing and cannot claim a replay.
    pub expected_deadline_unix: Option<u64>,
    /// How far past `now` the new deadline lies.
    pub extend_for_secs: u64,
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
            retain_until_unix: Some(now_unix.saturating_add(input.retention_secs())),
            updated_unix: now_unix,
            ..self.clone()
        })
    }

    /// Move a parked session's retention deadline later. Returns the renewed
    /// record; does not write it.
    ///
    /// Extend-only. A renewal that would end before the current deadline is
    /// refused rather than quietly clamped, because a caller that asked for a
    /// shorter promise believes something about the session that is not true.
    /// An expired session is refused too: its promise has already lapsed, and
    /// renewing it would claim a continuity the host never guaranteed.
    pub fn renew(
        &self,
        extend_for_secs: u64,
        now_unix: u64,
    ) -> Result<Self, SessionTransitionError> {
        match self.state {
            SandboxResidency::Closed => return Err(SessionTransitionError::Closed),
            SandboxResidency::Active => return Err(SessionTransitionError::NotHibernated),
            SandboxResidency::Hibernated => {}
        }
        let deadline_unix = self
            .retain_until_unix
            .ok_or(SessionTransitionError::NoDeadline)?;
        if now_unix >= deadline_unix {
            return Err(SessionTransitionError::Expired { deadline_unix });
        }
        let requested_unix = now_unix.saturating_add(extend_for_secs);
        if requested_unix < deadline_unix {
            return Err(SessionTransitionError::WouldShorten {
                deadline_unix,
                requested_unix,
            });
        }
        Ok(Self {
            retain_until_unix: Some(requested_unix),
            updated_unix: now_unix,
            ..self.clone()
        })
    }

    /// Whether this record's retention promise holds at `now_unix`. `None` for
    /// a record with no deadline, which is every active one.
    #[must_use]
    pub fn retention_status(&self, now_unix: u64) -> Option<RetentionStatus> {
        let until_unix = self.retain_until_unix?;
        Some(if now_unix < until_unix {
            RetentionStatus::Alive {
                until_unix,
                remaining_secs: until_unix - now_unix,
            }
        } else {
            RetentionStatus::Expired {
                until_unix,
                expired_for_secs: now_unix - until_unix,
            }
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
            retain_until_unix: None,
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

    /// Park a session, refusing if it has moved past the fenced generation.
    ///
    /// A retry of a park that already applied — same generation observed, same
    /// input — is answered with [`TransitionResult::Replayed`] and writes
    /// nothing, provided the caller supplied the generation it observed. A
    /// retry that changed its input for the same step is refused naming the
    /// input. With [`GenerationFence::ReadCurrent`] neither can be recognised,
    /// and a second park refuses on the state machine as it always did.
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
        fence: GenerationFence,
        input: ParkInput,
        now_unix: u64,
    ) -> Result<TransitionResult> {
        let current = self.load(id)?;
        let claim = TransitionClaim {
            identity: park_identity(id, fence.resolve(&current), &input),
            replayable: fence.is_observed(),
        };
        if classify_retry(&current, &claim)? == RetryVerdict::Replay {
            return Ok(TransitionResult::Replayed(current));
        }
        let mut parked = current
            .park(&input, now_unix)
            .map_err(|e| refused(&current, e))?;
        parked.last_transition = Some(RecordedTransition::new(claim.identity, None));
        self.write(&parked)?;
        Ok(TransitionResult::Applied(parked))
    }

    /// Extend a parked session's retention deadline.
    ///
    /// Fenced and retry-exact like `park`, with one more observation: the
    /// deadline the caller read. A retry carrying both the generation and the
    /// deadline replays; a renewal whose deadline moved since the caller read
    /// it is refused naming both values.
    pub fn renew(
        &self,
        id: &AgentSessionId,
        request: RenewRequest,
        now_unix: u64,
    ) -> Result<TransitionResult> {
        let current = self.load(id)?;
        let claim = renew_claim(&current, &request);
        if classify_retry(&current, &claim)? == RetryVerdict::Replay {
            return Ok(TransitionResult::Replayed(current));
        }
        if let Some(expected) = request.expected_deadline_unix
            && current.retain_until_unix != Some(expected)
        {
            return Err(TransitionConflict::ObservedStateMoved {
                session: current.session_id.as_str().to_string(),
                name: "retention deadline",
                current: current
                    .retain_until_unix
                    .map_or_else(|| "(none)".to_string(), |d| format!("unix {d}")),
                expected: format!("unix {expected}"),
                last: describe_last_transition(&current),
            }
            .into());
        }
        let mut renewed = current
            .renew(request.extend_for_secs, now_unix)
            .map_err(|e| refused(&current, e))?;
        renewed.last_transition = Some(RecordedTransition::new(claim.identity, None));
        self.write(&renewed)?;
        Ok(TransitionResult::Applied(renewed))
    }

    /// Resume a session, refusing if it has moved past the generation its
    /// claim observed.
    ///
    /// The identity is the caller's to build, because what determines a
    /// resume's outcome — the plan material — is not something this store
    /// holds. A replay is recognised here as well as by the caller, so two
    /// retries racing past the caller's check still write only once.
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
        transition: ResumeTransition<'_>,
    ) -> Result<TransitionResult> {
        let current = self.load(id)?;
        if classify_retry(&current, transition.claim)? == RetryVerdict::Replay {
            return Ok(TransitionResult::Replayed(current));
        }
        let current_head = transition.current_head;
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
        let mut live = current
            .resume(transition.now_unix)
            .map_err(|e| refused(&current, e))?;
        live.last_transition = Some(RecordedTransition::new(
            transition.claim.identity.clone(),
            transition.admitted_plan_id.map(str::to_string),
        ));
        self.write(&live)?;
        Ok(TransitionResult::Applied(live))
    }
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
            retain_until_unix: None,
            last_transition: None,
        }
    }

    /// A minimal park input for tests that only care about the reason.
    fn park_input(reason: ParkReason) -> ParkInput {
        ParkInput {
            reason,
            journal_cursor: 0,
            approval_head: None,
            retain_for_secs: None,
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
                GenerationFence::Observed(1),
                ParkInput {
                    reason: ParkReason::ApprovalWait,
                    journal_cursor: 42,
                    approval_head: Some(head.clone()),
                    retain_for_secs: None,
                },
                1_755_000_100,
            )
            .unwrap()
            .into_record();

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
                GenerationFence::Observed(1),
                ParkInput {
                    reason: ParkReason::Idle,
                    journal_cursor: 7,
                    approval_head: None,
                    retain_for_secs: None,
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
                    GenerationFence::Observed(1),
                    ParkInput {
                        reason: ParkReason::Idle,
                        journal_cursor: 99,
                        approval_head: None,
                        retain_for_secs: None,
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
                GenerationFence::Observed(1),
                park_input(ParkReason::ApprovalWait),
                1_755_000_100,
            )
            .unwrap()
            .into_record();
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
                GenerationFence::Observed(1),
                park_input(ParkReason::Idle),
                1_755_000_100,
            )
            .unwrap();

        let live = resume_at(&store, &rec.session_id, 1, None, 1_755_000_200)
            .unwrap()
            .into_record();
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
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                park_input(ParkReason::Idle),
                100,
            )
            .unwrap();
        resume_at(&store, &rec.session_id, 1, None, 200).unwrap(); // now generation 2

        // A caller still holding generation 1 must not be able to park it.
        let err = store
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                park_input(ParkReason::Operator),
                300,
            )
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
        assert!(resume_at(&store, &rec.session_id, 1, None, 400).is_err());
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
            retain_for_secs: None,
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

    /// Resume through the store with a bare resume identity, the way a caller
    /// that holds no plan material of its own would.
    fn resume_at(
        store: &AgentSessionStore,
        id: &AgentSessionId,
        generation: u64,
        head: Option<&mvm_core::checkpoint::ApprovalHead>,
        now_unix: u64,
    ) -> Result<TransitionResult> {
        let claim = TransitionClaim {
            identity: TransitionIdentity::new(TransitionKind::Resume, id.as_str(), generation),
            replayable: true,
        };
        store.resume(
            id,
            ResumeTransition {
                claim: &claim,
                current_head: head,
                admitted_plan_id: Some("plan-test"),
                now_unix,
            },
        )
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
                GenerationFence::Observed(1),
                ParkInput {
                    reason: ParkReason::ApprovalWait,
                    journal_cursor: 5,
                    approval_head: Some(head.clone()),
                    retain_for_secs: None,
                },
                100,
            )
            .unwrap();

        let live = resume_at(&store, &rec.session_id, 1, Some(&head), 200)
            .unwrap()
            .into_record();
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
                GenerationFence::Observed(1),
                ParkInput {
                    reason: ParkReason::ApprovalWait,
                    journal_cursor: 5,
                    approval_head: Some(head_of("ab")),
                    retain_for_secs: None,
                },
                100,
            )
            .unwrap();

        let err = resume_at(&store, &rec.session_id, 1, Some(&head_of("cd")), 200)
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
                GenerationFence::Observed(1),
                ParkInput {
                    reason: ParkReason::Idle,
                    journal_cursor: 0,
                    approval_head: None,
                    retain_for_secs: None,
                },
                100,
            )
            .unwrap();
        assert!(resume_at(&store, &rec.session_id, 1, Some(&head_of("cd")), 200).is_ok());
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
                    retain_for_secs: None,
                },
                100,
            )
            .unwrap();
        let cold = parked.demote(200).unwrap().demote(300).unwrap();
        assert_eq!(cold.journal_cursor, 42);
        assert_eq!(cold.parent_checkpoint, Some(digest_of("11")));
        assert_eq!(cold.approval_head, Some(head));
    }

    // ── exact retry ─────────────────────────────────────────────────────

    fn record_bytes(tmp: &Path, id: &str) -> Vec<u8> {
        std::fs::read(tmp.join(id).join(RECORD_FILE)).unwrap()
    }

    fn resume_claim(id: &AgentSessionId, generation: u64, image: &str) -> TransitionClaim {
        TransitionClaim {
            identity: TransitionIdentity::new(TransitionKind::Resume, id.as_str(), generation)
                .input("image_sha256", image),
            replayable: true,
        }
    }

    fn resume_with(
        store: &AgentSessionStore,
        id: &AgentSessionId,
        claim: &TransitionClaim,
        now_unix: u64,
    ) -> Result<TransitionResult> {
        store.resume(
            id,
            ResumeTransition {
                claim,
                current_head: None,
                admitted_plan_id: Some("plan-first"),
                now_unix,
            },
        )
    }

    #[test]
    fn an_exact_park_retry_replays_the_original_result_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        let first = store
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                park_input(ParkReason::ApprovalWait),
                100,
            )
            .unwrap();
        assert!(!first.is_replay());
        let before = record_bytes(tmp.path(), "sess-alpha");

        // Later, which is the only time a retry can happen: the clock must not
        // make it look like a new request.
        let retry = store
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                park_input(ParkReason::ApprovalWait),
                9_999,
            )
            .unwrap();
        assert!(retry.is_replay(), "an identical retry must be a replay");
        assert_eq!(retry.record(), first.record());
        assert_eq!(retry.record().updated_unix, 100);
        assert_eq!(
            record_bytes(tmp.path(), "sess-alpha"),
            before,
            "a replay must not rewrite a byte"
        );
    }

    #[test]
    fn a_park_retry_with_a_different_input_is_a_conflict_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                park_input(ParkReason::ApprovalWait),
                100,
            )
            .unwrap();
        let before = record_bytes(tmp.path(), "sess-alpha");

        let err = store
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                park_input(ParkReason::Operator),
                200,
            )
            .expect_err("a changed request for the same step must not apply");
        let conflict = err
            .downcast_ref::<TransitionConflict>()
            .expect("the refusal is a typed conflict");
        assert!(
            matches!(conflict, TransitionConflict::ChangedRequest { .. }),
            "{conflict:?}"
        );
        let text = err.to_string();
        assert!(
            text.contains("reason: recorded approval_wait, retried operator"),
            "{text}"
        );
        assert_eq!(record_bytes(tmp.path(), "sess-alpha"), before);
    }

    #[test]
    fn a_park_retry_without_an_observed_generation_cannot_claim_a_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store
            .park(
                &rec.session_id,
                GenerationFence::ReadCurrent,
                park_input(ParkReason::Idle),
                100,
            )
            .unwrap();
        let before = record_bytes(tmp.path(), "sess-alpha");

        let err = store
            .park(
                &rec.session_id,
                GenerationFence::ReadCurrent,
                park_input(ParkReason::Idle),
                200,
            )
            .expect_err("without an observed generation a retry refuses as it always did");
        let text = err.to_string();
        assert!(text.contains("not active"), "{text}");
        assert!(
            text.contains("last transition was a park from generation 1"),
            "{text}"
        );
        assert_eq!(record_bytes(tmp.path(), "sess-alpha"), before);
    }

    #[test]
    fn a_park_applied_without_an_observed_generation_replays_for_a_caller_who_supplies_it() {
        // The recorded identity names the generation the park was evaluated
        // at, however that generation was obtained, so a later exact retry
        // still recognises it.
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store
            .park(
                &rec.session_id,
                GenerationFence::ReadCurrent,
                park_input(ParkReason::Idle),
                100,
            )
            .unwrap();
        let retry = store
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                park_input(ParkReason::Idle),
                200,
            )
            .unwrap();
        assert!(retry.is_replay());
    }

    #[test]
    fn an_exact_resume_retry_replays_after_the_generation_it_observed_moved() {
        // The case the fence alone gets wrong: the resume already advanced the
        // generation the retry observed, so a plain fence would refuse the
        // retry of a resume that succeeded.
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                park_input(ParkReason::Operator),
                100,
            )
            .unwrap();
        let claim = resume_claim(&rec.session_id, 1, "aa");
        let first = resume_with(&store, &rec.session_id, &claim, 200).unwrap();
        assert_eq!(first.record().generation, 2);
        let before = record_bytes(tmp.path(), "sess-alpha");

        let retry = resume_with(&store, &rec.session_id, &claim, 300).unwrap();
        assert!(retry.is_replay());
        assert_eq!(retry.record(), first.record());
        assert_eq!(retry.record().generation, 2, "no second generation opened");
        assert_eq!(
            retry
                .record()
                .last_transition
                .as_ref()
                .and_then(|t| t.admitted_plan_id.as_deref()),
            Some("plan-first"),
            "the replay carries the plan the original resume was admitted under"
        );
        assert_eq!(record_bytes(tmp.path(), "sess-alpha"), before);
    }

    #[test]
    fn a_resume_retry_with_different_material_is_a_conflict_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        store
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                park_input(ParkReason::Operator),
                100,
            )
            .unwrap();
        resume_with(
            &store,
            &rec.session_id,
            &resume_claim(&rec.session_id, 1, "aa"),
            200,
        )
        .unwrap();
        let before = record_bytes(tmp.path(), "sess-alpha");

        let err = resume_with(
            &store,
            &rec.session_id,
            &resume_claim(&rec.session_id, 1, "bb"),
            300,
        )
        .expect_err("a resume from the same generation with other material must not apply");
        assert!(
            err.to_string()
                .contains("image_sha256: recorded aa, retried bb"),
            "{err}"
        );
        assert_eq!(record_bytes(tmp.path(), "sess-alpha"), before);
    }

    #[test]
    fn a_retry_against_a_superseded_generation_names_the_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        let park = |generation, now| {
            store.park(
                &rec.session_id,
                GenerationFence::Observed(generation),
                park_input(ParkReason::Operator),
                now,
            )
        };
        park(1, 100).unwrap();
        resume_with(
            &store,
            &rec.session_id,
            &resume_claim(&rec.session_id, 1, "aa"),
            200,
        )
        .unwrap();
        park(2, 300).unwrap();

        // The first resume is no longer the last transition, so its retry is
        // not a replay — and it must not apply a second time either.
        let err = resume_with(
            &store,
            &rec.session_id,
            &resume_claim(&rec.session_id, 1, "aa"),
            400,
        )
        .expect_err("a retry of a superseded transition must refuse");
        let conflict = err.downcast_ref::<TransitionConflict>().unwrap();
        assert_eq!(
            conflict,
            &TransitionConflict::Superseded {
                session: "sess-alpha".to_string(),
                current: 2,
                expected: 1,
                last: "; its last transition was a park from generation 2".to_string(),
            }
        );
        assert_eq!(
            store.load(&rec.session_id).unwrap().state,
            SandboxResidency::Hibernated
        );
    }

    #[test]
    fn park_identity_covers_every_park_input() {
        let id = AgentSessionId::parse("sess-alpha").unwrap();
        let base = ParkInput {
            reason: ParkReason::Idle,
            journal_cursor: 1,
            approval_head: None,
            retain_for_secs: None,
        };
        let digest = |generation, input: &ParkInput| park_identity(&id, generation, input).digest();
        let reference = digest(1, &base);
        assert_ne!(digest(2, &base), reference, "generation");
        for changed in [
            ParkInput {
                reason: ParkReason::Operator,
                ..base.clone()
            },
            ParkInput {
                journal_cursor: 2,
                ..base.clone()
            },
            ParkInput {
                approval_head: Some(head_of("ab")),
                ..base.clone()
            },
            ParkInput {
                retain_for_secs: Some(60),
                ..base.clone()
            },
        ] {
            assert_ne!(digest(1, &changed), reference, "{changed:?}");
        }
    }

    #[test]
    fn the_hashed_reason_spelling_is_the_stored_one() {
        for reason in [
            ParkReason::ApprovalWait,
            ParkReason::Idle,
            ParkReason::HostShutdown,
            ParkReason::Operator,
            ParkReason::RetentionDemotion,
        ] {
            assert_eq!(
                serde_json::to_string(&reason).unwrap(),
                format!("\"{}\"", park_reason_key(reason))
            );
        }
    }

    #[test]
    fn a_record_with_a_last_transition_round_trips() {
        let mut rec = record("sess-alpha");
        rec.last_transition = Some(RecordedTransition::new(
            resume_claim(&rec.session_id, 1, "aa").identity,
            Some("plan-first".to_string()),
        ));
        let json = serde_json::to_string(&rec).unwrap();
        assert_eq!(
            serde_json::from_str::<AgentSessionRecord>(&json).unwrap(),
            rec
        );
    }

    // ── retention deadline ──────────────────────────────────────────────

    const HOUR: u64 = 60 * 60;

    fn parked_at(reason: ParkReason, retain_for_secs: Option<u64>, now: u64) -> AgentSessionRecord {
        record("sess-alpha")
            .park(
                &ParkInput {
                    retain_for_secs,
                    ..park_input(reason)
                },
                now,
            )
            .unwrap()
    }

    #[test]
    fn each_reason_has_a_named_default_retention() {
        assert_eq!(
            default_retention(ParkReason::ApprovalWait),
            APPROVAL_WAIT_RETENTION
        );
        assert_eq!(default_retention(ParkReason::Idle), IDLE_RETENTION);
        assert_eq!(
            default_retention(ParkReason::HostShutdown),
            HOST_SHUTDOWN_RETENTION
        );
        assert_eq!(default_retention(ParkReason::Operator), OPERATOR_RETENTION);
        assert_eq!(
            default_retention(ParkReason::RetentionDemotion),
            RETENTION_DEMOTION_RETENTION
        );
        // Tied to what they are named for, not copied from it.
        assert_eq!(
            APPROVAL_WAIT_RETENTION.as_millis(),
            u128::from(mvm_contract::policy::approval::MAX_APPROVAL_TTL_MS)
        );
        assert_eq!(IDLE_RETENTION, crate::standby_pool::STANDBY_POOL_TTL);
    }

    #[test]
    fn a_park_sets_the_reasons_default_deadline() {
        let parked = parked_at(ParkReason::ApprovalWait, None, 1_000);
        assert_eq!(
            parked.retain_until_unix,
            Some(1_000 + APPROVAL_WAIT_RETENTION.as_secs())
        );
    }

    #[test]
    fn an_explicit_retention_overrides_the_default() {
        let parked = parked_at(ParkReason::ApprovalWait, Some(5 * HOUR), 1_000);
        assert_eq!(parked.retain_until_unix, Some(1_000 + 5 * HOUR));
    }

    #[test]
    fn a_resume_clears_the_deadline() {
        let live = parked_at(ParkReason::Operator, None, 1_000)
            .resume(2_000)
            .unwrap();
        assert_eq!(live.retain_until_unix, None);
        assert_eq!(live.retention_status(2_000), None);
    }

    #[test]
    fn a_renewal_moves_the_deadline_later() {
        let parked = parked_at(ParkReason::Operator, Some(HOUR), 1_000);
        let renewed = parked.renew(10 * HOUR, 2_000).unwrap();
        assert_eq!(renewed.retain_until_unix, Some(2_000 + 10 * HOUR));
        assert_eq!(renewed.updated_unix, 2_000);
        assert_eq!(
            renewed.generation, parked.generation,
            "a renewal is not a residency"
        );
    }

    #[test]
    fn a_renewal_that_would_shorten_the_deadline_refuses() {
        let parked = parked_at(ParkReason::Operator, Some(10 * HOUR), 1_000);
        assert_eq!(
            parked.renew(HOUR, 2_000),
            Err(SessionTransitionError::WouldShorten {
                deadline_unix: 1_000 + 10 * HOUR,
                requested_unix: 2_000 + HOUR,
            })
        );
    }

    #[test]
    fn a_renewal_to_exactly_the_current_deadline_is_not_a_shortening() {
        let parked = parked_at(ParkReason::Operator, Some(HOUR), 1_000);
        let renewed = parked.renew(HOUR - 500, 1_500).unwrap();
        assert_eq!(renewed.retain_until_unix, parked.retain_until_unix);
    }

    #[test]
    fn an_expired_session_cannot_be_renewed() {
        let parked = parked_at(ParkReason::Operator, Some(HOUR), 1_000);
        let deadline = 1_000 + HOUR;
        let err = parked.renew(30 * 24 * HOUR, deadline).unwrap_err();
        assert_eq!(
            err,
            SessionTransitionError::Expired {
                deadline_unix: deadline
            }
        );
        assert!(err.to_string().contains("past its promise"), "{err}");
    }

    #[test]
    fn a_closed_or_active_session_cannot_be_renewed() {
        let mut closed = parked_at(ParkReason::Operator, None, 1_000);
        closed.state = SandboxResidency::Closed;
        assert_eq!(
            closed.renew(HOUR, 1_001),
            Err(SessionTransitionError::Closed)
        );
        assert_eq!(
            record("sess-alpha").renew(HOUR, 1_001),
            Err(SessionTransitionError::NotHibernated)
        );
    }

    #[test]
    fn retention_status_is_alive_before_the_deadline_and_expired_from_it() {
        let parked = parked_at(ParkReason::Operator, Some(100), 1_000);
        assert_eq!(
            parked.retention_status(1_060),
            Some(RetentionStatus::Alive {
                until_unix: 1_100,
                remaining_secs: 40
            })
        );
        assert_eq!(
            parked.retention_status(1_100),
            Some(RetentionStatus::Expired {
                until_unix: 1_100,
                expired_for_secs: 0
            })
        );
        assert_eq!(record("sess-alpha").retention_status(1_100), None);
    }

    /// A parked session in a store, and its deadline.
    fn stored_parked(tmp: &Path) -> (AgentSessionStore, AgentSessionId, u64) {
        let store = AgentSessionStore::at(tmp);
        let rec = record("sess-alpha");
        store.write(&rec).unwrap();
        let parked = store
            .park(
                &rec.session_id,
                GenerationFence::Observed(1),
                ParkInput {
                    retain_for_secs: Some(HOUR),
                    ..park_input(ParkReason::Operator)
                },
                1_000,
            )
            .unwrap()
            .into_record();
        (store, rec.session_id, parked.retain_until_unix.unwrap())
    }

    fn renew_request(deadline: Option<u64>, extend_for_secs: u64) -> RenewRequest {
        RenewRequest {
            generation: GenerationFence::Observed(1),
            expected_deadline_unix: deadline,
            extend_for_secs,
        }
    }

    #[test]
    fn an_exact_renew_retry_replays_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, id, deadline) = stored_parked(tmp.path());
        let request = renew_request(Some(deadline), 5 * HOUR);
        let first = store.renew(&id, request, 2_000).unwrap();
        assert!(!first.is_replay());
        let before = record_bytes(tmp.path(), "sess-alpha");

        let retry = store.renew(&id, request, 3_000).unwrap();
        assert!(retry.is_replay());
        assert_eq!(retry.record(), first.record());
        assert_eq!(record_bytes(tmp.path(), "sess-alpha"), before);
    }

    #[test]
    fn a_renewal_from_the_new_deadline_is_a_new_renewal_not_a_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, id, deadline) = stored_parked(tmp.path());
        let first = store
            .renew(&id, renew_request(Some(deadline), 5 * HOUR), 2_000)
            .unwrap()
            .into_record();
        let second = store
            .renew(&id, renew_request(first.retain_until_unix, 5 * HOUR), 4_000)
            .unwrap();
        assert!(!second.is_replay());
        assert_eq!(second.record().retain_until_unix, Some(4_000 + 5 * HOUR));
    }

    #[test]
    fn a_renew_retry_asking_for_another_extension_is_a_conflict_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, id, deadline) = stored_parked(tmp.path());
        store
            .renew(&id, renew_request(Some(deadline), 5 * HOUR), 2_000)
            .unwrap();
        let err = store
            .renew(&id, renew_request(Some(deadline), 9 * HOUR), 2_100)
            .unwrap_err();
        assert!(
            err.to_string().contains(&format!(
                "extend_for_secs: recorded {}, retried {}",
                5 * HOUR,
                9 * HOUR
            )),
            "{err}"
        );
    }

    #[test]
    fn a_renewal_from_a_deadline_that_moved_is_refused_naming_both() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, id, deadline) = stored_parked(tmp.path());
        let err = store
            .renew(&id, renew_request(Some(deadline + 7), 5 * HOUR), 2_000)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains(&format!(
                "retention deadline is unix {deadline}, not the expected unix {}",
                deadline + 7
            )),
            "{text}"
        );
    }

    #[test]
    fn a_renew_without_an_observed_deadline_cannot_claim_a_replay() {
        // Without the deadline the caller read, a retry reads the deadline the
        // first renewal wrote and so looks like a renewal from there.
        let tmp = tempfile::tempdir().unwrap();
        let (store, id, _) = stored_parked(tmp.path());
        store
            .renew(&id, renew_request(None, 5 * HOUR), 2_000)
            .unwrap();
        let retry = store
            .renew(&id, renew_request(None, 5 * HOUR), 2_500)
            .unwrap();
        assert!(!retry.is_replay());
        assert_eq!(retry.record().retain_until_unix, Some(2_500 + 5 * HOUR));
    }

    #[test]
    fn a_store_renewal_of_an_expired_session_refuses_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, id, deadline) = stored_parked(tmp.path());
        let before = record_bytes(tmp.path(), "sess-alpha");
        let err = store
            .renew(&id, renew_request(Some(deadline), 5 * HOUR), deadline + 1)
            .unwrap_err();
        assert!(err.to_string().contains("past its promise"), "{err}");
        assert_eq!(record_bytes(tmp.path(), "sess-alpha"), before);
    }

    #[test]
    fn renew_identity_ignores_the_clock() {
        let parked = parked_at(ParkReason::Operator, Some(HOUR), 1_000);
        let request = renew_request(parked.retain_until_unix, HOUR);
        let a = renew_claim(&parked, &request);
        let mut later = parked.clone();
        later.updated_unix = 99_999;
        assert_eq!(renew_claim(&later, &request), a);
        assert!(a.replayable);
    }

    #[test]
    fn a_record_with_a_deadline_round_trips() {
        let parked = parked_at(ParkReason::Operator, Some(HOUR), 1_000);
        let json = serde_json::to_string(&parked).unwrap();
        assert!(json.contains("\"retain_until_unix\""), "{json}");
        assert_eq!(
            serde_json::from_str::<AgentSessionRecord>(&json).unwrap(),
            parked
        );
    }
}
