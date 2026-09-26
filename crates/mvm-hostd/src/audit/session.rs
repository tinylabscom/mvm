//! Per-session integrity: the `session.sealed` record, the session ledger, and
//! the per-session verdict.
//!
//! A *session* is one admitted run: every chain entry that carries the plan id
//! a `plan.admitted` entry introduced. The chain already makes each entry
//! tamper-evident; what it could not say is whether a session is *whole*. A
//! removed entry breaks the chain, but a session that simply stops — its tail
//! truncated, or its last entries never written — reads as a shorter session,
//! not a damaged one.
//!
//! The seal closes that for a session that reached its end. When a run exits,
//! fails, or is stopped, the host appends one chain-signed `session.sealed`
//! entry stating how many entries the session had, which lines were its first
//! and last, the chain head it was computed against, and an RFC 6962 Merkle
//! root over exactly those lines. [`verify_session`] recomputes every one of
//! those from the chain and reports `VERIFIED`, `MISMATCH` with the reason, or
//! `UNSEALED` when there is no seal to hold the session to.
//!
//! # The ledger is derived, not stored
//!
//! Each seal also names the seal before it (`seal.prev_seal`, the SHA-256 of
//! the previous `session.sealed` line, or zeros for the first). The seals are
//! therefore a hash-chained ledger of sessions that lives *inside* the audit
//! chain: listing sessions is a pass over the verified chain, and there is no
//! second file an attacker could edit, no second key, and no second trust root
//! to keep consistent with the first. The cost of that choice is that a
//! listing reads the segment set; rotation bounds each segment, and the
//! attested-prefix fast path in [`crate::audit::merkle::read_leaves`] keeps the
//! verification part proportional to what was appended since the last
//! published root.
//!
//! # What a seal detects, and what it does not
//!
//! - Any edit, removal, or reordering of an entry: the chain itself refuses,
//!   and the verdict is `MISMATCH` with the chain's own reason.
//! - A seal whose numbers do not describe the chain it sits in — written by a
//!   buggy writer or by anyone holding the host key — is a `MISMATCH` naming
//!   the field (count, sequence, root, head, ledger).
//! - Truncating the log after a session's seal leaves the session `VERIFIED`:
//!   everything it claimed is still there. Truncating *through* the seal makes
//!   the session `UNSEALED`, which a verifier must treat as "cannot vouch".
//! - A session that never sealed (a crash, a host that lost power) is also
//!   `UNSEALED`; the seal cannot tell that from truncation. Neither can it see
//!   a whole session removed from the tail. Both are what an externally
//!   anchored root (`trust audit publish-root` with a witness) is for.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use mvm_contract::merkle::merkle_root;
use mvm_contract::verify::{
    AuditVerifyError, PlanAuditEntry, SignedEnvelope, hash_line, verify_audit_chain_bytes,
};
use mvm_core::plan::ExecutionPlan;
use serde::{Deserialize, Serialize};

use crate::supervisor::audit_file::VerifyError;
use crate::supervisor::audit_set::{SegmentSetError, read_verified_set};

/// The chain event that seals a session.
pub const SESSION_SEALED_EVENT: &str = "session.sealed";

/// The event that opens a session.
pub const SESSION_OPENED_EVENT: &str = "plan.admitted";

/// `prev_seal` of the first seal in a chain.
pub const GENESIS_SEAL: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Every seal label carries this prefix, so a plan's own `audit_labels` —
/// copied into each of its entries — can never collide with a seal field.
const LABEL_PREFIX: &str = "seal.";

/// Why a session was sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealReason {
    /// The workload ran and its exit was reported.
    Exited,
    /// The run failed between admission and a successful boot.
    Failed,
    /// A persistent machine was stopped by the operator.
    Stopped,
}

impl SealReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Exited => "exited",
            Self::Failed => "failed",
            Self::Stopped => "stopped",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "exited" => Some(Self::Exited),
            "failed" => Some(Self::Failed),
            "stopped" => Some(Self::Stopped),
            _ => None,
        }
    }
}

/// The integrity summary a `session.sealed` entry carries.
///
/// Positions are 0-based leaf indices over the tenant's whole segment set, the
/// same indices `trust audit prove` uses. Hashes are lowercase hex SHA-256 of
/// the exact chain lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSeal {
    /// Entries in the session up to the chain head, excluding seals.
    pub event_count: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    /// The last line of the chain when the seal was computed.
    pub head_seq: u64,
    pub first_entry: String,
    pub last_entry: String,
    pub chain_head: String,
    /// RFC 6962 Merkle root over the session's lines, in chain order.
    pub session_root: String,
    /// Hash of the previous `session.sealed` line, or [`GENESIS_SEAL`].
    pub prev_seal: String,
    pub started_at: String,
    pub ended_at: String,
    pub reason: SealReason,
    /// From the session's last `plan.exited`, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<String>,
    /// From the session's last `plan.failed`, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// Digest of the measured compute environment (image, kernel and verity
    /// state) the signed plan recorded, when it recorded one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_environment: Option<String>,
    /// Content root of the session's snapshots. Reserved: no writer sets it
    /// until snapshot lineage is recorded per session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_root: Option<String>,
}

impl SessionSeal {
    /// The seal as chain-entry labels.
    #[must_use]
    pub fn to_labels(&self) -> Vec<(String, String)> {
        let mut labels = vec![
            label("event_count", self.event_count.to_string()),
            label("first_seq", self.first_seq.to_string()),
            label("last_seq", self.last_seq.to_string()),
            label("head_seq", self.head_seq.to_string()),
            label("first_entry", self.first_entry.clone()),
            label("last_entry", self.last_entry.clone()),
            label("chain_head", self.chain_head.clone()),
            label("session_root", self.session_root.clone()),
            label("prev_seal", self.prev_seal.clone()),
            label("started_at", self.started_at.clone()),
            label("ended_at", self.ended_at.clone()),
            label("reason", self.reason.as_str().to_string()),
        ];
        let optional = [
            ("exit_code", &self.exit_code),
            ("error_class", &self.error_class),
            ("compute_environment", &self.compute_environment),
            ("snapshot_root", &self.snapshot_root),
        ];
        for (name, value) in optional {
            if let Some(value) = value {
                labels.push(label(name, value.clone()));
            }
        }
        labels
    }

    /// Read a seal back from an entry's labels. Every required field must be
    /// present and well-formed; a seal missing one is not a seal.
    pub fn from_labels(labels: &BTreeMap<String, String>) -> Result<Self, String> {
        let get = |name: &str| {
            labels
                .get(&format!("{LABEL_PREFIX}{name}"))
                .cloned()
                .ok_or_else(|| format!("seal is missing {LABEL_PREFIX}{name}"))
        };
        let number = |name: &str| {
            get(name)?
                .parse::<u64>()
                .map_err(|_| format!("{LABEL_PREFIX}{name} is not a number"))
        };
        let hash = |name: &str| {
            let value = get(name)?;
            is_hex_hash(&value)
                .then_some(value)
                .ok_or_else(|| format!("{LABEL_PREFIX}{name} is not a SHA-256 hex digest"))
        };
        let optional = |name: &str| labels.get(&format!("{LABEL_PREFIX}{name}")).cloned();
        let reason = get("reason")?;
        Ok(Self {
            event_count: number("event_count")?,
            first_seq: number("first_seq")?,
            last_seq: number("last_seq")?,
            head_seq: number("head_seq")?,
            first_entry: hash("first_entry")?,
            last_entry: hash("last_entry")?,
            chain_head: hash("chain_head")?,
            session_root: hash("session_root")?,
            prev_seal: hash("prev_seal")?,
            started_at: get("started_at")?,
            ended_at: get("ended_at")?,
            reason: SealReason::parse(&reason)
                .ok_or_else(|| format!("{LABEL_PREFIX}reason {reason:?} is not a seal reason"))?,
            exit_code: optional("exit_code"),
            error_class: optional("error_class"),
            compute_environment: optional("compute_environment"),
            snapshot_root: optional("snapshot_root"),
        })
    }
}

fn label(name: &str, value: String) -> (String, String) {
    (format!("{LABEL_PREFIX}{name}"), value)
}

fn is_hex_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// One chain line with its position, hash, and decoded entry.
#[derive(Debug, Clone)]
pub struct Leaf<'a> {
    pub seq: u64,
    pub line: &'a str,
    pub hash: String,
    pub entry: PlanAuditEntry,
}

/// Decode chain lines into [`Leaf`]s. The lines must already have been
/// verified; this only reads them.
pub fn parse_leaves(lines: &[String]) -> Result<Vec<Leaf<'_>>> {
    lines
        .iter()
        .enumerate()
        .map(|(seq, line)| {
            let envelope: SignedEnvelope =
                serde_json::from_str(line).with_context(|| format!("decoding audit line {seq}"))?;
            Ok(Leaf {
                seq: seq as u64,
                line,
                hash: hex(&hash_line(line.as_bytes())),
                entry: envelope.entry,
            })
        })
        .collect()
}

/// The leaves whose entry belongs to `plan_id`, seals included.
///
/// Sealing runs at every exit over the whole segment set, so it must not
/// decode every line: a textual prefilter on the exact serialized field picks
/// the candidates, and each candidate is then decoded and compared properly.
/// The prefilter cannot miss a line — an entry's own `plan_id` serializes to
/// exactly this text — and a line that merely mentions the id elsewhere is
/// dropped by the decoded comparison.
fn leaves_for_plan<'a>(lines: &'a [String], plan_id: &str) -> Result<Vec<Leaf<'a>>> {
    let needle = serde_json::to_string(plan_id).map(|quoted| format!("\"plan_id\":{quoted}"))?;
    let mut leaves = Vec::new();
    for (seq, line) in lines.iter().enumerate() {
        if !line.contains(&needle) {
            continue;
        }
        let envelope: SignedEnvelope =
            serde_json::from_str(line).with_context(|| format!("decoding audit line {seq}"))?;
        if envelope.entry.plan_id == plan_id {
            leaves.push(Leaf {
                seq: seq as u64,
                line,
                hash: hex(&hash_line(line.as_bytes())),
                entry: envelope.entry,
            });
        }
    }
    Ok(leaves)
}

/// Hash of the last `session.sealed` line in `lines` (any session), or
/// [`GENESIS_SEAL`].
fn last_seal_hash(lines: &[String]) -> Result<String> {
    let needle = format!("\"event\":\"{SESSION_SEALED_EVENT}\"");
    for (seq, line) in lines.iter().enumerate().rev() {
        if !line.contains(&needle) {
            continue;
        }
        let envelope: SignedEnvelope =
            serde_json::from_str(line).with_context(|| format!("decoding audit line {seq}"))?;
        if envelope.entry.event == SESSION_SEALED_EVENT {
            return Ok(hex(&hash_line(line.as_bytes())));
        }
    }
    Ok(GENESIS_SEAL.to_string())
}

fn is_seal(leaf: &Leaf<'_>) -> bool {
    leaf.entry.event == SESSION_SEALED_EVENT
}

/// What the caller knows about the session being sealed that the chain does
/// not: why it ended, and the identities the admitted plan recorded.
#[derive(Debug, Clone)]
pub struct SealRequest<'a> {
    pub plan_id: &'a str,
    pub reason: SealReason,
    pub compute_environment: Option<String>,
    pub snapshot_root: Option<String>,
}

/// Compute the seal for `request.plan_id` over the verified chain `lines`.
pub fn compute_seal(lines: &[String], request: &SealRequest<'_>) -> Result<SessionSeal> {
    let leaves = leaves_for_plan(lines, request.plan_id)?;
    let session: Vec<&Leaf<'_>> = leaves.iter().filter(|leaf| !is_seal(leaf)).collect();
    let (Some(first), Some(last), Some(head)) = (session.first(), session.last(), lines.last())
    else {
        anyhow::bail!("no audit entries for session {} to seal", request.plan_id);
    };
    let head_seq = (lines.len() - 1) as u64;
    let chain_head = hex(&hash_line(head.as_bytes()));
    let prev_seal = last_seal_hash(lines)?;
    let last_label = |event: &str, key: &str| {
        session
            .iter()
            .rev()
            .find(|leaf| leaf.entry.event == event)
            .and_then(|leaf| leaf.entry.labels.get(key).cloned())
    };
    let session_lines: Vec<&str> = session.iter().map(|leaf| leaf.line).collect();
    Ok(SessionSeal {
        event_count: session.len() as u64,
        first_seq: first.seq,
        last_seq: last.seq,
        head_seq,
        first_entry: first.hash.clone(),
        last_entry: last.hash.clone(),
        chain_head,
        session_root: hex(&merkle_root(&session_lines)),
        prev_seal,
        started_at: first.entry.timestamp.clone(),
        ended_at: last.entry.timestamp.clone(),
        reason: request.reason,
        exit_code: last_label("plan.exited", "exit_code"),
        error_class: last_label("plan.failed", "error_class"),
        compute_environment: request.compute_environment.clone(),
        snapshot_root: request.snapshot_root.clone(),
    })
}

/// The session's last seal, if it has one and no session entry follows it.
/// A seal that no longer covers the session's end is not current.
pub fn current_seal(lines: &[String], plan_id: &str) -> Result<Option<SessionSeal>> {
    let mut current = None;
    for leaf in &leaves_for_plan(lines, plan_id)? {
        current = if is_seal(leaf) {
            SessionSeal::from_labels(&leaf.entry.labels).ok()
        } else {
            None
        };
    }
    Ok(current)
}

/// The verdict on one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// The chain verifies and every seal describes it exactly.
    Verified,
    /// The chain or a seal disagrees with what is on disk.
    Mismatch,
    /// The chain verifies but the session has no seal, so its completeness
    /// cannot be vouched for.
    Unsealed,
    /// No such session in this chain.
    NotFound,
}

impl Verdict {
    /// Process exit status for a scripted `trust audit verify <session>`.
    #[must_use]
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Verified => 0,
            Self::Mismatch => 1,
            Self::Unsealed => 2,
            Self::NotFound => 3,
        }
    }
}

/// The specific way a session failed to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchReason {
    /// A line does not link to its predecessor, or segments do not join.
    ChainBreak,
    /// A line's signature, or its agreement with its signed bytes, failed.
    Signature,
    /// A line could not be decoded.
    Malformed,
    /// The chain ends partway through a record.
    TruncatedTail,
    /// The seal's entry count is not the session's.
    CountMismatch,
    /// The seal names first/last entries the chain does not have there.
    SequenceMismatch,
    /// The Merkle root over the session's entries differs from the seal's.
    RootMismatch,
    /// The seal's chain head is not a line before it.
    HeadMismatch,
    /// The seal does not link to the previous seal.
    LedgerBreak,
    /// The seal's labels are missing or malformed.
    MalformedSeal,
    /// The chain could not be read.
    Io,
}

/// The full per-session report.
#[derive(Debug, Clone, Serialize)]
pub struct SessionVerification {
    pub plan_id: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<MismatchReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Entries for the session found in the chain, excluding seals.
    pub event_count: u64,
    /// Seals checked, in chain order.
    pub seals: Vec<SealCheck>,
    /// Session entries appended after the last seal's chain head. Not a
    /// mismatch — a late entry cannot hide an earlier removal — but reported,
    /// because the seal does not cover them.
    pub late_entries: u64,
}

/// One seal and where it sits.
#[derive(Debug, Clone, Serialize)]
pub struct SealCheck {
    pub seq: u64,
    pub seal: SessionSeal,
}

impl SessionVerification {
    fn new(plan_id: &str, verdict: Verdict) -> Self {
        Self {
            plan_id: plan_id.to_string(),
            verdict,
            reason: None,
            detail: None,
            event_count: 0,
            seals: Vec::new(),
            late_entries: 0,
        }
    }

    /// The verdict for a session whose chain does not verify: a seal inside
    /// a broken chain vouches for nothing, so the chain's reason is the
    /// session's.
    #[must_use]
    pub fn chain_failure(plan_id: &str, reason: MismatchReason, detail: impl Into<String>) -> Self {
        Self::new(plan_id, Verdict::Mismatch).mismatch(reason, detail)
    }

    fn mismatch(mut self, reason: MismatchReason, detail: impl Into<String>) -> Self {
        self.verdict = Verdict::Mismatch;
        self.reason = Some(reason);
        self.detail = Some(detail.into());
        self
    }
}

/// Check `plan_id`'s seals against chain `lines` that have already verified.
#[must_use]
pub fn verify_session_in_lines(lines: &[String], plan_id: &str) -> SessionVerification {
    let report = SessionVerification::new(plan_id, Verdict::Verified);
    let leaves = match parse_leaves(lines) {
        Ok(leaves) => leaves,
        Err(error) => return report.mismatch(MismatchReason::Malformed, format!("{error:#}")),
    };
    let session: Vec<&Leaf<'_>> = leaves
        .iter()
        .filter(|leaf| leaf.entry.plan_id == plan_id && !is_seal(leaf))
        .collect();
    let seals: Vec<&Leaf<'_>> = leaves
        .iter()
        .filter(|leaf| leaf.entry.plan_id == plan_id && is_seal(leaf))
        .collect();
    let mut report = SessionVerification {
        event_count: session.len() as u64,
        ..report
    };
    if session.is_empty() && seals.is_empty() {
        report.verdict = Verdict::NotFound;
        report.detail = Some(format!("no session {plan_id} in this chain"));
        return report;
    }
    if seals.is_empty() {
        report.verdict = Verdict::Unsealed;
        report.detail = Some(
            "it has no seal: it may still be running, it may have ended without one, or \
             the log may have been truncated through it"
                .to_string(),
        );
        return report;
    }
    let mut covered_through = 0;
    for seal_leaf in &seals {
        let seal = match SessionSeal::from_labels(&seal_leaf.entry.labels) {
            Ok(seal) => seal,
            Err(detail) => {
                return report.mismatch(
                    MismatchReason::MalformedSeal,
                    format!("seal at line {}: {detail}", seal_leaf.seq),
                );
            }
        };
        if let Err((reason, detail)) = check_seal(&leaves, &session, seal_leaf, &seal) {
            return report.mismatch(reason, format!("seal at line {}: {detail}", seal_leaf.seq));
        }
        covered_through = covered_through.max(head_position(&leaves, seal_leaf, &seal));
        report.seals.push(SealCheck {
            seq: seal_leaf.seq,
            seal,
        });
    }
    report.late_entries = session
        .iter()
        .filter(|leaf| leaf.seq > covered_through)
        .count() as u64;
    report
}

/// Where the seal's chain head actually sits, 0 if nowhere (only called after
/// [`check_seal`] accepted it).
fn head_position(leaves: &[Leaf<'_>], seal_leaf: &Leaf<'_>, seal: &SessionSeal) -> u64 {
    leaves[..seal_leaf.seq as usize]
        .iter()
        .rev()
        .find(|leaf| leaf.hash == seal.chain_head)
        .map_or(0, |leaf| leaf.seq)
}

/// Hold one seal to the chain. Positions are compared relative to the chain
/// head rather than absolutely, so a deliberate, recorded prune of older
/// segments — which shifts every index by the same amount — does not read as
/// a mismatch, while any change *within* the session still does.
fn check_seal(
    leaves: &[Leaf<'_>],
    session: &[&Leaf<'_>],
    seal_leaf: &Leaf<'_>,
    seal: &SessionSeal,
) -> Result<(), (MismatchReason, String)> {
    let before = &leaves[..seal_leaf.seq as usize];
    let Some(head) = before
        .iter()
        .rev()
        .find(|leaf| leaf.hash == seal.chain_head)
    else {
        return Err((
            MismatchReason::HeadMismatch,
            format!(
                "its chain head {} is not a line before it",
                short(&seal.chain_head)
            ),
        ));
    };
    let shift = i128::from(head.seq) - i128::from(seal.head_seq);
    let covered: Vec<&&Leaf<'_>> = session.iter().filter(|leaf| leaf.seq <= head.seq).collect();
    if covered.len() as u64 != seal.event_count {
        return Err((
            MismatchReason::CountMismatch,
            format!(
                "it records {} entries, the chain has {} up to its head",
                seal.event_count,
                covered.len()
            ),
        ));
    }
    let (Some(first), Some(last)) = (covered.first(), covered.last()) else {
        return Err((
            MismatchReason::CountMismatch,
            "it seals a session with no entries".to_string(),
        ));
    };
    let at = |recorded: u64| i128::from(recorded) + shift;
    if first.hash != seal.first_entry
        || last.hash != seal.last_entry
        || i128::from(first.seq) != at(seal.first_seq)
        || i128::from(last.seq) != at(seal.last_seq)
    {
        return Err((
            MismatchReason::SequenceMismatch,
            format!(
                "it records entries {}..={} ({}..{}), the chain has {}..={} ({}..{})",
                seal.first_seq,
                seal.last_seq,
                short(&seal.first_entry),
                short(&seal.last_entry),
                first.seq,
                last.seq,
                short(&first.hash),
                short(&last.hash)
            ),
        ));
    }
    let lines: Vec<&str> = covered.iter().map(|leaf| leaf.line).collect();
    let root = hex(&merkle_root(&lines));
    if root != seal.session_root {
        return Err((
            MismatchReason::RootMismatch,
            format!(
                "it records root {}, the session's entries hash to {}",
                short(&seal.session_root),
                short(&root)
            ),
        ));
    }
    let prev_seal = before
        .iter()
        .rev()
        .find(|leaf| is_seal(leaf))
        .map_or(GENESIS_SEAL, |leaf| leaf.hash.as_str());
    if prev_seal != seal.prev_seal {
        return Err((
            MismatchReason::LedgerBreak,
            format!(
                "it links to seal {}, the previous seal in the chain is {}",
                short(&seal.prev_seal),
                short(prev_seal)
            ),
        ));
    }
    Ok(())
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

/// Verify `plan_id` from the genesis anchor: the whole segment set first, then
/// its seals. A chain that does not verify yields `MISMATCH` with the chain's
/// own reason — a seal inside a broken chain vouches for nothing.
pub fn verify_session(
    audit_dir: &Path,
    tenant: &str,
    plan_id: &str,
    vk: &VerifyingKey,
) -> SessionVerification {
    match read_lines_from_genesis(audit_dir, tenant, vk) {
        Ok(lines) => verify_session_in_lines(&lines, plan_id),
        Err((reason, detail)) => SessionVerification::chain_failure(plan_id, reason, detail),
    }
}

/// Every line of `tenant`'s chain, verified from genesis across the segment
/// set, or the classified reason it does not verify.
pub fn read_lines_from_genesis(
    audit_dir: &Path,
    tenant: &str,
    vk: &VerifyingKey,
) -> Result<Vec<String>, (MismatchReason, String)> {
    match read_verified_set(audit_dir, tenant, vk) {
        Ok(segments) => Ok(segments
            .iter()
            .flat_map(|s| s.lines().into_iter().map(str::to_string))
            .collect()),
        Err(SegmentSetError::NoChain { .. }) => {
            let path = crate::audit::emitter::audit_path_for_tenant(audit_dir, tenant);
            let content = std::fs::read_to_string(&path).map_err(|e| {
                (
                    MismatchReason::Io,
                    format!("reading audit chain {}: {e}", path.display()),
                )
            })?;
            verify_audit_chain_bytes(&content, vk)
                .map_err(|e| (classify_contract(&e), e.to_string()))?;
            Ok(content
                .lines()
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect())
        }
        Err(error) => Err((classify_set(&error), error.to_string())),
    }
}

fn classify_set(error: &SegmentSetError) -> MismatchReason {
    match error {
        SegmentSetError::Io(_) | SegmentSetError::NoChain { .. } => MismatchReason::Io,
        SegmentSetError::Segment { source, .. } => classify_file(source),
        SegmentSetError::MissingSegment { .. }
        | SegmentSetError::Spliced { .. }
        | SegmentSetError::EntryCountMismatch { .. }
        | SegmentSetError::Unsealed { .. }
        | SegmentSetError::MissingHandoff { .. }
        | SegmentSetError::UncorroboratedPrune { .. }
        | SegmentSetError::TruncatedFront { .. } => MismatchReason::ChainBreak,
    }
}

fn classify_file(error: &VerifyError) -> MismatchReason {
    match error {
        VerifyError::Io(_) => MismatchReason::Io,
        VerifyError::Malformed { .. } => MismatchReason::Malformed,
        VerifyError::PrevHashMismatch { .. } => MismatchReason::ChainBreak,
        VerifyError::SignatureInvalid { .. } | VerifyError::EntryCanonicalMismatch { .. } => {
            MismatchReason::Signature
        }
        VerifyError::TruncatedTail { .. } => MismatchReason::TruncatedTail,
    }
}

fn classify_contract(error: &AuditVerifyError) -> MismatchReason {
    match error {
        AuditVerifyError::Malformed { .. } => MismatchReason::Malformed,
        AuditVerifyError::PrevHashMismatch { .. } => MismatchReason::ChainBreak,
        AuditVerifyError::SignatureInvalid { .. }
        | AuditVerifyError::EntryCanonicalMismatch { .. } => MismatchReason::Signature,
        AuditVerifyError::KeyDecode(_) => MismatchReason::Io,
    }
}

/// One session in the ledger.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    pub plan_id: String,
    pub started_at: String,
    pub ended_at: String,
    pub event_count: u64,
    pub image_name: String,
    pub sealed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<SessionSeal>,
}

/// The ledger's own linkage: whether every seal names the one before it.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerCheck {
    pub seals: u64,
    pub intact: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Time bounds for listing and showing. A session is in range when any part
/// of it is; an event when its own timestamp is.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeRange {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl TimeRange {
    fn overlaps(&self, start: &str, end: &str) -> bool {
        let (Some(start), Some(end)) = (parse_ts(start), parse_ts(end)) else {
            return true;
        };
        self.since.is_none_or(|since| end >= since) && self.until.is_none_or(|until| start <= until)
    }

    fn contains(&self, at: &str) -> bool {
        self.overlaps(at, at)
    }
}

fn parse_ts(ts: &str) -> Option<DateTime<Utc>> {
    mvm_core::util::time::parse_iso8601(ts)
}

/// Every session in chain `lines`, in the order they were admitted, with the
/// ledger's linkage check. Sessions are plan ids that were admitted or sealed;
/// host-level entries under no plan are not sessions.
pub fn list_sessions(
    lines: &[String],
    range: TimeRange,
) -> Result<(Vec<SessionSummary>, LedgerCheck)> {
    let leaves = parse_leaves(lines)?;
    let mut order: Vec<String> = Vec::new();
    let mut sessions: BTreeMap<String, SessionSummary> = BTreeMap::new();
    for leaf in &leaves {
        let opens = leaf.entry.event == SESSION_OPENED_EVENT || is_seal(leaf);
        let plan_id = &leaf.entry.plan_id;
        if !sessions.contains_key(plan_id) {
            if !opens {
                continue;
            }
            order.push(plan_id.clone());
            sessions.insert(
                plan_id.clone(),
                SessionSummary {
                    plan_id: plan_id.clone(),
                    started_at: leaf.entry.timestamp.clone(),
                    ended_at: leaf.entry.timestamp.clone(),
                    event_count: 0,
                    image_name: leaf.entry.image_name.clone(),
                    sealed: false,
                    seal_seq: None,
                    seal: None,
                },
            );
        }
        let summary = sessions
            .get_mut(plan_id)
            .expect("inserted above when absent");
        if is_seal(leaf) {
            summary.sealed = true;
            summary.seal_seq = Some(leaf.seq);
            summary.seal = SessionSeal::from_labels(&leaf.entry.labels).ok();
        } else {
            summary.event_count += 1;
            summary.ended_at = leaf.entry.timestamp.clone();
        }
    }
    let ledger = check_ledger(&leaves);
    let listed = order
        .into_iter()
        .filter_map(|plan_id| sessions.remove(&plan_id))
        .filter(|s| range.overlaps(&s.started_at, &s.ended_at))
        .collect();
    Ok((listed, ledger))
}

fn check_ledger(leaves: &[Leaf<'_>]) -> LedgerCheck {
    let mut previous = GENESIS_SEAL.to_string();
    let mut seals = 0;
    for leaf in leaves.iter().filter(|leaf| is_seal(leaf)) {
        seals += 1;
        let linked = SessionSeal::from_labels(&leaf.entry.labels).map(|seal| seal.prev_seal);
        match linked {
            Ok(prev) if prev == previous => previous.clone_from(&leaf.hash),
            Ok(prev) => {
                return LedgerCheck {
                    seals,
                    intact: false,
                    detail: Some(format!(
                        "seal at line {} links to {}, the previous seal is {}",
                        leaf.seq,
                        short(&prev),
                        short(&previous)
                    )),
                };
            }
            Err(detail) => {
                return LedgerCheck {
                    seals,
                    intact: false,
                    detail: Some(format!("seal at line {}: {detail}", leaf.seq)),
                };
            }
        }
    }
    LedgerCheck {
        seals,
        intact: true,
        detail: None,
    }
}

/// One event of a session, as `trust audit show` prints it.
#[derive(Debug, Clone, Serialize)]
pub struct SessionEvent {
    pub seq: u64,
    pub envelope: SignedEnvelope,
}

/// Filters for a session's events.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Shell-style glob over the event name (`plan.*`, `*.sealed`).
    pub kind: Option<String>,
    pub range: TimeRange,
}

/// The events of `plan_id` in chain `lines` that pass `filter`, seals included.
pub fn session_events(
    lines: &[String],
    plan_id: &str,
    filter: &EventFilter,
) -> Result<Vec<SessionEvent>> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(seq, line)| {
            let envelope: SignedEnvelope = match serde_json::from_str(line) {
                Ok(envelope) => envelope,
                Err(error) => {
                    return Some(Err(anyhow::anyhow!("decoding audit line {seq}: {error}")));
                }
            };
            let entry = &envelope.entry;
            let keep = entry.plan_id == plan_id
                && filter
                    .kind
                    .as_deref()
                    .is_none_or(|kind| mvm_core::util::glob::glob_match(kind, &entry.event))
                && filter.range.contains(&entry.timestamp);
            keep.then_some(Ok(SessionEvent {
                seq: seq as u64,
                envelope,
            }))
        })
        .collect()
}

/// Resolve what an operator typed to one session's plan id: the full id, the
/// id without its `sha256:` prefix, or a unique prefix of at least eight hex
/// characters. Ambiguity is refused rather than guessed.
pub fn resolve_session(lines: &[String], selector: &str) -> Result<String> {
    let (sessions, _) = list_sessions(lines, TimeRange::default())?;
    let wanted = selector.strip_prefix("sha256:").unwrap_or(selector);
    if let Some(exact) = sessions.iter().find(|s| s.plan_id == selector) {
        return Ok(exact.plan_id.clone());
    }
    if wanted.len() < 8 {
        anyhow::bail!(
            "session selector {selector:?} is too short; give the plan id or at least 8 of its \
             hex characters"
        );
    }
    let matches: Vec<&SessionSummary> = sessions
        .iter()
        .filter(|s| {
            s.plan_id
                .strip_prefix("sha256:")
                .unwrap_or(&s.plan_id)
                .starts_with(wanted)
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(one.plan_id.clone()),
        [] => anyhow::bail!("no session matches {selector:?}"),
        many => anyhow::bail!(
            "{selector:?} matches {} sessions ({}); give more of the plan id",
            many.len(),
            many.iter()
                .map(|s| s.plan_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

impl crate::audit::emitter::AuditEmitter {
    /// Seal `plan`'s session: compute its integrity summary over the verified
    /// chain and append it as a chain-signed `session.sealed` entry.
    ///
    /// Call at the session's end — exit, failure, or stop — and before the
    /// closing root is published, so that root covers the seal. The seal is a
    /// sync barrier like every event not listed as deferrable: it is on disk
    /// before this returns. See [`crate::audit::session`] for what it lets a
    /// verifier detect.
    pub fn seal_session(&self, plan: &ExecutionPlan, reason: SealReason) -> Result<SessionSeal> {
        let tenant = &plan.tenant.0;
        let lines =
            crate::audit::merkle::read_leaves(self.audit_dir(), tenant, &self.verifying_key())
                .context("reading the verified chain to seal the session")?;
        // Idempotent: a session already sealed with nothing after its seal is
        // left alone, so two teardown paths reaching the same run write one
        // seal between them.
        if let Some(existing) = current_seal(&lines, &plan.plan_id.0)? {
            return Ok(existing);
        }
        let seal = compute_seal(
            &lines,
            &SealRequest {
                plan_id: &plan.plan_id.0,
                reason,
                compute_environment: compute_environment_digest(plan),
                snapshot_root: None,
            },
        )?;
        self.emit(plan, SESSION_SEALED_EVENT, seal.to_labels())?;
        Ok(seal)
    }
}

/// The measured compute-environment identity the signed plan recorded, if it
/// recorded one.
fn compute_environment_digest(plan: &ExecutionPlan) -> Option<String> {
    plan.asset_identities
        .iter()
        .find(|asset| matches!(asset.kind, mvm_core::plan::AssetKind::ComputeEnvironment))
        .map(|asset| asset.digest.clone())
}

#[cfg(test)]
mod tests;

/// The claim-8 witnesses for sessions. Kept beside the verifier they guard,
/// so the mutation lane that breaks this file on purpose runs them.
#[cfg(test)]
mod witnesses {
    use super::tests::{Chain, plan, request};
    use super::*;

    /// A seal the host key really signed, but whose numbers are wrong — what a
    /// buggy writer, or anyone holding the key, would produce. Each field is
    /// checked on its own.
    #[test]
    fn a_correctly_signed_seal_that_lies_is_refused_field_by_field() {
        type Lie = fn(&mut SessionSeal);
        let cases: [(Lie, MismatchReason); 6] = [
            (|s| s.event_count += 1, MismatchReason::CountMismatch),
            (|s| s.first_seq += 1, MismatchReason::SequenceMismatch),
            (
                |s| s.last_entry = "ef".repeat(32),
                MismatchReason::SequenceMismatch,
            ),
            (
                |s| s.session_root = GENESIS_SEAL.to_string(),
                MismatchReason::RootMismatch,
            ),
            (
                |s| s.chain_head = "ab".repeat(32),
                MismatchReason::HeadMismatch,
            ),
            (
                |s| s.prev_seal = "cd".repeat(32),
                MismatchReason::LedgerBreak,
            ),
        ];
        for (lie, expected) in cases {
            let chain = Chain::new();
            let p = plan("sha256:aaaa1111");
            chain.emitter.emit_admitted(&p, "host:test").unwrap();
            chain.emitter.emit_exited(&p, 0, "mock").unwrap();
            let mut seal =
                compute_seal(&chain.lines(), &request(&p.plan_id.0, SealReason::Exited)).unwrap();
            lie(&mut seal);
            chain.append_seal(&p, seal.to_labels());

            let report = chain.verify(&p.plan_id.0);
            assert_eq!(report.verdict, Verdict::Mismatch, "{expected:?}");
            assert_eq!(report.reason, Some(expected), "{report:?}");
        }
    }

    #[test]
    fn truncating_through_the_seal_leaves_the_session_unsealed() {
        let chain = Chain::new();
        let p = plan("sha256:aaaa1111");
        chain.run_and_seal(&p, 0);
        let mut lines = chain.lines();
        lines.truncate(chain.line_index(&p.plan_id.0, SESSION_SEALED_EVENT));
        chain.write_lines(&lines);

        let report = chain.verify(&p.plan_id.0);
        assert_eq!(report.verdict, Verdict::Unsealed, "{report:?}");
        assert_eq!(report.verdict.exit_code(), 2);
    }
}
