//! Session queries over a verified tenant chain. Raw chain parsing and seal
//! validation remain authoritative in hostd; callers cannot bypass verification.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mvm_hostd::audit::session as engine;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::LocalAuditReader;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SealReason {
    Exited,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionSeal {
    pub event_count: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub head_seq: u64,
    pub first_entry: String,
    pub last_entry: String,
    pub chain_head: String,
    pub session_root: String,
    pub prev_seal: String,
    pub started_at: String,
    pub ended_at: String,
    pub reason: SealReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct LedgerCheck {
    pub seals: u64,
    pub intact: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Verified,
    Mismatch,
    Unsealed,
    NotFound,
}

impl Verdict {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Verified => 0,
            Self::Mismatch => 1,
            Self::Unsealed => 2,
            Self::NotFound => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum MismatchReason {
    ChainBreak,
    Signature,
    Malformed,
    TruncatedTail,
    CountMismatch,
    SequenceMismatch,
    RootMismatch,
    EnvironmentMismatch,
    SnapshotRootMismatch,
    HeadMismatch,
    LedgerBreak,
    MalformedSeal,
    Io,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SealCheck {
    pub seq: u64,
    pub seal: SessionSeal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionVerification {
    pub plan_id: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<MismatchReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub event_count: u64,
    pub seals: Vec<SealCheck>,
    pub late_entries: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct TimeRange {
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub since: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub until: Option<DateTime<Utc>>,
}

impl From<TimeRange> for engine::TimeRange {
    fn from(range: TimeRange) -> Self {
        Self {
            since: range.since,
            until: range.until,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct EventFilter {
    pub kind: Option<String>,
    #[serde(default)]
    pub range: TimeRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionEvent {
    pub seq: u64,
    pub envelope: SessionEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionEnvelope {
    pub entry: SessionEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical: Option<String>,
    pub prev_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionEntry {
    pub timestamp: String,
    pub tenant: String,
    pub plan_id: String,
    pub plan_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<u32>,
    pub image_name: String,
    pub image_sha256: String,
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_commitment: Option<mvm_contract::plan::CallerCommitment>,
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
}

/// Immutable verified chain. There is deliberately no constructor from raw lines.
pub struct VerifiedSessions {
    lines: Vec<String>,
}

impl VerifiedSessions {
    pub fn list(&self, range: TimeRange) -> Result<(Vec<SessionSummary>, LedgerCheck)> {
        let (sessions, ledger) = engine::list_sessions(&self.lines, range.into())?;
        Ok((report(sessions)?, report(ledger)?))
    }

    pub fn resolve(&self, selector: &str) -> Result<String> {
        resolve_or_exact(&self.lines, selector)
    }

    pub fn events(&self, selector: &str, filter: &EventFilter) -> Result<Vec<SessionEvent>> {
        let plan_id = self.resolve(selector)?;
        report(engine::session_events(
            &self.lines,
            &plan_id,
            &engine::EventFilter {
                kind: filter.kind.clone(),
                range: filter.range.into(),
            },
        )?)
    }

    /// The exact verified bytes for human rendering, indexed by event sequence.
    pub fn line(&self, seq: u64) -> Option<&str> {
        usize::try_from(seq)
            .ok()
            .and_then(|seq| self.lines.get(seq))
            .map(String::as_str)
    }
}

impl LocalAuditReader {
    /// Verify from genesis before exposing any session listing or selector.
    pub fn sessions(&self, tenant: &str) -> Result<Option<VerifiedSessions>> {
        if !has_chain(&self.audit_dir, tenant)? {
            return Ok(None);
        }
        let lines =
            mvm_hostd::audit::merkle::read_leaves(&self.audit_dir, tenant, &self.verifying_key)
                .with_context(|| {
                    format!(
                        "the audit chain for tenant '{tenant}' does not verify; run \
                         `mvmctl trust audit verify --tenant {tenant}` for the reason"
                    )
                })?;
        Ok(Some(VerifiedSessions { lines }))
    }

    pub fn verify_session(&self, tenant: &str, selector: &str) -> Result<SessionVerification> {
        if !has_chain(&self.audit_dir, tenant)? {
            let mut result = absent(selector)?;
            result.detail = Some(format!("no audit chain for tenant '{tenant}'"));
            return Ok(result);
        }
        match engine::read_lines_from_genesis(&self.audit_dir, tenant, &self.verifying_key) {
            Ok(lines) => {
                let plan_id =
                    resolve_or_exact(&lines, selector).unwrap_or_else(|_| selector.to_owned());
                report(engine::verify_session_in_lines(&lines, &plan_id))
            }
            Err((reason, detail)) => report(engine::SessionVerification::chain_failure(
                selector, reason, detail,
            )),
        }
    }
}

/// Do not mint a signer on a pristine host just to list an absent chain.
pub fn open_default(tenant: &str) -> Result<Option<LocalAuditReader>> {
    let dir = mvm_hostd::audit::emitter::default_audit_dir()?;
    if !has_chain(&dir, tenant)? {
        return Ok(None);
    }
    Ok(Some(LocalAuditReader::open_default()?))
}

pub fn absent(selector: &str) -> Result<SessionVerification> {
    report(engine::verify_session_in_lines(&[], selector))
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    #[serde(default = "default_tenant")]
    pub tenant: String,
    #[serde(default)]
    pub range: TimeRange,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ShowRequest {
    #[serde(default = "default_tenant")]
    pub tenant: String,
    pub selector: String,
    #[serde(default)]
    pub filter: EventFilter,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    #[serde(default = "default_tenant")]
    pub tenant: String,
    pub selector: String,
}

fn default_tenant() -> String {
    "local".into()
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ListReport {
    pub sessions: Vec<SessionSummary>,
    /// None means no chain exists, not a verified empty ledger.
    pub ledger: Option<LedgerCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ShowReport {
    pub plan_id: String,
    pub events: Vec<SessionEvent>,
}

pub fn list(request: &ListRequest) -> Result<ListReport> {
    let sessions = open_default(&request.tenant)?
        .map(|reader| reader.sessions(&request.tenant))
        .transpose()?
        .flatten();
    match sessions {
        Some(sessions) => {
            let (sessions, ledger) = sessions.list(request.range)?;
            Ok(ListReport {
                sessions,
                ledger: Some(ledger),
            })
        }
        None => Ok(ListReport {
            sessions: Vec::new(),
            ledger: None,
        }),
    }
}

pub fn show(request: &ShowRequest) -> Result<ShowReport> {
    let reader = open_default(&request.tenant)?.context("no audit chain for tenant")?;
    let sessions = reader
        .sessions(&request.tenant)?
        .context("no audit chain for tenant")?;
    Ok(ShowReport {
        plan_id: sessions.resolve(&request.selector)?,
        events: sessions.events(&request.selector, &request.filter)?,
    })
}

pub fn verify(request: &VerifyRequest) -> Result<SessionVerification> {
    match open_default(&request.tenant)? {
        Some(reader) => reader.verify_session(&request.tenant, &request.selector),
        None => absent(&request.selector),
    }
}

fn has_chain(dir: &std::path::Path, tenant: &str) -> Result<bool> {
    Ok(!super::discover_source_ids(dir, Some(tenant))?.is_empty())
}

fn resolve_or_exact(lines: &[String], selector: &str) -> Result<String> {
    match engine::resolve_session(lines, selector) {
        Ok(plan_id) => Ok(plan_id),
        Err(error) => {
            // Host-level entries need not belong to an admitted session. Match
            // their decoded identity, never a substring in arbitrary labels.
            if engine::parse_leaves(lines)?
                .iter()
                .any(|leaf| leaf.entry.plan_id == selector)
            {
                Ok(selector.to_owned())
            } else {
                Err(error)
            }
        }
    }
}

// Own the stable public report schema without exposing hostd implementation
// types. The authoritative engine's serialized report is the compatibility
// boundary; no untyped Value or unchecked hostd handle crosses it.
fn report<T: DeserializeOwned>(value: impl Serialize) -> Result<T> {
    Ok(serde_json::from_slice(&serde_json::to_vec(&value)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const PLAN: &str = "sha256:0123456789abcdef";

    fn entry(event: &str) -> mvm_contract::verify::PlanAuditEntry {
        mvm_contract::verify::PlanAuditEntry {
            timestamp: "2026-08-01T00:00:00Z".into(),
            tenant: "local".into(),
            plan_id: PLAN.into(),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "worker".into(),
            image_sha256: "a".repeat(64),
            caller_commitment: None,
            event: event.into(),
            labels: Default::default(),
        }
    }

    fn signed_chain(sealed: bool, lying_seal: bool) -> (tempfile::TempDir, LocalAuditReader) {
        use mvm_contract::verify::{hash_line, seal};
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let first =
            serde_json::to_string(&seal(entry("plan.admitted"), [0; 32], &key).unwrap()).unwrap();
        let mut lines = vec![first];
        if sealed {
            let mut summary = engine::compute_seal(
                &lines,
                &engine::SealRequest {
                    plan_id: PLAN,
                    reason: engine::SealReason::Stopped,
                    image_sha256: Some("a".repeat(64)),
                    kernel_sha256: None,
                    compute_environment: Some("a".repeat(64)),
                },
            )
            .unwrap();
            if lying_seal {
                summary.event_count += 1;
            }
            let mut last = entry("session.sealed");
            last.labels = summary.to_labels().into_iter().collect();
            let previous = hash_line(lines[0].as_bytes());
            lines.push(serde_json::to_string(&seal(last, previous, &key).unwrap()).unwrap());
        }
        std::fs::write(
            dir.path().join("local.jsonl"),
            format!("{}\n", lines.join("\n")),
        )
        .unwrap();
        let reader = LocalAuditReader::new(dir.path(), key.verifying_key());
        (dir, reader)
    }

    #[test]
    fn signed_sessions_list_show_and_verify_through_the_facade() {
        let (_dir, reader) = signed_chain(true, false);
        let sessions = reader.sessions("local").unwrap().unwrap();
        let (listed, ledger) = sessions.list(TimeRange::default()).unwrap();
        assert!(ledger.intact);
        assert_eq!(listed.len(), 1);
        assert!(listed[0].sealed);
        assert_eq!(sessions.resolve("01234567").unwrap(), PLAN);
        let events = sessions
            .events("01234567", &EventFilter::default())
            .unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            sessions
                .line(events[0].seq)
                .unwrap()
                .contains("plan.admitted")
        );
        assert_eq!(
            reader.verify_session("local", "01234567").unwrap().verdict,
            Verdict::Verified
        );
    }

    #[test]
    fn unsealed_and_signed_but_false_seal_are_distinct() {
        let (_dir, reader) = signed_chain(false, false);
        assert_eq!(
            reader.verify_session("local", PLAN).unwrap().verdict,
            Verdict::Unsealed
        );
        let (_dir, reader) = signed_chain(true, true);
        let report = reader.verify_session("local", PLAN).unwrap();
        assert_eq!(report.verdict, Verdict::Mismatch);
        assert_eq!(report.reason, Some(MismatchReason::CountMismatch));
    }

    #[test]
    fn tampered_signed_chain_and_wrong_trusted_key_fail_closed() {
        let (dir, reader) = signed_chain(true, false);
        let wrong = SigningKey::from_bytes(&[8; 32]);
        let wrong_reader = LocalAuditReader::new(dir.path(), wrong.verifying_key());
        assert!(wrong_reader.sessions("local").is_err());
        assert_eq!(
            wrong_reader.verify_session("local", PLAN).unwrap().verdict,
            Verdict::Mismatch
        );
        let path = dir.path().join("local.jsonl");
        let original = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, original.replace("\"worker\"", "\"tampered\"")).unwrap();
        assert!(reader.sessions("local").is_err());
        assert_eq!(
            reader.verify_session("local", PLAN).unwrap().verdict,
            Verdict::Mismatch
        );
    }

    #[test]
    fn absent_session_is_not_found() {
        let report = absent("sha256:ab").unwrap();
        assert_eq!(report.verdict, Verdict::NotFound);
        assert_eq!(report.verdict.exit_code(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn default_session_reader_rejects_a_wrong_length_host_key() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        std::fs::create_dir(home.path().join("audit")).unwrap();
        std::fs::write(home.path().join("audit/local.jsonl"), "").unwrap();
        let keys = home.path().join("keys");
        std::fs::create_dir(&keys).unwrap();
        let key = keys.join("host-signer.ed25519");
        std::fs::write(&key, [1; 31]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = open_default("local").err().expect("invalid key must fail");
        assert!(format!("{error:#}").contains("32"), "{error:#}");
        assert_eq!(std::fs::read(&key).unwrap().len(), 31);
    }

    #[test]
    fn invalid_selector_is_refused() {
        let sessions = VerifiedSessions { lines: Vec::new() };
        assert!(
            sessions
                .resolve("ab")
                .unwrap_err()
                .to_string()
                .contains("too short")
        );
        assert!(
            sessions
                .events("no-match", &EventFilter::default())
                .is_err()
        );
    }

    #[test]
    fn malformed_chain_is_never_available_for_listing_or_selectors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("local.jsonl"), b"{\"tampered\":true}\n").unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let reader = LocalAuditReader::new(dir.path(), key.verifying_key());
        assert!(reader.sessions("local").is_err());
        assert_eq!(
            reader.verify_session("local", "abcdefgh").unwrap().verdict,
            Verdict::Mismatch
        );
    }
}
