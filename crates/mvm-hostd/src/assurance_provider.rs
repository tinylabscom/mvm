//! Durable controller boundary for admitted assurance provider requests.
//!
//! The sibling controller may retry a request after either process crashes.
//! This wrapper commits the request identity before it calls the admitted
//! campaign runner and commits the typed terminal response before it returns
//! bytes to the controller stream. A matching completed retry receives the
//! same response; running or failed work is never executed a second time.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use mvm_contract::assurance::{
    AssuranceId, AssuranceSessionRequest, CAMPAIGN_PROVIDER_RESPONSE_SCHEMA,
    CampaignProviderRequest, CampaignProviderResponse, EvidenceRef, MAX_CAMPAIGN_PROVIDER_BYTES,
    OperatorSessionBundle, Sha256Digest, TRIAL_EVIDENCE_SCHEMA, TrialEvidenceRecord,
};
use mvm_contract::protocol::extension_controller::DEFAULT_MAX_PAYLOAD_BYTES;
use sha2::{Digest, Sha256};

use crate::extension_controller::ExtensionControllerHandler;

const PROVIDER_DESCRIPTOR_SCHEMA: &str = "mvm.extension.descriptor/v1";
const PROVIDER_CAPABILITY: &str = "mvm.boundary.campaign.v1";
const JOURNAL_SCHEMA: &str = "mvm.assurance.provider-journal/v1";
const MAX_JOURNAL_BYTES: u64 = 2 * 1024 * 1024;

/// Host-owned output of one admitted campaign run.
///
/// There is deliberately no `certifying` field. The controller derives that
/// bit from the evidence identities and verification facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedCampaignOutput {
    pub evidence: Vec<TrialEvidenceRecord>,
    pub missing_brokers: Vec<String>,
}

impl AdmittedCampaignOutput {
    #[must_use]
    pub fn evaluated(evidence: Vec<TrialEvidenceRecord>) -> Self {
        Self {
            evidence,
            missing_brokers: Vec::new(),
        }
    }
}

/// Narrow production seam implemented by the admission/boot controller.
///
/// Implementations receive the strict counterparty request and the complete
/// operator declarations after every overlapping identity has joined. They do
/// not receive arbitrary commands or a generic MVM client.
pub trait AdmittedCampaignRunner: Send + Sync {
    fn run(
        &self,
        request: &CampaignProviderRequest,
        sessions: &[AssuranceSessionRequest],
    ) -> Result<AdmittedCampaignOutput>;
}

/// Generic `MVEX` campaign handler with durable terminal replay.
pub struct CampaignProviderController<R> {
    provider_id: AssuranceId,
    version: String,
    journal_root: PathBuf,
    operator_sessions: Mutex<Option<OperatorSessionBundle>>,
    run_gate: Mutex<()>,
    runner: R,
}

impl<R> CampaignProviderController<R> {
    /// Construct a provider around an admitted runner and a private state root.
    pub fn new(
        provider_id: AssuranceId,
        version: impl Into<String>,
        journal_root: impl Into<PathBuf>,
        runner: R,
    ) -> Self {
        Self {
            provider_id,
            version: version.into(),
            journal_root: journal_root.into(),
            operator_sessions: Mutex::new(None),
            run_gate: Mutex::new(()),
            runner,
        }
    }
}

/// Serve one generic admitted-provider process.
///
/// The runner is supplied by the host admission orchestrator. This helper
/// owns only the process boundary and durable controller; it does not select
/// a provider, load ambient configuration, or expose a general command path.
/// A concrete provider executable can therefore inject its typed runner while
/// reusing the exact same MVEX and replay implementation.
pub fn serve_provider<R: AdmittedCampaignRunner>(
    provider_id: AssuranceId,
    version: impl Into<String>,
    journal_root: impl Into<PathBuf>,
    runner: R,
    reader: &mut impl Read,
    writer: &mut impl std::io::Write,
) -> Result<()> {
    let journal_root = journal_root.into();
    prepare_provider_state_root(&journal_root)?;
    let controller = CampaignProviderController::new(provider_id, version, journal_root, runner);
    crate::extension_controller::serve_extension_controller(
        reader,
        writer,
        DEFAULT_MAX_PAYLOAD_BYTES,
        &controller,
    )
}

/// Create and validate the explicit private provider state root.
///
/// Concrete provider binaries call this before reading fixed configuration
/// beneath the root; [`serve_provider`] repeats it before opening journals.
pub fn prepare_provider_state_root(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("assurance provider journal root must be an absolute path");
    }
    std::fs::create_dir_all(path)
        .with_context(|| format!("creating provider journal root {}", path.display()))?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting provider journal root {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("assurance provider journal root must be a non-symlink directory");
    }
    set_private_directory(path)
}

impl<R: AdmittedCampaignRunner> ExtensionControllerHandler for CampaignProviderController<R> {
    fn descriptor(&self) -> Result<Vec<u8>> {
        #[derive(serde::Serialize)]
        struct Descriptor<'a> {
            schema: &'static str,
            id: &'a AssuranceId,
            version: &'a str,
            class: &'static str,
            provides: [&'static str; 1],
            authority: &'static str,
        }

        if self.version.is_empty()
            || self.version.len() > 128
            || self.version.chars().any(char::is_control)
        {
            anyhow::bail!("assurance provider version is outside its bound");
        }
        serde_json::to_vec(&Descriptor {
            schema: PROVIDER_DESCRIPTOR_SCHEMA,
            id: &self.provider_id,
            version: &self.version,
            class: "admitted_campaign_controller",
            provides: [PROVIDER_CAPABILITY],
            authority: "typed_bounded_only",
        })
        .context("encoding assurance provider descriptor")
    }

    fn start(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let request = CampaignProviderRequest::parse_json(payload)
            .context("validating assurance campaign provider request")?;
        let bundle = self
            .operator_sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("operator session state is unavailable"))?
            .clone()
            .ok_or_else(|| anyhow::anyhow!("operator session bundle was not opened"))?;
        let sessions = request
            .join_session_bundle(bundle.clone())
            .context("joining campaigns to operator session declarations")?;
        let _run_lease = self.run_gate.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => {
                anyhow::anyhow!("assurance provider concurrent-session budget is exhausted")
            }
            std::sync::TryLockError::Poisoned(_) => {
                anyhow::anyhow!("assurance provider concurrency gate is unavailable")
            }
        })?;
        let request_digest = joined_request_digest(payload, &bundle)?;
        let path = self.journal_path(&request.request_id);
        match claim_request(&path, &request.request_id, &request_digest)? {
            Claim::Fresh => {}
            Claim::Completed(response) => return response.to_json().map_err(Into::into),
            Claim::Running => {
                anyhow::bail!(
                    "assurance campaign was interrupted after durable acceptance; refusing replay"
                )
            }
            Claim::Failed => {
                anyhow::bail!("assurance campaign previously failed; refusing replay")
            }
        }

        let output = match self.runner.run(&request, &sessions) {
            Ok(output) => output,
            Err(error) => {
                persist_terminal(
                    &path,
                    ProviderJournal::failed(request.request_id, request_digest),
                )
                .context("committing failed assurance provider request")?;
                return Err(error.context("admitted assurance campaign failed"));
            }
        };
        let response = assemble_response(&request, output)?;
        persist_terminal(
            &path,
            ProviderJournal::completed(
                request.request_id.clone(),
                request_digest,
                response.clone(),
            ),
        )
        .context("committing assurance provider response")?;
        response.to_json().map_err(Into::into)
    }

    fn open_session(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let bundle = OperatorSessionBundle::parse_json(payload)
            .context("validating operator session bundle")?;
        let mut current = self
            .operator_sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("operator session state is unavailable"))?;
        match current.as_ref() {
            Some(existing) if existing == &bundle => {}
            Some(_) => {
                anyhow::bail!("controller already holds a different operator session bundle")
            }
            None => *current = Some(bundle.clone()),
        }
        serde_json::to_vec(&OperatorSessionAccepted {
            schema: "mvm.assurance.operator-session-accepted/v1",
            request_id: &bundle.request_id,
            session_count: bundle.sessions.len(),
        })
        .context("encoding operator session acknowledgement")
    }

    fn cancel(&self, _payload: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!(
            "campaign-provider cancellation requires the admitted session identity contract"
        )
    }
}

#[derive(serde::Serialize)]
struct OperatorSessionAccepted<'a> {
    schema: &'static str,
    request_id: &'a AssuranceId,
    session_count: usize,
}

fn joined_request_digest(request: &[u8], bundle: &OperatorSessionBundle) -> Result<Sha256Digest> {
    let bundle = bundle
        .to_json()
        .context("encoding operator session bundle for durable identity")?;
    let mut hasher = Sha256::new();
    hasher.update(b"mvm.assurance.joined-provider-request/v1\0");
    hasher.update(Sha256::digest(request));
    hasher.update(Sha256::digest(bundle));
    Ok(Sha256Digest::from_bytes(&hasher.finalize().into()))
}

impl<R> CampaignProviderController<R> {
    fn journal_path(&self, request_id: &AssuranceId) -> PathBuf {
        self.journal_root.join(format!("{request_id}.json"))
    }
}

fn assemble_response(
    request: &CampaignProviderRequest,
    output: AdmittedCampaignOutput,
) -> Result<CampaignProviderResponse> {
    let certifying =
        output.missing_brokers.is_empty() && evidence_is_certifying(request, &output.evidence);
    let status = if certifying {
        "evaluated"
    } else {
        "inconclusive_evidence"
    };
    let response = CampaignProviderResponse {
        schema: CAMPAIGN_PROVIDER_RESPONSE_SCHEMA.to_string(),
        request_id: request.request_id.clone(),
        status: status.to_string(),
        certifying,
        missing_brokers: output.missing_brokers,
        evidence: output.evidence,
    };
    response.validate()?;
    if response.to_json()?.len() > MAX_CAMPAIGN_PROVIDER_BYTES {
        anyhow::bail!("assurance provider response exceeds its byte limit");
    }
    Ok(response)
}

fn evidence_is_certifying(
    request: &CampaignProviderRequest,
    evidence: &[TrialEvidenceRecord],
) -> bool {
    if !request.require_disposable_target || evidence.len() != request.campaigns.len() {
        return false;
    }
    let expected: BTreeSet<_> = request
        .campaigns
        .iter()
        .map(|campaign| &campaign.campaign_id)
        .collect();
    let actual: BTreeSet<_> = evidence.iter().map(|trial| &trial.campaign_id).collect();
    expected == actual
        && actual.len() == evidence.len()
        && evidence.iter().all(|trial| {
            trial.schema == TRIAL_EVIDENCE_SCHEMA
                && trial.source_run_id == request.source_run_id
                && trial.subject_revision == request.subject_revision
                && trial.source_digest == request.source_digest
                && trial.policy_digest.as_ref() == Some(&request.requested_policy_digest)
                && trial.artifact_digest.is_some()
                && trial.disposable_target
                && trial.identity_verified
                && trial.observer_verified
                && trial.cleanup_verified
                && (!request.require_attestation || trial.attestation_verified)
                && trial.attempted_effect
                && !trial.boundary_crossed
                && contains_reference(&trial.evidence_refs, "mvm:audit:")
                && contains_reference(&trial.evidence_refs, "mvm:receipt:")
        })
}

fn contains_reference(references: &[EvidenceRef], prefix: &str) -> bool {
    references
        .iter()
        .any(|reference| reference.as_str().starts_with(prefix))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalStatus {
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderJournal {
    schema: String,
    request_id: AssuranceId,
    request_digest: Sha256Digest,
    status: JournalStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<CampaignProviderResponse>,
}

impl ProviderJournal {
    fn running(request_id: AssuranceId, request_digest: Sha256Digest) -> Self {
        Self {
            schema: JOURNAL_SCHEMA.to_string(),
            request_id,
            request_digest,
            status: JournalStatus::Running,
            response: None,
        }
    }

    fn completed(
        request_id: AssuranceId,
        request_digest: Sha256Digest,
        response: CampaignProviderResponse,
    ) -> Self {
        Self {
            schema: JOURNAL_SCHEMA.to_string(),
            request_id,
            request_digest,
            status: JournalStatus::Completed,
            response: Some(response),
        }
    }

    fn failed(request_id: AssuranceId, request_digest: Sha256Digest) -> Self {
        Self {
            schema: JOURNAL_SCHEMA.to_string(),
            request_id,
            request_digest,
            status: JournalStatus::Failed,
            response: None,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.schema != JOURNAL_SCHEMA {
            anyhow::bail!("unsupported assurance provider journal schema");
        }
        match (&self.status, &self.response) {
            (JournalStatus::Completed, Some(response)) => {
                if response.request_id != self.request_id {
                    anyhow::bail!("provider journal response identity mismatch");
                }
                response.validate()?;
            }
            (JournalStatus::Running | JournalStatus::Failed, None) => {}
            _ => anyhow::bail!("provider journal has an invalid terminal shape"),
        }
        Ok(())
    }
}

enum Claim {
    Fresh,
    Running,
    Completed(CampaignProviderResponse),
    Failed,
}

fn claim_request(
    path: &Path,
    request_id: &AssuranceId,
    request_digest: &Sha256Digest,
) -> Result<Claim> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("provider journal path has no parent"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating provider journal directory {}", parent.display()))?;
    set_private_directory(parent)?;
    let journal = ProviderJournal::running(request_id.clone(), request_digest.clone());
    let encoded = encode_journal(&journal)?;
    match create_private(path, &encoded) {
        Ok(()) => return Ok(Claim::Fresh),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("creating provider journal {}", path.display()));
        }
    }
    let existing = load_journal(path)?;
    if existing.request_id != *request_id || existing.request_digest != *request_digest {
        anyhow::bail!("provider retry identity does not match the durable request");
    }
    Ok(match existing.status {
        JournalStatus::Running => Claim::Running,
        JournalStatus::Completed => Claim::Completed(
            existing
                .response
                .expect("validated completed journal has a response"),
        ),
        JournalStatus::Failed => Claim::Failed,
    })
}

fn load_journal(path: &Path) -> Result<ProviderJournal> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading provider journal metadata {}", path.display()))?;
    if metadata.len() > MAX_JOURNAL_BYTES {
        anyhow::bail!("assurance provider journal exceeds its byte limit");
    }
    let encoded = std::fs::read(path)
        .with_context(|| format!("reading provider journal {}", path.display()))?;
    let journal: ProviderJournal =
        serde_json::from_slice(&encoded).context("parsing assurance provider journal")?;
    journal.validate()?;
    Ok(journal)
}

fn persist_terminal(path: &Path, journal: ProviderJournal) -> Result<()> {
    journal.validate()?;
    let encoded = encode_journal(&journal)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("provider journal path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("provider journal path has no UTF-8 file name"))?;
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    write_private(&temporary, &encoded)?;
    std::fs::rename(&temporary, path).with_context(|| {
        format!(
            "replacing provider journal {} with {}",
            path.display(),
            temporary.display()
        )
    })?;
    sync_directory(parent)
}

fn encode_journal(journal: &ProviderJournal) -> Result<Vec<u8>> {
    let mut encoded = serde_json::to_vec(journal).context("encoding assurance provider journal")?;
    encoded.push(b'\n');
    if u64::try_from(encoded.len()).expect("usize fits in u64") > MAX_JOURNAL_BYTES {
        anyhow::bail!("assurance provider journal exceeds its byte limit");
    }
    Ok(encoded)
}

fn create_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        sync_directory(parent).map_err(std::io::Error::other)?;
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating private provider journal {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing private provider journal {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("committing private provider journal {}", path.display()))
}

fn set_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).with_context(
            || format!("restricting provider journal directory {}", path.display()),
        )?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .with_context(|| format!("opening provider journal directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("committing provider journal directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, Condvar};

    use mvm_contract::assurance::{
        CounterpartyCampaign, OPERATOR_SESSION_BUNDLE_SCHEMA, SubjectKind,
    };
    use mvm_contract::protocol::extension_controller::{
        ExtensionFrame, ExtensionMessageKind, decode_extension_frame, encode_extension_frame,
    };

    use super::*;

    const SOURCE_DIGEST: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const POLICY_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const ARTIFACT_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn id(value: &str) -> AssuranceId {
        AssuranceId::parse(value).expect("identifier")
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::parse(value).expect("digest")
    }

    fn request() -> CampaignProviderRequest {
        CampaignProviderRequest {
            schema: "mvm.security.campaign-request/v1".to_string(),
            request_id: id("mvm-request-1"),
            source_run_id: id("scout-1"),
            subject_kind: SubjectKind::LocalRepository,
            subject_locator: "repository-ref-1".to_string(),
            subject_revision: Some("0123456789abcdef".to_string()),
            source_digest: digest(SOURCE_DIGEST),
            artifact_locator: Some("oci:example/app:1".to_string()),
            requested_policy_digest: digest(POLICY_DIGEST),
            profile: "sealed".to_string(),
            runner: "mvm".to_string(),
            build_posture: "verified".to_string(),
            timeout_seconds: 600,
            max_trials: 1,
            require_disposable_target: true,
            require_attestation: false,
            campaigns: vec![CounterpartyCampaign {
                campaign_id: id("mvm-campaign-1"),
                finding_id: id("SCOUT-RCE-001"),
                narrative_id: Some(id("mvm.boundary.process-exec.v1")),
                objective: Some("attempt the declared process effect".to_string()),
                expected_boundary: Some("the effect cannot cross from guest to host".to_string()),
                required_capabilities: vec![id("observation.stream.v1")],
            }],
        }
    }

    fn evidence() -> TrialEvidenceRecord {
        TrialEvidenceRecord {
            schema: "mvm.security.trial-evidence/v1".to_string(),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_run_id: id("scout-1"),
            subject_revision: Some("0123456789abcdef".to_string()),
            source_digest: digest(SOURCE_DIGEST),
            artifact_digest: Some(digest(ARTIFACT_DIGEST)),
            policy_digest: Some(digest(POLICY_DIGEST)),
            disposable_target: true,
            identity_verified: true,
            observer_verified: true,
            cleanup_verified: true,
            attestation_verified: false,
            attempted_effect: true,
            effect_observed_in_guest: false,
            boundary_crossed: false,
            blocked_edges: vec![id("guest-host-process")],
            evidence_refs: vec![
                EvidenceRef::parse("mvm:audit:trial-1").expect("audit ref"),
                EvidenceRef::parse("mvm:receipt:trial-1").expect("receipt ref"),
            ],
        }
    }

    fn operator_bundle() -> OperatorSessionBundle {
        OperatorSessionBundle {
            schema: OPERATOR_SESSION_BUNDLE_SCHEMA.to_string(),
            request_id: id("mvm-request-1"),
            sessions: vec![
                AssuranceSessionRequest::parse_json(include_bytes!(
                    "../../mvm-contract/fixtures/assurance-ai-session-request-v1.json"
                ))
                .expect("session request"),
            ],
        }
    }

    struct FixtureRunner {
        calls: AtomicUsize,
        fail: bool,
    }

    struct BlockingRunner {
        calls: AtomicUsize,
        started: Barrier,
        released: (Mutex<bool>, Condvar),
    }

    impl BlockingRunner {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                started: Barrier::new(2),
                released: (Mutex::new(false), Condvar::new()),
            }
        }

        fn release(&self) {
            let (lock, ready) = &self.released;
            *lock.lock().expect("provider release lock") = true;
            ready.notify_all();
        }
    }

    impl AdmittedCampaignRunner for BlockingRunner {
        fn run(
            &self,
            _request: &CampaignProviderRequest,
            _sessions: &[AssuranceSessionRequest],
        ) -> Result<AdmittedCampaignOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.wait();
            let (lock, ready) = &self.released;
            let mut released = lock.lock().expect("provider release lock");
            while !*released {
                released = ready.wait(released).expect("provider release wait");
            }
            Ok(AdmittedCampaignOutput::evaluated(vec![evidence()]))
        }
    }

    impl AdmittedCampaignRunner for FixtureRunner {
        fn run(
            &self,
            _request: &CampaignProviderRequest,
            sessions: &[AssuranceSessionRequest],
        ) -> Result<AdmittedCampaignOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(sessions.len(), 1);
            if self.fail {
                anyhow::bail!("sensitive runner diagnostic must not persist");
            }
            Ok(AdmittedCampaignOutput::evaluated(vec![evidence()]))
        }
    }

    fn payload(request: &CampaignProviderRequest) -> Vec<u8> {
        serde_json::to_vec(request).expect("request JSON")
    }

    fn open_operator_sessions<R: AdmittedCampaignRunner>(
        controller: &CampaignProviderController<R>,
    ) {
        controller
            .open_session(&operator_bundle().to_json().expect("bundle JSON"))
            .expect("open operator sessions");
    }

    #[test]
    fn completed_retry_returns_the_durable_response_without_running_twice() {
        let state = tempfile::tempdir().expect("state");
        let runner = FixtureRunner {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        let controller = CampaignProviderController::new(
            id("org.tinylabs.mvm-extension-provider"),
            "1.0.0",
            state.path(),
            runner,
        );
        let request = request();
        open_operator_sessions(&controller);
        let first = controller
            .start(&payload(&request))
            .expect("first response");
        let second = controller
            .start(&payload(&request))
            .expect("durable duplicate response");
        assert_eq!(first, second);
        assert_eq!(controller.runner.calls.load(Ordering::SeqCst), 1);
        let response: CampaignProviderResponse =
            serde_json::from_slice(&first).expect("typed response");
        assert!(response.certifying);
    }

    #[test]
    fn completed_retry_survives_controller_restart_without_running_twice() {
        let state = tempfile::tempdir().expect("state");
        let request = request();
        let first = {
            let controller = CampaignProviderController::new(
                id("org.tinylabs.mvm-extension-provider"),
                "1.0.0",
                state.path(),
                FixtureRunner {
                    calls: AtomicUsize::new(0),
                    fail: false,
                },
            );
            open_operator_sessions(&controller);
            let response = controller
                .start(&payload(&request))
                .expect("first response");
            assert_eq!(controller.runner.calls.load(Ordering::SeqCst), 1);
            response
        };

        let restarted = CampaignProviderController::new(
            id("org.tinylabs.mvm-extension-provider"),
            "1.0.0",
            state.path(),
            FixtureRunner {
                calls: AtomicUsize::new(0),
                fail: false,
            },
        );
        open_operator_sessions(&restarted);
        let replay = restarted
            .start(&payload(&request))
            .expect("durable response after restart");
        assert_eq!(replay, first);
        assert_eq!(restarted.runner.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn concurrent_start_is_refused_before_a_second_campaign_execution() {
        let state = tempfile::tempdir().expect("state");
        let controller = CampaignProviderController::new(
            id("org.tinylabs.mvm-extension-provider"),
            "1.0.0",
            state.path(),
            BlockingRunner::new(),
        );
        open_operator_sessions(&controller);
        let body = payload(&request());

        std::thread::scope(|scope| {
            let first = scope.spawn(|| controller.start(&body));
            controller.runner.started.wait();
            let error = controller
                .start(&body)
                .expect_err("concurrent execution must be refused");
            assert!(
                error.to_string().contains("budget is exhausted"),
                "{error:#}"
            );
            controller.runner.release();
            first
                .join()
                .expect("first runner thread")
                .expect("first run");
        });
        assert_eq!(controller.runner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sibling_frame_round_trip_returns_host_assembled_evidence() {
        let state = tempfile::tempdir().expect("state");
        let request = request();
        let bundle_payload = operator_bundle().to_json().expect("bundle JSON");
        let mut input = encode_extension_frame(
            &ExtensionFrame {
                kind: ExtensionMessageKind::Hello,
                sequence: 1,
                payload: Vec::new(),
            },
            1024 * 1024,
        )
        .expect("hello frame");
        input.extend(
            encode_extension_frame(
                &ExtensionFrame {
                    kind: ExtensionMessageKind::OpenSession,
                    sequence: 2,
                    payload: bundle_payload,
                },
                1024 * 1024,
            )
            .expect("open-session frame"),
        );
        input.extend(
            encode_extension_frame(
                &ExtensionFrame {
                    kind: ExtensionMessageKind::Start,
                    sequence: 3,
                    payload: payload(&request),
                },
                1024 * 1024,
            )
            .expect("start frame"),
        );
        let mut output = Vec::new();
        serve_provider(
            id("org.tinylabs.mvm-extension-provider"),
            "1.0.0",
            state.path(),
            FixtureRunner {
                calls: AtomicUsize::new(0),
                fail: false,
            },
            &mut Cursor::new(input),
            &mut output,
        )
        .expect("serve provider frames");

        let (descriptor, consumed) =
            decode_extension_frame(&output, 1024 * 1024).expect("descriptor frame");
        assert_eq!(descriptor.kind, ExtensionMessageKind::Describe);
        assert!(
            String::from_utf8(descriptor.payload)
                .expect("UTF-8")
                .contains(PROVIDER_CAPABILITY)
        );
        let (opened, opened_bytes) =
            decode_extension_frame(&output[consumed..], 1024 * 1024).expect("opened frame");
        assert_eq!(opened.kind, ExtensionMessageKind::Complete);
        assert!(
            String::from_utf8(opened.payload)
                .expect("UTF-8")
                .contains("session_count")
        );
        let (complete, terminal) =
            decode_extension_frame(&output[consumed + opened_bytes..], 1024 * 1024)
                .expect("complete frame");
        assert_eq!(complete.kind, ExtensionMessageKind::Complete);
        assert_eq!(consumed + opened_bytes + terminal, output.len());
        let response: CampaignProviderResponse =
            serde_json::from_slice(&complete.payload).expect("typed response");
        assert!(response.certifying);
    }

    #[test]
    fn interrupted_claim_and_identity_mismatch_never_call_the_runner() {
        let state = tempfile::tempdir().expect("state");
        let controller = CampaignProviderController::new(
            id("org.tinylabs.mvm-extension-provider"),
            "1.0.0",
            state.path(),
            FixtureRunner {
                calls: AtomicUsize::new(0),
                fail: false,
            },
        );
        let request = request();
        open_operator_sessions(&controller);
        let body = payload(&request);
        let request_digest =
            joined_request_digest(&body, &operator_bundle()).expect("joined digest");
        assert!(matches!(
            claim_request(
                &controller.journal_path(&request.request_id),
                &request.request_id,
                &request_digest,
            )
            .expect("claim"),
            Claim::Fresh
        ));
        let error = controller.start(&body).expect_err("interrupted retry");
        assert!(error.to_string().contains("interrupted"));

        let mut changed = request;
        changed.timeout_seconds = 601;
        let mismatch = controller
            .start(&payload(&changed))
            .expect_err("mismatched retry");
        assert!(mismatch.to_string().contains("identity"));
        assert_eq!(controller.runner.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn failed_request_is_durable_without_persisting_the_diagnostic() {
        let state = tempfile::tempdir().expect("state");
        let controller = CampaignProviderController::new(
            id("org.tinylabs.mvm-extension-provider"),
            "1.0.0",
            state.path(),
            FixtureRunner {
                calls: AtomicUsize::new(0),
                fail: true,
            },
        );
        let prompt_marker = "prompt-must-not-enter-provider-journal";
        let credential_marker = "credential-must-not-enter-provider-journal";
        let diagnostic_marker = "sensitive runner diagnostic must not persist";
        let mut request = request();
        request.subject_locator = credential_marker.to_string();
        request.campaigns[0].objective = Some(prompt_marker.to_string());
        let mut bundle = operator_bundle();
        bundle.sessions[0].source.subject_locator = credential_marker.to_string();
        bundle.sessions[0].narrative.objective = prompt_marker.to_string();
        controller
            .open_session(&bundle.to_json().expect("bundle JSON"))
            .expect("open operator sessions");
        controller
            .start(&payload(&request))
            .expect_err("runner refusal");
        let retry = controller
            .start(&payload(&request))
            .expect_err("failed retry");
        assert!(retry.to_string().contains("previously failed"));
        assert_eq!(controller.runner.calls.load(Ordering::SeqCst), 1);
        let durable =
            std::fs::read_to_string(controller.journal_path(&request.request_id)).expect("journal");
        assert!(!durable.contains(prompt_marker));
        assert!(!durable.contains(credential_marker));
        assert!(!durable.contains(diagnostic_marker));
        assert!(
            u64::try_from(durable.len()).expect("usize fits in u64") <= MAX_JOURNAL_BYTES,
            "provider journal exceeded its declared bound"
        );
    }

    #[test]
    fn missing_or_mismatched_operator_bundle_refuses_before_runner_or_journal() {
        let state = tempfile::tempdir().expect("state");
        let controller = CampaignProviderController::new(
            id("org.tinylabs.mvm-extension-provider"),
            "1.0.0",
            state.path(),
            FixtureRunner {
                calls: AtomicUsize::new(0),
                fail: false,
            },
        );
        let request = request();
        let missing = controller
            .start(&payload(&request))
            .expect_err("missing operator authority");
        assert!(missing.to_string().contains("was not opened"));

        let mut mismatched = operator_bundle();
        mismatched.sessions[0].source.finding_id = id("SCOUT-RCE-999");
        controller
            .open_session(&mismatched.to_json().expect("bundle JSON"))
            .expect("open mismatched bundle");
        let mismatch = controller
            .start(&payload(&request))
            .expect_err("mismatched operator authority");
        assert!(mismatch.to_string().contains("joining campaigns"));
        assert_eq!(controller.runner.calls.load(Ordering::SeqCst), 0);
        assert!(!controller.journal_path(&request.request_id).exists());
    }

    #[test]
    fn certification_is_host_derived_and_fails_closed_on_missing_evidence() {
        let request = request();
        let mut missing_receipt = evidence();
        missing_receipt
            .evidence_refs
            .retain(|reference| !reference.as_str().starts_with("mvm:receipt:"));
        let response = assemble_response(
            &request,
            AdmittedCampaignOutput::evaluated(vec![missing_receipt]),
        )
        .expect("response");
        assert!(!response.certifying);

        let mut wrong_schema = evidence();
        wrong_schema.schema = "mvm.security.trial-evidence/v2".to_string();
        let response = assemble_response(
            &request,
            AdmittedCampaignOutput::evaluated(vec![wrong_schema]),
        )
        .expect("response");
        assert!(!response.certifying);

        let mut attested = request;
        attested.require_attestation = true;
        let response = assemble_response(
            &attested,
            AdmittedCampaignOutput::evaluated(vec![evidence()]),
        )
        .expect("response");
        assert!(!response.certifying);
    }

    #[test]
    fn journal_root_is_explicit_private_and_not_a_symlink() {
        assert!(prepare_provider_state_root(Path::new("relative-provider-state")).is_err());

        let state = tempfile::tempdir().expect("provider state parent");
        let root = state.path().join("private");
        prepare_provider_state_root(&root).expect("explicit root");
        assert!(root.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};

            assert_eq!(
                std::fs::metadata(&root)
                    .expect("root metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            let linked = state.path().join("linked");
            symlink(&root, &linked).expect("state symlink");
            assert!(prepare_provider_state_root(&linked).is_err());
        }
    }
}
