//! Typed launch attestation records and a local hash-chained JSONL log.
//!
//! This module is intentionally dependency-light and does not write to the
//! chain-signed host audit subsystem. Launch paths can build one record per
//! run, append it locally, and later bridge the same record into a signed host
//! envelope without changing the record shape.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::arch::GuestArch;
use crate::packs::{OciDigest, PackBackend, PackKind, Sha256Hex};
use crate::plan::bundle::KeyId;

pub const LAUNCH_ATTESTATION_SCHEMA_VERSION: u32 = 1;
pub const LAUNCH_ATTESTATION_LOG_FILE: &str = "launch-attestations.jsonl";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LaunchRunId(String);

impl LaunchRunId {
    pub fn new(value: impl Into<String>) -> Result<Self, LaunchAttestationError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(LaunchAttestationError::InvalidRunId(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for LaunchRunId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        LaunchRunId::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAttestationRecord {
    pub schema_version: u32,
    pub run_id: LaunchRunId,
    pub source_input: LaunchSourceInput,
    pub builder: BuilderIdentity,
    pub packs: Vec<LaunchPackIdentity>,
    pub local_verification: LocalVerification,
    pub derivation: LaunchDerivation,
    pub policy_admission: PolicyAdmission,
    pub command: CommandIdentity,
    pub result: LaunchResult,
    pub backend: BackendIdentity,
    pub launcher_version: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

impl LaunchAttestationRecord {
    pub fn builder(run_id: LaunchRunId) -> LaunchAttestationRecordBuilder {
        LaunchAttestationRecordBuilder {
            run_id,
            source_input: None,
            builder: None,
            packs: Vec::new(),
            local_verification: None,
            derivation: None,
            policy_admission: None,
            command: None,
            result: None,
            backend: None,
            launcher_version: None,
            started_at: None,
            finished_at: None,
        }
    }

    fn validate(&self) -> Result<(), LaunchAttestationError> {
        if self.schema_version != LAUNCH_ATTESTATION_SCHEMA_VERSION {
            return Err(LaunchAttestationError::UnsupportedSchemaVersion {
                got: self.schema_version,
                expected: LAUNCH_ATTESTATION_SCHEMA_VERSION,
            });
        }
        if self.packs.is_empty() {
            return Err(LaunchAttestationError::MissingPackIdentity);
        }
        if self.launcher_version.trim().is_empty() {
            return Err(LaunchAttestationError::MissingField("launcher_version"));
        }
        if self.finished_at < self.started_at {
            return Err(LaunchAttestationError::InvalidTimestamps);
        }
        if !self.policy_admission.admitted && self.policy_admission.refusal_reason.is_none() {
            return Err(LaunchAttestationError::MissingRefusalReason);
        }
        if matches!(self.result.outcome, LaunchOutcome::Success)
            && self.result.exit_status.is_none()
        {
            return Err(LaunchAttestationError::MissingExitStatus);
        }
        Ok(())
    }
}

#[must_use = "call `.build()` to validate and create a launch attestation record"]
pub struct LaunchAttestationRecordBuilder {
    run_id: LaunchRunId,
    source_input: Option<LaunchSourceInput>,
    builder: Option<BuilderIdentity>,
    packs: Vec<LaunchPackIdentity>,
    local_verification: Option<LocalVerification>,
    derivation: Option<LaunchDerivation>,
    policy_admission: Option<PolicyAdmission>,
    command: Option<CommandIdentity>,
    result: Option<LaunchResult>,
    backend: Option<BackendIdentity>,
    launcher_version: Option<String>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
}

impl LaunchAttestationRecordBuilder {
    pub fn source_input(mut self, source_input: LaunchSourceInput) -> Self {
        self.source_input = Some(source_input);
        self
    }

    pub fn builder_identity(mut self, builder: BuilderIdentity) -> Self {
        self.builder = Some(builder);
        self
    }

    pub fn pack(mut self, pack: LaunchPackIdentity) -> Self {
        self.packs.push(pack);
        self
    }

    pub fn local_verification(mut self, verification: LocalVerification) -> Self {
        self.local_verification = Some(verification);
        self
    }

    pub fn derivation(mut self, derivation: LaunchDerivation) -> Self {
        self.derivation = Some(derivation);
        self
    }

    pub fn policy_admission(mut self, admission: PolicyAdmission) -> Self {
        self.policy_admission = Some(admission);
        self
    }

    pub fn command(mut self, command: CommandIdentity) -> Self {
        self.command = Some(command);
        self
    }

    pub fn result(mut self, result: LaunchResult) -> Self {
        self.result = Some(result);
        self
    }

    pub fn backend(mut self, backend: BackendIdentity) -> Self {
        self.backend = Some(backend);
        self
    }

    pub fn launcher_version(mut self, version: impl Into<String>) -> Self {
        self.launcher_version = Some(version.into());
        self
    }

    pub fn started_at(mut self, started_at: DateTime<Utc>) -> Self {
        self.started_at = Some(started_at);
        self
    }

    pub fn finished_at(mut self, finished_at: DateTime<Utc>) -> Self {
        self.finished_at = Some(finished_at);
        self
    }

    pub fn build(self) -> Result<LaunchAttestationRecord, LaunchAttestationError> {
        let record = LaunchAttestationRecord {
            schema_version: LAUNCH_ATTESTATION_SCHEMA_VERSION,
            run_id: self.run_id,
            source_input: self
                .source_input
                .ok_or(LaunchAttestationError::MissingField("source_input"))?,
            builder: self
                .builder
                .ok_or(LaunchAttestationError::MissingField("builder"))?,
            packs: self.packs,
            local_verification: self
                .local_verification
                .ok_or(LaunchAttestationError::MissingField("local_verification"))?,
            derivation: self
                .derivation
                .ok_or(LaunchAttestationError::MissingField("derivation"))?,
            policy_admission: self
                .policy_admission
                .ok_or(LaunchAttestationError::MissingField("policy_admission"))?,
            command: self
                .command
                .ok_or(LaunchAttestationError::MissingField("command"))?,
            result: self
                .result
                .ok_or(LaunchAttestationError::MissingField("result"))?,
            backend: self
                .backend
                .ok_or(LaunchAttestationError::MissingField("backend"))?,
            launcher_version: self
                .launcher_version
                .ok_or(LaunchAttestationError::MissingField("launcher_version"))?,
            started_at: self
                .started_at
                .ok_or(LaunchAttestationError::MissingField("started_at"))?,
            finished_at: self
                .finished_at
                .ok_or(LaunchAttestationError::MissingField("finished_at"))?,
        };
        record.validate()?;
        Ok(record)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSourceInput {
    pub kind: LaunchSourceKind,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_hash: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci_digest: Option<OciDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flake_lock_hash: Option<Sha256Hex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchSourceKind {
    OciImage,
    Flake,
    LocalProject,
    RuntimePack,
    BuilderPrepared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderIdentity {
    pub used_builder_vm: bool,
    pub builder_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_environment_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPackIdentity {
    pub kind: PackKind,
    pub pack_hash: Sha256Hex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<KeyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    pub artifact_hashes: Vec<LaunchArtifactHash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchArtifactHash {
    pub name: String,
    pub sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVerification {
    pub verified_at: DateTime<Utc>,
    pub verifier_version: String,
    pub file_count: u64,
    pub revocation_checked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_root_hash: Option<Sha256Hex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchDerivation {
    pub source: LaunchDerivationSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pack_hash: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_proof_hash: Option<Sha256Hex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchDerivationSource {
    WarmStandby,
    LocalSnapshot,
    PreparedColdBoot,
    BuilderPrepare,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAdmission {
    pub admitted: bool,
    pub plan_hash: Sha256Hex,
    pub policy_hash: Sha256Hex,
    pub network_policy_hash: Sha256Hex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandIdentity {
    pub argv_redacted: Vec<String>,
    pub argv_digest: Sha256Hex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd_digest: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_digest: Option<Sha256Hex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchResult {
    pub outcome: LaunchOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<OutputDigestMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_digest: Option<Sha256Hex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchOutcome {
    Success,
    Refused,
    BuilderFallback,
    VerificationFailure,
    Interrupted,
    LaunchFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputDigestMetadata {
    pub stdout_sha256: Sha256Hex,
    pub stderr_sha256: Sha256Hex,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendIdentity {
    pub backend: PackBackend,
    pub backend_version: String,
    pub host_arch: GuestArch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAttestationEnvelope {
    pub schema_version: u32,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<Sha256Hex>,
    pub record: LaunchAttestationRecord,
    pub entry_hash: Sha256Hex,
}

impl LaunchAttestationEnvelope {
    fn new(
        sequence: u64,
        previous_hash: Option<Sha256Hex>,
        record: LaunchAttestationRecord,
    ) -> Result<Self, LaunchAttestationError> {
        let payload = LaunchAttestationEnvelopePayload {
            schema_version: LAUNCH_ATTESTATION_SCHEMA_VERSION,
            sequence,
            previous_hash,
            record,
        };
        let entry_hash = payload.entry_hash()?;
        Ok(Self {
            schema_version: payload.schema_version,
            sequence: payload.sequence,
            previous_hash: payload.previous_hash,
            record: payload.record,
            entry_hash,
        })
    }

    fn payload(&self) -> LaunchAttestationEnvelopePayload {
        LaunchAttestationEnvelopePayload {
            schema_version: self.schema_version,
            sequence: self.sequence,
            previous_hash: self.previous_hash.clone(),
            record: self.record.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchAttestationEnvelopePayload {
    schema_version: u32,
    sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_hash: Option<Sha256Hex>,
    record: LaunchAttestationRecord,
}

impl LaunchAttestationEnvelopePayload {
    fn entry_hash(&self) -> Result<Sha256Hex, LaunchAttestationError> {
        let bytes = serde_json::to_vec(self)?;
        Ok(Sha256Hex::from_bytes(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLaunchAttestationLog {
    pub entries: Vec<LaunchAttestationEnvelope>,
    pub head: Option<Sha256Hex>,
}

pub struct LaunchAttestationLog {
    path: PathBuf,
}

impl LaunchAttestationLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, LaunchAttestationError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        Ok(Self { path })
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from(crate::config::mvm_state_dir())
            .join("log")
            .join(LAUNCH_ATTESTATION_LOG_FILE)
    }

    pub fn open_default() -> Result<Self, LaunchAttestationError> {
        Self::open(Self::default_path())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(
        &self,
        record: LaunchAttestationRecord,
    ) -> Result<LaunchAttestationEnvelope, LaunchAttestationError> {
        record.validate()?;
        let verified = self.verify()?;
        let sequence = verified
            .entries
            .last()
            .map(|entry| entry.sequence.saturating_add(1))
            .unwrap_or(0);
        let envelope = LaunchAttestationEnvelope::new(sequence, verified.head, record)?;
        let line = serde_json::to_string(&envelope)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| LaunchAttestationError::Io {
                path: self.path.clone(),
                source,
            })?;
        harden_private_file(&self.path)?;
        writeln!(file, "{line}").map_err(|source| LaunchAttestationError::Io {
            path: self.path.clone(),
            source,
        })?;
        Ok(envelope)
    }

    pub fn verify(&self) -> Result<VerifiedLaunchAttestationLog, LaunchAttestationError> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(VerifiedLaunchAttestationLog {
                    entries: Vec::new(),
                    head: None,
                });
            }
            Err(source) => {
                return Err(LaunchAttestationError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let mut entries = Vec::new();
        let mut previous_hash = None;
        for (line_index, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: LaunchAttestationEnvelope =
                serde_json::from_str(line).map_err(|source| {
                    LaunchAttestationError::MalformedLine {
                        line: line_index + 1,
                        source,
                    }
                })?;
            verify_entry(
                line_index + 1,
                &entry,
                entries.len() as u64,
                previous_hash.as_ref(),
            )?;
            previous_hash = Some(entry.entry_hash.clone());
            entries.push(entry);
        }
        Ok(VerifiedLaunchAttestationLog {
            entries,
            head: previous_hash,
        })
    }
}

fn verify_entry(
    line: usize,
    entry: &LaunchAttestationEnvelope,
    expected_sequence: u64,
    expected_previous_hash: Option<&Sha256Hex>,
) -> Result<(), LaunchAttestationError> {
    if entry.schema_version != LAUNCH_ATTESTATION_SCHEMA_VERSION {
        return Err(LaunchAttestationError::UnsupportedEnvelopeSchemaVersion {
            line,
            got: entry.schema_version,
            expected: LAUNCH_ATTESTATION_SCHEMA_VERSION,
        });
    }
    if entry.sequence != expected_sequence {
        return Err(LaunchAttestationError::SequenceMismatch {
            line,
            expected: expected_sequence,
            actual: entry.sequence,
        });
    }
    if entry.previous_hash.as_ref() != expected_previous_hash {
        return Err(LaunchAttestationError::PreviousHashMismatch { line });
    }
    entry.record.validate()?;
    let computed = entry.payload().entry_hash()?;
    if computed != entry.entry_hash {
        return Err(LaunchAttestationError::EntryHashMismatch {
            line,
            expected: entry.entry_hash.clone(),
            actual: computed,
        });
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<(), LaunchAttestationError> {
    fs::create_dir_all(path).map_err(|source| LaunchAttestationError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    harden_private_dir(path)
}

#[cfg(unix)]
fn harden_private_dir(path: &Path) -> Result<(), LaunchAttestationError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)
        .map_err(|source| LaunchAttestationError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    if permissions.mode() & 0o777 != 0o700 {
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).map_err(|source| LaunchAttestationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_private_dir(_path: &Path) -> Result<(), LaunchAttestationError> {
    Ok(())
}

#[cfg(unix)]
fn harden_private_file(path: &Path) -> Result<(), LaunchAttestationError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)
        .map_err(|source| LaunchAttestationError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    if permissions.mode() & 0o777 != 0o600 {
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions).map_err(|source| LaunchAttestationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_private_file(_path: &Path) -> Result<(), LaunchAttestationError> {
    Ok(())
}

#[derive(Debug, Error)]
pub enum LaunchAttestationError {
    #[error("invalid launch run id {0:?}")]
    InvalidRunId(String),
    #[error("launch attestation schema version {got} not supported (expected {expected})")]
    UnsupportedSchemaVersion { got: u32, expected: u32 },
    #[error(
        "launch attestation envelope schema version {got} at line {line} not supported (expected {expected})"
    )]
    UnsupportedEnvelopeSchemaVersion {
        line: usize,
        got: u32,
        expected: u32,
    },
    #[error("launch attestation record is missing field {0}")]
    MissingField(&'static str),
    #[error("launch attestation record must include at least one pack identity")]
    MissingPackIdentity,
    #[error("launch attestation refusal records must include a refusal reason")]
    MissingRefusalReason,
    #[error("successful launch attestation records must include an exit status")]
    MissingExitStatus,
    #[error("launch attestation finished_at is earlier than started_at")]
    InvalidTimestamps,
    #[error("launch attestation line {line} is malformed: {source}")]
    MalformedLine {
        line: usize,
        source: serde_json::Error,
    },
    #[error(
        "launch attestation sequence mismatch at line {line}: expected {expected}, got {actual}"
    )]
    SequenceMismatch {
        line: usize,
        expected: u64,
        actual: u64,
    },
    #[error("launch attestation previous hash mismatch at line {line}")]
    PreviousHashMismatch { line: usize },
    #[error(
        "launch attestation entry hash mismatch at line {line}: expected {expected:?}, got {actual:?}"
    )]
    EntryHashMismatch {
        line: usize,
        expected: Sha256Hex,
        actual: Sha256Hex,
    },
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use tempfile::TempDir;

    use super::*;

    fn hash(value: &str) -> Sha256Hex {
        Sha256Hex::from_bytes(value.as_bytes())
    }

    fn digest(value: &str) -> OciDigest {
        OciDigest::new(format!("sha256:{}", hash(value).as_str())).expect("valid digest")
    }

    fn ts(seconds: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, seconds)
            .single()
            .expect("valid timestamp")
    }

    fn record(run_id: &str) -> LaunchAttestationRecord {
        LaunchAttestationRecord::builder(LaunchRunId::new(run_id).expect("run id"))
            .source_input(LaunchSourceInput {
                kind: LaunchSourceKind::OciImage,
                reference: format!("docker.io/library/alpine@{}", digest("alpine").as_str()),
                identity_hash: Some(hash("source")),
                oci_digest: Some(digest("alpine")),
                flake_lock_hash: None,
            })
            .builder_identity(BuilderIdentity {
                used_builder_vm: false,
                builder_id: "not-used".to_string(),
                build_environment_id: None,
            })
            .pack(LaunchPackIdentity {
                kind: PackKind::Runtime,
                pack_hash: hash("runtime-pack"),
                signer_key_id: None,
                channel: Some("stable".to_string()),
                artifact_hashes: vec![
                    LaunchArtifactHash {
                        name: "kernel".to_string(),
                        sha256: hash("kernel"),
                    },
                    LaunchArtifactHash {
                        name: "rootfs".to_string(),
                        sha256: hash("rootfs"),
                    },
                ],
            })
            .local_verification(LocalVerification {
                verified_at: ts(1),
                verifier_version: "mvm-core-test".to_string(),
                file_count: 2,
                revocation_checked: true,
                trust_root_hash: Some(hash("trust-root")),
            })
            .derivation(LaunchDerivation {
                source: LaunchDerivationSource::WarmStandby,
                identity: Some("warm-standby-1".to_string()),
                parent_pack_hash: Some(hash("runtime-pack")),
                readiness_proof_hash: Some(hash("agent-ready")),
            })
            .policy_admission(PolicyAdmission {
                admitted: true,
                plan_hash: hash("plan"),
                policy_hash: hash("policy"),
                network_policy_hash: hash("network-policy"),
                refusal_reason: None,
            })
            .command(CommandIdentity {
                argv_redacted: vec!["/bin/true".to_string()],
                argv_digest: hash("argv"),
                cwd_digest: Some(hash("cwd")),
                environment_digest: Some(hash("env")),
            })
            .result(LaunchResult {
                outcome: LaunchOutcome::Success,
                exit_status: Some(0),
                output_digest: Some(OutputDigestMetadata {
                    stdout_sha256: hash("stdout"),
                    stderr_sha256: hash("stderr"),
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                }),
                error_digest: None,
            })
            .backend(BackendIdentity {
                backend: PackBackend::Libkrun,
                backend_version: "test-backend".to_string(),
                host_arch: GuestArch::host(),
            })
            .launcher_version("mvmctl-test")
            .started_at(ts(0))
            .finished_at(ts(2))
            .build()
            .expect("record")
    }

    #[test]
    fn launch_attestation_record_roundtrips() {
        let record = record("run-1");
        let encoded = serde_json::to_string(&record).expect("json");
        let decoded: LaunchAttestationRecord = serde_json::from_str(&encoded).expect("decode");

        assert_eq!(decoded, record);
        assert_eq!(decoded.command.argv_redacted, ["/bin/true"]);
        assert_eq!(
            decoded.policy_admission.network_policy_hash,
            hash("network-policy")
        );
    }

    #[test]
    fn builder_rejects_missing_pack_identity() {
        let err = LaunchAttestationRecord::builder(LaunchRunId::new("run-1").expect("run id"))
            .source_input(LaunchSourceInput {
                kind: LaunchSourceKind::LocalProject,
                reference: ".".to_string(),
                identity_hash: Some(hash("source")),
                oci_digest: None,
                flake_lock_hash: None,
            })
            .builder_identity(BuilderIdentity {
                used_builder_vm: true,
                builder_id: "builder".to_string(),
                build_environment_id: Some("env".to_string()),
            })
            .local_verification(LocalVerification {
                verified_at: ts(1),
                verifier_version: "test".to_string(),
                file_count: 0,
                revocation_checked: false,
                trust_root_hash: None,
            })
            .derivation(LaunchDerivation {
                source: LaunchDerivationSource::BuilderPrepare,
                identity: Some("builder-run".to_string()),
                parent_pack_hash: None,
                readiness_proof_hash: None,
            })
            .policy_admission(PolicyAdmission {
                admitted: true,
                plan_hash: hash("plan"),
                policy_hash: hash("policy"),
                network_policy_hash: hash("network"),
                refusal_reason: None,
            })
            .command(CommandIdentity {
                argv_redacted: vec!["echo".to_string(), "redacted".to_string()],
                argv_digest: hash("argv"),
                cwd_digest: None,
                environment_digest: None,
            })
            .result(LaunchResult {
                outcome: LaunchOutcome::Success,
                exit_status: Some(0),
                output_digest: None,
                error_digest: None,
            })
            .backend(BackendIdentity {
                backend: PackBackend::Libkrun,
                backend_version: "test".to_string(),
                host_arch: GuestArch::host(),
            })
            .launcher_version("test")
            .started_at(ts(0))
            .finished_at(ts(2))
            .build()
            .expect_err("pack identity required");

        assert!(matches!(err, LaunchAttestationError::MissingPackIdentity));
    }

    #[test]
    fn append_hash_chains_records() {
        let tmp = TempDir::new().expect("tempdir");
        let log = LaunchAttestationLog::open(tmp.path().join("launch.jsonl")).expect("log");

        let first = log.append(record("run-1")).expect("append first");
        let second = log.append(record("run-2")).expect("append second");
        let verified = log.verify().expect("verify");

        assert_eq!(verified.entries.len(), 2);
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert_eq!(second.previous_hash, Some(first.entry_hash));
        assert_eq!(verified.head, Some(second.entry_hash));
    }

    #[test]
    fn verify_detects_modified_record() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("launch.jsonl");
        let log = LaunchAttestationLog::open(&path).expect("log");
        log.append(record("run-1")).expect("append");

        let raw = fs::read_to_string(&path).expect("read log");
        fs::write(&path, raw.replace("warm-standby-1", "warm-standby-2")).expect("tamper");

        let err = log.verify().expect_err("tamper rejected");
        assert!(matches!(
            err,
            LaunchAttestationError::EntryHashMismatch { .. }
        ));
    }

    #[test]
    fn verify_detects_reordered_records() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("launch.jsonl");
        let log = LaunchAttestationLog::open(&path).expect("log");
        log.append(record("run-1")).expect("append first");
        log.append(record("run-2")).expect("append second");

        let raw = fs::read_to_string(&path).expect("read log");
        let mut lines = raw.lines().collect::<Vec<_>>();
        lines.reverse();
        fs::write(&path, format!("{}\n", lines.join("\n"))).expect("reorder");

        let err = log.verify().expect_err("reorder rejected");
        assert!(matches!(
            err,
            LaunchAttestationError::SequenceMismatch { .. }
                | LaunchAttestationError::PreviousHashMismatch { .. }
        ));
    }
}
