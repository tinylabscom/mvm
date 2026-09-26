//! The verdict on one instruction file.
//!
//! Order matters and is fixed: the digest is checked against the blocklist
//! before any signature is looked at, so a blocked file is refused however
//! validly it was signed; then each sidecar present is checked against the
//! trusted publishers, and one that verifies is enough.

use std::path::{Path, PathBuf};

use mvm_hostd::audit::emitter::InstructionTrustEvent;
use serde::Serialize;

use super::policy::{EffectivePolicy, PublisherTrust};
use super::scan::InstructionFile;
use super::sign::{KeyedSignature, KeyedSignatureError};
use super::{KEYED_SIDECAR_SUFFIX, KEYLESS_SIDECAR_SUFFIX, sidecar_path};

/// The largest instruction file read for verification. Anything larger is
/// refused unread rather than pulled into memory: no agent instruction file
/// is legitimately this big.
pub const MAX_INSTRUCTION_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Why a file was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Failure {
    /// The file's digest is on the blocklist.
    DigestBlocked { note: Option<String> },
    /// A signature verified, but not from a trusted publisher.
    PublisherMismatch { signer: String },
    /// A signature is present and does not verify over these bytes.
    BadSignature { detail: String },
    /// Only a keyless signature is present and this build cannot check one.
    VerifierUnavailable,
    /// The file could not be read as an instruction file.
    Unreadable { detail: String },
}

impl Failure {
    /// The audit-label spelling.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Failure::DigestBlocked { .. } => "digest_blocked",
            Failure::PublisherMismatch { .. } => "publisher_mismatch",
            Failure::BadSignature { .. } => "bad_signature",
            Failure::VerifierUnavailable => "verifier_unavailable",
            Failure::Unreadable { .. } => "unreadable",
        }
    }

    /// A one-line explanation for an operator.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Failure::DigestBlocked { note: Some(note) } => {
                format!("digest is blocked: {note}")
            }
            Failure::DigestBlocked { note: None } => "digest is blocked".to_string(),
            Failure::PublisherMismatch { signer } => {
                format!("signed by {signer}, which is not a trusted publisher")
            }
            Failure::BadSignature { detail } => format!("bad signature: {detail}"),
            Failure::VerifierUnavailable => "keyless signature cannot be checked: this mvmctl \
                 was built without the Sigstore verifier (`--features user`)"
                .to_string(),
            Failure::Unreadable { detail } => format!("unreadable: {detail}"),
        }
    }

    /// How strongly this failure indicates tampering, for picking the one to
    /// report when several sidecars all fail.
    fn severity(&self) -> u8 {
        match self {
            Failure::DigestBlocked { .. } => 4,
            Failure::BadSignature { .. } => 3,
            Failure::PublisherMismatch { .. } => 2,
            Failure::Unreadable { .. } => 1,
            Failure::VerifierUnavailable => 0,
        }
    }
}

/// The outcome for one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Verdict {
    /// Signed by a trusted publisher.
    Verified { publisher: String, signer: String },
    /// No signature beside it.
    Unsigned,
    /// Refused for a named reason.
    Failed(Failure),
}

impl Verdict {
    /// The chain-signed audit event recording this verdict.
    #[must_use]
    pub fn audit_event(&self) -> InstructionTrustEvent {
        match self {
            Verdict::Verified { .. } => InstructionTrustEvent::Verified,
            Verdict::Unsigned => InstructionTrustEvent::Unsigned,
            Verdict::Failed(_) => InstructionTrustEvent::Blocked,
        }
    }

    /// Whether this verdict passes.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Verdict::Verified { .. })
    }

    /// A one-line explanation for an operator.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Verdict::Verified { publisher, signer } => {
                format!("verified: publisher `{publisher}` ({signer})")
            }
            Verdict::Unsigned => "unsigned: no signature beside the file".to_string(),
            Verdict::Failed(failure) => failure.describe(),
        }
    }
}

/// One file and its verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileReport {
    #[serde(flatten)]
    pub file: InstructionFile,
    /// SHA-256 of the content verified, when it could be read.
    pub sha256: Option<String>,
    pub verdict: Verdict,
}

/// Verify one instruction file under `policy`.
#[must_use]
pub fn verify_file(file: InstructionFile, policy: &EffectivePolicy) -> FileReport {
    let content = match read_content(&file) {
        Ok(content) => content,
        Err(detail) => {
            return FileReport {
                file,
                sha256: None,
                verdict: Verdict::Failed(Failure::Unreadable { detail }),
            };
        }
    };
    let sha256 = mvm_core::plan::bundle::sha256_hex(&content);
    let verdict = verdict_for(&file.path, &content, &sha256, policy);
    FileReport {
        file,
        sha256: Some(sha256),
        verdict,
    }
}

fn verdict_for(path: &Path, content: &[u8], sha256: &str, policy: &EffectivePolicy) -> Verdict {
    if let Some(note) = policy.blocked(sha256) {
        return Verdict::Failed(Failure::DigestBlocked {
            note: note.map(str::to_string),
        });
    }
    let keyless = read_sidecar(&sidecar_path(path, KEYLESS_SIDECAR_SUFFIX));
    let keyed = read_sidecar(&sidecar_path(path, KEYED_SIDECAR_SUFFIX));
    if keyless.is_none() && keyed.is_none() {
        return Verdict::Unsigned;
    }
    let mut failures = Vec::new();
    for attempt in [
        keyless.map(|bundle| bundle.and_then(|b| check_keyless(content, &b, policy))),
        keyed.map(|envelope| envelope.and_then(|e| check_keyed(&e, sha256, policy))),
    ]
    .into_iter()
    .flatten()
    {
        match attempt {
            Ok(verified) => return verified,
            Err(failure) => failures.push(failure),
        }
    }
    let worst = failures
        .into_iter()
        .max_by_key(Failure::severity)
        .expect("at least one sidecar was present and failed");
    Verdict::Failed(worst)
}

/// Read a sidecar: `None` when absent, `Some(Err)` when present but unreadable.
fn read_sidecar(path: &Path) -> Option<Result<Vec<u8>, Failure>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(Ok(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => Some(Err(Failure::Unreadable {
            detail: format!("reading {}: {error}", path.display()),
        })),
    }
}

/// Read the bytes an agent would read at this path.
///
/// A symlink is followed only while its target stays under the scanned root:
/// a link out of the root would have the gate verify one file while the
/// guest, which gets the root and not the host filesystem, sees another or
/// nothing.
fn read_content(file: &InstructionFile) -> Result<Vec<u8>, String> {
    let target = content_path(file)?;
    let size = std::fs::metadata(&target)
        .map_err(|e| format!("reading metadata: {e}"))?
        .len();
    if size > MAX_INSTRUCTION_FILE_BYTES {
        return Err(format!(
            "{size} bytes exceeds the {MAX_INSTRUCTION_FILE_BYTES}-byte instruction file limit"
        ));
    }
    std::fs::read(&target).map_err(|e| format!("reading: {e}"))
}

fn content_path(file: &InstructionFile) -> Result<PathBuf, String> {
    let meta = std::fs::symlink_metadata(&file.path).map_err(|e| format!("reading: {e}"))?;
    if !meta.file_type().is_symlink() {
        return Ok(file.path.clone());
    }
    let target =
        std::fs::canonicalize(&file.path).map_err(|e| format!("symlink does not resolve: {e}"))?;
    let root = std::fs::canonicalize(&file.root).map_err(|e| format!("resolving root: {e}"))?;
    if target.starts_with(&root) && target.is_file() {
        Ok(target)
    } else {
        Err("symlink points outside the scanned root".to_string())
    }
}

fn check_keyless(
    content: &[u8],
    bundle: &[u8],
    policy: &EffectivePolicy,
) -> Result<Verdict, Failure> {
    if !mvm_core::crypto::image_verify::keyless_verifier_available() {
        return Err(Failure::VerifierUnavailable);
    }
    let mut issuers: Vec<&str> = policy
        .publishers()
        .iter()
        .filter_map(|p| match &p.trust {
            PublisherTrust::Keyless(pattern) => Some(pattern.issuer.as_str()),
            PublisherTrust::Keyed { .. } => None,
        })
        .collect();
    issuers.sort_unstable();
    issuers.dedup();
    if issuers.is_empty() {
        return Err(Failure::PublisherMismatch {
            signer: "a keyless signer (the policy trusts no keyless publisher)".to_string(),
        });
    }
    let mut failure = None;
    for issuer in issuers {
        match mvm_core::crypto::image_verify::verify_signed_payload_signer(content, bundle, issuer)
        {
            Ok(signer) => {
                let matched = policy.publishers().iter().find(|p| match &p.trust {
                    PublisherTrust::Keyless(pattern) => {
                        pattern.matches(&signer.issuer, &signer.identity)
                    }
                    PublisherTrust::Keyed { .. } => false,
                });
                return match matched {
                    Some(publisher) => Ok(Verdict::Verified {
                        publisher: publisher.name.clone(),
                        signer: signer.identity,
                    }),
                    None => Err(Failure::PublisherMismatch {
                        signer: signer.identity,
                    }),
                };
            }
            Err(error) => {
                let detail = error.to_string();
                // A signature made under another issuer is a publisher the
                // policy does not trust, not evidence of tampering.
                failure = Some(if detail.contains("issuer mismatch") {
                    Failure::PublisherMismatch { signer: detail }
                } else {
                    Failure::BadSignature { detail }
                });
            }
        }
    }
    Err(failure.expect("at least one issuer was tried"))
}

fn check_keyed(
    envelope: &[u8],
    sha256: &str,
    policy: &EffectivePolicy,
) -> Result<Verdict, Failure> {
    let envelope = KeyedSignature::from_json(envelope).map_err(|error| Failure::BadSignature {
        detail: error.to_string(),
    })?;
    let key_id = envelope.key_id();
    let publisher = policy
        .publishers()
        .iter()
        .find_map(|p| match &p.trust {
            PublisherTrust::Keyed { key_id: id, key } if *id == key_id => Some((p, key)),
            _ => None,
        })
        .ok_or_else(|| Failure::PublisherMismatch {
            signer: format!("ed25519 key {}", key_id.0),
        })?;
    envelope
        .verify(sha256, publisher.1)
        .map_err(|error| match error {
            KeyedSignatureError::Malformed(_)
            | KeyedSignatureError::DigestMismatch
            | KeyedSignatureError::BadSignature(_) => Failure::BadSignature {
                detail: error.to_string(),
            },
        })?;
    Ok(Verdict::Verified {
        publisher: publisher.0.name.clone(),
        signer: format!("ed25519 key {}", key_id.0),
    })
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
