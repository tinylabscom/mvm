//! Chain-signed file-backed [`AuditSigner`] — Plan 37 §22 Wave 3.
//!
//! Each emitted [`AuditEntry`] is wrapped in a [`SignedEnvelope`] that
//! carries the SHA-256 hash of the previous envelope on disk plus an
//! Ed25519 signature over `serde_json(entry) || prev_hash`. Tampering
//! with any entry — re-ordering, modifying, deleting, or swapping
//! between tenants — breaks either the chain or the signature, both
//! of which are checked by [`verify_audit_chain`].
//!
//! Per-tenant streams live at `<audit_dir>/<tenant>.jsonl`. The chain
//! seed (`prev_hash` for the first entry) is `[0u8; 32]`. The signer
//! restores its in-memory cursor from the last line on disk so that
//! a process restart resumes the chain without gaps.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::audit::{AuditEntry, AuditError, AuditSigner};

/// On-disk representation of one audit line: the original entry, the
/// hash of the previous envelope (genesis = 32 zero bytes), and an
/// Ed25519 signature over `serde_json(entry) || prev_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub entry: AuditEntry,
    /// base64 url-safe-no-pad of the 32-byte SHA-256 of the previous
    /// envelope's full JSON line. Genesis is 32 zero bytes.
    pub prev_hash: String,
    /// base64 url-safe-no-pad of the 64-byte Ed25519 signature over
    /// `serde_json::to_vec(entry) || prev_hash_bytes`.
    pub signature: String,
}

/// Chain-signed file signer. Holds an Ed25519 private key, a base
/// directory, and an in-memory `tenant -> last_envelope_hash` cursor
/// that is lazily restored from disk on first emit per tenant.
pub struct FileAuditSigner {
    signing_key: SigningKey,
    audit_dir: PathBuf,
    cursors: Mutex<HashMap<String, [u8; 32]>>,
}

impl FileAuditSigner {
    /// Create the signer rooted at `audit_dir`. The directory is
    /// created if missing (mode 0700-equivalent — `OpenOptions` later
    /// applies platform defaults, callers wanting tighter perms should
    /// pre-create the dir).
    pub fn open(signing_key: SigningKey, audit_dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let audit_dir = audit_dir.into();
        std::fs::create_dir_all(&audit_dir)?;
        Ok(Self {
            signing_key,
            audit_dir,
            cursors: Mutex::new(HashMap::new()),
        })
    }

    /// Public verifying key matching the embedded signing key. Use
    /// when handing the verifier to operators / test code.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn tenant_path(&self, tenant: &str) -> PathBuf {
        self.audit_dir.join(format!("{tenant}.jsonl"))
    }

    /// Re-seed the in-memory cursor from disk on first emit per tenant.
    /// Hashes the last on-disk line; returns `[0; 32]` (genesis) if no
    /// file exists or the file is empty.
    fn restore_cursor(&self, tenant: &str) -> std::io::Result<[u8; 32]> {
        let path = self.tenant_path(tenant);
        if !path.exists() {
            return Ok([0u8; 32]);
        }
        let content = std::fs::read_to_string(&path)?;
        let last = content.lines().rfind(|l| !l.is_empty());
        match last {
            None => Ok([0u8; 32]),
            Some(line) => Ok(hash_line(line.as_bytes())),
        }
    }
}

#[async_trait]
impl AuditSigner for FileAuditSigner {
    async fn sign_and_emit(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let tenant = entry.tenant.0.clone();

        let prev_hash = {
            let mut cursors = self.cursors.lock().expect("cursors poisoned");
            if let Some(h) = cursors.get(&tenant) {
                *h
            } else {
                let h = self
                    .restore_cursor(&tenant)
                    .map_err(|e| AuditError::Io(e.to_string()))?;
                cursors.insert(tenant.clone(), h);
                h
            }
        };

        let entry_bytes = serde_json::to_vec(entry).map_err(|e| AuditError::Io(e.to_string()))?;
        let mut to_sign = entry_bytes;
        to_sign.extend_from_slice(&prev_hash);
        let signature = self.signing_key.sign(&to_sign);

        let envelope = SignedEnvelope {
            entry: entry.clone(),
            prev_hash: URL_SAFE_NO_PAD.encode(prev_hash),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        let line = serde_json::to_string(&envelope).map_err(|e| AuditError::Io(e.to_string()))?;
        let new_hash = hash_line(line.as_bytes());

        let path = self.tenant_path(&tenant);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        writeln!(file, "{line}").map_err(|e| AuditError::Io(e.to_string()))?;

        self.cursors
            .lock()
            .expect("cursors poisoned")
            .insert(tenant, new_hash);
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("io error: {0}")]
    Io(String),
    #[error("malformed envelope at line {line}: {reason}")]
    Malformed { line: usize, reason: String },
    #[error("prev_hash mismatch at line {line}: chain broken")]
    PrevHashMismatch { line: usize },
    #[error("signature invalid at line {line}")]
    SignatureInvalid { line: usize },
}

/// Walk a chain-signed audit file, verifying each envelope's
/// `prev_hash` against the running chain hash and each signature
/// against `verifying_key`. Returns the number of valid entries on
/// success. Stops at the first failure and reports its line index.
pub fn verify_audit_chain(path: &Path, verifying_key: &VerifyingKey) -> Result<usize, VerifyError> {
    let content = std::fs::read_to_string(path).map_err(|e| VerifyError::Io(e.to_string()))?;
    let mut prev_hash = [0u8; 32];
    let mut count = 0usize;
    for (idx, line) in content.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let envelope: SignedEnvelope =
            serde_json::from_str(line).map_err(|e| VerifyError::Malformed {
                line: idx,
                reason: e.to_string(),
            })?;
        let claimed_prev =
            URL_SAFE_NO_PAD
                .decode(&envelope.prev_hash)
                .map_err(|e| VerifyError::Malformed {
                    line: idx,
                    reason: format!("prev_hash b64: {e}"),
                })?;
        if claimed_prev.as_slice() != prev_hash.as_slice() {
            return Err(VerifyError::PrevHashMismatch { line: idx });
        }
        let sig_bytes =
            URL_SAFE_NO_PAD
                .decode(&envelope.signature)
                .map_err(|e| VerifyError::Malformed {
                    line: idx,
                    reason: format!("signature b64: {e}"),
                })?;
        let sig_arr: [u8; 64] =
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::Malformed {
                    line: idx,
                    reason: "signature must be 64 bytes".to_string(),
                })?;
        let signature = Signature::from_bytes(&sig_arr);
        let entry_bytes =
            serde_json::to_vec(&envelope.entry).map_err(|e| VerifyError::Malformed {
                line: idx,
                reason: format!("entry reserialize: {e}"),
            })?;
        let mut to_verify = entry_bytes;
        to_verify.extend_from_slice(&prev_hash);
        verifying_key
            .verify(&to_verify, &signature)
            .map_err(|_| VerifyError::SignatureInvalid { line: idx })?;
        prev_hash = hash_line(line.as_bytes());
        count += 1;
    }
    Ok(count)
}

fn hash_line(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use mvm_plan::{PlanId, TenantId};
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_entry(tenant: &str, event: &str) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now(),
            tenant: TenantId(tenant.to_string()),
            plan_id: PlanId("plan-1".to_string()),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "img".to_string(),
            image_sha256: "abc123".to_string(),
            event: event.to_string(),
            labels: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn first_entry_uses_genesis_prev_hash() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "plan.verified"))
            .await
            .unwrap();

        let content = std::fs::read_to_string(signer.tenant_path("tenant-a")).unwrap();
        let envelope: SignedEnvelope = serde_json::from_str(content.trim()).unwrap();
        let prev = URL_SAFE_NO_PAD.decode(&envelope.prev_hash).unwrap();
        assert_eq!(prev, vec![0u8; 32], "genesis prev_hash must be all zeros");
    }

    #[tokio::test]
    async fn second_entry_chains_to_first() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "plan.verified"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "plan.admitted"))
            .await
            .unwrap();

        let path = signer.tenant_path("tenant-a");
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let first_hash = hash_line(lines[0].as_bytes());
        let second: SignedEnvelope = serde_json::from_str(lines[1]).unwrap();
        let second_prev = URL_SAFE_NO_PAD.decode(&second.prev_hash).unwrap();
        assert_eq!(second_prev, first_hash, "chain links must match");
    }

    #[tokio::test]
    async fn full_chain_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        for i in 0..5 {
            signer
                .sign_and_emit(&make_entry("tenant-a", &format!("event-{i}")))
                .await
                .unwrap();
        }
        let count = verify_audit_chain(&signer.tenant_path("tenant-a"), &vk).unwrap();
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn tampering_with_entry_breaks_signature() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "real-event"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "real-event-2"))
            .await
            .unwrap();

        // Flip a byte in the first line's `event` field. The chain
        // hash on the second line was computed over the *original*
        // first line, so verification of the *first* line should fail
        // on signature first (signature was over the original entry).
        let path = signer.tenant_path("tenant-a");
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("real-event", "fake-event", 1);
        std::fs::write(&path, tampered).unwrap();

        let err = verify_audit_chain(&path, &vk).expect_err("tamper must break verify");
        match err {
            VerifyError::SignatureInvalid { line } => assert_eq!(line, 0),
            other => panic!("expected SignatureInvalid at line 0, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deleting_a_middle_line_breaks_chain() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        for i in 0..3 {
            signer
                .sign_and_emit(&make_entry("tenant-a", &format!("e-{i}")))
                .await
                .unwrap();
        }
        let path = signer.tenant_path("tenant-a");
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // Drop the middle line — the third line now claims a prev_hash
        // computed over the (now-missing) second line.
        let truncated = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&path, truncated).unwrap();

        let err = verify_audit_chain(&path, &vk).expect_err("drop must break chain");
        match err {
            VerifyError::PrevHashMismatch { line } => assert_eq!(line, 1),
            other => panic!("expected PrevHashMismatch at line 1, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn restart_resumes_chain_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();

        {
            let signer = FileAuditSigner::open(key.clone(), dir.path()).unwrap();
            signer
                .sign_and_emit(&make_entry("tenant-a", "before-restart"))
                .await
                .unwrap();
        }
        // Drop signer, open a fresh one with the same key + dir.
        let signer2 = FileAuditSigner::open(key, dir.path()).unwrap();
        signer2
            .sign_and_emit(&make_entry("tenant-a", "after-restart"))
            .await
            .unwrap();

        // Both lines should still verify as one continuous chain.
        let count = verify_audit_chain(&signer2.tenant_path("tenant-a"), &vk).unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn separate_tenants_have_independent_chains() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();

        signer
            .sign_and_emit(&make_entry("tenant-a", "e1"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-b", "e1"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "e2"))
            .await
            .unwrap();

        let count_a = verify_audit_chain(&signer.tenant_path("tenant-a"), &vk).unwrap();
        let count_b = verify_audit_chain(&signer.tenant_path("tenant-b"), &vk).unwrap();
        assert_eq!(count_a, 2);
        assert_eq!(count_b, 1);
    }

    #[tokio::test]
    async fn verifier_rejects_wrong_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "e1"))
            .await
            .unwrap();

        let other_vk = fresh_key().verifying_key();
        let err = verify_audit_chain(&signer.tenant_path("tenant-a"), &other_vk)
            .expect_err("wrong key must fail");
        assert!(matches!(err, VerifyError::SignatureInvalid { line: 0 }));
    }
}
