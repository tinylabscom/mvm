//! Chain head + JSONL append + secondary persistence.
//!
//! Holds the chain-signing key (software in-memory) + the
//! `O_APPEND`-only FD on the JSONL + the latest chain head. The single
//! entry point is [`Chain::append_entry`]: takes a typed
//! [`AppendEntryRequest::AppendEntry`], synthesizes a `CanonicalEntry`
//! with the current `prev_hash`, JCS-canonicalizes, signs, appends,
//! fsyncs, updates head, persists secondary, returns the new head.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use mvm_core::protocol::audit_signer::AuditSignerErrorCode;
use mvm_core::security::SIG_ALG_ED25519;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit_signer::canonical::CanonicalEntry;

/// The full on-disk JSONL line. `canonical` is the JCS-canonical entry
/// bytes (base64); `sig` is the chain key's signature over those
/// bytes; `sig_alg` is one of [`SIG_ALG_ED25519`] etc.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OnDiskEntry {
    /// JCS-canonical entry bytes, base64-encoded.
    pub canonical: String,
    /// Signature of `canonical` bytes by the chain key.
    pub sig: String,
    /// Signature algorithm (`SIG_ALG_ED25519`, `SIG_ALG_ECDSA_P256`).
    pub sig_alg: u8,
    /// Hex-encoded SHA-256 hash of `prev_hash || canonical_bytes`.
    /// Provided so a verifier can re-derive the chain head without
    /// rebuilding it from the canonical-bytes hashing pipeline.
    pub entry_hash: String,
}

pub struct Chain {
    signing_key: SigningKey,
    pub_key_bytes: Vec<u8>,
    head: String,
    jsonl_file: File,
    secondary_head_path: std::path::PathBuf,
}

impl Chain {
    /// Open or create the chain. If the JSONL exists and has entries,
    /// scans the file to find the latest entry-hash and uses it as the
    /// initial head. Otherwise initializes with [`CanonicalEntry::
    /// genesis_prev_hash`].
    pub fn open(
        jsonl_path: &Path,
        secondary_head_path: &Path,
        software_chain_key_path: Option<&Path>,
    ) -> Result<Self> {
        let signing_key = match software_chain_key_path {
            Some(p) => {
                let bytes = std::fs::read(p).with_context(|| {
                    format!("mvm-audit-signer chain key read failed: {}", p.display())
                })?;
                let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    anyhow::anyhow!(
                        "mvm-audit-signer chain key must be 32 bytes; got {}",
                        v.len()
                    )
                })?;
                SigningKey::from_bytes(&arr)
            }
            None => {
                let mut rng = OsRng;
                SigningKey::generate(&mut rng)
            }
        };
        let pub_key_bytes = signing_key.verifying_key().to_bytes().to_vec();

        // O_APPEND-only. Combined with the dir-immutable flag the
        // supervisor sets on the parent dir, this means we can only
        // append; we can't rewrite, truncate, or unlink.
        let jsonl_file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(jsonl_path)
            .with_context(|| {
                format!(
                    "mvm-audit-signer JSONL O_APPEND open failed: {}",
                    jsonl_path.display()
                )
            })?;

        // Determine initial head by reading the existing file end-to-end
        // if present. A future revision can short-circuit via the
        // secondary head file (which is faster and tamper-evident).
        let head = match std::fs::read_to_string(jsonl_path) {
            Ok(contents) if !contents.is_empty() => {
                let last_line = contents.lines().last().unwrap_or("");
                if last_line.is_empty() {
                    CanonicalEntry::genesis_prev_hash()
                } else {
                    let parsed: OnDiskEntry =
                        serde_json::from_str(last_line).with_context(|| {
                            format!(
                                "mvm-audit-signer existing chain tail malformed: {}",
                                jsonl_path.display()
                            )
                        })?;
                    parsed.entry_hash
                }
            }
            _ => CanonicalEntry::genesis_prev_hash(),
        };

        Ok(Self {
            signing_key,
            pub_key_bytes,
            head,
            jsonl_file,
            secondary_head_path: secondary_head_path.to_path_buf(),
        })
    }

    /// Current head hash (hex). For tests + supervisor inspection.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Public key bytes of the chain-signing key (32 for Ed25519).
    pub fn pub_key(&self) -> Vec<u8> {
        self.pub_key_bytes.clone()
    }

    /// Append one canonical entry. Returns the new head on success.
    pub fn append(&mut self, mut entry: CanonicalEntry) -> Result<String, AuditSignerErrorCode> {
        // Allow-list gate: unknown categories are rejected before any
        // signing work happens. Keeps the chain to a known set of values
        // so downstream tooling can rely on category meaning.
        if !crate::audit_signer::category::is_allowed(&entry.category) {
            return Err(AuditSignerErrorCode::InvalidRequest);
        }
        // Cross-check the caller's prev_hash matches our in-memory head.
        // If a caller (the audit-signer's own RPC handler) hands us an
        // entry with prev_hash != head we treat it as drift and refuse.
        if entry.prev_hash != self.head {
            return Err(AuditSignerErrorCode::ChainDriftDetected);
        }
        // JCS-canonical bytes (the bytes-to-sign + the bytes-on-disk).
        let canonical_bytes = entry
            .jcs_bytes()
            .map_err(|_| AuditSignerErrorCode::InternalError)?;
        // entry_hash = SHA256(prev_hash || canonical_bytes).
        let entry_hash = compute_entry_hash(&entry.prev_hash, &canonical_bytes);
        // Sign the canonical bytes.
        let sig = self.signing_key.sign(&canonical_bytes);
        let on_disk = OnDiskEntry {
            canonical: base64_encode(&canonical_bytes),
            sig: base64_encode(&sig.to_bytes()),
            sig_alg: SIG_ALG_ED25519,
            entry_hash: entry_hash.clone(),
        };
        let line =
            serde_json::to_string(&on_disk).map_err(|_| AuditSignerErrorCode::InternalError)?;
        // Append line + newline. O_APPEND ensures the write is atomic
        // up to the OS write-size guarantee (typically 4 KiB on Linux).
        writeln!(self.jsonl_file, "{}", line).map_err(|_| AuditSignerErrorCode::FsyncFailed)?;
        // Fsync. Hard-fail on error.
        self.jsonl_file
            .sync_all()
            .map_err(|_| AuditSignerErrorCode::FsyncFailed)?;
        // Update in-memory head + persist secondary location.
        self.head = entry_hash.clone();
        std::fs::write(&self.secondary_head_path, &self.head)
            .map_err(|_| AuditSignerErrorCode::FsyncFailed)?;
        // Caller might also want the canonical entry back for diagnostics.
        entry.prev_hash = self.head.clone(); // unused but keeps the value tidy
        Ok(entry_hash)
    }
}

/// `entry_hash = hex(SHA256(prev_hash_ascii || canonical_bytes))` — the
/// chain link. Each entry commits to the previous head plus its own JCS
/// canonical bytes. Shared by the writer ([`Chain::append`]) and the
/// verifier (`super::verify`) so the two computations can't drift.
pub(crate) fn compute_entry_hash(prev_hash: &str, canonical_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical_bytes);
    hex::encode(hasher.finalize())
}

// hex + base64 — kept tiny so we don't pull in extra workspace deps.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Verifier, VerifyingKey};
    use tempfile::tempdir;

    use super::*;

    fn sample_entry(prev: String) -> CanonicalEntry {
        CanonicalEntry {
            category: "plan".into(),
            correlation_id: "01HCORR0000000000000000".into(),
            fields: serde_json::json!({"verb": "now"}),
            prev_hash: prev,
            session_id: "sess-001".into(),
            tenant_id: "t-001".into(),
            ts: "2026-05-27T22:30:00Z".into(),
            workload_id: "wl-001".into(),
        }
    }

    #[test]
    fn fresh_chain_starts_at_genesis_head() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let chain = Chain::open(&jsonl, &head, None).unwrap();
        assert_eq!(chain.head(), CanonicalEntry::genesis_prev_hash());
    }

    #[test]
    fn append_advances_head_persists_secondary_and_verifies_signature() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head_path = dir.path().join("HEAD");
        let mut chain = Chain::open(&jsonl, &head_path, None).unwrap();
        let pub_key = chain.pub_key();

        let entry = sample_entry(chain.head().to_string());
        let entry_clone = entry.clone();
        let new_head = chain.append(entry).expect("append must succeed");
        assert_ne!(new_head, CanonicalEntry::genesis_prev_hash());
        assert_eq!(chain.head(), new_head);

        // Secondary head file matches.
        let secondary = std::fs::read_to_string(&head_path).unwrap();
        assert_eq!(secondary, new_head);

        // Signature verifies against the chain pub key.
        let jsonl_contents = std::fs::read_to_string(&jsonl).unwrap();
        let last_line = jsonl_contents.lines().last().unwrap();
        let on_disk: OnDiskEntry = serde_json::from_str(last_line).unwrap();
        let canonical_bytes = entry_clone.jcs_bytes().unwrap();
        use base64::Engine;
        let on_disk_canonical = base64::engine::general_purpose::STANDARD
            .decode(&on_disk.canonical)
            .unwrap();
        assert_eq!(canonical_bytes, on_disk_canonical);
        let pk_arr: [u8; 32] = pub_key.try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk_arr).unwrap();
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&on_disk.sig)
            .unwrap();
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(&canonical_bytes, &sig)
            .expect("on-disk signature must verify");
    }

    #[test]
    fn append_rejects_drifted_prev_hash() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let mut chain = Chain::open(&jsonl, &head, None).unwrap();
        let bogus_entry = sample_entry("deadbeef".repeat(8));
        let err = chain.append(bogus_entry).unwrap_err();
        assert_eq!(err, AuditSignerErrorCode::ChainDriftDetected);
    }

    #[test]
    fn reopening_chain_recovers_head_from_jsonl_tail() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let first_head = {
            let mut chain = Chain::open(&jsonl, &head, None).unwrap();
            let entry = sample_entry(chain.head().to_string());
            chain.append(entry).unwrap()
        };
        // Reopen — should resume at the first-append head.
        let chain = Chain::open(&jsonl, &head, None).unwrap();
        assert_eq!(chain.head(), first_head);
    }

    #[test]
    fn two_appends_chain_correctly() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let mut chain = Chain::open(&jsonl, &head, None).unwrap();
        let h0 = chain.head().to_string();

        let e1 = sample_entry(h0.clone());
        let h1 = chain.append(e1).unwrap();
        assert_ne!(h1, h0);

        let e2 = sample_entry(h1.clone());
        let h2 = chain.append(e2).unwrap();
        assert_ne!(h2, h1);

        // Both lines on disk, ordered, with the correct entry_hash chain.
        let jsonl_contents = std::fs::read_to_string(&jsonl).unwrap();
        let lines: Vec<&str> = jsonl_contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed_1: OnDiskEntry = serde_json::from_str(lines[0]).unwrap();
        let parsed_2: OnDiskEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed_1.entry_hash, h1);
        assert_eq!(parsed_2.entry_hash, h2);
    }
}
