//! Verifier for the workload audit chain — the `OnDiskEntry`/JCS format
//! written by [`crate::audit_signer::chain::Chain`].
//!
//! Symmetric to the writer: for each line it re-derives the entry hash,
//! checks the `prev_hash` link to the running head, re-canonicalizes the
//! parsed entry to confirm the stored bytes are truly JCS, and verifies
//! the chain key's signature over the canonical bytes. `mvmctl trust
//! audit verify` runs this over `~/.mvm/audit/<tenant>.workload.jsonl`
//! against the host public key — the workload-emitted chain is a separate
//! file from the host-lifecycle chain (`<tenant>.jsonl`, verified by
//! [`crate::supervisor::verify_audit_chain`]); both are signed under the
//! same host key.

use std::path::Path;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mvm_core::security::SIG_ALG_ED25519;
use thiserror::Error;

use crate::audit_signer::canonical::CanonicalEntry;
use crate::audit_signer::category;
use crate::audit_signer::chain::{OnDiskEntry, compute_entry_hash};

/// A workload-chain verification failure. Line numbers are zero-based
/// into the JSONL so a caller can point an operator at the bad entry.
#[derive(Debug, Error)]
pub enum WorkloadVerifyError {
    #[error("io error: {0}")]
    Io(String),
    #[error("malformed entry at line {line}: {reason}")]
    Malformed { line: usize, reason: String },
    #[error("stored canonical bytes are not JCS-canonical at line {line}")]
    NonCanonical { line: usize },
    #[error("disallowed category `{category}` at line {line}")]
    DisallowedCategory { line: usize, category: String },
    #[error("unsupported signature algorithm {sig_alg:#04x} at line {line}")]
    UnsupportedSigAlg { line: usize, sig_alg: u8 },
    #[error("prev_hash mismatch at line {line}: chain broken")]
    PrevHashMismatch { line: usize },
    #[error("entry_hash mismatch at line {line}: recomputed head differs")]
    EntryHashMismatch { line: usize },
    #[error("signature invalid at line {line}")]
    SignatureInvalid { line: usize },
}

/// Verify the workload audit chain at `path` against `verifying_key`,
/// returning the number of entries on success. Fails closed on the first
/// broken link, hash mismatch, bad signature, non-canonical blob,
/// disallowed category, or unsupported algorithm.
pub fn verify_workload_chain(
    path: &Path,
    verifying_key: &VerifyingKey,
) -> Result<usize, WorkloadVerifyError> {
    let content =
        std::fs::read_to_string(path).map_err(|e| WorkloadVerifyError::Io(e.to_string()))?;
    let mut prev_hash = CanonicalEntry::genesis_prev_hash();
    let mut count = 0usize;
    for (idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let on_disk: OnDiskEntry =
            serde_json::from_str(line).map_err(|e| WorkloadVerifyError::Malformed {
                line: idx,
                reason: e.to_string(),
            })?;
        // Algorithm gate first — only Ed25519 ships today; ECDSA-P256
        // (`SIG_ALG_ECDSA_P256`) verification lands with the HW-enclave key.
        if on_disk.sig_alg != SIG_ALG_ED25519 {
            return Err(WorkloadVerifyError::UnsupportedSigAlg {
                line: idx,
                sig_alg: on_disk.sig_alg,
            });
        }
        let canonical_bytes = base64::engine::general_purpose::STANDARD
            .decode(on_disk.canonical.as_bytes())
            .map_err(|e| WorkloadVerifyError::Malformed {
                line: idx,
                reason: format!("canonical b64: {e}"),
            })?;
        let entry: CanonicalEntry = serde_json::from_slice(&canonical_bytes).map_err(|e| {
            WorkloadVerifyError::Malformed {
                line: idx,
                reason: format!("canonical entry: {e}"),
            }
        })?;
        // Same allow-list the writer gates on — a chain must never carry a
        // category downstream tooling won't recognise.
        if !category::is_allowed(&entry.category) {
            return Err(WorkloadVerifyError::DisallowedCategory {
                line: idx,
                category: entry.category,
            });
        }
        // The stored bytes must be exactly the JCS re-serialization of the
        // parsed entry; a non-canonical blob can't enter through the writer.
        let recanonical = entry
            .jcs_bytes()
            .map_err(|e| WorkloadVerifyError::Malformed {
                line: idx,
                reason: format!("re-canonicalize: {e}"),
            })?;
        if recanonical != canonical_bytes {
            return Err(WorkloadVerifyError::NonCanonical { line: idx });
        }
        // Chain link: the entry's own prev_hash must equal the running head.
        if entry.prev_hash != prev_hash {
            return Err(WorkloadVerifyError::PrevHashMismatch { line: idx });
        }
        // Recompute the entry hash and confirm it matches the stored head.
        let expected_hash = compute_entry_hash(&prev_hash, &canonical_bytes);
        if expected_hash != on_disk.entry_hash {
            return Err(WorkloadVerifyError::EntryHashMismatch { line: idx });
        }
        // Signature over the canonical bytes by the chain key.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(on_disk.sig.as_bytes())
            .map_err(|e| WorkloadVerifyError::Malformed {
                line: idx,
                reason: format!("sig b64: {e}"),
            })?;
        let sig_arr: [u8; 64] =
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| WorkloadVerifyError::Malformed {
                    line: idx,
                    reason: format!("signature length {} != 64", sig_bytes.len()),
                })?;
        let signature = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(&canonical_bytes, &signature)
            .map_err(|_| WorkloadVerifyError::SignatureInvalid { line: idx })?;

        prev_hash = on_disk.entry_hash;
        count += 1;
    }
    Ok(count)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    use super::*;
    use crate::audit_signer::chain::Chain;

    fn entry(prev: &str, category: &str) -> CanonicalEntry {
        CanonicalEntry {
            category: category.into(),
            correlation_id: "01HCORR0000000000000000".into(),
            fields: serde_json::json!({"action": "emit", "n": 1}),
            prev_hash: prev.into(),
            session_id: "sess-1".into(),
            tenant_id: "t-1".into(),
            ts: "2026-06-15T00:00:00Z".into(),
            workload_id: "wl-1".into(),
        }
    }

    /// Build a chain of `n` `workload_audit` entries signed by a known key.
    /// Returns the JSONL path + the signing key (so tests can craft adversarial
    /// lines and derive the verifying key).
    fn build(dir: &tempfile::TempDir, n: usize) -> (std::path::PathBuf, SigningKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let key_path = dir.path().join("chain.key");
        std::fs::write(&key_path, sk.to_bytes()).unwrap();
        let jsonl = dir.path().join("t-1.workload.jsonl");
        let head = dir.path().join("HEAD");
        let mut chain = Chain::open(&jsonl, &head, Some(&key_path)).unwrap();
        for _ in 0..n {
            let e = entry(chain.head(), "workload_audit");
            chain.append(e).expect("append must succeed");
        }
        (jsonl, sk)
    }

    fn vk(sk: &SigningKey) -> VerifyingKey {
        sk.verifying_key()
    }

    /// Replicate the writer's signing pipeline to craft an adversarial line
    /// (used for category / sig_alg fixtures the writer would itself refuse).
    fn craft_line(sk: &SigningKey, e: &CanonicalEntry, sig_alg: u8) -> String {
        let canonical = e.jcs_bytes().unwrap();
        let entry_hash = compute_entry_hash(&e.prev_hash, &canonical);
        let sig = sk.sign(&canonical);
        let on_disk = OnDiskEntry {
            canonical: base64::engine::general_purpose::STANDARD.encode(&canonical),
            sig: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            sig_alg,
            entry_hash,
        };
        serde_json::to_string(&on_disk).unwrap()
    }

    fn read_lines(p: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn valid_chain_verifies_and_counts() {
        let dir = tempdir().unwrap();
        let (path, sk) = build(&dir, 3);
        let count = verify_workload_chain(&path, &vk(&sk)).expect("clean chain must verify");
        assert_eq!(count, 3);
    }

    #[test]
    fn empty_chain_verifies_as_zero() {
        let dir = tempdir().unwrap();
        let (path, sk) = build(&dir, 0);
        assert_eq!(verify_workload_chain(&path, &vk(&sk)).unwrap(), 0);
    }

    #[test]
    fn wrong_key_fails_signature() {
        let dir = tempdir().unwrap();
        let (path, _sk) = build(&dir, 1);
        let other = SigningKey::generate(&mut OsRng);
        let err = verify_workload_chain(&path, &vk(&other)).expect_err("wrong key must fail");
        assert!(
            matches!(err, WorkloadVerifyError::SignatureInvalid { line: 0 }),
            "got {err:?}"
        );
    }

    #[test]
    fn tampered_signature_fails() {
        let dir = tempdir().unwrap();
        let (path, sk) = build(&dir, 1);
        let mut on_disk: OnDiskEntry = serde_json::from_str(&read_lines(&path)[0]).unwrap();
        // Flip the first signature byte (decode, mutate, re-encode) so the
        // entry_hash still matches but the signature does not.
        let mut sig = base64::engine::general_purpose::STANDARD
            .decode(on_disk.sig.as_bytes())
            .unwrap();
        sig[0] ^= 0xff;
        on_disk.sig = base64::engine::general_purpose::STANDARD.encode(&sig);
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&on_disk).unwrap()),
        )
        .unwrap();
        let err = verify_workload_chain(&path, &vk(&sk)).expect_err("tampered sig must fail");
        assert!(
            matches!(err, WorkloadVerifyError::SignatureInvalid { line: 0 }),
            "got {err:?}"
        );
    }

    #[test]
    fn tampered_entry_hash_fails() {
        let dir = tempdir().unwrap();
        let (path, sk) = build(&dir, 1);
        let mut on_disk: OnDiskEntry = serde_json::from_str(&read_lines(&path)[0]).unwrap();
        on_disk.entry_hash = "0".repeat(64);
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&on_disk).unwrap()),
        )
        .unwrap();
        let err = verify_workload_chain(&path, &vk(&sk)).expect_err("bad entry_hash must fail");
        assert!(
            matches!(err, WorkloadVerifyError::EntryHashMismatch { line: 0 }),
            "got {err:?}"
        );
    }

    #[test]
    fn broken_prev_link_fails() {
        let dir = tempdir().unwrap();
        let (path, sk) = build(&dir, 2);
        // Drop the first line: line 0 is now the second entry whose prev_hash
        // points at the (now-absent) first entry, not genesis.
        let lines = read_lines(&path);
        std::fs::write(&path, format!("{}\n", lines[1])).unwrap();
        let err = verify_workload_chain(&path, &vk(&sk)).expect_err("broken link must fail");
        assert!(
            matches!(err, WorkloadVerifyError::PrevHashMismatch { line: 0 }),
            "got {err:?}"
        );
    }

    #[test]
    fn disallowed_category_fails() {
        let dir = tempdir().unwrap();
        let (path, sk) = build(&dir, 0);
        // Craft a properly-signed line whose category is outside the allow-list.
        let e = entry(&CanonicalEntry::genesis_prev_hash(), "totally-bogus");
        let line = craft_line(&sk, &e, SIG_ALG_ED25519);
        std::fs::write(&path, format!("{line}\n")).unwrap();
        let err = verify_workload_chain(&path, &vk(&sk)).expect_err("bad category must fail");
        match err {
            WorkloadVerifyError::DisallowedCategory { line, category } => {
                assert_eq!(line, 0);
                assert_eq!(category, "totally-bogus");
            }
            other => panic!("expected DisallowedCategory, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_sig_alg_fails() {
        let dir = tempdir().unwrap();
        let (path, sk) = build(&dir, 0);
        let e = entry(&CanonicalEntry::genesis_prev_hash(), "workload_audit");
        let line = craft_line(&sk, &e, mvm_core::security::SIG_ALG_ECDSA_P256);
        std::fs::write(&path, format!("{line}\n")).unwrap();
        let err = verify_workload_chain(&path, &vk(&sk)).expect_err("ECDSA not supported yet");
        assert!(
            matches!(
                err,
                WorkloadVerifyError::UnsupportedSigAlg {
                    line: 0,
                    sig_alg: 0x02
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn malformed_line_fails() {
        let dir = tempdir().unwrap();
        let (path, sk) = build(&dir, 0);
        std::fs::write(&path, "not json at all\n").unwrap();
        let err = verify_workload_chain(&path, &vk(&sk)).expect_err("malformed must fail");
        assert!(
            matches!(err, WorkloadVerifyError::Malformed { line: 0, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn blank_lines_are_skipped() {
        let dir = tempdir().unwrap();
        let (path, sk) = build(&dir, 2);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push('\n'); // trailing blank line
        std::fs::write(&path, content).unwrap();
        assert_eq!(verify_workload_chain(&path, &vk(&sk)).unwrap(), 2);
    }
}
