//! Standalone verifier for mvm's chain-signed audit log (claim 8).
//!
//! `mvm-supervisor` writes per-tenant `<tenant>.jsonl` streams where
//! each line is a [`SignedEnvelope`]: an audit entry, the SHA-256 of
//! the previous line, and an Ed25519 signature over
//! `serde_json(entry) || prev_hash`. `mvm_supervisor::verify_audit_chain`
//! verifies those streams from a file path — but it lives in a crate
//! that pulls tokio/libc/rustix and cannot compile to `wasm32`.
//!
//! This crate re-implements *exactly* that verification against an
//! in-memory `&str` and an Ed25519 public key, with no filesystem and
//! no `mvm-*` dependencies, so the same logic runs in a browser tab
//! (see `web/audit-verify/`) and lets anyone audit a downloaded log
//! with no host and no trust in a server. The boundary rationale is
//! ADR-070.
//!
//! Byte-exactness: the signed payload is `serde_json::to_vec(entry)`.
//! [`MirrorEntry`] reproduces `mvm_supervisor::audit::AuditEntry`'s
//! serde shape field-for-field (declaration order, `#[serde(transparent)]`
//! string ids flattened to `String`, `skip_serializing_if` on the
//! bundle fields, `deny_unknown_fields`) so re-serializing here yields
//! the identical bytes that were signed — without depending on the
//! supervisor's types or on chrono. `mvm-supervisor`'s
//! `mvm_verify_matches_supervisor_chain` test pins this equivalence so
//! a field added upstream trips CI here.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// Mirror of `mvm_supervisor::audit::AuditEntry`. Field order and serde
/// attributes MUST match the upstream struct byte-for-byte — the
/// signature is computed over `serde_json::to_vec(entry)`, so any
/// divergence (reordered field, different skip rule) makes a genuine,
/// untampered line fail to verify. The `#[serde(transparent)]` newtype
/// ids upstream serialize as bare strings, so they are `String` here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorEntry {
    /// RFC 3339 timestamp, passed through verbatim (no chrono parse).
    pub timestamp: String,
    /// Tenant id (`TenantId`, transparent string upstream).
    pub tenant: String,
    /// Plan id (`PlanId`, transparent string upstream).
    pub plan_id: String,
    /// Plan schema/content version.
    pub plan_version: u32,
    /// Bundle id at event time; omitted from the wire when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    /// Bundle version at event time; omitted from the wire when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<u32>,
    /// Image name the workload ran.
    pub image_name: String,
    /// Image digest the workload ran (sha256 hex).
    pub image_sha256: String,
    /// Audit event name (e.g. `plan.admitted`).
    pub event: String,
    /// Free-form labels; a `BTreeMap` so key order is canonical.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// On-disk representation of one audit line. Mirrors
/// `mvm_supervisor::audit_file::SignedEnvelope`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    /// The audit entry that was signed.
    pub entry: MirrorEntry,
    /// base64 url-safe-no-pad of the previous line's SHA-256 (genesis
    /// is 32 zero bytes).
    pub prev_hash: String,
    /// base64 url-safe-no-pad of the 64-byte Ed25519 signature over
    /// `serde_json::to_vec(entry) || prev_hash_bytes`.
    pub signature: String,
}

/// A condensed view of one verified entry, for display.
#[derive(Debug, Clone, Serialize)]
pub struct EntrySummary {
    /// 0-based line index in the stream.
    pub line: usize,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Tenant id.
    pub tenant: String,
    /// Audit event name.
    pub event: String,
    /// Image name.
    pub image_name: String,
    /// Image digest (sha256 hex).
    pub image_sha256: String,
}

/// Outcome of a successful verification.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedChain {
    /// Number of verified entries.
    pub count: usize,
    /// One summary per verified entry, in stream order.
    pub entries: Vec<EntrySummary>,
}

/// Why a chain failed to verify. Variants mirror
/// `mvm_supervisor::audit_file::VerifyError` plus the key-decode case
/// this crate owns (the supervisor receives an already-parsed key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerifyError {
    /// A line could not be parsed, or a field could not be decoded.
    Malformed {
        /// 0-based line index.
        line: usize,
        /// Human-readable reason.
        reason: String,
    },
    /// A line's `prev_hash` did not match the running chain hash.
    PrevHashMismatch {
        /// 0-based line index.
        line: usize,
    },
    /// A line's signature did not verify against the public key.
    SignatureInvalid {
        /// 0-based line index.
        line: usize,
    },
    /// The supplied public key could not be decoded.
    KeyDecode(String),
}

impl fmt::Display for AuditVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { line, reason } => {
                write!(f, "malformed envelope at line {line}: {reason}")
            }
            Self::PrevHashMismatch { line } => {
                write!(f, "prev_hash mismatch at line {line}: chain broken")
            }
            Self::SignatureInvalid { line } => write!(f, "signature invalid at line {line}"),
            Self::KeyDecode(reason) => write!(f, "public key decode failed: {reason}"),
        }
    }
}

impl std::error::Error for AuditVerifyError {}

/// Parse a 32-byte Ed25519 public key from hex (64 hex chars, optional
/// `0x` prefix and surrounding whitespace).
pub fn verifying_key_from_hex(hex: &str) -> Result<VerifyingKey, AuditVerifyError> {
    let bytes = decode_hex32(hex)?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| AuditVerifyError::KeyDecode(e.to_string()))
}

/// Verify a chain-signed audit stream (`content`) against `verifying_key`.
///
/// Walks every non-empty line, checking each envelope's `prev_hash`
/// against the running chain hash and its signature against the key.
/// Returns the verified entries on success; stops at the first failure
/// and reports its line index. This is the byte-for-byte counterpart of
/// `mvm_supervisor::verify_audit_chain`, operating on a string.
pub fn verify_audit_chain_bytes(
    content: &str,
    verifying_key: &VerifyingKey,
) -> Result<VerifiedChain, AuditVerifyError> {
    let mut prev_hash = [0u8; 32];
    let mut entries = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let envelope: SignedEnvelope =
            serde_json::from_str(line).map_err(|e| AuditVerifyError::Malformed {
                line: idx,
                reason: e.to_string(),
            })?;

        let claimed_prev = URL_SAFE_NO_PAD.decode(&envelope.prev_hash).map_err(|e| {
            AuditVerifyError::Malformed {
                line: idx,
                reason: format!("prev_hash b64: {e}"),
            }
        })?;
        if claimed_prev.as_slice() != prev_hash.as_slice() {
            return Err(AuditVerifyError::PrevHashMismatch { line: idx });
        }

        let sig_bytes = URL_SAFE_NO_PAD.decode(&envelope.signature).map_err(|e| {
            AuditVerifyError::Malformed {
                line: idx,
                reason: format!("signature b64: {e}"),
            }
        })?;
        let sig_arr: [u8; 64] =
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| AuditVerifyError::Malformed {
                    line: idx,
                    reason: "signature must be 64 bytes".to_string(),
                })?;
        let signature = Signature::from_bytes(&sig_arr);

        let entry_bytes =
            serde_json::to_vec(&envelope.entry).map_err(|e| AuditVerifyError::Malformed {
                line: idx,
                reason: format!("entry reserialize: {e}"),
            })?;
        let mut to_verify = entry_bytes;
        to_verify.extend_from_slice(&prev_hash);
        verifying_key
            .verify(&to_verify, &signature)
            .map_err(|_| AuditVerifyError::SignatureInvalid { line: idx })?;

        prev_hash = hash_line(line.as_bytes());
        entries.push(EntrySummary {
            line: idx,
            timestamp: envelope.entry.timestamp,
            tenant: envelope.entry.tenant,
            event: envelope.entry.event,
            image_name: envelope.entry.image_name,
            image_sha256: envelope.entry.image_sha256,
        });
    }
    Ok(VerifiedChain {
        count: entries.len(),
        entries,
    })
}

fn hash_line(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Decode exactly 32 bytes from a hex string. A tiny local decoder so
/// the crate needs no `hex` dependency.
fn decode_hex32(input: &str) -> Result<[u8; 32], AuditVerifyError> {
    let s = input.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() != 64 {
        return Err(AuditVerifyError::KeyDecode(format!(
            "expected 64 hex chars (32 bytes), got {}",
            s.len()
        )));
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, AuditVerifyError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(AuditVerifyError::KeyDecode(format!(
            "non-hex character {:?}",
            c as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const SEED: [u8; 32] = [7u8; 32];

    fn signing_key() -> SigningKey {
        // Deterministic key from a fixed seed — no RNG dependency.
        SigningKey::from_bytes(&SEED)
    }

    fn entry(event: &str, bundle: Option<&str>) -> MirrorEntry {
        MirrorEntry {
            timestamp: "2026-06-03T12:00:00Z".to_string(),
            tenant: "tenant-a".to_string(),
            plan_id: "plan-1".to_string(),
            plan_version: 1,
            bundle_id: bundle.map(str::to_string),
            bundle_version: bundle.map(|_| 2),
            image_name: "worker".to_string(),
            image_sha256: "abc123".to_string(),
            event: event.to_string(),
            labels: BTreeMap::new(),
        }
    }

    /// Re-implement the supervisor's writer so tests produce genuine
    /// chains: sign `to_vec(entry) || prev_hash`, then emit the
    /// envelope and advance the chain by hashing the written line.
    fn build_chain(key: &SigningKey, entries: &[MirrorEntry]) -> String {
        let mut prev_hash = [0u8; 32];
        let mut out = String::new();
        for e in entries {
            let entry_bytes = serde_json::to_vec(e).unwrap();
            let mut to_sign = entry_bytes;
            to_sign.extend_from_slice(&prev_hash);
            let sig = key.sign(&to_sign);
            let env = SignedEnvelope {
                entry: e.clone(),
                prev_hash: URL_SAFE_NO_PAD.encode(prev_hash),
                signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            };
            let line = serde_json::to_string(&env).unwrap();
            prev_hash = hash_line(line.as_bytes());
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    #[test]
    fn valid_chain_verifies() {
        let key = signing_key();
        let chain = build_chain(
            &key,
            &[
                entry("plan.admitted", None),
                entry("plan.launched", Some("bundle-x")),
                entry("plan.failed", None),
            ],
        );
        let out = verify_audit_chain_bytes(&chain, &key.verifying_key()).unwrap();
        assert_eq!(out.count, 3);
        assert_eq!(out.entries[1].event, "plan.launched");
        assert_eq!(out.entries[0].line, 0);
    }

    #[test]
    fn genesis_prev_hash_is_zero() {
        let key = signing_key();
        let chain = build_chain(&key, &[entry("plan.admitted", None)]);
        let env: SignedEnvelope = serde_json::from_str(chain.trim()).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&env.prev_hash).unwrap(),
            vec![0u8; 32]
        );
    }

    #[test]
    fn wrong_key_fails_at_first_line() {
        let chain = build_chain(&signing_key(), &[entry("plan.admitted", None)]);
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let err = verify_audit_chain_bytes(&chain, &other).unwrap_err();
        assert_eq!(err, AuditVerifyError::SignatureInvalid { line: 0 });
    }

    #[test]
    fn tampered_entry_breaks_signature() {
        let key = signing_key();
        let chain = build_chain(&key, &[entry("plan.admitted", None)]);
        // Flip the event value in place without re-signing.
        let tampered = chain.replace("plan.admitted", "plan.ADMITTED");
        let err = verify_audit_chain_bytes(&tampered, &key.verifying_key()).unwrap_err();
        assert_eq!(err, AuditVerifyError::SignatureInvalid { line: 0 });
    }

    #[test]
    fn deleted_middle_line_breaks_chain() {
        let key = signing_key();
        let chain = build_chain(
            &key,
            &[
                entry("plan.admitted", None),
                entry("plan.launched", None),
                entry("plan.failed", None),
            ],
        );
        let mut lines: Vec<&str> = chain.lines().collect();
        lines.remove(1); // drop the middle entry — line 2's prev_hash now dangles
        let spliced = format!("{}\n", lines.join("\n"));
        let err = verify_audit_chain_bytes(&spliced, &key.verifying_key()).unwrap_err();
        assert_eq!(err, AuditVerifyError::PrevHashMismatch { line: 1 });
    }

    #[test]
    fn malformed_line_is_reported() {
        let err = verify_audit_chain_bytes("not json at all", &signing_key().verifying_key())
            .unwrap_err();
        assert!(matches!(err, AuditVerifyError::Malformed { line: 0, .. }));
    }

    #[test]
    fn empty_input_verifies_to_zero() {
        let out = verify_audit_chain_bytes("\n\n", &signing_key().verifying_key()).unwrap();
        assert_eq!(out.count, 0);
    }

    #[test]
    fn absent_bundle_is_omitted_from_signed_bytes() {
        // The skip_serializing_if mirror must hold: None => no key on
        // the wire, Some => key present. If this drifts, real chains
        // with absent bundle ids stop verifying.
        let none = serde_json::to_string(&entry("e", None)).unwrap();
        assert!(!none.contains("bundle_id"));
        let some = serde_json::to_string(&entry("e", Some("b"))).unwrap();
        assert!(some.contains("\"bundle_id\":\"b\""));
    }

    #[test]
    fn hex_key_parsing() {
        let vk = signing_key().verifying_key();
        let hex: String = vk.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            verifying_key_from_hex(&hex).unwrap().to_bytes(),
            vk.to_bytes()
        );
        assert_eq!(
            verifying_key_from_hex(&format!("0x{hex}"))
                .unwrap()
                .to_bytes(),
            vk.to_bytes()
        );
        assert!(verifying_key_from_hex("tooshort").is_err());
        assert!(matches!(
            verifying_key_from_hex(&"zz".repeat(32)),
            Err(AuditVerifyError::KeyDecode(_))
        ));
    }
}
