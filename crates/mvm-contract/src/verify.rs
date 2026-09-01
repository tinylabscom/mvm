//! Verifier for mvm's chain-signed audit log (claim 8).
//!
//! `mvm-supervisor` writes per-tenant `<tenant>.jsonl` streams where
//! each line is a [`SignedEnvelope`]: an audit entry, the SHA-256 of
//! the previous line, and an Ed25519 signature over
//! `serde_json(entry) || prev_hash`. `mvm_hostd::supervisor::verify_audit_chain`
//! verifies those streams from a file path — but it lives in a crate
//! that pulls tokio/libc/rustix and cannot compile to `wasm32`.
//!
//! This module re-implements *exactly* that verification against an
//! in-memory `&str` and an Ed25519 public key, with no filesystem and
//! no other `mvm-*` dependencies, so the same logic runs in a browser
//! tab (see `web/audit-verify/`) and lets anyone audit a downloaded
//! log with no host and no trust in a server.
//!
//! Byte-exactness: a line carries the bytes its signature covers, in
//! `canonical`, and verification reads them rather than re-deriving them. The
//! readable `entry` is checked against those bytes so the copy a human reads
//! cannot differ from the copy that was attested.
//!
//! Lines written before `canonical` existed carry no such copy, and are
//! verified the original way — by re-serializing `entry`, which requires
//! [`PlanAuditEntry`] to reproduce `mvm_hostd::supervisor::audit::AuditEntry`'s
//! serde shape field-for-field (declaration order, `#[serde(transparent)]`
//! string ids flattened to `String`, `skip_serializing_if` on the bundle
//! fields, `deny_unknown_fields`). That path is kept indefinitely: a log
//! written before the writer improved is still evidence. `mvm-hostd`'s
//! `mvm_verify_matches_supervisor_chain` test pins the equivalence so a field
//! added upstream trips CI here, and
//! `frozen_corpus::the_pre_stored_bytes_corpus_still_verifies` pins the old
//! shape against a committed fixture.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A chain-signed audit entry.
///
/// Generic over identifier and timestamp types so the host can use its
/// strongly-typed `TenantId` / `PlanId` / `PolicyId` newtypes and `DateTime<Utc>`
/// while the browser verifier uses plain strings. The serde shape is the same
/// in all cases: the ids serialize as bare strings (`#[serde(transparent)]`
/// upstream), the bundle fields are omitted when absent, and labels are a
/// canonical-ordered map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAuditEntry<Tenant = String, Plan = String, Bundle = String, Time = String> {
    /// RFC 3339 timestamp. The host uses `DateTime<Utc>`; the browser verifier
    /// passes the string through.
    pub timestamp: Time,
    /// Tenant id. `TenantId` upstream; serializes as a bare string.
    pub tenant: Tenant,
    /// Plan id. `PlanId` upstream; serializes as a bare string.
    pub plan_id: Plan,
    /// Plan schema/content version.
    pub plan_version: u32,
    /// Bundle id at event time; omitted from the wire when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<Bundle>,
    /// Bundle version at event time; omitted from the wire when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<u32>,
    /// Image name the workload ran.
    pub image_name: String,
    /// Image digest the workload ran (sha256 hex).
    pub image_sha256: String,
    /// Audit event name (e.g. `plan.admitted`).
    pub event: String,
    /// Opaque caller commitment copied from the exact admitted plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_commitment: Option<crate::plan::CallerCommitment>,
    /// Free-form labels; a `BTreeMap` so key order is canonical.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// On-disk representation of one audit line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope<T = PlanAuditEntry> {
    /// The audit entry that was signed, decoded for reading.
    pub entry: T,
    /// base64 url-safe-no-pad of the exact entry bytes covered by
    /// `signature`. `None` on lines written before this field existed, which
    /// are verified by re-serializing `entry` instead — indefinitely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical: Option<String>,
    /// base64 url-safe-no-pad of the previous line's SHA-256 (genesis
    /// is 32 zero bytes).
    pub prev_hash: String,
    /// base64 url-safe-no-pad of the 64-byte Ed25519 signature over
    /// `signed_entry_bytes || prev_hash_bytes`.
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
/// `mvm_hostd::supervisor::audit_file::VerifyError` plus the key-decode case
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
    /// A line's readable entry disagrees with the bytes that were signed.
    EntryCanonicalMismatch {
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
            Self::EntryCanonicalMismatch { line } => write!(
                f,
                "line {line}: the readable entry disagrees with the bytes that were signed"
            ),
            Self::KeyDecode(reason) => write!(f, "public key decode failed: {reason}"),
        }
    }
}

impl core::error::Error for AuditVerifyError {}

/// Parse a 32-byte Ed25519 public key from hex (64 hex chars, optional
/// `0x` prefix and surrounding whitespace).
pub fn verifying_key_from_hex(hex: &str) -> Result<VerifyingKey, AuditVerifyError> {
    let bytes = decode_hex32(hex).map_err(AuditVerifyError::KeyDecode)?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| AuditVerifyError::KeyDecode(e.to_string()))
}

/// Verify a chain-signed audit stream (`content`) against `verifying_key`.
///
/// Walks every non-empty line, checking each envelope's `prev_hash`
/// against the running chain hash and its signature against the key.
/// Returns the verified entries on success; stops at the first failure
/// and reports its line index. This is the byte-for-byte counterpart of
/// `mvm_hostd::supervisor::verify_audit_chain`, operating on a string.
/// The bytes a line's signature covers.
///
/// Post-`canonical` lines carry them verbatim, and the readable `entry` is
/// checked against them so the copy a human reads cannot say something
/// different from the copy the signature protects. Pre-`canonical` lines fall
/// back to re-serializing `entry`, which stays supported indefinitely: a log
/// written before this field existed is evidence, and evidence does not stop
/// verifying because the writer improved.
///
/// Byte-for-byte counterpart of
/// `mvm_hostd::supervisor::audit_file::signed_bytes_for`.
/// The bytes a line's signature covers.
///
/// Post-`canonical` lines carry them verbatim; the readable `entry` is checked
/// against them so the copy a human reads cannot say something different from
/// the copy the signature protects. Pre-`canonical` lines fall back to
/// re-serializing `entry`, which stays supported indefinitely.
pub fn signed_bytes_for<T>(
    envelope: &SignedEnvelope<T>,
    line: usize,
) -> Result<Vec<u8>, AuditVerifyError>
where
    T: Serialize + for<'de> Deserialize<'de> + PartialEq,
{
    let Some(encoded) = envelope.canonical.as_deref() else {
        return serde_json::to_vec(&envelope.entry).map_err(|e| AuditVerifyError::Malformed {
            line,
            reason: format!("entry reserialize: {e}"),
        });
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| AuditVerifyError::Malformed {
            line,
            reason: format!("canonical b64: {e}"),
        })?;
    let decoded: T = serde_json::from_slice(&bytes).map_err(|e| AuditVerifyError::Malformed {
        line,
        reason: format!("canonical entry parse: {e}"),
    })?;
    if decoded != envelope.entry {
        return Err(AuditVerifyError::EntryCanonicalMismatch { line });
    }
    Ok(bytes)
}

/// Event name of the record that opens every segment after the first.
///
/// Mirrors `mvm_hostd::supervisor::audit_segment::CHAIN_CONTINUED`. The two
/// crates cannot share a constant (this one is `no_std` and sits below the
/// host), so the value is pinned by
/// `the_handoff_contract_matches_the_host_writer`.
pub const CHAIN_CONTINUED: &str = "chain.continued";

/// Label carrying the predecessor's final line hash inside the signed body.
/// Mirrors `mvm_hostd::supervisor::audit_segment::LABEL_PREV_TIP`.
pub const LABEL_PREV_TIP: &str = "chain.prev_tip";

/// Label carrying this segment's sequence number.
pub const LABEL_SEGMENT: &str = "chain.segment";

/// Label carrying the sequence number of the segment this one continues.
pub const LABEL_PREV_SEGMENT: &str = "chain.prev_segment";

/// The chain hash a segment's opening entry authorizes, if it is a well-formed
/// continuation record.
///
/// Still only a claim when this returns: it becomes a fact when the signature
/// over `signed_bytes || tip` verifies. Sequence contiguity is checked here so
/// a record cannot assert its own gap and be adopted anyway.
fn continuation_start_hash(entry: &PlanAuditEntry) -> Option<[u8; 32]> {
    if entry.event != CHAIN_CONTINUED {
        return None;
    }
    let segment: u64 = entry.labels.get(LABEL_SEGMENT)?.parse().ok()?;
    let prev: u64 = entry.labels.get(LABEL_PREV_SEGMENT)?.parse().ok()?;
    if segment != prev + 1 {
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(entry.labels.get(LABEL_PREV_TIP)?)
        .ok()?
        .try_into()
        .ok()
}

pub fn verify_audit_chain_bytes(
    content: &str,
    verifying_key: &VerifyingKey,
) -> Result<VerifiedChain, AuditVerifyError> {
    let mut prev_hash = [0u8; 32];
    let mut entries = Vec::new();
    let mut seen_a_line = false;
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
            // Mirrors the host verifier's line-0 rule for rotated chains: a
            // segment after the first opens by claiming its predecessor's final
            // line hash rather than genesis, and that is accepted only when the
            // *signed body* names the identical hash. The signature check below
            // over `signed_bytes || prev_hash` is what authenticates it.
            //
            // This mirror is not optional politeness. The host's own Merkle
            // root builder verifies through this function, so a host that
            // rotated and a verifier that did not learn about handoffs would
            // stop being able to publish a root at all.
            let adopted = continuation_start_hash(&envelope.entry)
                .filter(|tip| !seen_a_line && tip.as_slice() == claimed_prev.as_slice());
            match adopted {
                Some(tip) => prev_hash = tip,
                None => return Err(AuditVerifyError::PrevHashMismatch { line: idx }),
            }
        }
        seen_a_line = true;

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

        let mut to_verify = signed_bytes_for(&envelope, idx)?;
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

/// SHA-256 of `bytes` with no domain-separation prefix. The chain hash
/// each audit line advances the running `prev_hash` by. Shared with
/// `merkle` (the empty-tree Merkle root is the SHA-256 of the empty
/// input, i.e. `hash_line(&[])`).
///
/// Public because the writer must advance the chain by exactly the rule the
/// verifiers replay. A second definition of this function is a second
/// definition of what the chain *is*: the two would agree until one was
/// edited, and the symptom would be a log that stopped verifying rather
/// than a failing build. Every producer and consumer calls this one.
pub fn hash_line(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Sign `entry` into a chain link that follows `prev_hash`.
///
/// Serializes `entry`, base64-encodes the bytes into `canonical`, signs
/// `entry_bytes || prev_hash`, and returns the complete envelope. This is the
/// pure half of the writer that both `mvm-hostd` and the browser demo share.
pub fn seal<T: Serialize>(
    entry: T,
    prev_hash: [u8; 32],
    signing_key: &SigningKey,
) -> Result<SignedEnvelope<T>, serde_json::Error> {
    let entry_bytes = serde_json::to_vec(&entry)?;
    let canonical = URL_SAFE_NO_PAD.encode(&entry_bytes);
    let mut to_sign = entry_bytes;
    to_sign.extend_from_slice(&prev_hash);
    let signature = signing_key.sign(&to_sign);
    Ok(SignedEnvelope {
        entry,
        canonical: Some(canonical),
        prev_hash: URL_SAFE_NO_PAD.encode(prev_hash),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Decode exactly 32 bytes from a hex string. A tiny local decoder so
/// the crate needs no `hex` dependency; the `Err` is a human-readable
/// reason so each caller can wrap it into its own error type (`verify`
/// into [`AuditVerifyError::KeyDecode`], `merkle` into its hex-decode
/// variant).
pub(crate) fn decode_hex32(input: &str) -> Result<[u8; 32], String> {
    let s = input.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars (32 bytes), got {}", s.len()));
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

/// Encode 32 bytes as 64 lowercase hex chars. The inverse of
/// [`decode_hex32`], colocated so the crate's hex codec lives in one
/// place; `merkle` renders sibling and root hashes through it.
pub(crate) fn encode_hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(hex_nibble_char(b >> 4));
        out.push(hex_nibble_char(b & 0x0f));
    }
    out
}

fn hex_nibble_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        // `n` is always a single hex nibble: every caller masks with
        // `>> 4` or `& 0x0f`, so values above 15 are unreachable.
        _ => '0',
    }
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("non-hex character {:?}", c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::{Signer, SigningKey};

    const SEED: [u8; 32] = [7u8; 32];

    fn signing_key() -> SigningKey {
        // Deterministic key from a fixed seed — no RNG dependency.
        SigningKey::from_bytes(&SEED)
    }

    fn entry(event: &str, bundle: Option<&str>) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: "2026-06-03T12:00:00Z".to_string(),
            tenant: "tenant-a".to_string(),
            plan_id: "plan-1".to_string(),
            plan_version: 1,
            bundle_id: bundle.map(str::to_string),
            bundle_version: bundle.map(|_| 2),
            image_name: "worker".to_string(),
            image_sha256: "abc123".to_string(),
            event: event.to_string(),
            caller_commitment: None,
            labels: BTreeMap::new(),
        }
    }

    /// Which on-disk shape a fixture chain is written in.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Shape {
        /// Pre-`canonical`: the signed bytes are not written down, so a
        /// verifier has to re-derive them. Still on disk in the wild.
        Legacy,
        /// The signed bytes are stored on the line.
        Stored,
    }

    /// Re-implement the supervisor's writer so tests produce genuine chains:
    /// sign `to_vec(entry) || prev_hash`, then emit the envelope and advance
    /// the chain by hashing the written line.
    fn build_chain_shaped(key: &SigningKey, entries: &[PlanAuditEntry], shape: Shape) -> String {
        let mut prev_hash = [0u8; 32];
        let mut out = String::new();
        for e in entries {
            let entry_bytes = serde_json::to_vec(e).unwrap();
            let mut to_sign = entry_bytes.clone();
            to_sign.extend_from_slice(&prev_hash);
            let sig = key.sign(&to_sign);
            let env = SignedEnvelope {
                entry: e.clone(),
                canonical: match shape {
                    Shape::Legacy => None,
                    Shape::Stored => Some(URL_SAFE_NO_PAD.encode(&entry_bytes)),
                },
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

    fn build_chain(key: &SigningKey, entries: &[PlanAuditEntry]) -> String {
        build_chain_shaped(key, entries, Shape::Stored)
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
    fn caller_commitment_is_covered_by_the_audit_signature() {
        let key = signing_key();
        let mut committed = entry("plan.admitted", None);
        committed.caller_commitment = Some(crate::plan::CallerCommitment::from_bytes([1; 32]));
        let chain = build_chain(&key, &[committed]);
        assert!(verify_audit_chain_bytes(&chain, &key.verifying_key()).is_ok());

        let mut envelope: SignedEnvelope =
            serde_json::from_str(chain.trim()).expect("envelope parses");
        envelope.entry.caller_commitment = Some(crate::plan::CallerCommitment::from_bytes([2; 32]));
        let tampered = format!(
            "{}\n",
            serde_json::to_string(&envelope).expect("tampered envelope serializes")
        );
        assert!(verify_audit_chain_bytes(&tampered, &key.verifying_key()).is_err());
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

    /// Editing a line in place is refused whichever copy of the entry the
    /// editor reaches.
    ///
    /// A blind edit hits the readable `entry` and the stored bytes are
    /// base64, so it is caught as a disagreement between the two rather than
    /// as a bad signature — a sharper answer to the same question. An editor
    /// who decodes and rewrites the stored bytes hits the signature instead.
    /// Both are refused; neither can produce a line that verifies.
    #[test]
    fn tampering_with_either_copy_of_the_entry_is_refused() {
        let key = signing_key();
        let chain = build_chain(&key, &[entry("plan.admitted", None)]);

        let readable_edit = chain.replace("plan.admitted", "plan.ADMITTED");
        assert_eq!(
            verify_audit_chain_bytes(&readable_edit, &key.verifying_key()).unwrap_err(),
            AuditVerifyError::EntryCanonicalMismatch { line: 0 },
            "editing the readable half must be caught"
        );

        // Now rewrite the signed bytes too, so both halves agree on the lie.
        let mut env: SignedEnvelope = serde_json::from_str(chain.trim()).unwrap();
        env.entry.event = "plan.ADMITTED".to_string();
        env.canonical = Some(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&env.entry).unwrap()));
        let both_edited = format!("{}\n", serde_json::to_string(&env).unwrap());
        assert_eq!(
            verify_audit_chain_bytes(&both_edited, &key.verifying_key()).unwrap_err(),
            AuditVerifyError::SignatureInvalid { line: 0 },
            "a consistent forgery must still fail the signature"
        );

        // And the same edit on a pre-`canonical` line still fails the way it
        // always did.
        let legacy = build_chain_shaped(&key, &[entry("plan.admitted", None)], Shape::Legacy)
            .replace("plan.admitted", "plan.ADMITTED");
        assert_eq!(
            verify_audit_chain_bytes(&legacy, &key.verifying_key()).unwrap_err(),
            AuditVerifyError::SignatureInvalid { line: 0 },
        );
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

    /// Logs written before the signed bytes were stored keep verifying. There
    /// is no cutover: evidence somebody already holds must not stop verifying
    /// because the writer improved.
    #[test]
    fn a_chain_written_without_stored_bytes_still_verifies() {
        let key = signing_key();
        let chain = build_chain_shaped(&key, &[entry("plan.admitted", None)], Shape::Legacy);
        assert!(
            !chain.contains("canonical"),
            "the fixture must be in the old shape"
        );
        let out = verify_audit_chain_bytes(&chain, &key.verifying_key()).unwrap();
        assert_eq!(out.count, 1);
    }

    /// The whole point of storing the bytes: verification no longer depends on
    /// this crate re-serializing an entry the way the writer did.
    ///
    /// The fixture signs a permutation of the entry's field order — semantically
    /// identical, byte-different from what `serde_json::to_vec` emits here. Under
    /// the old re-serialize rule this genuine line is rejected; reading the bytes
    /// off the line accepts it. That is exactly the failure a future field
    /// addition would cause across a whole historical log.
    #[test]
    fn a_line_whose_signed_bytes_differ_from_our_serializer_still_verifies() {
        let key = signing_key();
        let e = entry("plan.admitted", None);

        // Re-emit the same entry with keys in a different order.
        let value: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&e).unwrap())
            .expect("entry as a json object");
        let map = value.as_object().expect("object");
        let permuted: serde_json::Map<String, serde_json::Value> = map
            .iter()
            .rev()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let signed_bytes = serde_json::to_vec(&serde_json::Value::Object(permuted)).unwrap();
        assert_ne!(
            signed_bytes,
            serde_json::to_vec(&e).unwrap(),
            "the fixture must differ from our own serialization"
        );

        let prev_hash = [0u8; 32];
        let mut to_sign = signed_bytes.clone();
        to_sign.extend_from_slice(&prev_hash);
        let sig = key.sign(&to_sign);
        let env = SignedEnvelope {
            entry: e,
            canonical: Some(URL_SAFE_NO_PAD.encode(&signed_bytes)),
            prev_hash: URL_SAFE_NO_PAD.encode(prev_hash),
            signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        };
        let line = format!("{}\n", serde_json::to_string(&env).unwrap());

        let out = verify_audit_chain_bytes(&line, &key.verifying_key())
            .expect("a genuine line must verify from the bytes it carries");
        assert_eq!(out.count, 1);

        // And the same line without its stored bytes is rejected — which is
        // what every historical line would have done after a schema change.
        let mut legacy = env.clone();
        legacy.canonical = None;
        let legacy_line = format!("{}\n", serde_json::to_string(&legacy).unwrap());
        assert!(
            matches!(
                verify_audit_chain_bytes(&legacy_line, &key.verifying_key()),
                Err(AuditVerifyError::SignatureInvalid { line: 0 })
            ),
            "without the stored bytes the same entry cannot be verified"
        );
    }

    /// The readable copy cannot say something the signature does not cover.
    #[test]
    fn a_readable_entry_that_disagrees_with_the_signed_bytes_is_refused() {
        let key = signing_key();
        let chain = build_chain(&key, &[entry("plan.admitted", None)]);
        let mut env: SignedEnvelope = serde_json::from_str(chain.trim()).unwrap();

        // Rewrite only the human-readable half.
        env.entry.event = "plan.launched".to_string();
        let line = format!("{}\n", serde_json::to_string(&env).unwrap());

        assert!(
            matches!(
                verify_audit_chain_bytes(&line, &key.verifying_key()),
                Err(AuditVerifyError::EntryCanonicalMismatch { line: 0 })
            ),
            "a doctored readable entry must be caught, not silently ignored"
        );
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
    #[test]
    fn hash_line_is_plain_sha256_of_the_line() {
        // Pins the rule itself, not just that two callers agree. Until now
        // this function was written out three times -- here, and twice in
        // mvm-hostd -- so "the chain hash" had three definitions that
        // happened to match. Anything that changes this (a domain-separation
        // prefix, a different digest, hashing the trimmed line) breaks every
        // chain already on disk, and should have to edit this test to do it.
        use sha2::{Digest, Sha256};

        let line = br#"{"entry":{},"prev_hash":"","signature":""}"#;
        let mut expected = Sha256::new();
        expected.update(line);
        let expected: [u8; 32] = expected.finalize().into();

        assert_eq!(hash_line(line), expected);
        // Genesis: the empty input, which merkle also relies on.
        assert_eq!(hash_line(&[]), {
            let mut h = Sha256::new();
            h.update([]);
            let out: [u8; 32] = h.finalize().into();
            out
        });
    }
}
