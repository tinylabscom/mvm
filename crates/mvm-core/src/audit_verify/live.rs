//! Authenticate particular entries of a tenant's live audit segment in place,
//! without walking the history before them.
//!
//! The full walk ([`super::set::read_verified_set`]) attests every segment
//! from the first, and its cost grows with every entry the host has ever
//! written. A caller that only needs to trust a few entries it can name — one
//! it just appended, or the creation record of a resource it is about to use —
//! can hold each of those entries to what the full walk checks of it instead:
//! the host signature over the exact signed bytes, and the chain link to the
//! line before it. That costs one read of the live segment, bounded by the
//! segment rotation size, and one signature per match.
//!
//! What this deliberately does not do is re-attest the history before the
//! match. History stays verified where history is the question:
//! `mvmctl trust audit verify`, doctor's chain check, and the recovery paths.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;

use super::PlanAuditEntry;

/// The entries of a live segment that matched, each authenticated in place.
#[derive(Debug)]
pub struct LiveMatches {
    /// The live segment the entries were read from.
    pub segment: PathBuf,
    /// Authenticated matching entries, in chain order.
    pub entries: Vec<PlanAuditEntry>,
    /// How many lines were parsed, which is the work that grows per line: the
    /// lines carrying `needle`, never the rest of the segment.
    pub parsed: usize,
}

/// Authenticate every entry of `tenant`'s live segment that contains `needle`
/// verbatim and that `wanted` accepts.
///
/// `needle` is a value the wanted entry carries readably, such as an id. A
/// line without it cannot be a match and is never parsed, so the cost of an
/// unrelated line is one substring search. Every match must carry a valid
/// host signature over its signed bytes and claim the line before it as its
/// predecessor; the first line of the live segment may only be an ordinary
/// entry when the live segment is the first one, since every later segment
/// opens with its continuation record. Any match that fails either check is an
/// error, never a skipped line.
pub fn authenticate_live_entries(
    audit_dir: &Path,
    tenant: &str,
    trusted_key: &VerifyingKey,
    needle: &str,
    wanted: impl Fn(&PlanAuditEntry) -> bool,
) -> Result<LiveMatches> {
    use super::SignedEnvelope;
    use super::set::segment_shape;
    use ed25519_dalek::{Signature, Verifier as _};
    use mvm_contract::verify::{hash_line, signed_bytes_for};

    let (active_seq, active) = segment_shape(audit_dir, tenant)?.active;
    let content = std::fs::read_to_string(&active)
        .with_context(|| format!("reading live audit segment {}", active.display()))?;
    ensure!(
        content.is_empty() || content.ends_with('\n'),
        "live audit segment ends mid-record"
    );
    let lines: Vec<&str> = content.lines().filter(|line| !line.is_empty()).collect();
    let mut entries = Vec::new();
    let mut parsed = 0;
    for (idx, line) in lines.iter().enumerate() {
        if !line.contains(needle) {
            continue;
        }
        parsed += 1;
        let envelope: SignedEnvelope =
            serde_json::from_str(line).context("malformed live audit line")?;
        if !wanted(&envelope.entry) {
            continue;
        }
        let prev = match idx {
            0 => {
                ensure!(
                    active_seq == 1,
                    "audit entry is not chained into the live segment"
                );
                [0u8; 32]
            }
            _ => hash_line(lines[idx - 1].as_bytes()),
        };
        let claimed_prev: [u8; 32] = decode_b64(&envelope.prev_hash)
            .context("audit entry prev_hash")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("audit entry prev_hash is not 32 bytes"))?;
        ensure!(
            claimed_prev == prev,
            "audit entry is not chained to the entry before it"
        );
        let signature: [u8; 64] = decode_b64(&envelope.signature)
            .context("audit entry signature")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("audit entry signature is not 64 bytes"))?;
        // Also proves the readable entry is the one that was signed.
        let mut signed = signed_bytes_for(&envelope, idx)
            .map_err(|e| anyhow::anyhow!("audit entry is not authentic: {e}"))?;
        signed.extend_from_slice(&prev);
        trusted_key
            .verify(&signed, &Signature::from_bytes(&signature))
            .map_err(|_| anyhow::anyhow!("audit entry signature is invalid"))?;
        entries.push(envelope.entry);
    }
    Ok(LiveMatches {
        segment: active,
        entries,
        parsed,
    })
}

fn decode_b64(text: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text)?)
}
