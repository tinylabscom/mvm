//! Verifier for `.mvmev` evidence archives.
//!
//! Reports **three independent results** and does not collapse them:
//!
//! | Result | Basis |
//! |---|---|
//! | integrity | checked from the archive |
//! | inclusion | checked from the archive |
//! | completeness | checked only for a tenant-scoped archive; otherwise host-attested |
//!
//! The split is the point. A plan-scoped archive is a subsequence of the log,
//! and a subsequence carries nothing that would attest its own completeness —
//! the host asserts it. Printing one green line over all three would report an
//! assertion as a check, which is precisely the claim this format exists to
//! avoid making.
//!
//! Each result is computed independently: one failing does not short-circuit
//! the others, so a report names every problem rather than the first.
//!
//! # Why inclusion is two checks, not one
//!
//! [`mvm_contract::merkle::verify_membership`] attests that a leaf is in the
//! host-signed tree. It says nothing about *which* leaf the member beside it
//! came from — a proof built for the wrong leaf verifies perfectly well and
//! attests the wrong entry. So inclusion also requires each proof's
//! `leaf_index` to equal the index its own leaf citation claims.

use std::collections::BTreeMap;
use std::io::Read;

use anyhow::{Context, Result, bail};
use ed25519_dalek::VerifyingKey;
use mvm_contract::merkle::{InclusionProof, verify_membership};
use mvm_core::plan::bundle::ensure_safe_path;
use mvm_core::receipt::SignedExecutionReceipt;
use mvm_core::receipt_archive::{Completeness, SignedEvidenceManifest};
use sha2::{Digest, Sha256};

use crate::audit::receipt_archive::{HOST_PUBKEY_MEMBER, MANIFEST_MEMBER, proof_member_for};

/// Largest archive this verifier will read into memory.
///
/// Matches the existing admitted-artifact ceiling rather than inventing a
/// second number: an archive is an artifact, and a reader that allocated on an
/// attacker-chosen length would be the bug this bound exists to stop.
pub const ARCHIVE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Outcome of one checkable property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// The verifier checked this and it held.
    Passed,
    /// The verifier checked this and it did not hold.
    Failed(String),
}

impl CheckResult {
    /// Whether this check held.
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Outcome of the scope-completeness property.
///
/// Three arms, not two. "The host said so" is neither a pass nor a failure,
/// and folding it into `Passed` is how an assertion gets reported as a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletenessResult {
    /// The archive carried every leaf and the count matched the signed root.
    Derived,
    /// The host asserted coverage; a filtered archive cannot show it.
    Attested,
    /// The archive claimed derivable coverage and did not have it.
    Failed(String),
}

impl CompletenessResult {
    /// Whether this result is a failure. `Attested` is not.
    #[must_use]
    pub fn failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

/// What one archive verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Manifest signature, member digests, and receipt self-consistency.
    pub integrity: CheckResult,
    /// Every proof binds to the signed root, at its own receipt's leaf.
    pub inclusion: CheckResult,
    /// Whether scope coverage was derived, asserted, or contradicted.
    pub completeness: CompletenessResult,
}

impl VerifyReport {
    /// Process exit code: bit 1 integrity, bit 2 inclusion, bit 4 completeness.
    ///
    /// Zero means nothing failed. An `Attested` completeness contributes no
    /// bit — it is not a failure, and the caller reports it in words.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        let mut code = 0;
        if !self.integrity.passed() {
            code |= 1;
        }
        if !self.inclusion.passed() {
            code |= 2;
        }
        if self.completeness.failed() {
            code |= 4;
        }
        code
    }

    /// Whether every checked property held.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.exit_code() == 0
    }
}

/// Read, then check, an evidence archive.
///
/// Structural problems — oversize input, an unreadable tar, a missing
/// manifest, an unsafe member path — are hard errors rather than report
/// entries: there is nothing to report *about* if the archive cannot be
/// opened. Everything the archive claims about itself becomes a result.
pub fn verify_archive(bytes: &[u8]) -> Result<VerifyReport> {
    if bytes.len() > ARCHIVE_MAX_BYTES {
        bail!(
            "archive is {} bytes, over the {ARCHIVE_MAX_BYTES}-byte limit",
            bytes.len()
        );
    }
    let members = read_members(bytes)?;

    let manifest_bytes = members
        .get(MANIFEST_MEMBER)
        .with_context(|| format!("archive has no {MANIFEST_MEMBER}"))?;
    let signed: SignedEvidenceManifest =
        serde_json::from_slice(manifest_bytes).context("decoding the archive manifest")?;

    let vk = read_host_key(&members)?;

    Ok(VerifyReport {
        integrity: check_integrity(&signed, &members, &vk),
        inclusion: check_inclusion(&signed, &members, &vk),
        completeness: check_completeness(&signed),
    })
}

/// Read every tar member, bounded and path-checked.
fn read_members(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    let mut out = BTreeMap::new();
    let mut total = 0usize;
    for entry in archive.entries().context("reading archive entries")? {
        let mut entry = entry.context("reading an archive entry")?;
        let name = entry
            .path()
            .context("archive member has an unreadable path")?
            .to_string_lossy()
            .into_owned();
        // Refused before any read, and long before anything could be written:
        // a member name is attacker-influenced the moment an archive arrives.
        ensure_safe_path(&name)
            .map_err(|e| anyhow::anyhow!("archive member path {name:?} rejected: {e}"))?;
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("reading archive member {name:?}"))?;
        total = total.saturating_add(buf.len());
        if total > ARCHIVE_MAX_BYTES {
            bail!("archive members exceed the {ARCHIVE_MAX_BYTES}-byte limit when expanded");
        }
        out.insert(name, buf);
    }
    Ok(out)
}

fn read_host_key(members: &BTreeMap<String, Vec<u8>>) -> Result<VerifyingKey> {
    let raw = members
        .get(HOST_PUBKEY_MEMBER)
        .with_context(|| format!("archive has no {HOST_PUBKEY_MEMBER}"))?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{HOST_PUBKEY_MEMBER} must be 32 bytes, got {}", raw.len()))?;
    VerifyingKey::from_bytes(&arr).context("decoding the embedded host key")
}

/// Manifest signature, signer binding, member digests, receipt self-consistency.
fn check_integrity(
    signed: &SignedEvidenceManifest,
    members: &BTreeMap<String, Vec<u8>>,
    vk: &VerifyingKey,
) -> CheckResult {
    if let Err(e) = signed.verify() {
        return CheckResult::Failed(format!("manifest signature: {e}"));
    }
    // The manifest verifies under whatever key `signed_by` names. That is only
    // evidence about *this host* if the embedded key is that same key.
    let embedded_did = mvm_core::did_key::DidKey::from_verifying_key(*vk).to_did_key();
    if embedded_did != signed.signed_by {
        return CheckResult::Failed(format!(
            "embedded host key is {embedded_did}, manifest was signed by {}",
            signed.signed_by
        ));
    }

    for (name, want) in &signed.manifest.members {
        let Some(bytes) = members.get(name) else {
            return CheckResult::Failed(format!("manifest names member {name}, archive lacks it"));
        };
        let got = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        if &got != want {
            return CheckResult::Failed(format!("member {name}: digest {got} != manifest {want}"));
        }
    }

    for leaf in &signed.manifest.leaves {
        if !leaf.member.starts_with("receipts/") {
            continue;
        }
        let Some(bytes) = members.get(&leaf.member) else {
            return CheckResult::Failed(format!("receipt member {} missing", leaf.member));
        };
        let receipt: SignedExecutionReceipt = match serde_json::from_slice(bytes) {
            Ok(r) => r,
            Err(e) => return CheckResult::Failed(format!("decoding {}: {e}", leaf.member)),
        };
        if let Err(e) = receipt.verify() {
            return CheckResult::Failed(format!("receipt {}: {e}", leaf.member));
        }
    }
    CheckResult::Passed
}

/// Every leaf's proof binds to the signed root, at that leaf's own index.
fn check_inclusion(
    signed: &SignedEvidenceManifest,
    members: &BTreeMap<String, Vec<u8>>,
    vk: &VerifyingKey,
) -> CheckResult {
    for leaf in &signed.manifest.leaves {
        let proof_member = proof_member_for(leaf.index);
        let Some(proof_bytes) = members.get(&proof_member) else {
            return CheckResult::Failed(format!(
                "leaf {} ({}) has no proof at {proof_member}",
                leaf.index, leaf.member
            ));
        };
        let proof: InclusionProof = match serde_json::from_slice(proof_bytes) {
            Ok(p) => p,
            Err(e) => return CheckResult::Failed(format!("decoding {proof_member}: {e}")),
        };
        if let Err(e) = verify_membership(
            &proof,
            &signed.manifest.audit_root,
            vk,
            &signed.manifest.tenant,
        ) {
            return CheckResult::Failed(format!("{proof_member}: {e}"));
        }
        // Membership alone would accept a proof for a different leaf: valid
        // arithmetic, wrong entry. The binding to this leaf's own index is
        // what makes the proof evidence about this leaf.
        if proof.leaf_index != leaf.index {
            return CheckResult::Failed(format!(
                "leaf {} cites {} but {proof_member} proves leaf {}",
                leaf.index, leaf.member, proof.leaf_index
            ));
        }
    }
    CheckResult::Passed
}

/// Derived for a tenant-scoped archive; otherwise the host's assertion.
fn check_completeness(signed: &SignedEvidenceManifest) -> CompletenessResult {
    match signed.manifest.completeness {
        Completeness::Attested => CompletenessResult::Attested,
        Completeness::Derivable => {
            let have = signed.manifest.leaves.len() as u64;
            let want = signed.manifest.audit_root.tree_size;
            if have == want {
                CompletenessResult::Derived
            } else {
                CompletenessResult::Failed(format!(
                    "archive claims derivable coverage but carries {have} leaves \
                     for a tree of {want}"
                ))
            }
        }
    }
}
