//! Host-side Merkle transparency-log root + inclusion-proof builder.
//!
//! The chain-signed audit log (`<audit_dir>/<tenant>.jsonl`) is a stream of
//! [`SignedEnvelope`](crate::supervisor::SignedEnvelope) JSON lines. This
//! module turns that stream into RFC 6962 transparency-log artifacts: a
//! Merkle root over the whole log and an `O(log n)` inclusion proof for a
//! single line. All the tree math lives in
//! [`mvm_contract::merkle`] (the same `no_std` code a browser runs); this
//! module only supplies the leaf bytes and the fail-closed policy.
//!
//! ## Leaf bytes
//!
//! Each leaf is one `SignedEnvelope` JSON line **verbatim** — the exact
//! bytes `verify_audit_chain` re-hashes to advance the chain, in file
//! order. The verifier re-hashes `InclusionProof::leaf_line` the same way,
//! so the host's leaf bytes and the verifier's leaf bytes are identical
//! (the CI cross-check test pins this).
//!
//! ## Fail-closed
//!
//! A root is only ever built over a chain that
//! [`verify_audit_chain`](crate::supervisor::verify_audit_chain) accepts.
//! A tampered, reordered, or truncated chain refuses here rather than
//! publishing a root that would attest a corrupt log.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_contract::merkle::{InclusionProof, build_inclusion_proof, merkle_root};

use crate::audit::emitter;
use mvm_contract::verify::verify_audit_chain_bytes;

/// Read a tenant's audit lines as Merkle leaves, in file order, **after**
/// verifying the chain is intact — from the SAME bytes. The file is read
/// once into a buffer; the chain is verified over that buffer and the leaves
/// are derived from it, so the root is provably over exactly the verified
/// bytes (no read → verify → re-read TOCTOU window). Empty lines are skipped
/// (matching the chain verifier), so every returned element is a genuine
/// `SignedEnvelope` line — the exact bytes the inclusion verifier re-hashes.
///
/// Fails closed if the chain does not verify under `vk`: a corrupt log
/// never yields a root. Public so the CLI `prove` verb can resolve a
/// selector against the identical leaf set the root and proofs are built
/// over (a single reader, so indices can't drift).
pub fn read_leaves(audit_dir: &Path, tenant: &str, vk: &VerifyingKey) -> Result<Vec<String>> {
    // Spans the whole segment set, oldest first, not just the active segment.
    //
    // A root over the active segment alone would be a root that silently
    // attests less than it used to the first time a host rotates — the same
    // tree_size arithmetic, a quietly smaller log underneath it, and every
    // previously issued inclusion proof pointing at leaf indices that no longer
    // mean what they meant. Spanning the set keeps leaf indices globally
    // ordered across rotations, which is the property those proofs rest on.
    //
    // `read_verified_set` verifies each segment *and* the handoffs between
    // them, from the same buffers it returns, so the fail-closed policy now
    // covers "a segment was removed" as well as "a line was edited".
    match crate::supervisor::audit_set::read_verified_set(audit_dir, tenant, vk) {
        Ok(segments) => Ok(segments
            .iter()
            .flat_map(|s| s.lines().into_iter().map(str::to_string))
            .collect()),
        // An un-rotated host has no segment set to speak of; fall back to the
        // single-file read so a chain that never rotated behaves exactly as it
        // did before, including its error text.
        Err(crate::supervisor::audit_set::SegmentSetError::NoChain { .. }) => {
            let path = emitter::audit_path_for_tenant(audit_dir, tenant);
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading audit chain {}", path.display()))?;
            verify_audit_chain_bytes(&content, vk).map_err(|e| {
                anyhow::anyhow!(
                    "refusing to build a Merkle root over an unverified audit chain at {}: {e}",
                    path.display()
                )
            })?;
            Ok(content
                .lines()
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect())
        }
        Err(e) => Err(anyhow::anyhow!(
            "refusing to build a Merkle root over an unverified audit chain for {tenant}: {e}"
        )),
    }
}

/// Build the Merkle root over `tenant`'s audit chain in `audit_dir`,
/// returning the root hash and the number of leaves (`tree_size`). The chain
/// is verified under `vk` first; a corrupt log yields no root.
pub fn build_root_in(audit_dir: &Path, tenant: &str, vk: &VerifyingKey) -> Result<([u8; 32], u64)> {
    let leaves = read_leaves(audit_dir, tenant, vk)?;
    let tree_size = leaves.len() as u64;
    Ok((merkle_root(&leaves), tree_size))
}

/// Build an inclusion proof for the leaf at `leaf_index` in `tenant`'s audit
/// chain in `audit_dir`. The chain is verified under `vk` first.
pub fn build_inclusion_in(
    audit_dir: &Path,
    tenant: &str,
    vk: &VerifyingKey,
    leaf_index: usize,
) -> Result<InclusionProof> {
    let leaves = read_leaves(audit_dir, tenant, vk)?;
    build_inclusion_proof(&leaves, leaf_index)
        .map_err(|e| anyhow::anyhow!("building inclusion proof for leaf {leaf_index}: {e}"))
}

/// Build and sign a transparency-log root over `tenant`'s chain, without
/// writing anything.
///
/// [`crate::audit::emitter::AuditEmitter::publish_root`] is this plus the
/// sidecar write. Split out because an evidence archive needs the signed root
/// as a value and must not leave a published-root file behind as a side
/// effect of exporting — but both paths have to produce byte-identical
/// signing material, so there is one implementation.
pub fn sign_root_in(
    audit_dir: &Path,
    tenant: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<mvm_contract::merkle::SignedAuditRoot> {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    let vk = signing_key.verifying_key();
    let (root, tree_size) = build_root_in(audit_dir, tenant, &vk)?;
    let root_hash = hex::encode(root);
    let timestamp = chrono::Utc::now().to_rfc3339();
    let payload =
        mvm_contract::merkle::root_signing_bytes(tenant, tree_size, &root_hash, &timestamp)
            .map_err(|e| anyhow::anyhow!("serializing Merkle root signing payload: {e}"))?;
    let signature = signing_key.sign(&payload);
    Ok(mvm_contract::merkle::SignedAuditRoot {
        tenant: tenant.to_string(),
        tree_size,
        root_hash,
        timestamp,
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        signer_pubkey: hex::encode(vk.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry};
    use ed25519_dalek::SigningKey;
    use mvm_contract::merkle::{verify_inclusion, verify_signed_root};
    use mvm_core::plan::{PlanId, TenantId};
    use rand::Rng;
    use std::collections::BTreeMap;

    fn fresh_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn entry(tenant: &str, event: &str) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: chrono::Utc::now(),
            tenant: TenantId(tenant.to_string()),
            plan_id: PlanId(format!("plan-{event}")),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "img".to_string(),
            image_sha256: "abc123".to_string(),
            event: event.to_string(),
            labels: BTreeMap::new(),
        }
    }

    /// Seed a real chain of `n` entries via `FileAuditSigner` and return the
    /// dir, the signer's key, and the raw leaf lines.
    fn seed_chain(n: usize) -> (tempfile::TempDir, SigningKey, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let signer = FileAuditSigner::open(key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for i in 0..n {
            rt.block_on(signer.sign_and_emit(&entry("local", &format!("e-{i}"))))
                .unwrap();
        }
        let content = std::fs::read_to_string(dir.path().join("local.jsonl")).unwrap();
        let lines: Vec<String> = content.lines().map(str::to_string).collect();
        (dir, key, lines)
    }

    #[test]
    fn build_root_matches_direct_merkle_root_over_lines() {
        let (dir, key, lines) = seed_chain(5);
        let vk = key.verifying_key();
        let (root, size) = build_root_in(dir.path(), "local", &vk).unwrap();
        assert_eq!(size, 5);
        // The host builder's root is exactly `merkle_root` over the verbatim
        // chain lines — no re-encoding of the leaf bytes.
        assert_eq!(root, merkle_root(&lines));
    }

    #[test]
    fn build_root_refuses_a_tampered_chain() {
        let (dir, key, _lines) = seed_chain(3);
        let vk = key.verifying_key();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, content.replacen("e-0", "e-hijacked", 1)).unwrap();
        // A chain that no longer verifies must not yield a root.
        assert!(build_root_in(dir.path(), "local", &vk).is_err());
        assert!(build_inclusion_in(dir.path(), "local", &vk, 0).is_err());
    }

    #[test]
    fn build_root_refuses_wrong_key() {
        let (dir, _key, _lines) = seed_chain(2);
        let other = fresh_key().verifying_key();
        assert!(build_root_in(dir.path(), "local", &other).is_err());
    }

    #[test]
    fn every_built_proof_verifies_against_the_built_root() {
        for n in [1usize, 2, 3, 5, 8] {
            let (dir, key, _lines) = seed_chain(n);
            let vk = key.verifying_key();
            let (root, size) = build_root_in(dir.path(), "local", &vk).unwrap();
            assert_eq!(size, n as u64);
            for i in 0..n {
                let proof = build_inclusion_in(dir.path(), "local", &vk, i).unwrap();
                assert_eq!(proof.leaf_index, i as u64);
                assert_eq!(proof.tree_size, n as u64);
                let recomputed = verify_inclusion(&proof).expect("proof must verify");
                assert_eq!(recomputed, root, "leaf {i} of {n} folded to the wrong root");
                assert_eq!(proof.root, hex::encode(root));
            }
        }
    }

    // The anti-drift guarantee: build the root + a proof on the HOST side,
    // then verify them with the `mvm_contract::merkle` verifier (the exact
    // code a browser runs). Agreement proves the host's leaf bytes == the
    // verifier's leaf bytes. Sibling to
    // `mvm_verify_matches_supervisor_chain` in `supervisor::audit_file`.
    #[test]
    fn host_built_artifacts_verify_with_no_std_verifier() {
        let (dir, key, _lines) = seed_chain(6);
        let vk = key.verifying_key();
        let (root, size) = build_root_in(dir.path(), "local", &vk).unwrap();

        // A host-built proof verifies through the wasm-clean verifier and
        // folds to the same root.
        let proof = build_inclusion_in(dir.path(), "local", &vk, 4).unwrap();
        assert_eq!(verify_inclusion(&proof).unwrap(), root);
        assert_eq!(proof.root, hex::encode(root));

        // A proof for the WRONG leaf must not verify against the real root:
        // re-point the leaf_index and the fold lands on a different root.
        let mut wrong = build_inclusion_in(dir.path(), "local", &vk, 4).unwrap();
        wrong.leaf_index = 2;
        assert!(
            verify_inclusion(&wrong).map(|r| r != root).unwrap_or(true),
            "a wrong-leaf proof must not fold to the real root"
        );

        // And a host-signed root over the same tree verifies with the
        // no_std signed-root verifier, then a byte-flip on the root_hash is
        // rejected.
        let timestamp = "2026-07-26T00:00:00Z";
        let root_hex = hex::encode(root);
        let payload =
            mvm_contract::merkle::root_signing_bytes("local", size, &root_hex, timestamp).unwrap();
        use ed25519_dalek::Signer;
        let sig = key.sign(&payload);
        use base64::Engine;
        let mut signed = mvm_contract::merkle::SignedAuditRoot {
            tenant: "local".to_string(),
            tree_size: size,
            root_hash: root_hex,
            timestamp: timestamp.to_string(),
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            signer_pubkey: hex::encode(vk.to_bytes()),
        };
        assert_eq!(verify_signed_root(&signed, &vk), Ok(()));
        signed.root_hash = hex::encode([0xffu8; 32]);
        assert!(verify_signed_root(&signed, &vk).is_err());
    }
}
