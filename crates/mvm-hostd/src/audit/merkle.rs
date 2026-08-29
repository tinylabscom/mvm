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
//!
//! ## What the last root pays for
//!
//! Verifying every line from genesis costs `O(all history)`, and a root is
//! published at every admission — so on a host that has launched a lot, the
//! boot path was re-verifying tens of thousands of entries to add a handful.
//! That is quadratic in a host's lifetime and it sat in the launch budget.
//!
//! A published [`SignedAuditRoot`](mvm_contract::merkle::SignedAuditRoot) is
//! already a host-signed statement that the first `tree_size` leaves hash to
//! `root_hash`. So when the leaves read now still hash to it under that
//! signature, the prefix has been attested at the same strength a genesis walk
//! would establish line by line, and only the lines appended since need
//! walking. That is what
//! `leaves_over_attested_prefix` does, and the seed it rests on is a host
//! signature rather than a stored integer — a stronger anchor than the
//! [`ChainCheckpoint`](crate::supervisor::audit_file::ChainCheckpoint) that
//! `doctor` resumes from, and the reason this one is not confined to a health
//! check.
//!
//! It never accuses. Every doubt — no root, a stale one, a prefix that no
//! longer hashes to it — declines to the genesis walk, so every refusal this
//! module emits is still anchored at genesis.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_contract::merkle::{
    InclusionProof, SignedAuditRoot, build_inclusion_proof, leaf_hash, merkle_root,
    merkle_root_of_leaf_hashes, verify_signed_root,
};

use crate::audit::emitter;
use crate::audit::leaf_cache;
use crate::supervisor::audit_file::verify_chain_bytes_resuming;
use crate::supervisor::audit_set::{SegmentContent, read_topology_verified_set};
use mvm_contract::verify::{hash_line, verify_audit_chain_bytes};

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
///
/// Which lines are verified *here* depends on whether the last published root
/// still describes this log — see [`leaves_over_attested_prefix`] for the seed
/// that stands in for the prefix, and what makes it as strong as walking it.
/// Either way the leaves are the same and a chain that does not verify still
/// yields no root; only the work differs.
pub fn read_leaves(audit_dir: &Path, tenant: &str, vk: &VerifyingKey) -> Result<Vec<String>> {
    if let Some(leaves) = leaves_over_attested_prefix(audit_dir, tenant, vk) {
        return Ok(leaves);
    }
    read_leaves_from_genesis(audit_dir, tenant, vk)
}

/// [`read_leaves`], always walking every interior from the genesis anchor.
///
/// The unconditional path, and the only one that ever produces a refusal — see
/// [`leaves_over_attested_prefix`], which declines rather than accuses.
fn read_leaves_from_genesis(
    audit_dir: &Path,
    tenant: &str,
    vk: &VerifyingKey,
) -> Result<Vec<String>> {
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

/// Leaves for a chain whose prefix is attested by the last published root,
/// verifying only what was appended after it.
///
/// A published [`SignedAuditRoot`] is already a host-signed statement of the
/// form "the first `tree_size` leaves of this log hash to `root_hash`". So
/// when the leaves read now still hash to that value under that signature,
/// the prefix has been attested — by the same key, at the same strength, as
/// the per-line signatures a genesis walk would check one at a time. Only the
/// lines appended since need walking, which is what turns a cost that grows
/// with the whole history into one that grows with a single run's entries.
///
/// This is deliberately a stronger seed than [`ChainCheckpoint`] — a stored
/// integer, which is why that fast path is confined to `doctor`. Forging this
/// one means forging a host signature, the same bar as forging the chain.
///
/// Returns `None` rather than an error on *every* doubt: no published root, a
/// root for another tenant, a root that will not verify, one that reaches past
/// the log or back before the live segment, a prefix that no longer hashes to
/// it, or a suffix that will not walk. A mismatch is as consistent with a
/// stale root or a rotation as with tampering, and only the genesis walk can
/// tell those apart — so this path never accuses, it only declines, and every
/// refusal the caller ever emits stays anchored at genesis.
///
/// [`ChainCheckpoint`]: crate::supervisor::audit_file::ChainCheckpoint
fn leaves_over_attested_prefix(
    audit_dir: &Path,
    tenant: &str,
    vk: &VerifyingKey,
) -> Option<Vec<String>> {
    let published = read_published_root(audit_dir, tenant)?;
    if published.tenant != tenant {
        return None;
    }
    verify_signed_root(&published, vk).ok()?;

    // No interior is walked here. The structural checks still are, so a
    // removed or spliced segment refuses exactly as it does on the full path;
    // what the published root is standing in for is the per-line work.
    let segments = read_segment_bytes(audit_dir, tenant, vk)?;
    let active = segments.last().filter(|s| s.active)?;
    let lines: Vec<&str> = segments.iter().flat_map(SegmentContent::lines).collect();
    let active_start = lines.len() - active.lines().len();

    let attested = usize::try_from(published.tree_size).ok()?;
    // A root reaching past the log describes a different log. A root landing
    // before the live segment would need a resume point inside a sealed one,
    // which is reachable but not worth a second seek path: it happens once per
    // rotation, and the genesis walk that follows re-establishes the prefix.
    if attested == 0 || attested > lines.len() || attested < active_start {
        return None;
    }
    if hex::encode(merkle_root(&lines[..attested])) != published.root_hash {
        return None;
    }

    // The seed is the attested prefix's final line hash, which is what the
    // next line's signature commits to. `walk_chain` numbers lines including
    // blank ones; leaf indices skip them, so the resume point is translated
    // rather than reused.
    let seed = hash_line(lines[attested - 1].as_bytes());
    let resume = raw_line_index(&active.content, attested - active_start)?;
    verify_chain_bytes_resuming(&active.content, vk, resume, seed).ok()?;

    Some(lines.into_iter().map(str::to_string).collect())
}

/// The segment set's bytes, oldest first, structurally verified.
///
/// An un-rotated host has no set to walk, and its single chain file is that
/// same list with one element — so the fast path covers it too rather than
/// leaving a cliff at the first rotation.
fn read_segment_bytes(
    audit_dir: &Path,
    tenant: &str,
    vk: &VerifyingKey,
) -> Option<Vec<SegmentContent>> {
    match read_topology_verified_set(audit_dir, tenant, vk) {
        Ok(segments) => Some(segments),
        Err(crate::supervisor::audit_set::SegmentSetError::NoChain { .. }) => {
            let path = emitter::audit_path_for_tenant(audit_dir, tenant);
            Some(vec![SegmentContent {
                seq: 0,
                content: std::fs::read_to_string(&path).ok()?,
                path,
                active: true,
                entries: None,
            }])
        }
        Err(_) => None,
    }
}

/// The published root sidecar, or `None` when there is not a readable one.
fn read_published_root(audit_dir: &Path, tenant: &str) -> Option<SignedAuditRoot> {
    let path = emitter::audit_root_path_for_tenant(audit_dir, tenant);
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Index into `content.lines()` of the `nth`-th non-blank line.
///
/// The two line numberings differ the moment a blank line exists: leaves skip
/// them, `walk_chain` counts them. Resuming at the wrong index would verify
/// the wrong suffix, so the translation is explicit.
fn raw_line_index(content: &str, nth: usize) -> Option<usize> {
    if nth == 0 {
        return Some(0);
    }
    let mut seen = 0;
    for (idx, line) in content.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        seen += 1;
        if seen == nth {
            return Some(idx + 1);
        }
    }
    (seen == nth).then_some(content.lines().count())
}

/// Build the Merkle root over `tenant`'s audit chain in `audit_dir`,
/// returning the root hash and the number of leaves (`tree_size`). The chain
/// is verified under `vk` first; a corrupt log yields no root.
pub fn build_root_in(audit_dir: &Path, tenant: &str, vk: &VerifyingKey) -> Result<([u8; 32], u64)> {
    if let Some(built) = root_over_cached_prefix(audit_dir, tenant, vk) {
        return Ok(built);
    }
    let leaves = read_leaves(audit_dir, tenant, vk)?;
    let tree_size = leaves.len() as u64;
    let root = merkle_root(&leaves);
    seed_leaf_cache(audit_dir, tenant, &leaves);
    Ok((root, tree_size))
}

/// The root, folded from cached leaf hashes plus whatever the live segment has
/// gained since — without reading a sealed segment at all.
///
/// [`leaves_over_attested_prefix`] removed the *verification* of an unchanged
/// prefix; this removes the *reading and hashing* of one. Both rest on the same
/// signature, and the difference is what is asked of it: there, that the
/// prefix's lines are the attested ones; here, that the cached hashes of those
/// lines are. The fold is the check — a cache that does not reproduce the
/// signed root is discarded, so the cache is never believed, only confirmed.
///
/// The live segment is still read in full every time, and its new lines are
/// verified against the chain exactly as before. Only the part a published root
/// already covers comes from cache.
///
/// Declines, never accuses — same contract as [`leaves_over_attested_prefix`],
/// and for the same reason. Every path out of here that is not a fold over an
/// attested prefix hands the question to the genesis walk.
fn root_over_cached_prefix(
    audit_dir: &Path,
    tenant: &str,
    vk: &VerifyingKey,
) -> Option<([u8; 32], u64)> {
    let published = read_published_root(audit_dir, tenant)?;
    if published.tenant != tenant {
        return None;
    }
    verify_signed_root(&published, vk).ok()?;

    let cache = leaf_cache::read(audit_dir, tenant)?;
    if cache.tree_size() != published.tree_size {
        return None;
    }

    // The fold is the whole trust argument: these hashes are the ones the host
    // signed for, or they are not used.
    if !cache.folds_to(&published.root_hash) {
        return None;
    }

    // The fold says nothing about the files those leaves came from. The set's
    // shape does, cheaply — a lost segment must reach the genesis walk, which
    // names it, rather than being folded over as though nothing were missing.
    let shape = crate::supervisor::audit_set::segment_shape(audit_dir, tenant).ok()?;
    if shape.active.0 != cache.active_seq || shape.sealed.len() != cache.sealed.len() {
        return None;
    }
    if sealed_fingerprints(&shape)? != cache.sealed {
        return None;
    }

    // The live segment is read in full whatever happens, so the portion the
    // cache claims is checked line by line rather than assumed. Sealed
    // segments buy their speed by not being read; this one does not, and an
    // edit here is caught at publish time exactly as it was before.
    let content = std::fs::read_to_string(&shape.active.1).ok()?;
    let active_lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    let already = usize::try_from(cache.prefix_lines_in_active).ok()?;
    if already > active_lines.len() {
        return None;
    }
    let cached_active = cache.active_prefix_hashes()?;
    if cached_active.len() != already
        || active_lines[..already]
            .iter()
            .zip(cached_active)
            .any(|(line, cached)| leaf_hash(line.as_bytes()) != *cached)
    {
        return None;
    }

    // The suffix is the part no published root covers, so it is verified in
    // full, seeded from the attested prefix's final line.
    let appended = &active_lines[already..];
    if !appended.is_empty() {
        // `already == 0` puts that final line in the *previous* segment, which
        // this path deliberately did not read. That happens once per rotation;
        // hand it to the genesis walk rather than growing a second seek path.
        if already == 0 {
            return None;
        }
        let seed = hash_line(active_lines[already - 1].as_bytes());
        let resume = raw_line_index(&content, already)?;
        verify_chain_bytes_resuming(&content, vk, resume, seed).ok()?;
    }

    let mut leaf_hashes = cache.leaf_hashes;
    leaf_hashes.extend(appended.iter().map(|l| leaf_hash(l.as_bytes())));
    let tree_size = leaf_hashes.len() as u64;
    let root = merkle_root_of_leaf_hashes(&leaf_hashes);

    leaf_cache::write(
        audit_dir,
        tenant,
        &leaf_cache::LeafCache {
            sealed: cache.sealed,
            active_seq: shape.active.0,
            prefix_lines_in_active: active_lines.len() as u64,
            leaf_hashes,
        },
    );
    Some((root, tree_size))
}

/// Fingerprint every sealed segment in `shape`, or `None` if any is gone.
fn sealed_fingerprints(
    shape: &crate::supervisor::audit_set::SegmentShape,
) -> Option<Vec<leaf_cache::SealedFingerprint>> {
    shape
        .sealed
        .iter()
        .map(|(seq, path)| leaf_cache::SealedFingerprint::probe(*seq, path))
        .collect()
}

/// Seed the cache from leaves a genesis walk just verified, so the next launch
/// has something to fold.
///
/// Best effort throughout: every early return leaves no cache, which costs
/// another genesis walk and nothing else.
fn seed_leaf_cache(audit_dir: &Path, tenant: &str, leaves: &[String]) {
    let Ok(shape) = crate::supervisor::audit_set::segment_shape(audit_dir, tenant) else {
        return;
    };
    let Some(sealed) = sealed_fingerprints(&shape) else {
        return;
    };
    let Ok(content) = std::fs::read_to_string(&shape.active.1) else {
        return;
    };
    let active_lines = content.lines().filter(|l| !l.is_empty()).count();
    // The cache describes a prefix ending inside the live segment. Fewer leaves
    // than that segment holds means these two reads disagree about the log —
    // most likely because it was appended to between them — and a cache built
    // across that disagreement would mis-index its suffix.
    if leaves.len() < active_lines {
        return;
    }
    leaf_cache::write(
        audit_dir,
        tenant,
        &leaf_cache::LeafCache {
            sealed,
            active_seq: shape.active.0,
            prefix_lines_in_active: active_lines as u64,
            leaf_hashes: leaves.iter().map(|l| leaf_hash(l.as_bytes())).collect(),
        },
    );
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

    /// Grow `dir`'s chain by `n` more entries, then publish a root over it.
    fn grow_and_publish(
        dir: &Path,
        key: &ed25519_dalek::SigningKey,
        n: usize,
        tag: &str,
    ) -> mvm_contract::merkle::SignedAuditRoot {
        let signer = FileAuditSigner::open(key.clone(), dir).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for i in 0..n {
            rt.block_on(signer.sign_and_emit(&entry("local", &format!("{tag}-{i}"))))
                .unwrap();
        }
        crate::audit::emitter::AuditEmitter::with_dir(key.clone(), dir)
            .unwrap()
            .publish_root("local")
            .unwrap()
    }

    /// Append `n` entries under an explicit rotation policy, so a test decides
    /// exactly when the chain splits instead of inferring it from entry sizes.
    fn grow_with_rotation(
        dir: &Path,
        key: &ed25519_dalek::SigningKey,
        n: usize,
        tag: &str,
        rotation: crate::supervisor::RotationPolicy,
    ) {
        let signer = FileAuditSigner::open(key.clone(), dir)
            .unwrap()
            .with_rotation(rotation);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for i in 0..n {
            rt.block_on(signer.sign_and_emit(&entry("local", &format!("{tag}-{i}"))))
                .unwrap();
        }
    }

    fn segment_count(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".seg-"))
            .count()
    }

    /// Re-sign `root` under `key` after mutating it, so a test can present a
    /// root that is genuinely signed and still wrong about the log.
    fn resign(mut root: SignedAuditRoot, key: &SigningKey) -> SignedAuditRoot {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let payload = mvm_contract::merkle::root_signing_bytes(
            &root.tenant,
            root.tree_size,
            &root.root_hash,
            &root.timestamp,
        )
        .unwrap();
        root.signature =
            base64::engine::general_purpose::STANDARD.encode(key.sign(&payload).to_bytes());
        root.signer_pubkey = hex::encode(key.verifying_key().to_bytes());
        root
    }

    fn write_root(dir: &Path, root: &SignedAuditRoot) {
        std::fs::write(
            emitter::audit_root_path_for_tenant(dir, "local"),
            serde_json::to_vec(root).unwrap(),
        )
        .unwrap();
    }

    /// Flip one field of the line at `idx` in `path`, keeping it valid JSON so
    /// the failure is the chain's to report rather than the parser's.
    fn tamper_line(path: &Path, idx: usize) {
        let content = std::fs::read_to_string(path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        lines[idx] = lines[idx].replacen("\"img\"", "\"IMG\"", 1);
        std::fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn the_fast_path_takes_the_published_root_at_its_word_and_agrees_with_genesis() {
        // The whole point of the fast path is that it is *not* a different
        // answer. Assert it engaged -- otherwise every test below it passes by
        // silently falling back -- and that its leaves are the genesis walk's.
        let (dir, key, _) = seed_chain(4);
        let vk = key.verifying_key();
        grow_and_publish(dir.path(), &key, 2, "published");
        grow_and_publish(dir.path(), &key, 3, "after");

        let fast = leaves_over_attested_prefix(dir.path(), "local", &vk)
            .expect("a verifying published root must engage the fast path");
        let full = read_leaves_from_genesis(dir.path(), "local", &vk).unwrap();
        assert_eq!(fast, full);
        assert_eq!(fast.len(), 9);
    }

    #[test]
    fn a_line_appended_after_the_published_root_is_still_verified() {
        // The suffix is the part the published root says nothing about, so it
        // is the part this path must walk itself. If it did not, a tampered
        // recent entry would be published into a root.
        let (dir, key, _) = seed_chain(3);
        let vk = key.verifying_key();
        grow_and_publish(dir.path(), &key, 1, "published");
        grow_with_rotation(
            dir.path(),
            &key,
            2,
            "after",
            crate::supervisor::RotationPolicy::never(),
        );

        tamper_line(&dir.path().join("local.jsonl"), 5);

        assert!(
            leaves_over_attested_prefix(dir.path(), "local", &vk).is_none(),
            "a tampered suffix line must not pass the resumed walk"
        );
        assert!(build_root_in(dir.path(), "local", &vk).is_err());
    }

    #[test]
    fn a_tampered_attested_prefix_declines_the_shortcut_and_then_refuses() {
        // The prefix is exactly what the published root vouches for, so the
        // shortcut has to notice when the bytes stop hashing to it -- and then
        // hand the refusal to the genesis walk rather than accusing itself.
        let (dir, key, _) = seed_chain(4);
        let vk = key.verifying_key();
        grow_and_publish(dir.path(), &key, 2, "published");
        grow_with_rotation(
            dir.path(),
            &key,
            2,
            "after",
            crate::supervisor::RotationPolicy::never(),
        );

        tamper_line(&dir.path().join("local.jsonl"), 1);

        assert!(
            leaves_over_attested_prefix(dir.path(), "local", &vk).is_none(),
            "a prefix that no longer hashes to the published root must decline"
        );
        assert!(build_root_in(dir.path(), "local", &vk).is_err());
    }

    #[test]
    fn a_root_signed_by_another_key_does_not_shortcut_the_walk() {
        // The seed's whole strength is the host signature over it. A root that
        // verifies under some *other* key is not a statement this host made.
        let (dir, key, _) = seed_chain(4);
        let vk = key.verifying_key();
        let root = grow_and_publish(dir.path(), &key, 2, "published");
        write_root(dir.path(), &resign(root, &fresh_key()));

        assert!(leaves_over_attested_prefix(dir.path(), "local", &vk).is_none());
        // Declining is not refusing: the chain itself is intact, so the
        // genesis walk still produces a root.
        assert!(build_root_in(dir.path(), "local", &vk).is_ok());
    }

    #[test]
    fn a_root_reaching_past_the_log_declines_rather_than_indexing_off_the_end() {
        let (dir, key, _) = seed_chain(4);
        let vk = key.verifying_key();
        let mut root = grow_and_publish(dir.path(), &key, 2, "published");
        root.tree_size += 1_000;
        write_root(dir.path(), &resign(root, &key));

        assert!(leaves_over_attested_prefix(dir.path(), "local", &vk).is_none());
        assert!(build_root_in(dir.path(), "local", &vk).is_ok());
    }

    #[test]
    fn no_published_root_leaves_the_genesis_walk_as_the_only_path() {
        let (dir, key, _) = seed_chain(3);
        let vk = key.verifying_key();
        assert!(leaves_over_attested_prefix(dir.path(), "local", &vk).is_none());
        assert_eq!(read_leaves(dir.path(), "local", &vk).unwrap().len(), 3);
    }

    #[test]
    fn the_fast_path_survives_a_rotation_by_falling_back_once() {
        // A root published before a rotation lands before the live segment,
        // which this path does not seek into. It must decline, not misindex --
        // and the root published after it re-establishes the shortcut.
        let (dir, key, _) = seed_chain(2);
        let vk = key.verifying_key();
        grow_and_publish(dir.path(), &key, 1, "published");
        grow_with_rotation(
            dir.path(),
            &key,
            4,
            "post",
            crate::supervisor::RotationPolicy::at_bytes(256),
        );
        assert!(segment_count(dir.path()) > 0, "the fixture must rotate");

        let across = read_leaves(dir.path(), "local", &vk).unwrap();
        assert_eq!(
            across,
            read_leaves_from_genesis(dir.path(), "local", &vk).unwrap()
        );

        grow_and_publish(dir.path(), &key, 1, "republished");
        assert!(
            leaves_over_attested_prefix(dir.path(), "local", &vk).is_some(),
            "a root published after the rotation must re-engage the fast path"
        );
    }

    #[test]
    fn raw_line_index_translates_leaf_numbering_across_blank_lines() {
        // Leaves skip blank lines; `walk_chain` counts them. Reusing a leaf
        // index as a resume point would verify the wrong suffix.
        let content = "a\n\nb\nc\n";
        assert_eq!(raw_line_index(content, 0), Some(0));
        assert_eq!(raw_line_index(content, 1), Some(1));
        assert_eq!(raw_line_index(content, 2), Some(3));
        assert_eq!(raw_line_index(content, 3), Some(4));
        assert_eq!(raw_line_index(content, 4), None);
    }

    /// Every test below this one would pass by silently falling back to the
    /// genesis walk, so the first thing to establish is that the cached path
    /// runs at all — and that it lands on the same root.
    #[test]
    fn the_cached_prefix_path_engages_and_agrees_with_the_genesis_walk() {
        let (dir, key, _) = seed_chain(4);
        let vk = key.verifying_key();
        grow_and_publish(dir.path(), &key, 2, "published");
        grow_with_rotation(
            dir.path(),
            &key,
            2,
            "after",
            crate::supervisor::RotationPolicy::never(),
        );

        let cached = root_over_cached_prefix(dir.path(), "local", &vk)
            .expect("a published root plus its seeded cache must engage the fast path");
        let leaves = read_leaves_from_genesis(dir.path(), "local", &vk).unwrap();
        assert_eq!(cached, (merkle_root(&leaves), leaves.len() as u64));
    }

    #[test]
    fn a_removed_sealed_segment_declines_the_cache() {
        // The fold proves the cached hashes are the attested ones. It cannot
        // prove the segments they came from are still there, which is why the
        // set's shape is checked separately.
        let (dir, key, _) = seed_chain(2);
        let vk = key.verifying_key();
        grow_with_rotation(
            dir.path(),
            &key,
            4,
            "post",
            crate::supervisor::RotationPolicy::at_bytes(256),
        );
        grow_and_publish(dir.path(), &key, 1, "published");
        assert!(root_over_cached_prefix(dir.path(), "local", &vk).is_some());

        let sealed = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.to_string_lossy().contains(".seg-"))
            .expect("the fixture must have rotated");
        std::fs::remove_file(&sealed).unwrap();

        assert!(
            root_over_cached_prefix(dir.path(), "local", &vk).is_none(),
            "a set missing a segment must reach the genesis walk, which names it"
        );
        assert!(build_root_in(dir.path(), "local", &vk).is_err());
    }

    #[test]
    fn a_resized_sealed_segment_declines_the_cache() {
        let (dir, key, _) = seed_chain(2);
        let vk = key.verifying_key();
        grow_with_rotation(
            dir.path(),
            &key,
            4,
            "post",
            crate::supervisor::RotationPolicy::at_bytes(256),
        );
        grow_and_publish(dir.path(), &key, 1, "published");
        assert!(root_over_cached_prefix(dir.path(), "local", &vk).is_some());

        let sealed = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.to_string_lossy().contains(".seg-"))
            .expect("the fixture must have rotated");
        let mut content = std::fs::read_to_string(&sealed).unwrap();
        content.push_str("{}\n");
        std::fs::write(&sealed, content).unwrap();

        assert!(
            root_over_cached_prefix(dir.path(), "local", &vk).is_none(),
            "a sealed segment that changed length must not be folded over"
        );
    }

    /// The narrowing this cache buys its speed with, stated as a test so it
    /// cannot quietly become something else.
    ///
    /// A sealed segment edited *in place*, preserving its length and mtime, is
    /// not detected when a root is published: publishing no longer reads sealed
    /// segments, and that is the entire saving. It is still detected by the
    /// genesis walk — which is what `mvmctl trust audit verify` runs, what
    /// `read_leaves` runs for an inclusion proof, and what any cache miss falls
    /// back to.
    ///
    /// Note what the published root is over: the *cached* leaves, which are the
    /// ones the log actually had. So this path never signs a statement blessing
    /// the altered content — it fails to notice it, which is a weaker failure
    /// than attesting it.
    #[test]
    fn an_in_place_sealed_edit_is_missed_at_publish_but_caught_by_the_genesis_walk() {
        let (dir, key, _) = seed_chain(2);
        let vk = key.verifying_key();
        grow_with_rotation(
            dir.path(),
            &key,
            4,
            "post",
            crate::supervisor::RotationPolicy::at_bytes(256),
        );
        grow_and_publish(dir.path(), &key, 1, "published");

        let sealed = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.to_string_lossy().contains(".seg-"))
            .expect("the fixture must have rotated");
        let before = std::fs::metadata(&sealed).unwrap();
        let content = std::fs::read_to_string(&sealed).unwrap();
        // Same byte count, different bytes.
        let edited = content.replacen("\"img\"", "\"IMG\"", 1);
        assert_eq!(edited.len(), content.len(), "the edit must preserve length");
        std::fs::write(&sealed, &edited).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&sealed)
            .and_then(|f| f.set_modified(before.modified().unwrap()))
            .expect("restore mtime so the fingerprint matches");

        // Missed here, on purpose.
        assert!(
            root_over_cached_prefix(dir.path(), "local", &vk).is_some(),
            "this test documents that the cached path does not read sealed segments"
        );
        // And caught the moment anything walks the chain.
        assert!(
            read_leaves_from_genesis(dir.path(), "local", &vk).is_err(),
            "the genesis walk must still refuse an edited sealed segment"
        );
    }

    #[test]
    fn consistency_holds_across_a_segment_rotation() {
        // The case that would break a naive implementation: `read_leaves`
        // spans the whole segment set, so leaf indices stay globally ordered
        // across a rotation. A root published before the rotation must still
        // be provably a prefix of one published after it -- if the tree were
        // rebuilt per-segment, the older root would describe leaves that no
        // longer sit where it says they do.
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();

        use crate::supervisor::RotationPolicy;
        grow_with_rotation(dir.path(), &key, 4, "pre", RotationPolicy::never());
        let before = crate::audit::emitter::AuditEmitter::with_dir(key.clone(), dir.path())
            .unwrap()
            .publish_root("local")
            .unwrap();
        assert_eq!(
            segment_count(dir.path()),
            0,
            "the fixture must publish its first root BEFORE any rotation"
        );

        // Now rotate: a threshold below one entry's size splits on every append.
        grow_with_rotation(dir.path(), &key, 6, "post", RotationPolicy::at_bytes(256));
        assert!(
            segment_count(dir.path()) > 0,
            "the fixture must really have rotated, or this test proves nothing"
        );

        let after = crate::audit::emitter::AuditEmitter::with_dir(key.clone(), dir.path())
            .unwrap()
            .publish_root("local")
            .unwrap();
        assert!(
            after.tree_size > before.tree_size,
            "the log grew across the rotation"
        );

        let report = verify_root_history(dir.path(), "local", &vk)
            .expect("the log is append-only across the rotation");
        assert_eq!(report.roots, 2);
        assert_eq!(report.transitions_checked, 1);
        assert_eq!(report.newest_tree_size, Some(after.tree_size));
    }

    #[test]
    fn a_rewritten_prefix_is_refused_even_though_every_root_still_verifies() {
        // The signature check cannot catch this: both roots are genuinely
        // host-signed. Only the consistency proof can, because the leaves no
        // longer extend what the older root committed to.
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();

        grow_and_publish(dir.path(), &key, 4, "a");
        grow_and_publish(dir.path(), &key, 4, "b");
        assert!(verify_root_history(dir.path(), "local", &vk).is_ok());

        // Rebuild the chain from scratch under the same key: every entry is
        // validly signed and the chain verifies, but it is a different log.
        let path = dir.path().join("local.jsonl");
        std::fs::remove_file(&path).unwrap();
        let signer = FileAuditSigner::open(key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for i in 0..8 {
            rt.block_on(signer.sign_and_emit(&entry("local", &format!("forged-{i}"))))
                .unwrap();
        }

        let err = verify_root_history(dir.path(), "local", &vk)
            .expect_err("a rewritten prefix must not pass");
        let text = format!("{err:#}");
        assert!(
            text.contains("not append-only") || text.contains("consistency proof"),
            "the refusal must come from the consistency check, not from a \
             signature or decode failure that would mask this: {text}"
        );
    }

    #[test]
    fn a_log_that_only_grew_proves_consistent_across_every_published_root() {
        let (dir, key, _) = seed_chain(3);
        let vk = key.verifying_key();

        grow_and_publish(dir.path(), &key, 0, "a");
        grow_and_publish(dir.path(), &key, 4, "b");
        grow_and_publish(dir.path(), &key, 2, "c");

        let report = verify_root_history(dir.path(), "local", &vk).expect("history verifies");
        assert_eq!(report.roots, 3);
        assert_eq!(
            report.transitions_checked, 2,
            "each successive pair is proven, not just the endpoints"
        );
        assert_eq!(report.newest_tree_size, Some(9));
    }

    #[test]
    fn an_empty_history_reports_that_it_checked_nothing() {
        // Reporting a pass over no roots would imply an attestation nobody
        // made. The counts are the honest answer.
        let (dir, key, _) = seed_chain(2);
        let vk = key.verifying_key();
        let report =
            verify_root_history(dir.path(), "local", &vk).expect("no history is not an error");
        assert_eq!(report, RootHistoryReport::default());
        assert_eq!(report.transitions_checked, 0);
    }

    #[test]
    fn a_root_signed_by_another_key_is_refused() {
        let (dir, key, _) = seed_chain(3);
        grow_and_publish(dir.path(), &key, 0, "a");
        // Verifying under a key that did not sign the history must fail
        // rather than quietly accepting whatever pubkey the root names.
        let stranger = fresh_key().verifying_key();
        assert!(verify_root_history(dir.path(), "local", &stranger).is_err());
    }

    #[test]
    fn a_rewritten_history_entry_is_refused() {
        let (dir, key, _) = seed_chain(3);
        let vk = key.verifying_key();
        grow_and_publish(dir.path(), &key, 0, "a");
        grow_and_publish(dir.path(), &key, 3, "b");
        assert!(verify_root_history(dir.path(), "local", &vk).is_ok());

        // Edit a published root's tree_size. Its signature no longer covers
        // the bytes, so this is caught before any proof is attempted.
        let path = crate::audit::emitter::audit_root_history_path_for_tenant(dir.path(), "local");
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        let edited = lines[0].replace("\"tree_size\":3", "\"tree_size\":2");
        assert_ne!(
            edited, lines[0],
            "the fixture must really have edited the root, or this test passes for free"
        );
        lines[0] = edited;
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let err = verify_root_history(dir.path(), "local", &vk)
            .expect_err("a tampered root must not pass");
        assert!(
            format!("{err:#}").contains("does not verify"),
            "the refusal must come from the signature check, not from some \
             unrelated failure that would mask a real regression: {err:#}"
        );
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

/// Verify that every root ever published for `tenant` describes a log that
/// only grew.
///
/// Walks the append-only history written by
/// [`crate::audit::emitter::AuditEmitter::publish_root`], checks each root's
/// signature under `vk`, and proves each successive pair is a prefix
/// extension using the RFC 6962 consistency proof.
///
/// # What this detects, and what it does not
///
/// Read [`mvm_contract::merkle`]'s module note before treating a pass here as
/// tamper-evidence. Three limits carry over unchanged:
///
/// 1. Every root in this history was signed by the host that produced the
///    log, and stored beside it. A host that rewrites the log reissues the
///    whole history and every check here passes. This is worth running
///    against accident, and against a later compromise that did not also
///    capture the earlier roots; it is not a defence against the host itself.
/// 2. Detection reaches back only to the oldest root present, and entries
///    appended and deleted *between* two publishes leave no trace in either.
///    The window is the publishing interval, not the log's lifetime.
/// 3. Tail truncation past the newest root stays undetectable.
///
/// An off-host witness is what makes this meaningful, which is why the roots
/// are also emitted to a sink. This function is the local half.
pub fn verify_root_history(
    audit_dir: &Path,
    tenant: &str,
    vk: &VerifyingKey,
) -> Result<RootHistoryReport> {
    use mvm_contract::merkle::{
        build_consistency_proof, verify_consistency_against_roots, verify_signed_root,
    };

    let path = crate::audit::emitter::audit_root_history_path_for_tenant(audit_dir, tenant);
    let Ok(content) = std::fs::read_to_string(&path) else {
        // No history is not a failure: a host that never published a root has
        // nothing to be inconsistent about. Saying "checked 0" is honest;
        // reporting a pass would imply an attestation nobody made.
        return Ok(RootHistoryReport::default());
    };

    let mut roots: Vec<mvm_contract::merkle::SignedAuditRoot> = Vec::new();
    for (n, line) in content.lines().filter(|l| !l.is_empty()).enumerate() {
        let root = serde_json::from_str(line).with_context(|| {
            format!(
                "decoding root history entry {} at {}",
                n + 1,
                path.display()
            )
        })?;
        roots.push(root);
    }
    for (n, root) in roots.iter().enumerate() {
        verify_signed_root(root, vk).map_err(|e| {
            anyhow::anyhow!(
                "root history entry {} for {tenant} does not verify: {e}",
                n + 1
            )
        })?;
        if root.tenant != tenant {
            anyhow::bail!(
                "root history entry {} claims tenant '{}', not '{tenant}'",
                n + 1,
                root.tenant
            );
        }
    }

    // The proofs are built from the log as it stands now. A pair that will not
    // prove against the current leaves is exactly the finding: either the log
    // was rewritten under a root that still verifies, or a root was issued
    // over something this log never was.
    let leaves = read_leaves(audit_dir, tenant, vk)?;
    let mut checked = 0usize;
    for pair in roots.windows(2) {
        let (old, new) = (&pair[0], &pair[1]);
        if old.tree_size == new.tree_size && old.root_hash == new.root_hash {
            // A republish with nothing appended in between. Nothing to prove
            // and nothing wrong with it.
            continue;
        }
        // Sizes are `u64` on the wire and `usize` in the tree math. A root
        // claiming more leaves than this platform can index is a corrupt
        // root, not a proof to attempt.
        let (old_n, new_n) = match (
            usize::try_from(old.tree_size),
            usize::try_from(new.tree_size),
        ) {
            (Ok(o), Ok(n)) => (o, n),
            _ => anyhow::bail!(
                "root history for {tenant} claims a tree size this host cannot index: {} -> {}",
                old.tree_size,
                new.tree_size
            ),
        };
        let proof = build_consistency_proof(&leaves, old_n, new_n).map_err(|e| {
            anyhow::anyhow!(
                "cannot build a consistency proof for {tenant} between sizes {} and {}: {e}",
                old.tree_size,
                new.tree_size
            )
        })?;
        verify_consistency_against_roots(&proof, old, new).map_err(|e| {
            anyhow::anyhow!(
                "the audit log for {tenant} is not append-only between sizes {} and {}: {e}",
                old.tree_size,
                new.tree_size
            )
        })?;
        checked += 1;
    }

    Ok(RootHistoryReport {
        roots: roots.len(),
        transitions_checked: checked,
        newest_tree_size: roots.last().map(|r| r.tree_size),
    })
}

/// What [`verify_root_history`] actually checked.
///
/// Counts rather than a bare bool, because "passed" over an empty history and
/// "passed" over two hundred transitions are different statements and a caller
/// reporting them identically would overstate the weaker one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootHistoryReport {
    /// Signed roots present in the history.
    pub roots: usize,
    /// Successive pairs proven to be prefix extensions.
    pub transitions_checked: usize,
    /// Tree size of the newest root, if any.
    pub newest_tree_size: Option<u64>,
}
