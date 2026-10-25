//! Content integrity and signed-chain lineage verification for checkpoints.
//!
//! Two fail-closed gates stand in front of every use of a stored checkpoint.
//! [`verify_content`] re-hashes the blobs a record names — whole files
//! directly, chunked blobs through their authenticated indexes — catching
//! flipped bytes at read time. The lineage walk ([`verify_lineage`],
//! [`checkpoint_ancestry`], [`checkpoint_children`]) recomputes each record's
//! content-address and checks it against the signed audit chain through a
//! caller-injected [`CheckpointChainAnchor`], so a record edited after it was
//! audited — or never audited at all — is refused before anything it names is
//! trusted.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::checkpoint::{CheckpointDigest, CheckpointId, CheckpointMeta, ContentBlob};

use super::materialization::clone_or_materialize_blob;
use super::{CheckpointStore, chunks, protection, sealed, sha256_file_hex};
use crate::lineage::{LineageAnchor, LineageGraph, LineageRecord};

/// Verify every blob named in `meta.content` exists in the checkpoint's content
/// dir and hashes to its recorded value. Fail-closed: any missing or mismatched
/// blob is an error.
///
/// The blobs are hashed concurrently, one per worker, so the wait is set by
/// the largest blob rather than the sum of all of them. The error reported is
/// the first failing blob in manifest order, whichever finished first.
pub fn verify_content(store: &CheckpointStore, meta: &CheckpointMeta) -> Result<()> {
    verify_content_except(store, meta, &[])
}

/// Digest of the contiguous bytes a chunked blob materializes to, retained in
/// its authenticated index so callers can bind an admitted image without
/// rereading a multi-gigabyte rootfs.
pub fn materialized_blob_sha256(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    name: &str,
) -> Result<String> {
    let blob = meta
        .content
        .iter()
        .find(|blob| blob.name == name)
        .with_context(|| format!("checkpoint '{}' has no {name} blob", meta.id))?;
    if let Some(keys) = store.keys_for(meta)? {
        return sealed::materialized_sha256(&keys, &store.content_dir(&meta.id), blob);
    }
    chunks::ensure_chunked_layout(&store.content_dir(&meta.id), meta)?;
    chunks::materialized_sha256(&store.content_dir(&meta.id), blob)
}

/// Rebuild every chunked blob in `destination_dir` from the authenticated
/// checkpoint index. Existing materialized copies are replaced so a snapshot
/// copy cannot bypass chunk verification.
///
/// A protected checkpoint has no plaintext anywhere a mirror could have
/// copied it from: every blob is opened from the store into
/// `destination_dir`, and the opaque copies a mirror left there are removed.
pub fn materialize_chunked_blobs(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    destination_dir: &Path,
) -> Result<()> {
    if let Some(keys) = store.keys_for(meta)? {
        protection::open_all_blobs(store, meta, &keys, destination_dir)?;
        return protection::remove_mirrored_sealed_content(meta, destination_dir);
    }
    let content_dir = store.content_dir(&meta.id);
    for blob in &meta.content {
        chunks::validate_blob_name(&blob.name)?;
        if !chunks::is_chunked_blob(&content_dir, blob) {
            continue;
        }
        let destination = destination_dir.join(&blob.name);
        match std::fs::remove_file(&destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("removing snapshot blob {}", destination.display()));
            }
        }
        chunks::materialize_blob_cached(
            store.root(),
            &meta.key_domain,
            &content_dir,
            blob,
            &destination,
        )
        .with_context(|| format!("materializing checkpoint blob {:?}", blob.name))?;
    }
    Ok(())
}

/// Materialize every checkpoint blob into `destination_dir`.
///
/// Chunked blobs are rebuilt from their authenticated indexes; the small
/// blobs a capture keeps whole are cloned through the normal CoW path. All
/// blob names, and the layout, are checked before any destination is changed.
pub fn materialize_checkpoint_blobs(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    destination_dir: &Path,
) -> Result<()> {
    materialize_checkpoint_manifest(store, meta, destination_dir).map(drop)
}

/// [`materialize_checkpoint_blobs`], returning the manifest of what was
/// written: the record's own content for a legacy checkpoint, and for a
/// protected one each blob's digest over the plaintext just opened, which is
/// what a backend verifying on load compares against.
pub(super) fn materialize_checkpoint_manifest(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    destination_dir: &Path,
) -> Result<Vec<ContentBlob>> {
    for blob in &meta.content {
        chunks::validate_blob_name(&blob.name)?;
    }
    if let Some(keys) = store.keys_for(meta)? {
        return protection::open_all_blobs(store, meta, &keys, destination_dir);
    }
    chunks::ensure_chunked_layout(&store.content_dir(&meta.id), meta)?;

    std::fs::create_dir_all(destination_dir).with_context(|| {
        format!(
            "creating checkpoint materialization directory {}",
            destination_dir.display()
        )
    })?;
    for blob in &meta.content {
        let destination = destination_dir.join(&blob.name);
        match std::fs::remove_file(&destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("removing stale checkpoint blob {}", destination.display())
                });
            }
        }
        clone_or_materialize_blob(store, meta, blob, &destination)?;
    }
    Ok(meta.content.clone())
}

/// [`verify_content`], leaving the digest of each whole-file blob named in
/// `deferred` to the restorer that loads it. Chunked blobs are always verified
/// here because the restorer only understands the materialized byte stream,
/// not its index digest and object membership.
///
/// Only for a restorer that verifies those blobs itself, against the same
/// recorded digests, on the exact bytes it loads — hashing them here as well
/// would read multi-gigabyte machine state twice and still leave a window
/// between this check and the load. A deferred blob must still exist.
pub(super) fn verify_content_except(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    deferred: &[&str],
) -> Result<()> {
    let dir = store.content_dir(&meta.id);
    if let Some(keys) = store.keys_for(meta)? {
        // Every byte of protected content is authenticated as it opens, so
        // nothing is deferred to a restorer.
        let results = mvm_fs::parallel::par_map(meta.content.iter().collect(), |blob| {
            sealed::verify_blob(&keys, &dir, blob)
                .with_context(|| format!("verifying checkpoint '{}' blob {:?}", meta.id, blob.name))
        });
        return results.into_iter().collect();
    }
    chunks::ensure_chunked_layout(&dir, meta)?;
    let tasks: Vec<_> = meta
        .content
        .iter()
        .cloned()
        .map(|blob| {
            let is_deferred = deferred.contains(&blob.name.as_str());
            (blob, is_deferred)
        })
        .collect();
    let results = mvm_fs::parallel::par_map(tasks, |(blob, is_deferred)| {
        chunks::validate_blob_name(&blob.name)?;
        let path = dir.join(&blob.name);
        if chunks::is_chunked_blob(&dir, &blob) {
            return chunks::verify_blob(&dir, &blob).map_err(|error| {
                anyhow::anyhow!(
                    "verifying checkpoint '{}' blob {:?}: {error:#}",
                    meta.id,
                    blob.name
                )
            });
        }
        if is_deferred {
            anyhow::ensure!(
                path.is_file(),
                "checkpoint '{}' blob {:?} is missing",
                meta.id,
                blob.name
            );
            return Ok(());
        }
        let actual = sha256_file_hex(&path)
            .with_context(|| format!("hashing checkpoint blob {}", path.display()))?;
        anyhow::ensure!(
            actual == blob.sha256,
            "checkpoint '{}' blob {:?} failed integrity (sha256): expected {}, got {}",
            meta.id,
            blob.name,
            blob.sha256,
            actual
        );
        Ok(())
    });
    for result in results {
        result?;
    }
    Ok(())
}

/// Resolves the signature-authenticated content-address a checkpoint's creation
/// was recorded under in the chain-signed audit log.
///
/// Injected (rather than called directly) so this crate's lineage walk stays
/// free of host-key loading, tenant resolution, and audit-file layout — those
/// live in the layer above (the CLI), which owns the host signer. An
/// implementation MUST verify the audit chain's signatures before trusting any
/// label it returns, so the value it yields is one no party but the host could
/// have produced.
pub trait CheckpointChainAnchor {
    /// The content-address recorded for `meta`'s creation in the tenant's
    /// signature-verified audit chain (`checkpoint.created`'s `meta_digest`, or
    /// `checkpoint.forked`'s `child_digest`), or `None` if the chain carries no
    /// creation entry for it.
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>>;

    /// The tenant whose signed audit chain recorded `meta`'s creation, or
    /// `None` if no chain carries a creation entry for it.
    fn recorded_creation_tenant(&self, meta: &CheckpointMeta) -> Result<Option<String>>;
}

/// Refuse to load `meta`'s saved machine state for any tenant but the one that
/// created it.
///
/// A restore maps the saved memory into a new guest. Each restore maps a
/// private copy, so no two guests share its pages, but the saved memory still
/// holds everything the creating tenant's workload had in RAM; handing it to
/// another tenant's guest would be a disclosure, not a restore.
///
/// The owner side is authenticated: it is the tenant the creation entry was
/// signed under. The `tenant` side is whatever the caller says it is running
/// as, so this is a policy guard against restoring into the wrong tenant, not
/// an authenticated boundary between tenants that share a host user.
pub(super) fn ensure_same_tenant(
    anchor: &dyn CheckpointChainAnchor,
    meta: &CheckpointMeta,
    tenant: &str,
) -> Result<()> {
    match anchor.recorded_creation_tenant(meta)? {
        Some(owner) if owner == tenant => Ok(()),
        Some(owner) => anyhow::bail!(
            "checkpoint '{}' belongs to tenant '{owner}'; refusing to restore its saved memory \
             for tenant '{tenant}'",
            meta.id
        ),
        None => anyhow::bail!(
            "checkpoint '{}' has no signed creation entry naming its tenant; refusing to \
             restore its saved memory",
            meta.id
        ),
    }
}

/// A checkpoint record participates in the shared, namespace-agnostic lineage
/// walk ([`crate::lineage`]) as a content-addressed record: its stored digest is
/// `meta_digest`, it recomputes via [`CheckpointMeta::compute_meta_digest`], and
/// its parent hash-link is `parent`.
impl LineageRecord for CheckpointMeta {
    fn stored_digest(&self) -> &CheckpointDigest {
        &self.meta_digest
    }
    fn recompute_digest(&self) -> CheckpointDigest {
        self.compute_meta_digest()
    }
    fn parent_link(&self) -> Option<&CheckpointDigest> {
        self.parent.as_ref()
    }
    fn kind(&self) -> &'static str {
        "checkpoint"
    }
    fn id_label(&self) -> String {
        self.id.to_string()
    }
    fn digest_field(&self) -> &'static str {
        "meta_digest"
    }
}

/// Bridge the checkpoint-specific anchor trait onto the generic one, so the
/// shared walk accepts a `&dyn CheckpointChainAnchor` unchanged.
impl LineageAnchor<CheckpointMeta> for dyn CheckpointChainAnchor + '_ {
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        CheckpointChainAnchor::recorded_creation_digest(self, meta)
    }
}

/// Adapts a [`CheckpointStore`] to the generic [`LineageGraph`] the shared walk
/// reads records from.
struct CheckpointGraph<'a>(&'a CheckpointStore);

impl LineageGraph for CheckpointGraph<'_> {
    type Record = CheckpointMeta;
    type Id = CheckpointId;
    fn read(&self, id: &CheckpointId) -> Result<CheckpointMeta> {
        self.0.read_meta(id)
    }
    fn by_digest(&self, digest: &CheckpointDigest) -> Result<Option<CheckpointMeta>> {
        self.0.by_digest(digest)
    }
    fn children_of(&self, parent_digest: &CheckpointDigest) -> Result<Vec<CheckpointMeta>> {
        self.0.children_of(parent_digest)
    }
}

/// Verify one checkpoint record against the signed audit chain: its stored
/// `meta_digest` must equal a recomputation of its own fields (catches a
/// post-seal edit that left the digest stale) AND must equal the
/// signature-verified digest the audit chain recorded at creation (catches a
/// full local re-forge, where an attacker rewrites content, digest, and links
/// all consistently — that survives recompute alone but not the signed chain,
/// which it cannot re-sign without the host key). Fails closed on a drift, a
/// mismatch against the chain, or the absence of any signed creation entry.
pub(super) fn verify_checkpoint_against_chain(
    anchor: &dyn CheckpointChainAnchor,
    meta: &CheckpointMeta,
) -> Result<()> {
    crate::lineage::verify_record_against_chain(anchor, meta)
}

/// Walk a checkpoint's lineage from `id` up to its genesis root, verifying each
/// record against the **signed** audit chain via `anchor`: at every hop the
/// record's recomputed content-address must equal both its stored `meta_digest`
/// and the digest the host signed into the audit chain at creation. The
/// parent hash-link is followed by content-address, so editing any ancestor's
/// sealed record — content manifest, lineage, anything the digest covers — is
/// caught here even though it is invisible to a plain parent-name back-pointer.
///
/// Fails closed on: a drift between a record and its stored digest, a record
/// whose digest disagrees with the signed chain (or has no signed entry), a
/// parent hash-link that resolves to no stored checkpoint (dangling lineage),
/// or a revisited digest (a would-be cycle — cryptographically infeasible for
/// genuine content-addresses, refused rather than looped on).
///
/// Threat boundary: this proves integrity against edits made *after* the host
/// signed each record. A malicious host that holds the signing key is out of
/// scope (it is out of scope for the whole audit chain), as is a checkpoint
/// that was never audited — for which there is nothing signed to anchor to.
pub fn verify_lineage(
    store: &CheckpointStore,
    id: &CheckpointId,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<()> {
    crate::lineage::verify_lineage_chain(&CheckpointGraph(store), id, anchor)
}

/// Enumerate a checkpoint's ancestry (itself + every ancestor up to genesis),
/// verifying each hop against the signed audit chain. Read-only navigation: it
/// records each node's [`crate::lineage::HopStatus`] and keeps walking rather
/// than bailing, so a caller can render the whole chain with a failed hop marked;
/// it still fails closed on a dangling parent or a cycle via
/// [`crate::lineage::Ancestry::broken`]. The backward analog of the forward
/// [`checkpoint_children`].
pub fn checkpoint_ancestry(
    store: &CheckpointStore,
    id: &CheckpointId,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<crate::lineage::Ancestry<CheckpointMeta>> {
    crate::lineage::collect_ancestry(&CheckpointGraph(store), id, anchor)
}

/// Enumerate a checkpoint's immediate children (forward is a tree — a checkpoint
/// may be forked many times), each verified against the signed audit chain.
pub fn checkpoint_children(
    store: &CheckpointStore,
    parent_digest: &CheckpointDigest,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<Vec<crate::lineage::VerifiedNode<CheckpointMeta>>> {
    crate::lineage::verified_children(&CheckpointGraph(store), parent_digest, anchor)
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{
        blob_named, first_stored_chunk, seed_fc_vm_full_checkpoint, seed_fs_quick_checkpoint,
        tamper_first_stored_chunk,
    };
    use super::super::{ForkParams, ForkParentLiveness, fork_checkpoint, materialized_source};
    use super::*;
    use mvm_core::checkpoint::CheckpointClass;

    /// Anchor that echoes each record's own recomputed digest: the signed audit
    /// chain agrees with what's on disk — the honest case.
    pub struct AgreeingAnchor;
    impl CheckpointChainAnchor for AgreeingAnchor {
        fn recorded_creation_tenant(&self, _meta: &CheckpointMeta) -> Result<Option<String>> {
            Ok(Some("local".to_string()))
        }

        fn recorded_creation_digest(
            &self,
            meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            Ok(Some(meta.compute_meta_digest()))
        }
    }

    /// Anchor that reports a fixed, unrelated digest for every record: models a
    /// signed chain that disagrees with the on-disk record (post-audit edit).
    pub struct DisagreeingAnchor(pub CheckpointDigest);
    impl CheckpointChainAnchor for DisagreeingAnchor {
        fn recorded_creation_tenant(&self, _meta: &CheckpointMeta) -> Result<Option<String>> {
            Ok(Some("local".to_string()))
        }

        fn recorded_creation_digest(
            &self,
            _meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            Ok(Some(self.0.clone()))
        }
    }

    /// Anchor with no signed creation entry for anything: models an un-audited
    /// checkpoint, which chain-anchored verification must refuse.
    pub struct UnauditedAnchor;
    impl CheckpointChainAnchor for UnauditedAnchor {
        fn recorded_creation_tenant(&self, _meta: &CheckpointMeta) -> Result<Option<String>> {
            Ok(None)
        }

        fn recorded_creation_digest(
            &self,
            _meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            Ok(None)
        }
    }

    /// Anchor that agrees on every digest but records the checkpoint's
    /// creation under `self.0`'s tenant (or under none).
    pub struct TenantAnchor(pub Option<&'static str>);
    impl CheckpointChainAnchor for TenantAnchor {
        fn recorded_creation_tenant(&self, _meta: &CheckpointMeta) -> Result<Option<String>> {
            Ok(self.0.map(str::to_string))
        }

        fn recorded_creation_digest(
            &self,
            meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            Ok(Some(meta.compute_meta_digest()))
        }
    }

    pub fn unrelated_digest() -> CheckpointDigest {
        CheckpointDigest::parse(format!("sha256:{}", "f".repeat(64))).unwrap()
    }

    #[test]
    fn verify_content_passes_for_intact_blobs_and_fails_on_tamper() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        verify_content(&store, &parent).unwrap();
        tamper_first_stored_chunk(&store, &parent, "rootfs.ext4");
        assert!(verify_content(&store, &parent).is_err());
    }

    /// A restorer that verifies blobs on load still requires them to exist:
    /// deferring the digest is not permission to proceed without the file.
    #[test]
    fn deferred_blobs_must_still_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fc_vm_full_checkpoint(&store, tmp.path(), "fcv-deferred");
        let memory = first_stored_chunk(&store, &parent, mvm_core::checkpoint::MEMORY_BLOB);

        tamper_first_stored_chunk(&store, &parent, mvm_core::checkpoint::MEMORY_BLOB);
        verify_content(&store, &parent).expect_err("the full check hashes memory.bin");
        verify_content_except(&store, &parent, &[mvm_core::checkpoint::MEMORY_BLOB])
            .expect_err("chunked blobs are verified before materialization");

        std::fs::remove_file(&memory).unwrap();
        let error = verify_content_except(&store, &parent, &[mvm_core::checkpoint::MEMORY_BLOB])
            .expect_err("a deferred blob must still exist");
        assert!(error.to_string().contains("missing"), "{error}");
    }

    // ── hash-linked lineage: verify_lineage ─────────────────────────────────

    /// Seed a bare fs_quick meta hash-linked to `parent`, written to the store.
    /// Only metadata is written (no content blobs) — `verify_lineage` reads
    /// meta.json and recomputes digests; it never touches blob bytes.
    fn seed_linked_meta(
        store: &CheckpointStore,
        id: &str,
        parent: Option<CheckpointDigest>,
        rootfs_sha: &str,
    ) -> CheckpointMeta {
        let m = CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .parent(parent)
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: rootfs_sha.into(),
            }])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build();
        store.write_meta(&m).unwrap();
        m
    }

    #[test]
    fn capture_writes_a_meta_digest_that_recomputes_equal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let meta = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        assert_eq!(meta.meta_digest, meta.compute_meta_digest());
        // A freshly captured genesis checkpoint is a valid one-node lineage.
        verify_lineage(&store, &meta.id, &AgreeingAnchor).unwrap();
    }

    #[test]
    fn verify_lineage_passes_for_genesis_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let root = seed_linked_meta(&store, "g0", None, "aa");
        assert!(root.parent.is_none());
        verify_lineage(&store, &root.id, &AgreeingAnchor).unwrap();
    }

    #[test]
    fn verify_lineage_walks_multiple_generations_to_genesis() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let g0 = seed_linked_meta(&store, "g0", None, "aa");
        let g1 = seed_linked_meta(&store, "g1", Some(g0.meta_digest.clone()), "bb");
        let g2 = seed_linked_meta(&store, "g2", Some(g1.meta_digest.clone()), "cc");
        verify_lineage(&store, &g2.id, &AgreeingAnchor).unwrap();
        // Each hop is a hash-link to the parent's content-address.
        assert_eq!(g2.parent.as_ref().unwrap(), &g1.meta_digest);
        assert_eq!(g1.parent.as_ref().unwrap(), &g0.meta_digest);
    }

    /// HEADLINE: editing an ancestor's recorded content sha in its meta.json —
    /// two hops up from the checkpoint under test — is invisible to the old
    /// name-based parent pointer but is caught here: the ancestor's stored
    /// meta_digest no longer matches a recomputation of its (now-edited) fields.
    #[test]
    fn verify_lineage_detects_an_edited_ancestor_content_sha() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let g0 = seed_linked_meta(&store, "g0", None, "aa");
        let g1 = seed_linked_meta(&store, "g1", Some(g0.meta_digest.clone()), "bb");
        let g2 = seed_linked_meta(&store, "g2", Some(g1.meta_digest.clone()), "cc");

        // Baseline: the intact chain verifies.
        verify_lineage(&store, &g2.id, &AgreeingAnchor).unwrap();

        // Tamper the ANCESTOR (g0): rewrite its recorded content sha, leaving
        // its stored meta_digest (and g1's hash-link to it) stale.
        let g0_meta_path = store.dir_for(&g0.id).join("meta.json");
        let mut tampered: CheckpointMeta =
            serde_json::from_slice(&std::fs::read(&g0_meta_path).unwrap()).unwrap();
        tampered.content[0].sha256 = "0".repeat(64);
        std::fs::write(&g0_meta_path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();

        let err = verify_lineage(&store, &g2.id, &AgreeingAnchor).unwrap_err();
        assert!(
            err.to_string().contains("meta_digest drift"),
            "expected a meta_digest drift error, got: {err}"
        );
    }

    #[test]
    fn verify_lineage_fails_closed_on_a_dangling_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        // A child hash-linked to a digest no stored checkpoint carries.
        let orphan_parent = CheckpointDigest::parse(format!("sha256:{}", "e".repeat(64))).unwrap();
        let child = seed_linked_meta(&store, "child", Some(orphan_parent), "cc");
        let err = verify_lineage(&store, &child.id, &AgreeingAnchor).unwrap_err();
        assert!(
            err.to_string().contains("lineage is broken"),
            "expected a dangling-parent error, got: {err}"
        );
    }

    /// A flipped blob byte does not touch meta.json, so `meta_digest` still
    /// recomputes equal — that tamper class is `verify_content`'s job (it
    /// re-hashes the bytes), while `verify_lineage` guards the metadata chain.
    #[test]
    fn content_byte_flip_fails_verify_content_though_meta_digest_recomputes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        tamper_first_stored_chunk(&store, &parent, "rootfs.ext4");
        assert!(verify_content(&store, &parent).is_err());
        assert_eq!(parent.meta_digest, parent.compute_meta_digest());
    }

    /// A chunked blob's recorded content-address is the SHA-256 of its index
    /// file, not of the bytes it materializes to. `meta_digest` covers that
    /// address, so the chain's one digest anchors every chunk through it.
    #[test]
    fn a_chunked_blob_records_its_index_digest_as_the_content_address() {
        use sha2::Digest as _;

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let meta = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let blob = blob_named(&meta, "rootfs.ext4");
        let index = std::fs::read(chunks::index_path(
            &store.content_dir(&meta.id),
            "rootfs.ext4",
        ))
        .unwrap();

        assert_eq!(blob.sha256, hex::encode(sha2::Sha256::digest(&index)));
        assert_ne!(
            blob.sha256,
            materialized_blob_sha256(&store, &meta, "rootfs.ext4").unwrap(),
            "the whole-file digest lives inside the index, not in the record"
        );
    }

    /// Replace a chunked blob's index after capture, then re-seal the record
    /// around it step by step. Each step defeats one more local check; the
    /// digest the chain recorded at capture refuses the last one.
    #[test]
    fn an_index_replaced_after_capture_fails_lineage_against_the_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let captured = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let chain = DisagreeingAnchor(captured.meta_digest.clone());
        verify_content(&store, &captured).unwrap();
        verify_lineage(&store, &captured.id, &chain).unwrap();

        // Re-chunk different bytes into the checkpoint, which rewrites its
        // index and links the new objects beside the old ones.
        let content_dir = store.content_dir(&captured.id);
        let substitute = tmp.path().join("substitute.ext4");
        std::fs::write(&substitute, b"substituted-ext4-bytes").unwrap();
        let pool = chunks::ObjectPool::new(store.root(), &captured.key_domain).unwrap();
        let replaced =
            chunks::chunk_blob(&pool, &content_dir, "rootfs.ext4", &substitute, true).unwrap();
        assert_ne!(replaced.sha256, blob_named(&captured, "rootfs.ext4").sha256);

        // The index alone: the record still names the captured index.
        let err = verify_content(&store, &captured).unwrap_err();
        assert!(
            format!("{err:#}").contains("index failed integrity"),
            "expected an index integrity refusal, got: {err:#}"
        );

        // The index and the recorded address: the record's own digest drifts.
        let mut edited = captured.clone();
        edited.content[0] = replaced;
        store.write_meta(&edited).unwrap();
        verify_content(&store, &edited).unwrap();
        let err = verify_lineage(&store, &captured.id, &chain).unwrap_err();
        assert!(
            err.to_string().contains("meta_digest drift"),
            "expected meta_digest drift, got: {err}"
        );

        // Everything local re-sealed: only the chain still disagrees.
        edited.meta_digest = edited.compute_meta_digest();
        store.write_meta(&edited).unwrap();
        verify_content(&store, &edited).unwrap();
        assert_eq!(edited.meta_digest, edited.compute_meta_digest());
        let err = verify_lineage(&store, &captured.id, &chain).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the signed audit chain"),
            "expected a chain mismatch, got: {err}"
        );
    }

    // ── the retired whole-blob layout ───────────────────────────────────────

    /// Rewrite `name` of a captured checkpoint into the layout captures used
    /// before chunking: the whole file in the content directory, no index, and
    /// a record re-sealed around the file's own digest.
    fn rewrite_as_whole_blob(
        store: &CheckpointStore,
        meta: &CheckpointMeta,
        name: &str,
    ) -> CheckpointMeta {
        let content_dir = store.content_dir(&meta.id);
        let whole = content_dir.join(name);
        chunks::materialize_blob(&content_dir, blob_named(meta, name), &whole).unwrap();
        std::fs::remove_file(chunks::index_path(&content_dir, name)).unwrap();
        let mut rewritten = meta.clone();
        for blob in &mut rewritten.content {
            if blob.name == name {
                blob.sha256 = sha256_file_hex(&whole).unwrap();
            }
        }
        rewritten.meta_digest = rewritten.compute_meta_digest();
        store.write_meta(&rewritten).unwrap();
        rewritten
    }

    fn assert_whole_blob_refusal(error: anyhow::Error, meta: &CheckpointMeta, name: &str) {
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!(
                "checkpoint '{}' stores {name} as one whole file",
                meta.id
            )) && message.contains("capture the machine again"),
            "expected the whole-blob refusal for {name}, got: {message}"
        );
    }

    #[test]
    fn a_whole_blob_fs_quick_checkpoint_is_refused_by_every_reader() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let captured = seed_fs_quick_checkpoint(&store, tmp.path(), "old");
        let old = rewrite_as_whole_blob(&store, &captured, "rootfs.ext4");

        assert_whole_blob_refusal(
            verify_content(&store, &old).unwrap_err(),
            &old,
            "rootfs.ext4",
        );
        assert_whole_blob_refusal(
            materialize_checkpoint_blobs(&store, &old, &tmp.path().join("child")).unwrap_err(),
            &old,
            "rootfs.ext4",
        );
        assert!(
            !tmp.path().join("child").exists(),
            "nothing is materialized from a refused checkpoint"
        );
        assert_whole_blob_refusal(
            materialized_blob_sha256(&store, &old, "rootfs.ext4").unwrap_err(),
            &old,
            "rootfs.ext4",
        );
        let fork = fork_checkpoint(
            &store,
            ForkParams {
                checkpoint: old.id.clone(),
                child_id: CheckpointId::new("child"),
                child_vm_name: "childvm".into(),
                dest_dir: tmp.path().join("childvm-state"),
                created_unix: 2,
                parent_liveness: ForkParentLiveness::MustBeStopped,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &AgreeingAnchor,
        );
        assert_whole_blob_refusal(fork.unwrap_err(), &old, "rootfs.ext4");

        // Removal is how a user gets rid of one, so it must keep working.
        store.remove(&old.id).unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn a_whole_blob_memory_image_is_refused_by_restore() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let captured = seed_fc_vm_full_checkpoint(&store, tmp.path(), "old-vm");
        let old = rewrite_as_whole_blob(&store, &captured, mvm_core::checkpoint::MEMORY_BLOB);

        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        assert_whole_blob_refusal(
            materialized_source(&store, &old, "rootfs.ext4", &scratch).unwrap_err(),
            &old,
            "memory.bin",
        );
        assert_whole_blob_refusal(
            verify_content_except(&store, &old, &[mvm_core::checkpoint::MEMORY_BLOB]).unwrap_err(),
            &old,
            "memory.bin",
        );
    }

    #[test]
    fn a_missing_chunked_blob_is_reported_missing_not_as_the_old_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let meta = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        std::fs::remove_file(chunks::index_path(
            &store.content_dir(&meta.id),
            "rootfs.ext4",
        ))
        .unwrap();

        let message = format!("{:#}", verify_content(&store, &meta).unwrap_err());
        assert!(!message.contains("whole file"), "{message}");
    }

    // ── chain-anchored verification (the signed-chain leg) ───────────────────

    #[test]
    fn verify_lineage_fails_when_chain_recorded_digest_disagrees() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let root = seed_linked_meta(&store, "g0", None, "aa");
        // The on-disk record is internally consistent (recompute == stored), but
        // the signed chain recorded a different content-address at creation — a
        // full local re-forge that only the signed chain can catch.
        let err =
            verify_lineage(&store, &root.id, &DisagreeingAnchor(unrelated_digest())).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the signed audit chain"),
            "expected a chain-mismatch error, got: {err}"
        );
    }

    #[test]
    fn verify_lineage_refuses_a_node_with_no_signed_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let root = seed_linked_meta(&store, "g0", None, "aa");
        let err = verify_lineage(&store, &root.id, &UnauditedAnchor).unwrap_err();
        assert!(
            err.to_string().contains("no signed audit entry"),
            "expected an un-audited-node error, got: {err}"
        );
    }
}
