//! Host-side image version-lineage store + chain-anchored verification. The
//! image analog of [`crate::checkpoint`]'s store/verify: a filesystem registry
//! of [`ImageNode`] records plus the fail-closed walk that proves a node's
//! version chain against the signed audit log.
//!
//! Lineage is PROVENANCE, never AUTHORIZATION — see [`mvm_core::image_lineage`].
//! Nothing here grants a child trust because an ancestor is present or verified;
//! boot integrity stays with dm-verity and admission with the signed bundle.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::checkpoint::CheckpointDigest;
use mvm_core::image_lineage::{ImageBuildIdentity, ImageNode};

use crate::lineage::{LineageAnchor, LineageGraph, LineageRecord};

/// Filesystem-backed registry over `config::images_dir()` (or any root, for
/// tests). Layout: `<root>/<node-digest>/node.json`. A node's directory name is
/// its own content-address, so a node is addressable by digest without an index.
pub struct ImageStore {
    root: PathBuf,
}

/// A serialized image node prepared for publication after its audit entry is
/// durable. Dropping an uncommitted stage removes its temporary file, so an
/// audit failure cannot leave a visible node behind.
#[must_use = "a staged image node must be committed after its audit entry succeeds"]
pub struct StagedImageNode {
    temp: Option<tempfile::NamedTempFile>,
    destination: PathBuf,
}

impl StagedImageNode {
    /// Atomically publish the staged node at its content-addressed destination.
    pub fn commit(mut self) -> Result<()> {
        let Some(temp) = self.temp.take() else {
            anyhow::bail!("staged image node was already committed");
        };
        let destination = self.destination.clone();
        match temp.persist(&destination) {
            Ok(_) => Ok(()),
            Err(error) => {
                let _ = error.file.close();
                Err(error.error).with_context(|| {
                    format!("publishing staged image node {}", destination.display())
                })
            }
        }
    }
}

impl ImageStore {
    /// Production constructor — uses the canonical `~/.mvm/images` path.
    pub fn open() -> Self {
        Self::at(mvm_core::config::images_dir())
    }

    /// Test/explicit-root constructor.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn dir_for(&self, node_digest: &CheckpointDigest) -> PathBuf {
        self.root.join(node_digest.as_str())
    }

    fn node_path(&self, node_digest: &CheckpointDigest) -> PathBuf {
        self.dir_for(node_digest).join("node.json")
    }

    /// Prepare a node under its own content-address without publishing it.
    pub fn stage(&self, node: &ImageNode) -> Result<StagedImageNode> {
        let dir = self.dir_for(&node.node_digest);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating image node dir {}", dir.display()))?;
        let json = serde_json::to_vec_pretty(node).context("serializing image node")?;
        let mut temp = tempfile::NamedTempFile::new_in(&dir)
            .with_context(|| format!("creating staged image node in {}", dir.display()))?;
        temp.write_all(&json)
            .with_context(|| format!("writing staged image node in {}", dir.display()))?;
        temp.flush().context("flushing staged image node")?;
        temp.as_file()
            .sync_all()
            .context("syncing staged image node")?;
        Ok(StagedImageNode {
            temp: Some(temp),
            destination: self.node_path(&node.node_digest),
        })
    }

    /// Persist a node under its own content-address atomically.
    pub fn save(&self, node: &ImageNode) -> Result<()> {
        self.stage(node)?.commit()
    }

    /// Read the node stored under `node_digest` (its directory name). Fails
    /// closed on a mis-filed record: the deserialized `node_digest` field must
    /// equal the requested digest (the directory name), so a node planted under
    /// another node's directory cannot slip through as that other node. This
    /// self-consistency is what the lineage walk's first hop
    /// (`graph.read(start)`) relies on; the walk then recomputes the digest to
    /// prove the field is genuine.
    pub fn read(&self, node_digest: &CheckpointDigest) -> Result<ImageNode> {
        let path = self.node_path(node_digest);
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let node: ImageNode = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {}", path.display()))?;
        if &node.node_digest != node_digest {
            anyhow::bail!(
                "image node at {} is mis-filed: its directory names {node_digest} but the \
                 record's node_digest is {}",
                path.display(),
                node.node_digest
            );
        }
        Ok(node)
    }

    /// Every node with a well-formed `node.json`. `O(n)` directory scan (matches
    /// [`crate::checkpoint::CheckpointStore::list`]).
    pub fn list(&self) -> Result<Vec<ImageNode>> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).context("reading images dir"),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let node_json = entry.path().join("node.json");
            if node_json.exists() {
                let bytes = std::fs::read(&node_json)
                    .with_context(|| format!("reading {}", node_json.display()))?;
                out.push(
                    serde_json::from_slice(&bytes)
                        .with_context(|| format!("parsing {}", node_json.display()))?,
                );
            }
        }
        Ok(out)
    }

    /// Look up a node by its content-address ([`ImageNode::node_digest`]). Scans
    /// `list()` and matches the stored field, so a returned node's own digest
    /// genuinely equals `digest` — the invariant the lineage walk relies on when
    /// it resolves a parent hash-link.
    pub fn by_digest(&self, digest: &CheckpointDigest) -> Result<Option<ImageNode>> {
        Ok(self.list()?.into_iter().find(|n| &n.node_digest == digest))
    }

    /// Nodes whose parent hash-link is `parent_digest`. Lineage is derived by
    /// content-address, not by a mutable name.
    pub fn children_of(&self, parent_digest: &CheckpointDigest) -> Result<Vec<ImageNode>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|n| n.parent.as_ref() == Some(parent_digest))
            .collect())
    }

    /// The current tip of `build_identity`'s version chain: the node with that
    /// identity that is nobody's parent. `Ok(None)` when no node carries the
    /// identity. A clean linear chain has exactly one such node; this is what a
    /// new build of the same identity hash-links its `parent` to.
    ///
    /// Fails closed on an ambiguous tip: if two or more nodes share the identity
    /// and none descends from the others (a fork), there is no single tip to
    /// build on, so this errors rather than silently pick a filesystem-order
    /// arbitrary one — a caller (the build path) must not set a new node's
    /// parent to a guessed head. It likewise errors if every matching node is
    /// referenced as a parent (a cyclic/broken set with no tip).
    pub fn head_for(&self, build_identity: &ImageBuildIdentity) -> Result<Option<ImageNode>> {
        let matching: Vec<ImageNode> = self
            .list()?
            .into_iter()
            .filter(|n| &n.build_identity == build_identity)
            .collect();
        if matching.is_empty() {
            return Ok(None);
        }
        let referenced_parents: std::collections::HashSet<&CheckpointDigest> =
            matching.iter().filter_map(|n| n.parent.as_ref()).collect();
        let tips: Vec<&ImageNode> = matching
            .iter()
            .filter(|n| !referenced_parents.contains(&n.node_digest))
            .collect();
        match tips.as_slice() {
            [tip] => Ok(Some((*tip).clone())),
            [] => anyhow::bail!(
                "image build identity {build_identity:?} has no version-chain tip: every \
                 matching node is referenced as a parent (a cyclic or broken chain)"
            ),
            _ => anyhow::bail!(
                "image build identity {build_identity:?} has an ambiguous version-chain tip: \
                 {} nodes share it and none descends from the others (a fork); refusing to \
                 pick one",
                tips.len()
            ),
        }
    }
}

/// Resolves the signature-authenticated content-address an image node's creation
/// was recorded under in the chain-signed audit log. The image analog of
/// [`crate::checkpoint::CheckpointChainAnchor`]: injected so this crate's walk
/// stays free of host-key loading and audit-file layout, which live in the CLI.
/// An implementation MUST verify the audit chain's signatures before trusting
/// any digest it returns.
pub trait ImageChainAnchor {
    /// The content-address recorded for `node`'s creation in the signature-
    /// verified audit chain (`image.created`'s `image_node_digest`), or `None`
    /// if the chain carries no creation entry for it.
    fn recorded_creation_digest(&self, node: &ImageNode) -> Result<Option<CheckpointDigest>>;
}

/// An [`ImageNode`] participates in the shared lineage walk: its stored digest
/// is `node_digest`, it recomputes via [`ImageNode::compute_node_digest`], and
/// its parent hash-link is `parent`.
impl LineageRecord for ImageNode {
    fn stored_digest(&self) -> &CheckpointDigest {
        &self.node_digest
    }
    fn recompute_digest(&self) -> CheckpointDigest {
        self.compute_node_digest()
    }
    fn parent_link(&self) -> Option<&CheckpointDigest> {
        self.parent.as_ref()
    }
    fn kind(&self) -> &'static str {
        "image node"
    }
    fn id_label(&self) -> String {
        self.node_digest.to_string()
    }
    fn digest_field(&self) -> &'static str {
        "node_digest"
    }
}

/// Bridge the image-specific anchor trait onto the generic one.
impl LineageAnchor<ImageNode> for dyn ImageChainAnchor + '_ {
    fn recorded_creation_digest(&self, node: &ImageNode) -> Result<Option<CheckpointDigest>> {
        ImageChainAnchor::recorded_creation_digest(self, node)
    }
}

/// Adapts an [`ImageStore`] to the generic [`LineageGraph`].
struct ImageGraph<'a>(&'a ImageStore);

impl LineageGraph for ImageGraph<'_> {
    type Record = ImageNode;
    type Id = CheckpointDigest;
    fn read(&self, id: &CheckpointDigest) -> Result<ImageNode> {
        self.0.read(id)
    }
    fn by_digest(&self, digest: &CheckpointDigest) -> Result<Option<ImageNode>> {
        self.0.by_digest(digest)
    }
    fn children_of(&self, parent_digest: &CheckpointDigest) -> Result<Vec<ImageNode>> {
        self.0.children_of(parent_digest)
    }
}

/// Walk an image node's version lineage from `node_digest` to its genesis root,
/// verifying each record against the **signed** audit chain via `anchor`: at
/// every hop the record's recomputed content-address must equal both its stored
/// `node_digest` and the digest the host signed into the audit chain at
/// creation. Fails closed on a recompute drift, a chain mismatch, a node with no
/// signed creation entry, a dangling parent hash-link, or a cycle — the same
/// guarantees as the checkpoint verifier, over the same shared walk.
///
/// This proves integrity of the provenance chain; it grants nothing. A verified
/// lineage does not admit or boot an image (dm-verity + signed bundle do).
pub fn verify_image_lineage(
    store: &ImageStore,
    node_digest: &CheckpointDigest,
    anchor: &dyn ImageChainAnchor,
) -> Result<()> {
    crate::lineage::verify_lineage_chain(&ImageGraph(store), node_digest, anchor)
}

/// Enumerate an image node's ancestry (itself + every ancestor up to genesis),
/// verifying each hop against the signed audit chain. Read-only navigation: each
/// node carries its [`crate::lineage::HopStatus`] and the walk fails closed on a
/// dangling parent or a cycle via [`crate::lineage::Ancestry::broken`] rather
/// than bailing on the first bad node. The image analog of
/// [`crate::checkpoint::checkpoint_ancestry`].
pub fn image_ancestry(
    store: &ImageStore,
    node_digest: &CheckpointDigest,
    anchor: &dyn ImageChainAnchor,
) -> Result<crate::lineage::Ancestry<ImageNode>> {
    crate::lineage::collect_ancestry(&ImageGraph(store), node_digest, anchor)
}

/// Enumerate an image node's immediate children (forward is a tree — the same
/// build identity can fork), each verified against the signed audit chain.
pub fn image_children(
    store: &ImageStore,
    parent_digest: &CheckpointDigest,
    anchor: &dyn ImageChainAnchor,
) -> Result<Vec<crate::lineage::VerifiedNode<ImageNode>>> {
    crate::lineage::verified_children(&ImageGraph(store), parent_digest, anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::image_lineage::{ImageCanonicalId, ImageIdentity, ImageProvenance};
    use std::collections::HashMap;

    fn flake_identity(slot: &str) -> ImageBuildIdentity {
        ImageBuildIdentity::Flake {
            slot_hash: slot.into(),
        }
    }

    fn node(slot: &str, revision: &str, parent: Option<CheckpointDigest>) -> ImageNode {
        ImageNode::builder(
            flake_identity(slot),
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: revision.into(),
                },
                artifacts: vec![mvm_core::checkpoint::ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: revision.into(),
                }],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .parent(parent)
        .created_unix(1)
        .build()
    }

    // ── mock anchors (mirror the checkpoint mod's Agreeing/Disagreeing/Unaudited)

    struct AgreeingAnchor;
    impl ImageChainAnchor for AgreeingAnchor {
        fn recorded_creation_digest(&self, n: &ImageNode) -> Result<Option<CheckpointDigest>> {
            Ok(Some(n.compute_node_digest()))
        }
    }

    /// Indexes only the node digests it was told about — models a signed chain
    /// that recorded some nodes' creation but not others'.
    struct IndexedAnchor(HashMap<String, CheckpointDigest>);
    impl IndexedAnchor {
        fn of(nodes: &[&ImageNode]) -> Self {
            Self(
                nodes
                    .iter()
                    .map(|n| (n.node_digest.to_string(), n.node_digest.clone()))
                    .collect(),
            )
        }
    }
    impl ImageChainAnchor for IndexedAnchor {
        fn recorded_creation_digest(&self, n: &ImageNode) -> Result<Option<CheckpointDigest>> {
            Ok(self.0.get(n.node_digest.as_str()).cloned())
        }
    }

    struct DisagreeingAnchor(CheckpointDigest);
    impl ImageChainAnchor for DisagreeingAnchor {
        fn recorded_creation_digest(&self, _n: &ImageNode) -> Result<Option<CheckpointDigest>> {
            Ok(Some(self.0.clone()))
        }
    }

    fn unrelated_digest() -> CheckpointDigest {
        CheckpointDigest::parse(format!("sha256:{}", "f".repeat(64))).unwrap()
    }

    // ── store tests ─────────────────────────────────────────────────────────

    #[test]
    fn save_then_read_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let n = node("slot-a", "rev-1", None);
        store.save(&n).unwrap();
        assert_eq!(store.read(&n.node_digest).unwrap(), n);
    }

    #[test]
    fn dropping_an_uncommitted_stage_does_not_publish_a_node() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let n = node("slot-a", "rev-1", None);

        {
            let _staged = store.stage(&n).unwrap();
            assert!(store.by_digest(&n.node_digest).unwrap().is_none());
        }

        assert!(store.by_digest(&n.node_digest).unwrap().is_none());
        let node_dir = store.dir_for(&n.node_digest);
        assert!(std::fs::read_dir(node_dir).unwrap().next().is_none());
    }

    #[test]
    fn by_digest_finds_the_node() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let n = node("slot-a", "rev-1", None);
        store.save(&n).unwrap();
        assert_eq!(store.by_digest(&n.node_digest).unwrap().as_ref(), Some(&n));
        assert!(store.by_digest(&unrelated_digest()).unwrap().is_none());
    }

    #[test]
    fn children_of_finds_lineage_by_hashlink() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let parent = node("slot-a", "rev-1", None);
        store.save(&parent).unwrap();
        let child = node("slot-a", "rev-2", Some(parent.node_digest.clone()));
        store.save(&child).unwrap();
        let kids = store.children_of(&parent.node_digest).unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].node_digest, child.node_digest);
    }

    #[test]
    fn head_for_returns_the_tip_and_none_for_unknown_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let g0 = node("slot-a", "rev-1", None);
        let g1 = node("slot-a", "rev-2", Some(g0.node_digest.clone()));
        let g2 = node("slot-a", "rev-3", Some(g1.node_digest.clone()));
        // A node on a DIFFERENT identity must not affect slot-a's head.
        let other = node("slot-b", "rev-1", None);
        for n in [&g0, &g1, &g2, &other] {
            store.save(n).unwrap();
        }
        // The tip is g2 (nobody's parent within slot-a).
        assert_eq!(
            store
                .head_for(&flake_identity("slot-a"))
                .unwrap()
                .unwrap()
                .node_digest,
            g2.node_digest
        );
        // Unknown identity → None.
        assert!(
            store
                .head_for(&flake_identity("slot-unknown"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn dir_name_is_the_node_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let n = node("slot-a", "rev-1", None);
        assert_eq!(
            store.dir_for(&n.node_digest),
            tmp.path().join(n.node_digest.as_str())
        );
    }

    #[test]
    fn read_rejects_a_misfiled_node() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let real = node("slot-a", "rev-1", None);
        let other = node("slot-a", "rev-2", None); // a different node_digest

        // Plant `real`'s record under `other`'s directory name.
        let dir = store.dir_for(&other.node_digest);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("node.json"),
            serde_json::to_vec_pretty(&real).unwrap(),
        )
        .unwrap();

        // Reading by the directory name must reject the mis-filed record...
        let err = store.read(&other.node_digest).unwrap_err();
        assert!(err.to_string().contains("mis-filed"), "{err}");
        // ...and so must the walk's first hop.
        let err = verify_image_lineage(&store, &other.node_digest, &AgreeingAnchor).unwrap_err();
        assert!(err.to_string().contains("mis-filed"), "{err}");
    }

    #[test]
    fn head_for_errors_on_an_ambiguous_forked_tip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        // g0 branches into two children — a genuine fork with two tips.
        let g0 = node("slot-a", "rev-1", None);
        let a = node("slot-a", "rev-2a", Some(g0.node_digest.clone()));
        let b = node("slot-a", "rev-2b", Some(g0.node_digest.clone()));
        for n in [&g0, &a, &b] {
            store.save(n).unwrap();
        }
        let err = store.head_for(&flake_identity("slot-a")).unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "{err}");
    }

    // ── lineage tests (mock anchors) ─────────────────────────────────────────

    fn seed_three_node_chain(store: &ImageStore) -> (ImageNode, ImageNode, ImageNode) {
        let g0 = node("slot-a", "rev-1", None);
        let g1 = node("slot-a", "rev-2", Some(g0.node_digest.clone()));
        let g2 = node("slot-a", "rev-3", Some(g1.node_digest.clone()));
        for n in [&g0, &g1, &g2] {
            store.save(n).unwrap();
        }
        (g0, g1, g2)
    }

    #[test]
    fn three_node_chain_verifies_end_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let (g0, g1, g2) = seed_three_node_chain(&store);
        // Each hop is a hash-link to the predecessor's content-address.
        assert_eq!(g2.parent.as_ref().unwrap(), &g1.node_digest);
        assert_eq!(g1.parent.as_ref().unwrap(), &g0.node_digest);
        let anchor = IndexedAnchor::of(&[&g0, &g1, &g2]);
        verify_image_lineage(&store, &g2.node_digest, &anchor).unwrap();
    }

    #[test]
    fn tampered_node_is_rejected_as_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let (g0, _g1, g2) = seed_three_node_chain(&store);
        verify_image_lineage(&store, &g2.node_digest, &AgreeingAnchor).unwrap();

        // Edit an ANCESTOR's node.json: change a load-bearing field but leave the
        // stored node_digest, so recompute no longer matches.
        let path = store.dir_for(&g0.node_digest).join("node.json");
        let mut tampered: ImageNode =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        tampered.created_unix = 999;
        std::fs::write(&path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();

        let err = verify_image_lineage(&store, &g2.node_digest, &AgreeingAnchor).unwrap_err();
        assert!(err.to_string().contains("node_digest drift"), "{err}");
    }

    #[test]
    fn node_absent_from_signed_chain_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let (g0, g1, g2) = seed_three_node_chain(&store);
        // The chain recorded g0 and g1 but NOT g2's creation.
        let anchor = IndexedAnchor::of(&[&g0, &g1]);
        let err = verify_image_lineage(&store, &g2.node_digest, &anchor).unwrap_err();
        assert!(err.to_string().contains("no signed audit entry"), "{err}");
    }

    #[test]
    fn chain_recorded_digest_disagreeing_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        let g0 = node("slot-a", "rev-1", None);
        store.save(&g0).unwrap();
        let err = verify_image_lineage(
            &store,
            &g0.node_digest,
            &DisagreeingAnchor(unrelated_digest()),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the signed audit chain"),
            "{err}"
        );
    }

    #[test]
    fn dangling_parent_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::at(tmp.path());
        // A child hash-linked to a digest no stored node carries.
        let orphan = CheckpointDigest::parse(format!("sha256:{}", "e".repeat(64))).unwrap();
        let child = node("slot-a", "rev-1", Some(orphan));
        store.save(&child).unwrap();
        let err = verify_image_lineage(&store, &child.node_digest, &AgreeingAnchor).unwrap_err();
        assert!(err.to_string().contains("lineage is broken"), "{err}");
    }
}
