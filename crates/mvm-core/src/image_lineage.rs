//! Immutable, audit-bound records of a compiled microVM image's version
//! lineage. An [`ImageNode`] is the image analog of [`crate::checkpoint`]'s
//! `CheckpointMeta`: a content-addressed record that hash-links to the prior
//! build of the *same* build identity, so a version chain (build N ← build N-1
//! ← … ← genesis) is a tamper-evident sequence anchored in the signed audit
//! chain.
//!
//! # Lineage is PROVENANCE, not AUTHORIZATION
//!
//! A node's `parent` edge, and any ancestor reachable through it, is a record
//! of *where this build came from* — never a grant of trust. Nothing here lets
//! a present or trusted ancestor confer admission or boot rights on a child.
//! Boot integrity stays gated by dm-verity (the tampered-rootfs claim);
//! admission stays gated by the signed, content-addressed bundle and its
//! pinned key id. A verified lineage proves only that the chain of records was
//! not edited after it was signed — it says nothing about whether the image
//! *may run*. Treat the lineage strictly as provenance metadata.
//!
//! The node reuses [`CheckpointDigest`] for its own content-address and its
//! `parent` hash-link, and [`ContentBlob`] for its artifact commitments, so the
//! image and checkpoint lineages share one digest shape and one verify walk
//! rather than forking a second copy.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checkpoint::{CheckpointDigest, ContentBlob};

/// The stable identity a version chain is keyed on. Two builds belong to the
/// same chain iff they share this identity; a new build's `parent` is the prior
/// head for the *same* identity. Deliberately coarse: it excludes anything that
/// legitimately moves build to build (a resolved digest, a lockfile hash) so
/// successive builds of one source line up on one chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImageBuildIdentity {
    /// A Nix flake output, keyed on the resolved slot hash of the flake ref.
    Flake { slot_hash: String },
    /// An OCI repository, keyed on registry + repository. A specific tag or
    /// digest is *not* part of the key — those advance within one repo's chain.
    Oci {
        registry: String,
        repository: String,
    },
}

/// The compiled image's own canonical source identity: the flake's Nix
/// revision hash or the OCI resolved manifest digest. Distinct from
/// [`ImageBuildIdentity`] (the chain key): this pins the exact image this node
/// records, not the line of builds it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImageCanonicalId {
    /// A Nix flake build, identified by its revision hash.
    Flake { revision_hash: String },
    /// An OCI image, identified by its resolved manifest digest.
    Oci { resolved_digest: String },
}

/// The compiled image's canonical identity plus content commitments to the
/// bytes it produced (rootfs / kernel). Committing to the artifact hashes means
/// the node content-addresses the *actual* image, not just a name for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageIdentity {
    /// Canonical source identity (flake revision hash / OCI resolved digest).
    pub canonical: ImageCanonicalId,
    /// Content-addressed commitments to the produced artifact bytes
    /// (`rootfs.ext4`, `kernel`, …). Order-invariant in the digest.
    pub artifacts: Vec<ContentBlob>,
}

/// Where this build's *external* base came from, recorded as a provenance
/// attribute. This is emphatically NOT the [`ImageNode::parent`] edge: the
/// parent is the predecessor build of the same identity (the walk edge), while
/// this records the upstream input the build consumed. The verifier records it
/// and never walks it, and it confers no trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImageProvenance {
    /// A Nix flake / template / local-project build input.
    Build {
        /// The supplied reference (flake ref, template name, project path).
        input_ref: String,
        /// Pin of the input (e.g. `flake.lock` hash), when recorded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lock_digest: Option<String>,
    },
    /// An OCI image pull input.
    Oci {
        /// The resolved manifest digest the reference pinned to.
        resolved_digest: String,
        /// The ordered layer digest set the manifest enumerated.
        #[serde(default)]
        layer_digests: Vec<String>,
    },
}

/// On-disk record for one image build in a version chain
/// (`<images_dir>/<node_digest>/node.json`).
///
/// `parent` hash-links to the predecessor node's `node_digest` (its
/// content-address) for the same `build_identity`, so a descendant detects any
/// post-seal edit of an ancestor — the recomputed ancestor digest no longer
/// matches the child's link. `node_digest` is the content-address of the
/// load-bearing fields, derived in [`ImageNodeBuilder::build`] and never set by
/// callers. `audit_ref` is a non-load-bearing back-pointer backfilled after the
/// chain-signed entry is emitted; it and `node_digest` are excluded from the
/// digest so the backfill does not perturb the content-address.
///
/// See the module docs: a node is PROVENANCE, never AUTHORIZATION.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageNode {
    /// Content-address of the load-bearing fields below. Required with no serde
    /// default: a record that carries no content-address cannot be
    /// lineage-verified, so a malformed node must fail closed rather than load
    /// as an unverifiable record.
    pub node_digest: CheckpointDigest,
    /// The version-chain key. `ImageStore::head_for` looks up by this.
    pub build_identity: ImageBuildIdentity,
    /// The predecessor node for the same `build_identity`, hash-linked by
    /// content-address. `None` = genesis. This is the walk edge.
    pub parent: Option<CheckpointDigest>,
    pub created_unix: u64,
    /// The compiled image's own canonical identity + artifact commitments.
    pub image_identity: ImageIdentity,
    /// The external base, recorded as a provenance attribute (not a walk edge).
    pub provenance: ImageProvenance,
    /// Non-load-bearing back-pointer to the signed audit entry. Excluded from
    /// the digest.
    pub audit_ref: Option<String>,
}

impl ImageNode {
    /// Start building a node. `node_digest` is derived in [`ImageNodeBuilder::build`].
    pub fn builder(
        build_identity: ImageBuildIdentity,
        image_identity: ImageIdentity,
        provenance: ImageProvenance,
    ) -> ImageNodeBuilder {
        ImageNodeBuilder {
            build_identity,
            parent: None,
            created_unix: 0,
            image_identity,
            provenance,
            audit_ref: None,
        }
    }

    /// Recompute this record's content-address from its load-bearing fields. A
    /// stored `node_digest` that no longer equals this value is proof the record
    /// was edited after it was sealed — the check `verify_image_lineage` walks
    /// with. Mirrors [`ImageNodeBuilder::build`]; the `node_digest_recomputes_*`
    /// tests pin that the two agree.
    pub fn compute_node_digest(&self) -> CheckpointDigest {
        ImageNodeDigestInput {
            build_identity: &self.build_identity,
            parent: &self.parent,
            created_unix: self.created_unix,
            image_canonical: &self.image_identity.canonical,
            image_artifacts: crate::checkpoint::sorted_content(&self.image_identity.artifacts),
            provenance: &self.provenance,
        }
        .digest()
    }
}

/// The load-bearing fields of an [`ImageNode`], borrowed in fixed declaration
/// order, that `node_digest` content-addresses. `node_digest` itself and
/// `audit_ref` are excluded: the former is what we are deriving (excluding it
/// avoids circularity), the latter is backfilled after the audit entry is
/// emitted and must not perturb the digest.
#[derive(Serialize)]
struct ImageNodeDigestInput<'a> {
    build_identity: &'a ImageBuildIdentity,
    parent: &'a Option<CheckpointDigest>,
    created_unix: u64,
    image_canonical: &'a ImageCanonicalId,
    /// Sorted by `name` so the digest is invariant to artifact ordering.
    image_artifacts: Vec<&'a ContentBlob>,
    provenance: &'a ImageProvenance,
}

impl ImageNodeDigestInput<'_> {
    fn digest(&self) -> CheckpointDigest {
        // Plain serde_json (not JCS): host-only, single-implementation, no
        // cross-language conformance need — the same posture the checkpoint
        // digest and the audit envelope take.
        let bytes =
            serde_json::to_vec(self).expect("image node digest input is always JSON-serializable");
        let hex = hex::encode(Sha256::digest(&bytes));
        // Reuse the checkpoint digest's shape validation rather than poke its
        // private field: the hex we produce is always a valid `sha256:<64 hex>`.
        CheckpointDigest::parse(format!("{}{hex}", CheckpointDigest::PREFIX))
            .expect("sha256 hex is always a valid checkpoint-digest shape")
    }
}

/// Fluent builder for [`ImageNode`]; obtain via [`ImageNode::builder`]. Derives
/// `node_digest` once in [`Self::build`], so a caller can never hand-set a
/// content-address that disagrees with the fields.
pub struct ImageNodeBuilder {
    build_identity: ImageBuildIdentity,
    parent: Option<CheckpointDigest>,
    created_unix: u64,
    image_identity: ImageIdentity,
    provenance: ImageProvenance,
    audit_ref: Option<String>,
}

impl ImageNodeBuilder {
    /// Hash-link this node to its predecessor's content-address
    /// ([`ImageNode::node_digest`]).
    pub fn parent(mut self, parent: Option<CheckpointDigest>) -> Self {
        self.parent = parent;
        self
    }
    pub fn created_unix(mut self, secs: u64) -> Self {
        self.created_unix = secs;
        self
    }
    pub fn audit_ref(mut self, r: Option<String>) -> Self {
        self.audit_ref = r;
        self
    }
    pub fn build(self) -> ImageNode {
        // Derive the content-address before moving the fields out. Mirrors
        // `ImageNode::compute_node_digest` — the `node_digest_recomputes_*`
        // tests pin that the two agree.
        let node_digest = ImageNodeDigestInput {
            build_identity: &self.build_identity,
            parent: &self.parent,
            created_unix: self.created_unix,
            image_canonical: &self.image_identity.canonical,
            image_artifacts: crate::checkpoint::sorted_content(&self.image_identity.artifacts),
            provenance: &self.provenance,
        }
        .digest();
        ImageNode {
            node_digest,
            build_identity: self.build_identity,
            parent: self.parent,
            created_unix: self.created_unix,
            image_identity: self.image_identity,
            provenance: self.provenance,
            audit_ref: self.audit_ref,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(name: &str, sha: &str) -> ContentBlob {
        ContentBlob {
            name: name.into(),
            sha256: sha.into(),
        }
    }

    fn flake_identity() -> ImageBuildIdentity {
        ImageBuildIdentity::Flake {
            slot_hash: "slot-abc".into(),
        }
    }

    fn flake_image(revision: &str, artifacts: Vec<ContentBlob>) -> ImageIdentity {
        ImageIdentity {
            canonical: ImageCanonicalId::Flake {
                revision_hash: revision.into(),
            },
            artifacts,
        }
    }

    fn flake_provenance() -> ImageProvenance {
        ImageProvenance::Build {
            input_ref: ".#app".into(),
            lock_digest: Some("sha256:lock".into()),
        }
    }

    fn fixture_node(artifacts: Vec<ContentBlob>) -> ImageNode {
        ImageNode::builder(
            flake_identity(),
            flake_image("rev-1", artifacts),
            flake_provenance(),
        )
        .created_unix(100)
        .build()
    }

    fn parent_digest() -> CheckpointDigest {
        CheckpointDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap()
    }

    #[test]
    fn node_roundtrips_through_json() {
        let node = ImageNode::builder(
            ImageBuildIdentity::Oci {
                registry: "docker.io".into(),
                repository: "library/alpine".into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Oci {
                    resolved_digest: format!("sha256:{}", "d".repeat(64)),
                },
                artifacts: vec![blob("rootfs.ext4", "aa")],
            },
            ImageProvenance::Oci {
                resolved_digest: format!("sha256:{}", "d".repeat(64)),
                layer_digests: vec![format!("sha256:{}", "e".repeat(64))],
            },
        )
        .parent(Some(parent_digest()))
        .created_unix(1_700_000_000)
        .audit_ref(Some("local.jsonl#5".into()))
        .build();

        let json = serde_json::to_string(&node).unwrap();
        let back: ImageNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
        assert_eq!(back.node_digest, node.node_digest);
        assert_eq!(back.parent.unwrap(), parent_digest());
    }

    #[test]
    fn node_rejects_unknown_fields() {
        let node = fixture_node(vec![blob("rootfs.ext4", "aa")]);
        let mut value: serde_json::Value = serde_json::to_value(&node).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("bogus".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<ImageNode>(value).is_err());
    }

    #[test]
    fn node_digest_wire_shape_is_sha256_prefixed_hex() {
        let n = fixture_node(vec![blob("rootfs.ext4", "aa")]);
        let s = n.node_digest.as_str();
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.len(), "sha256:".len() + 64);
    }

    #[test]
    fn node_digest_is_deterministic_across_builds() {
        let a = fixture_node(vec![blob("rootfs.ext4", "aa")]);
        let b = fixture_node(vec![blob("rootfs.ext4", "aa")]);
        assert_eq!(a.node_digest, b.node_digest);
    }

    #[test]
    fn identical_content_produces_identical_digest() {
        // Full-field equality (not just the fixture) → identical digest.
        let build = || {
            ImageNode::builder(
                flake_identity(),
                flake_image(
                    "rev-9",
                    vec![blob("kernel", "k1"), blob("rootfs.ext4", "r1")],
                ),
                flake_provenance(),
            )
            .parent(Some(parent_digest()))
            .created_unix(42)
            .build()
            .node_digest
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn node_digest_recomputes_equal_to_stored() {
        let n = fixture_node(vec![blob("rootfs.ext4", "aa"), blob("kernel", "bb")]);
        assert_eq!(n.node_digest, n.compute_node_digest());
    }

    #[test]
    fn node_digest_invariant_under_artifact_insertion_order() {
        let ordered = fixture_node(vec![blob("a", "1"), blob("b", "2"), blob("c", "3")]);
        let permuted = fixture_node(vec![blob("c", "3"), blob("a", "1"), blob("b", "2")]);
        assert_eq!(ordered.node_digest, permuted.node_digest);
    }

    #[test]
    fn node_digest_excludes_node_digest_and_audit_ref() {
        // audit_ref is backfilled after the chain entry is emitted; it must not
        // move the content-address. (node_digest is derived, so it cannot be an
        // input to itself — no circularity — which the recompute test also pins.)
        let without = fixture_node(vec![blob("rootfs.ext4", "aa")]);
        let with = ImageNode::builder(
            flake_identity(),
            flake_image("rev-1", vec![blob("rootfs.ext4", "aa")]),
            flake_provenance(),
        )
        .created_unix(100)
        .audit_ref(Some("local.jsonl#3".into()))
        .build();
        assert_eq!(without.node_digest, with.node_digest);
    }

    #[test]
    fn node_digest_covers_every_load_bearing_field() {
        // Flip exactly one load-bearing field per case; the content-address must
        // move. Guards a future field silently falling outside the digest input.
        let base = fixture_node(vec![blob("rootfs.ext4", "aa")]);
        let baseline = base.node_digest.clone();

        // build_identity
        let n = ImageNode::builder(
            ImageBuildIdentity::Flake {
                slot_hash: "slot-OTHER".into(),
            },
            flake_image("rev-1", vec![blob("rootfs.ext4", "aa")]),
            flake_provenance(),
        )
        .created_unix(100)
        .build();
        assert_ne!(baseline, n.node_digest, "build_identity");

        // parent
        let n = ImageNode::builder(
            flake_identity(),
            flake_image("rev-1", vec![blob("rootfs.ext4", "aa")]),
            flake_provenance(),
        )
        .parent(Some(parent_digest()))
        .created_unix(100)
        .build();
        assert_ne!(baseline, n.node_digest, "parent");

        // created_unix
        let n = ImageNode::builder(
            flake_identity(),
            flake_image("rev-1", vec![blob("rootfs.ext4", "aa")]),
            flake_provenance(),
        )
        .created_unix(200)
        .build();
        assert_ne!(baseline, n.node_digest, "created_unix");

        // image_identity.canonical
        let n = ImageNode::builder(
            flake_identity(),
            flake_image("rev-OTHER", vec![blob("rootfs.ext4", "aa")]),
            flake_provenance(),
        )
        .created_unix(100)
        .build();
        assert_ne!(baseline, n.node_digest, "image_canonical");

        // image_identity.artifacts
        let n = fixture_node(vec![blob("rootfs.ext4", "zz")]);
        assert_ne!(baseline, n.node_digest, "image_artifacts");

        // provenance
        let n = ImageNode::builder(
            flake_identity(),
            flake_image("rev-1", vec![blob("rootfs.ext4", "aa")]),
            ImageProvenance::Build {
                input_ref: ".#other".into(),
                lock_digest: Some("sha256:lock".into()),
            },
        )
        .created_unix(100)
        .build();
        assert_ne!(baseline, n.node_digest, "provenance");
    }
}
