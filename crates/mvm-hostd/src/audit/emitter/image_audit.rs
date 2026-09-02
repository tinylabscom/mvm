//! Wire-stable image version-lineage audit labels.

/// Emitted when a compiled image's version-lineage node is created.
pub const CREATED_EVENT: &str = "image.created";
/// Emitted when a fresh VM is launched from a prior image-lineage node.
pub const REVERTED_EVENT: &str = "image.reverted";
/// Label: how a restore was initiated (`revert` / `rewind` / `advance`).
pub const LABEL_VIA: &str = "via";
/// Label: the reconstructed `machine run` reference a restore re-runs.
pub const LABEL_REVERTED_REFERENCE: &str = "image_reverted_reference";
/// Label: the node's own content-address. The chain-anchor keys on this.
pub const LABEL_NODE_DIGEST: &str = "image_node_digest";
/// Label: the predecessor node's content-address.
pub const LABEL_PARENT_DIGEST: &str = "image_parent_digest";
/// Label: the build-identity discriminant (`"flake"` / `"oci"`).
pub const LABEL_BUILD_IDENTITY_KIND: &str = "image_build_identity_kind";
/// Label: the build-identity value.
pub const LABEL_BUILD_IDENTITY: &str = "image_build_identity";
/// Label: the provenance discriminant (`"build"` / `"oci"`).
pub const LABEL_PROVENANCE_KIND: &str = "image_provenance_kind";
/// Label: the build-provenance input reference.
pub const LABEL_PROVENANCE_INPUT_REF: &str = "image_provenance_input_ref";
/// Label: the build-provenance lock digest, when recorded.
pub const LABEL_PROVENANCE_LOCK_DIGEST: &str = "image_provenance_lock_digest";
/// Label: the OCI-provenance resolved manifest digest.
pub const LABEL_PROVENANCE_RESOLVED_DIGEST: &str = "image_provenance_resolved_digest";
/// Label: the OCI-provenance layer digest set (comma-joined).
pub const LABEL_PROVENANCE_LAYER_DIGESTS: &str = "image_provenance_layer_digests";
/// Sentinel for a genesis (parentless) node.
pub const GENESIS_PARENT: &str = "genesis";
