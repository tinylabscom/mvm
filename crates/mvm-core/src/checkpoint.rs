//! Immutable, audit-bound records of frozen microVM state. A checkpoint is the
//! origin a `fork` clones a new sandbox instance from.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vm_backend::RuntimeSourcePolicy;

/// Stable identifier for a checkpoint (also its on-disk directory name under
/// `config::checkpoints_dir()`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckpointId(String);

impl CheckpointId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CheckpointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Content-address of a [`CheckpointMeta`]: `sha256(serde_json(load-bearing
/// fields))` rendered `sha256:<64 lowercase hex>`. A child hash-links to its
/// parent by this digest, so editing an ancestor's sealed record is detectable
/// from any descendant — the recomputed ancestor digest no longer matches the
/// child's link.
///
/// This is a content-address, not a signature and not an exact-byte blob
/// digest. It shares the `sha256:<64-hex>` wire shape with several unrelated
/// ids (OCI manifest/layer digests, blob shas, semantic addresses) precisely so
/// the boundary between them is a type-system property, not a string check:
/// there is no `From`/`Into`/`Deref` to or from any of them (nor to
/// [`CheckpointId`]), so handing one where another is expected does not compile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CheckpointDigest(String);

impl CheckpointDigest {
    /// The fixed hash-axis prefix every checkpoint digest carries.
    pub const PREFIX: &'static str = "sha256:";

    /// Validates and wraps a `sha256:<64 lowercase hex>` string. Rejects any
    /// other prefix, wrong length, or non-lowercase-hex content. Shares the
    /// shape check with every other prefixed content-address newtype so none
    /// can drift.
    pub fn parse(value: impl Into<String>) -> Result<Self, CheckpointDigestParseError> {
        use crate::digest_shape::Sha256PrefixedShape;
        let value = value.into();
        match crate::digest_shape::validate_sha256_prefixed(&value) {
            Sha256PrefixedShape::Ok => Ok(Self(value)),
            Sha256PrefixedShape::MissingPrefix => {
                Err(CheckpointDigestParseError::MissingPrefix(value))
            }
            Sha256PrefixedShape::WrongLength { len } => {
                Err(CheckpointDigestParseError::WrongLength { len })
            }
            Sha256PrefixedShape::NonHex { ch } => Err(CheckpointDigestParseError::NonHex { ch }),
        }
    }

    /// The `sha256:<64-hex>` string view.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CheckpointDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for CheckpointDigest {
    type Err = CheckpointDigestParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for CheckpointDigest {
    type Error = CheckpointDigestParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<CheckpointDigest> for String {
    fn from(digest: CheckpointDigest) -> Self {
        digest.0
    }
}

/// [`CheckpointDigest::parse`] / [`CheckpointDigest::from_str`] failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CheckpointDigestParseError {
    /// The value did not start with `sha256:`.
    #[error("checkpoint digest must start with \"sha256:\", got {0:?}")]
    MissingPrefix(String),
    /// The hex portion (after the prefix) was not exactly 64 characters.
    #[error("checkpoint digest hex must be exactly 64 chars, got {len}")]
    WrongLength { len: usize },
    /// The hex portion contained a non-lowercase-hex character.
    #[error("checkpoint digest hex must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

/// The capture mechanism behind a checkpoint. Only `FsQuick` is currently
/// implemented; `VmFull` is reserved so the memory-state path can slot into the
/// same model without a new surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointClass {
    /// Copy-on-write clone of a quiesced rootfs (filesystem state only).
    FsQuick,
    /// Full machine memory state via the supervisor save/restore path.
    VmFull,
}

/// One named artifact inside a checkpoint's `content/` dir, with its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentBlob {
    pub name: String,
    pub sha256: String,
}

/// Saved guest memory image inside a vm_full checkpoint's content dir.
pub const MEMORY_BLOB: &str = "memory.bin";
/// Cloned rootfs image inside any checkpoint's content dir.
pub const ROOTFS_BLOB: &str = "rootfs.ext4";
/// dm-verity hash-tree sidecar carried beside a sealed rootfs.
pub const ROOTFS_VERITY_BLOB: &str = "rootfs.verity";
/// Absolute host paths the saved machine state embeds by path.
pub const DEVICE_ANCHORS_BLOB: &str = "device-anchors.json";
/// Persisted launch config of the VM a vm_full checkpoint was captured from.
/// Present only for backends that drive their VMM through a supervisor config
/// (HVF, and the removed Apple-Virtualization backend); Firecracker omits it.
pub const SUPERVISOR_CONFIG_BLOB: &str = "supervisor-config.json";
/// vCPU + deterministic device state the in-house HVF VMM writes beside
/// [`MEMORY_BLOB`]. Its presence in a content manifest is what identifies a
/// vm_full checkpoint as HVF-produced.
pub const HVF_FRAME_BLOB: &str = "memory.bin.hvf-frame";
/// Firecracker's machine-state blob, written beside [`MEMORY_BLOB`]. Its
/// presence identifies a vm_full checkpoint as Firecracker-produced.
pub const FC_VMSTATE_BLOB: &str = "vmstate.bin";

/// Which VMM produced a `vm_full` checkpoint. Derived from the content
/// manifest rather than stored, so it cannot drift from the bytes a restore
/// would actually load: each VMM writes a machine-state blob only it produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmFullOrigin {
    /// Firecracker: `memory.bin` + [`FC_VMSTATE_BLOB`].
    Firecracker,
    /// The in-house HVF VMM: `memory.bin` + [`HVF_FRAME_BLOB`].
    Hvf,
    /// A supervisor-config checkpoint with no recognizable machine-state blob —
    /// the removed Apple-Virtualization backend. Nothing on this host can load
    /// it, so every consumer must refuse rather than guess.
    Retired,
}

/// Classify a checkpoint by the machine-state blob its content manifest names.
///
/// Returns `None` for a manifest that names no machine state at all, which is
/// what an `fs_quick` checkpoint looks like — callers dispatching a full-VM
/// restore treat that as "not a vm_full checkpoint" rather than a backend.
#[must_use]
pub fn vm_full_origin(meta: &CheckpointMeta) -> Option<VmFullOrigin> {
    let named = |name: &str| meta.content.iter().any(|blob| blob.name == name);
    if named(HVF_FRAME_BLOB) {
        Some(VmFullOrigin::Hvf)
    } else if named(FC_VMSTATE_BLOB) {
        Some(VmFullOrigin::Firecracker)
    } else if named(SUPERVISOR_CONFIG_BLOB) {
        Some(VmFullOrigin::Retired)
    } else {
        None
    }
}

/// Absolute host paths to resources a vm_full snapshot embeds by path.
/// Captured at checkpoint time so a forked child can make those paths
/// resolve to its own copies without editing the snapshot bitcode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAnchors {
    /// Live rootfs block device path.
    pub rootfs: std::path::PathBuf,
    /// dm-verity hash tree sidecar, if the rootfs is verity-sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_verity: Option<std::path::PathBuf>,
    /// Config drive (config.json + role.toml), if attached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<std::path::PathBuf>,
    /// Secrets drive, if attached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<std::path::PathBuf>,
    /// vsock UDS path.
    pub vsock: std::path::PathBuf,
}

/// The durable agent session a checkpoint is a resume point for.
///
/// `generation` fences a resume: reopening a parked session increments it, so a
/// frame addressed to an earlier generation is refused rather than delivered
/// into a successor. `journal_cursor` is the session-journal position the
/// capture is consistent with, and `approval_head` names the approval-ledger
/// state the capture was admitted under — a resume bounds its fresh grants
/// against that head rather than against whatever the ledger holds later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBinding {
    pub session_id: mvm_contract::protocol::agent_session::AgentSessionId,
    pub generation: u64,
    pub journal_cursor: u64,
    pub approval_head: CheckpointDigest,
}

/// On-disk metadata for one checkpoint (`<checkpoints_dir>/<id>/meta.json`).
///
/// `parent` hash-links to the parent checkpoint's `meta_digest` (its
/// content-address), not to a mutable name — so a descendant can detect any
/// post-seal edit of an ancestor. `meta_digest` is the content-address of this
/// record's load-bearing fields, derived in [`CheckpointMetaBuilder::build`]
/// and never set by callers.
///
/// `audit_ref` is a non-load-bearing back-pointer backfilled after the
/// chain-signed entry is emitted; it and `meta_digest` are excluded from the
/// digest so the backfill does not perturb the content-address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointMeta {
    pub id: CheckpointId,
    pub class: CheckpointClass,
    pub vm_name: String,
    pub tag: Option<String>,
    pub parent: Option<CheckpointDigest>,
    pub created_unix: u64,
    pub content: Vec<ContentBlob>,
    pub supervisor_config_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_source_policy: Option<RuntimeSourcePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_overlay_version: Option<String>,
    /// Content-addressed snapshot-store entry containing this checkpoint's
    /// immutable bytes. It is part of the load-bearing digest so a claim
    /// cannot redirect materialization to an unrelated staged snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    /// The permission set the captured VM was admitted under. Load-bearing so a
    /// restore can bound a child against it: the digest covers this field, the
    /// signed chain covers the digest, and a record edited to widen what the
    /// parent held stops verifying before it can justify a wider child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<mvm_contract::grants::Grants>,
    /// Content-address of the load-bearing fields above. Required with no serde
    /// default: a record that carries no content-address cannot be
    /// lineage-verified, so a pre-lineage meta.json must fail closed rather than
    /// load as an unverifiable record.
    pub meta_digest: CheckpointDigest,
    pub audit_ref: Option<String>,
}

impl CheckpointMeta {
    pub fn builder(
        id: CheckpointId,
        class: CheckpointClass,
        vm_name: impl Into<String>,
    ) -> CheckpointMetaBuilder {
        CheckpointMetaBuilder {
            id,
            class,
            vm_name: vm_name.into(),
            tag: None,
            parent: None,
            created_unix: 0,
            content: Vec::new(),
            supervisor_config_digest: String::new(),
            runtime_source_policy: None,
            runtime_overlay_version: None,
            snapshot_id: None,
            grants: None,
            audit_ref: None,
        }
    }

    /// Recompute this record's content-address from its load-bearing fields. A
    /// stored `meta_digest` that no longer equals this value is proof the
    /// record was edited after it was sealed — the check `verify_lineage` walks
    /// with. Mirrors the derivation in [`CheckpointMetaBuilder::build`]; the
    /// `capture_*` tests pin that the two agree.
    pub fn compute_meta_digest(&self) -> CheckpointDigest {
        CheckpointDigestInput {
            id: &self.id,
            class: self.class,
            vm_name: &self.vm_name,
            tag: &self.tag,
            parent: &self.parent,
            created_unix: self.created_unix,
            content: sorted_content(&self.content),
            supervisor_config_digest: &self.supervisor_config_digest,
            runtime_source_policy: &self.runtime_source_policy,
            runtime_overlay_version: &self.runtime_overlay_version,
            snapshot_id: &self.snapshot_id,
            grants: &self.grants,
        }
        .digest()
    }

    /// Content-address the verified blob manifest independently of the
    /// checkpoint metadata. This is the stable ID for the immutable snapshot
    /// store entry and does not include mutable audit bookkeeping.
    pub fn compute_content_digest(&self) -> CheckpointDigest {
        content_manifest_digest(&self.content)
    }

    /// Return the same sealed record with its staged snapshot binding set.
    /// Rebuilding through the normal builder recomputes the load-bearing digest
    /// so the binding is covered by lineage verification.
    pub fn with_snapshot_id(&self, snapshot_id: impl Into<String>) -> Self {
        CheckpointMeta::builder(self.id.clone(), self.class, self.vm_name.clone())
            .tag(self.tag.clone())
            .parent(self.parent.clone())
            .created_unix(self.created_unix)
            .content(self.content.clone())
            .supervisor_config_digest(self.supervisor_config_digest.clone())
            .runtime_source_policy(self.runtime_source_policy)
            .runtime_overlay_version(self.runtime_overlay_version.clone())
            .snapshot_id(Some(snapshot_id.into()))
            .grants(self.grants.clone())
            .audit_ref(self.audit_ref.clone())
            .build()
    }
}

/// Content-address a checkpoint blob manifest independently of checkpoint
/// metadata. Blob names and their already-computed SHA-256 values are the
/// complete input, so deriving this ID never rereads the captured files.
pub fn content_manifest_digest(content: &[ContentBlob]) -> CheckpointDigest {
    let bytes = serde_json::to_vec(&sorted_content(content))
        .expect("checkpoint content manifest is always JSON-serializable");
    CheckpointDigest(format!(
        "{}{}",
        CheckpointDigest::PREFIX,
        hex::encode(Sha256::digest(bytes))
    ))
}

/// The load-bearing fields of a [`CheckpointMeta`], borrowed in fixed
/// declaration order, that `meta_digest` content-addresses. `meta_digest`
/// itself and `audit_ref` are excluded: the former is what we are deriving, the
/// latter is backfilled after the audit entry is emitted and must not perturb
/// the digest.
#[derive(Serialize)]
struct CheckpointDigestInput<'a> {
    id: &'a CheckpointId,
    class: CheckpointClass,
    vm_name: &'a str,
    tag: &'a Option<String>,
    parent: &'a Option<CheckpointDigest>,
    created_unix: u64,
    /// Sorted by `name` (capture builds it in insertion order) so the digest is
    /// invariant to blob ordering.
    content: Vec<&'a ContentBlob>,
    supervisor_config_digest: &'a str,
    runtime_source_policy: &'a Option<RuntimeSourcePolicy>,
    runtime_overlay_version: &'a Option<String>,
    snapshot_id: &'a Option<String>,
    /// Skipped when absent so a record that seals no grant hashes exactly as it
    /// did before the field existed. Without this, every checkpoint captured
    /// before grants were sealed would recompute to a different digest and be
    /// reported as `meta_digest drift` — i.e. as *tampered*, when the record is
    /// only schema-stale. The check is meant to be believed, so it must not cry
    /// tamper over a field nobody touched.
    #[serde(skip_serializing_if = "Option::is_none")]
    grants: &'a Option<mvm_contract::grants::Grants>,
}

impl CheckpointDigestInput<'_> {
    fn digest(&self) -> CheckpointDigest {
        // Plain serde_json (not JCS): this is host-only, single-implementation,
        // with no cross-language conformance need — the same posture the audit
        // envelope and the app-dep volume-hash derivation take.
        let bytes =
            serde_json::to_vec(self).expect("checkpoint digest input is always JSON-serializable");
        CheckpointDigest(format!(
            "{}{}",
            CheckpointDigest::PREFIX,
            hex::encode(Sha256::digest(&bytes))
        ))
    }
}

/// Content blobs borrowed and sorted by `name`, so a checkpoint's digest does
/// not depend on the order capture happened to append them. Shared with the
/// image-lineage node digest so both content-address a blob manifest the same
/// order-invariant way.
pub(crate) fn sorted_content(content: &[ContentBlob]) -> Vec<&ContentBlob> {
    let mut refs: Vec<&ContentBlob> = content.iter().collect();
    refs.sort_by(|a, b| a.name.cmp(&b.name));
    // Blob names index the manifest (fork/restore/diff look up by name); a
    // duplicate would make the content-address depend on tie-break order and
    // ambiguate the lookup. Capture never emits one — assert it in debug.
    debug_assert!(
        refs.windows(2).all(|w| w[0].name != w[1].name),
        "content manifest has duplicate blob names"
    );
    refs
}

/// Fluent builder for [`CheckpointMeta`]; obtain via [`CheckpointMeta::builder`].
///
/// Callers set only the fields they have; avoids a long positional constructor.
pub struct CheckpointMetaBuilder {
    id: CheckpointId,
    class: CheckpointClass,
    vm_name: String,
    tag: Option<String>,
    parent: Option<CheckpointDigest>,
    created_unix: u64,
    content: Vec<ContentBlob>,
    supervisor_config_digest: String,
    runtime_source_policy: Option<RuntimeSourcePolicy>,
    runtime_overlay_version: Option<String>,
    snapshot_id: Option<String>,
    grants: Option<mvm_contract::grants::Grants>,
    audit_ref: Option<String>,
}

impl CheckpointMetaBuilder {
    pub fn tag(mut self, tag: Option<String>) -> Self {
        self.tag = tag;
        self
    }
    /// Hash-link this checkpoint to its parent's content-address
    /// ([`CheckpointMeta::meta_digest`]).
    pub fn parent(mut self, parent: Option<CheckpointDigest>) -> Self {
        self.parent = parent;
        self
    }
    pub fn created_unix(mut self, secs: u64) -> Self {
        self.created_unix = secs;
        self
    }
    pub fn content(mut self, content: Vec<ContentBlob>) -> Self {
        self.content = content;
        self
    }
    pub fn supervisor_config_digest(mut self, d: impl Into<String>) -> Self {
        self.supervisor_config_digest = d.into();
        self
    }
    pub fn runtime_source_policy(mut self, policy: Option<RuntimeSourcePolicy>) -> Self {
        self.runtime_source_policy = policy;
        self
    }
    pub fn runtime_overlay_version(mut self, version: Option<String>) -> Self {
        self.runtime_overlay_version = version;
        self
    }
    pub fn snapshot_id(mut self, id: Option<String>) -> Self {
        self.snapshot_id = id;
        self
    }
    /// The permission set the captured VM was admitted under. Recorded so a
    /// later restore can bound its child against it.
    pub fn grants(mut self, grants: Option<mvm_contract::grants::Grants>) -> Self {
        self.grants = grants;
        self
    }
    pub fn audit_ref(mut self, r: Option<String>) -> Self {
        self.audit_ref = r;
        self
    }
    pub fn build(self) -> CheckpointMeta {
        // Derive the content-address before moving the fields out. Mirrors
        // `CheckpointMeta::compute_meta_digest` — two borrows of the same field
        // set with different owners (builder here, meta there); the
        // `capture_*_recomputes_equal` tests pin that they agree.
        let meta_digest = CheckpointDigestInput {
            id: &self.id,
            class: self.class,
            vm_name: &self.vm_name,
            tag: &self.tag,
            parent: &self.parent,
            created_unix: self.created_unix,
            content: sorted_content(&self.content),
            supervisor_config_digest: &self.supervisor_config_digest,
            runtime_source_policy: &self.runtime_source_policy,
            runtime_overlay_version: &self.runtime_overlay_version,
            snapshot_id: &self.snapshot_id,
            grants: &self.grants,
        }
        .digest();
        CheckpointMeta {
            id: self.id,
            class: self.class,
            vm_name: self.vm_name,
            tag: self.tag,
            parent: self.parent,
            created_unix: self.created_unix,
            content: self.content,
            supervisor_config_digest: self.supervisor_config_digest,
            runtime_source_policy: self.runtime_source_policy,
            runtime_overlay_version: self.runtime_overlay_version,
            snapshot_id: self.snapshot_id,
            grants: self.grants,
            meta_digest,
            audit_ref: self.audit_ref,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_digest() -> CheckpointDigest {
        CheckpointDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap()
    }

    #[test]
    fn meta_roundtrips_through_json() {
        let meta = CheckpointMeta::builder(
            CheckpointId::new("ckpt-abc123"),
            CheckpointClass::FsQuick,
            "myvm",
        )
        .content(vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "deadbeef".into(),
        }])
        .supervisor_config_digest("cfg99")
        .tag(Some("golden".to_string()))
        .parent(Some(parent_digest()))
        .created_unix(1_700_000_000)
        .runtime_source_policy(Some(RuntimeSourcePolicy::RequiredOverlay))
        .runtime_overlay_version(Some("0.17.0".to_string()))
        .build();

        let json = serde_json::to_string(&meta).unwrap();
        let back: CheckpointMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
        assert_eq!(back.class, CheckpointClass::FsQuick);
        assert_eq!(back.parent.unwrap(), parent_digest());
        assert_eq!(back.content[0].sha256, "deadbeef");
        assert_eq!(back.meta_digest, meta.meta_digest);
        assert_eq!(
            back.runtime_source_policy,
            Some(RuntimeSourcePolicy::RequiredOverlay)
        );
        assert_eq!(back.runtime_overlay_version.as_deref(), Some("0.17.0"));
    }

    #[test]
    fn meta_rejects_unknown_fields() {
        let json = r#"{"id":"x","class":"fs_quick","vm_name":"v","tag":null,
            "parent":null,"created_unix":1,"content":[],
            "supervisor_config_digest":"d","audit_ref":null,"bogus":true}"#;
        assert!(serde_json::from_str::<CheckpointMeta>(json).is_err());
    }

    #[test]
    fn builder_defaults_are_none() {
        let meta = CheckpointMeta::builder(CheckpointId::new("c1"), CheckpointClass::FsQuick, "vm")
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: "h".into(),
            }])
            .supervisor_config_digest("d")
            .created_unix(5)
            .build();
        assert!(meta.tag.is_none());
        assert!(meta.parent.is_none());
        assert!(meta.runtime_source_policy.is_none());
        assert!(meta.runtime_overlay_version.is_none());
        assert!(meta.audit_ref.is_none());
    }

    #[test]
    fn class_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&CheckpointClass::VmFull).unwrap(),
            "\"vm_full\""
        );
    }

    #[test]
    fn meta_carries_a_content_manifest() {
        let meta = CheckpointMeta::builder(CheckpointId::new("c1"), CheckpointClass::VmFull, "vm")
            .content(vec![
                ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "aa".into(),
                },
                ContentBlob {
                    name: "memory.bin".into(),
                    sha256: "bb".into(),
                },
                ContentBlob {
                    name: "machine-id".into(),
                    sha256: "cc".into(),
                },
            ])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build();
        let json = serde_json::to_string(&meta).unwrap();
        let back: CheckpointMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
        assert_eq!(back.content.len(), 3);
        assert_eq!(back.content[1].name, "memory.bin");
    }

    #[test]
    fn content_blob_roundtrips_and_denies_unknown() {
        let b: ContentBlob = serde_json::from_str(r#"{"name":"x","sha256":"y"}"#).unwrap();
        assert_eq!(b.name, "x");
        assert!(serde_json::from_str::<ContentBlob>(r#"{"name":"x","sha256":"y","z":1}"#).is_err());
    }

    #[test]
    fn old_shape_meta_without_meta_digest_fails_to_parse() {
        // The pre-lineage meta.json carried a name-based `parent` and no
        // `meta_digest`. That shape is intentionally unreadable now: a record
        // with no content-address cannot be lineage-verified, so it fails
        // closed (both the name-shaped parent and the missing digest are
        // rejected) rather than loading as an unverifiable record.
        let json = r#"{"id":"x","class":"fs_quick","vm_name":"v","tag":null,
            "parent":"ckpt-parent","created_unix":1,"content":[],
            "supervisor_config_digest":"d","audit_ref":null}"#;
        assert!(serde_json::from_str::<CheckpointMeta>(json).is_err());
    }

    fn digest_fixture_meta(content: Vec<ContentBlob>) -> CheckpointMeta {
        CheckpointMeta::builder(CheckpointId::new("c1"), CheckpointClass::FsQuick, "vm")
            .content(content)
            .supervisor_config_digest("cfg")
            .created_unix(7)
            .build()
    }

    fn blob(name: &str, sha: &str) -> ContentBlob {
        ContentBlob {
            name: name.into(),
            sha256: sha.into(),
        }
    }

    #[test]
    fn meta_digest_wire_shape_is_sha256_prefixed_hex() {
        let m = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        let s = m.meta_digest.as_str();
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.len(), "sha256:".len() + 64);
    }

    #[test]
    fn meta_digest_is_deterministic_across_builds() {
        let a = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        let b = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        assert_eq!(a.meta_digest, b.meta_digest);
    }

    #[test]
    fn meta_digest_recomputes_equal_to_stored() {
        let m = digest_fixture_meta(vec![blob("rootfs.ext4", "aa"), blob("memory.bin", "bb")]);
        assert_eq!(m.meta_digest, m.compute_meta_digest());
    }

    #[test]
    fn the_admitted_grant_is_inside_the_content_address() {
        // What makes the grant tamper-evident: a record edited to widen what
        // the captured VM held stops matching its own content-address, and the
        // signed chain records that address. Without this the grant would be
        // free-floating metadata a restore could not safely trust.
        let bounded =
            CheckpointMeta::builder(CheckpointId::new("c1"), CheckpointClass::FsQuick, "vm")
                .content(vec![blob("rootfs.ext4", "aa")])
                .supervisor_config_digest("cfg")
                .created_unix(7)
                .grants(Some(mvm_contract::grants::Grants {
                    cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1000 }),
                    ..Default::default()
                }))
                .build();
        let widened = CheckpointMeta {
            grants: Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 64_000 }),
                ..Default::default()
            }),
            ..bounded.clone()
        };
        assert_ne!(widened.compute_meta_digest(), widened.meta_digest);
        assert_ne!(bounded.meta_digest, widened.compute_meta_digest());
        // An unbounded record is likewise distinguishable from a bounded one.
        assert_ne!(
            bounded.meta_digest,
            digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]).meta_digest
        );
    }

    #[test]
    fn sealing_no_grant_leaves_a_records_digest_where_it_was() {
        // A record that seals no grant must hash exactly as it did before the
        // field existed, or every checkpoint captured earlier reports as
        // `meta_digest drift` — as tampered rather than as schema-stale. The
        // literal is this fixture's digest read off the commit before `grants`
        // was added, not a value re-derived from the code it is checking.
        let m = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        assert!(m.grants.is_none());
        assert_eq!(
            m.meta_digest.as_str(),
            "sha256:47b3411659eddf390da230557216188e6fe4b56572f8f8545702fcc04a608e5b"
        );
    }

    #[test]
    fn meta_digest_invariant_under_content_insertion_order() {
        // The blob manifest is content-addressed by name, not by the order
        // capture appended it — permuting the vec must not move the digest.
        let ordered = digest_fixture_meta(vec![blob("a", "1"), blob("b", "2"), blob("c", "3")]);
        let permuted = digest_fixture_meta(vec![blob("c", "3"), blob("a", "1"), blob("b", "2")]);
        assert_eq!(ordered.meta_digest, permuted.meta_digest);
    }

    #[test]
    fn meta_digest_changes_when_a_content_sha_changes() {
        let base = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        let edited = digest_fixture_meta(vec![blob("rootfs.ext4", "zz")]);
        assert_ne!(base.meta_digest, edited.meta_digest);
    }

    #[test]
    fn meta_digest_changes_when_parent_link_changes() {
        let genesis = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        let child =
            CheckpointMeta::builder(CheckpointId::new("c1"), CheckpointClass::FsQuick, "vm")
                .content(vec![blob("rootfs.ext4", "aa")])
                .supervisor_config_digest("cfg")
                .created_unix(7)
                .parent(Some(parent_digest()))
                .build();
        assert_ne!(genesis.meta_digest, child.meta_digest);
    }

    #[test]
    fn meta_digest_excludes_audit_ref() {
        // audit_ref is backfilled after the chain entry is emitted; it must not
        // move the content-address, or the backfill would invalidate it.
        let without = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        let with = CheckpointMeta::builder(CheckpointId::new("c1"), CheckpointClass::FsQuick, "vm")
            .content(vec![blob("rootfs.ext4", "aa")])
            .supervisor_config_digest("cfg")
            .created_unix(7)
            .audit_ref(Some("local.jsonl#3".to_string()))
            .build();
        assert_eq!(without.meta_digest, with.meta_digest);
    }

    #[test]
    fn meta_digest_covers_every_load_bearing_field() {
        // Flip exactly one load-bearing field per case and assert the
        // content-address moves. Guards a future field silently falling outside
        // the digest input (the two excluded fields — meta_digest, audit_ref —
        // are covered by their own tests above).
        #[derive(Clone)]
        struct Fields {
            id: String,
            class: CheckpointClass,
            vm: String,
            tag: Option<String>,
            parent: Option<CheckpointDigest>,
            created: u64,
            content: Vec<ContentBlob>,
            cfg: String,
            policy: Option<RuntimeSourcePolicy>,
            overlay: Option<String>,
            grants: Option<mvm_contract::grants::Grants>,
        }
        let build = |f: &Fields| {
            CheckpointMeta::builder(CheckpointId::new(f.id.clone()), f.class, f.vm.clone())
                .tag(f.tag.clone())
                .parent(f.parent.clone())
                .created_unix(f.created)
                .content(f.content.clone())
                .supervisor_config_digest(f.cfg.clone())
                .runtime_source_policy(f.policy)
                .runtime_overlay_version(f.overlay.clone())
                .grants(f.grants.clone())
                .build()
                .meta_digest
        };
        let base = Fields {
            id: "id0".into(),
            class: CheckpointClass::FsQuick,
            vm: "vm0".into(),
            tag: Some("t0".into()),
            parent: None,
            created: 100,
            content: vec![blob("rootfs.ext4", "aa")],
            cfg: "cfg0".into(),
            policy: Some(RuntimeSourcePolicy::PreferOverlay),
            overlay: Some("0.1.0".into()),
            grants: None,
        };
        let baseline = build(&base);

        let mut f = base.clone();
        f.id = "id1".into();
        assert_ne!(baseline, build(&f), "id");
        let mut f = base.clone();
        f.class = CheckpointClass::VmFull;
        assert_ne!(baseline, build(&f), "class");
        let mut f = base.clone();
        f.vm = "vm1".into();
        assert_ne!(baseline, build(&f), "vm_name");
        let mut f = base.clone();
        f.tag = Some("t1".into());
        assert_ne!(baseline, build(&f), "tag");
        let mut f = base.clone();
        f.created = 200;
        assert_ne!(baseline, build(&f), "created_unix");
        let mut f = base.clone();
        f.content = vec![blob("rootfs.ext4", "bb")];
        assert_ne!(baseline, build(&f), "content");
        let mut f = base.clone();
        f.cfg = "cfg1".into();
        assert_ne!(baseline, build(&f), "supervisor_config_digest");
        let mut f = base.clone();
        f.policy = Some(RuntimeSourcePolicy::RequiredOverlay);
        assert_ne!(baseline, build(&f), "runtime_source_policy");
        let mut f = base.clone();
        f.overlay = Some("0.2.0".into());
        assert_ne!(baseline, build(&f), "runtime_overlay_version");
        let mut f = base.clone();
        f.parent = Some(parent_digest());
        assert_ne!(baseline, build(&f), "parent");
        let mut f = base.clone();
        f.grants = Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1000 }),
            ..Default::default()
        });
        assert_ne!(baseline, build(&f), "grants");
    }

    #[test]
    fn checkpoint_digest_parse_accepts_and_round_trips_serde() {
        let s = format!("sha256:{}", "b".repeat(64));
        let d = CheckpointDigest::parse(s.clone()).unwrap();
        assert_eq!(d.as_str(), s);
        assert_eq!(d.to_string(), s);
        let via_from_str: CheckpointDigest = s.parse().unwrap();
        assert_eq!(via_from_str, d);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("{:?}", s));
        let back: CheckpointDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn checkpoint_digest_parse_rejects_malformed() {
        let wrong_prefix = format!("md5:{}", "a".repeat(64));
        assert_eq!(
            CheckpointDigest::parse(wrong_prefix.clone()).unwrap_err(),
            CheckpointDigestParseError::MissingPrefix(wrong_prefix)
        );
        assert_eq!(
            CheckpointDigest::parse(format!("sha256:{}", "a".repeat(63))).unwrap_err(),
            CheckpointDigestParseError::WrongLength { len: 63 }
        );
        assert_eq!(
            CheckpointDigest::parse(format!("sha256:{}", "A".repeat(64))).unwrap_err(),
            CheckpointDigestParseError::NonHex { ch: 'A' }
        );
        assert_eq!(
            CheckpointDigest::parse(format!("sha256:{}", "g".repeat(64))).unwrap_err(),
            CheckpointDigestParseError::NonHex { ch: 'g' }
        );
        let bad = "\"not-a-checkpoint-digest\"";
        assert!(serde_json::from_str::<CheckpointDigest>(bad).is_err());
    }

    /// `CheckpointDigest` shares the `sha256:<64-hex>` shape with [`OciDigest`]
    /// and [`SemanticAddress`], which is exactly why the boundary is a
    /// type-system property rather than a string check. A `sha256:...` string
    /// re-validates as each type independently, but there is no
    /// `From`/`TryFrom`/`Deref` from `CheckpointDigest` to any of them (or to
    /// `Sha256Hex`, whose wire shape omits the prefix), so a value of one type
    /// cannot be handed to code expecting another without an explicit,
    /// separate re-parse that names both types at the call site.
    ///
    /// [`OciDigest`]: crate::packs::OciDigest
    /// [`SemanticAddress`]: crate::semantic_address::SemanticAddress
    #[test]
    fn checkpoint_digest_shape_overlaps_oci_digest_but_types_never_convert() {
        let m = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        let digest = m.meta_digest;

        // Same shape, independently re-validated — not a type conversion.
        assert!(crate::packs::OciDigest::new(digest.as_str().to_string()).is_ok());
        assert!(
            crate::semantic_address::SemanticAddress::parse(digest.as_str()).is_ok(),
            "the semantic-address shape overlaps too"
        );

        // `Sha256Hex` carries no `sha256:` prefix, so the same string is
        // rejected there — a second, independent illustration of unrelated
        // types with coincidentally similar cousins.
        assert!(crate::packs::Sha256Hex::new(digest.as_str().to_string()).is_err());
    }

    fn test_binding() -> SessionBinding {
        SessionBinding {
            session_id: mvm_contract::protocol::agent_session::AgentSessionId::parse(
                "sess-incident-42",
            )
            .unwrap(),
            generation: 3,
            journal_cursor: 118,
            approval_head: CheckpointDigest::parse(format!("sha256:{}", "cd".repeat(32))).unwrap(),
        }
    }

    #[test]
    fn session_binding_roundtrips_and_denies_unknown() {
        let binding = test_binding();
        let json = serde_json::to_string(&binding).unwrap();
        let back: SessionBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);

        let with_extra = json.replace('{', "{\"surprise\":1,");
        assert!(serde_json::from_str::<SessionBinding>(&with_extra).is_err());
    }
}
