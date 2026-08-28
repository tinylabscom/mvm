//! Immutable, audit-bound records of frozen microVM state. A checkpoint is the
//! origin a `fork` clones a new sandbox instance from.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
/// ids (OCI manifest/layer digests, blob shas, workload addresses) precisely so
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

/// The approval-ledger head a [`SessionBinding`] was admitted under.
///
/// Shares the `sha256:<64-hex>` wire shape with [`CheckpointDigest`] — both
/// are heads of a hash chain — but an approval-ledger head is deliberately
/// not a `CheckpointDigest`. `CheckpointDigest`'s own doc explains why the
/// shape is shared with no conversion: so the boundary between unrelated
/// hash-chain heads is a type-system property, not a string check. Without
/// this newtype, `approval_head: CheckpointDigest` would let an approval head
/// be assigned wherever a checkpoint content-address is expected (or the
/// reverse) with the compiler saying nothing — and because `SessionBinding`
/// sits inside `CheckpointMeta`'s digest input, whichever encoding shipped
/// first would freeze into every sealed record's `meta_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ApprovalHead(String);

impl ApprovalHead {
    /// The fixed hash-axis prefix every approval head carries.
    pub const PREFIX: &'static str = "sha256:";

    /// Validates and wraps a `sha256:<64 lowercase hex>` string. Rejects any
    /// other prefix, wrong length, or non-lowercase-hex content.
    pub fn parse(value: impl Into<String>) -> Result<Self, ApprovalHeadParseError> {
        use crate::digest_shape::Sha256PrefixedShape;
        let value = value.into();
        match crate::digest_shape::validate_sha256_prefixed(&value) {
            Sha256PrefixedShape::Ok => Ok(Self(value)),
            Sha256PrefixedShape::MissingPrefix => Err(ApprovalHeadParseError::MissingPrefix(value)),
            Sha256PrefixedShape::WrongLength { len } => {
                Err(ApprovalHeadParseError::WrongLength { len })
            }
            Sha256PrefixedShape::NonHex { ch } => Err(ApprovalHeadParseError::NonHex { ch }),
        }
    }

    /// Wrap a raw 32-byte digest — the shape `PolicySet::digest` and the
    /// approval ledger produce — as the `sha256:<64-hex>` wire form.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(format!("{}{}", Self::PREFIX, hex::encode(bytes)))
    }

    /// The `sha256:<64-hex>` string view.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ApprovalHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for ApprovalHead {
    type Err = ApprovalHeadParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for ApprovalHead {
    type Error = ApprovalHeadParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<ApprovalHead> for String {
    fn from(head: ApprovalHead) -> Self {
        head.0
    }
}

/// [`ApprovalHead::parse`] / [`ApprovalHead::from_str`] failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApprovalHeadParseError {
    /// The value did not start with `sha256:`.
    #[error("approval head must start with \"sha256:\", got {0:?}")]
    MissingPrefix(String),
    /// The hex portion (after the prefix) was not exactly 64 characters.
    #[error("approval head hex must be exactly 64 chars, got {len}")]
    WrongLength { len: usize },
    /// The hex portion contained a non-lowercase-hex character.
    #[error("approval head hex must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
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
    pub approval_head: ApprovalHead,
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
    /// The durable agent session this checkpoint is a resume point for, when
    /// it has one. Load-bearing so a resume cannot be redirected to a
    /// different session or replayed at an earlier journal position: the
    /// digest covers this field and the signed chain covers the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionBinding>,
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
            runtime_overlay_version: None,
            snapshot_id: None,
            grants: None,
            session: None,
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
            runtime_overlay_version: &self.runtime_overlay_version,
            snapshot_id: &self.snapshot_id,
            grants: &self.grants,
            session: &self.session,
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
            .runtime_overlay_version(self.runtime_overlay_version.clone())
            .snapshot_id(Some(snapshot_id.into()))
            .grants(self.grants.clone())
            .session(self.session.clone())
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
    /// Skipped when absent for the same reason `grants` is: a record sealed
    /// before this field existed must hash exactly as it did then, or lineage
    /// verification reports drift on a record nobody edited.
    #[serde(skip_serializing_if = "Option::is_none")]
    session: &'a Option<SessionBinding>,
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
    runtime_overlay_version: Option<String>,
    snapshot_id: Option<String>,
    grants: Option<mvm_contract::grants::Grants>,
    session: Option<SessionBinding>,
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
    pub fn session(mut self, binding: Option<SessionBinding>) -> Self {
        self.session = binding;
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
            runtime_overlay_version: &self.runtime_overlay_version,
            snapshot_id: &self.snapshot_id,
            grants: &self.grants,
            session: &self.session,
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
            runtime_overlay_version: self.runtime_overlay_version,
            snapshot_id: self.snapshot_id,
            grants: self.grants,
            session: self.session,
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
    fn meta_rejects_unknown_fields() {
        let json = r#"{"id":"x","class":"fs_quick","vm_name":"v","tag":null,
            "parent":null,"created_unix":1,"content":[],
            "supervisor_config_digest":"d","audit_ref":null,"bogus":true}"#;
        assert!(serde_json::from_str::<CheckpointMeta>(json).is_err());
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

    /// The digest of a grant-less record, pinned so it cannot move by accident.
    ///
    /// It last moved deliberately when `runtime_source_policy` was removed from
    /// the meta: the overlay became the single runtime source, so the field had
    /// no remaining values to distinguish. Checkpoints captured before that
    /// change read as `meta_digest drift` — schema-stale, not tampered — which
    /// is the accepted cost of the no-back-compat rule on local state. Anything
    /// that moves this literal without a matching schema change in the same
    /// commit is a silent digest break.
    #[test]
    fn sealing_no_grant_leaves_a_records_digest_where_it_was() {
        let m = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        assert!(m.grants.is_none());
        assert_eq!(
            m.meta_digest.as_str(),
            "sha256:a139182b3a51e1f4ac84f8feb344c8beeb363ad5579ddc81d3547dc25c8224fe"
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
    fn meta_digest_changes_when_the_session_binding_changes() {
        let base =
            CheckpointMeta::builder(CheckpointId::new("cp-1"), CheckpointClass::VmFull, "vm-1")
                .session(Some(test_binding()))
                .build();

        let mut other_binding = test_binding();
        other_binding.generation += 1;
        let bumped =
            CheckpointMeta::builder(CheckpointId::new("cp-1"), CheckpointClass::VmFull, "vm-1")
                .session(Some(other_binding))
                .build();

        assert_ne!(base.meta_digest, bumped.meta_digest);
        assert_eq!(base.meta_digest, base.compute_meta_digest());
        assert_eq!(bumped.meta_digest, bumped.compute_meta_digest());
    }

    #[test]
    fn a_sessionless_checkpoint_hashes_as_it_did_before_the_field_existed() {
        // A record that binds no session must be byte-identical in the digest
        // input to one built before `session` was added, or every checkpoint on
        // disk reads as tampered.
        let sessionless =
            CheckpointMeta::builder(CheckpointId::new("cp-1"), CheckpointClass::VmFull, "vm-1")
                .build();
        assert!(sessionless.session.is_none());
        assert_eq!(sessionless.meta_digest, sessionless.compute_meta_digest());

        let input = CheckpointDigestInput {
            id: &sessionless.id,
            class: sessionless.class,
            vm_name: &sessionless.vm_name,
            tag: &sessionless.tag,
            parent: &sessionless.parent,
            created_unix: sessionless.created_unix,
            content: sorted_content(&sessionless.content),
            supervisor_config_digest: &sessionless.supervisor_config_digest,
            runtime_overlay_version: &sessionless.runtime_overlay_version,
            snapshot_id: &sessionless.snapshot_id,
            grants: &sessionless.grants,
            session: &None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(
            !json.contains("session"),
            "an absent session must not appear in the digest input: {json}"
        );
    }

    #[test]
    fn session_binding_survives_meta_json_roundtrip() {
        let meta =
            CheckpointMeta::builder(CheckpointId::new("cp-1"), CheckpointClass::VmFull, "vm-1")
                .session(Some(test_binding()))
                .build();
        let json = serde_json::to_string(&meta).unwrap();
        let back: CheckpointMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
        assert_eq!(back.session.unwrap().journal_cursor, 118);
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
    /// and [`WorkloadAddress`], which is exactly why the boundary is a
    /// type-system property rather than a string check. A `sha256:...` string
    /// re-validates as each type independently, but there is no
    /// `From`/`TryFrom`/`Deref` from `CheckpointDigest` to any of them (or to
    /// `Sha256Hex`, whose wire shape omits the prefix), so a value of one type
    /// cannot be handed to code expecting another without an explicit,
    /// separate re-parse that names both types at the call site.
    ///
    /// [`OciDigest`]: crate::packs::OciDigest
    /// [`WorkloadAddress`]: crate::workload_address::WorkloadAddress
    #[test]
    fn checkpoint_digest_shape_overlaps_oci_digest_but_types_never_convert() {
        let m = digest_fixture_meta(vec![blob("rootfs.ext4", "aa")]);
        let digest = m.meta_digest;

        // Same shape, independently re-validated — not a type conversion.
        assert!(crate::packs::OciDigest::new(digest.as_str().to_string()).is_ok());
        assert!(
            crate::workload_address::WorkloadAddress::parse(digest.as_str()).is_ok(),
            "the workload-address shape overlaps too"
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
            approval_head: ApprovalHead::parse(format!("sha256:{}", "cd".repeat(32))).unwrap(),
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

    #[test]
    fn approval_head_parse_accepts_and_round_trips_serde() {
        let s = format!("sha256:{}", "b".repeat(64));
        let d = ApprovalHead::parse(s.clone()).unwrap();
        assert_eq!(d.as_str(), s);
        assert_eq!(d.to_string(), s);
        let via_from_str: ApprovalHead = s.parse().unwrap();
        assert_eq!(via_from_str, d);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("{:?}", s));
        let back: ApprovalHead = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn approval_head_parse_rejects_malformed() {
        let wrong_prefix = format!("md5:{}", "a".repeat(64));
        assert_eq!(
            ApprovalHead::parse(wrong_prefix.clone()).unwrap_err(),
            ApprovalHeadParseError::MissingPrefix(wrong_prefix)
        );
        assert_eq!(
            ApprovalHead::parse(format!("sha256:{}", "a".repeat(63))).unwrap_err(),
            ApprovalHeadParseError::WrongLength { len: 63 }
        );
        assert_eq!(
            ApprovalHead::parse(format!("sha256:{}", "A".repeat(64))).unwrap_err(),
            ApprovalHeadParseError::NonHex { ch: 'A' }
        );
        let bad = "\"not-an-approval-head\"";
        assert!(serde_json::from_str::<ApprovalHead>(bad).is_err());
    }

    #[test]
    fn approval_head_from_bytes_produces_expected_hex() {
        let bytes = [0xabu8; 32];
        let head = ApprovalHead::from_bytes(&bytes);
        assert_eq!(head.as_str(), format!("sha256:{}", "ab".repeat(32)));
    }

    /// Same shape, independently re-validated as two distinct types — not a
    /// conversion. There is no `From`/`TryFrom`/`Deref` between `ApprovalHead`
    /// and `CheckpointDigest`, so a value of one is never accepted where the
    /// other is expected; `SessionBinding.approval_head` typed as
    /// `ApprovalHead` is what makes that a compile-time property.
    #[test]
    fn approval_head_shape_overlaps_checkpoint_digest_but_types_never_convert() {
        let s = format!("sha256:{}", "c".repeat(64));
        assert!(ApprovalHead::parse(s.clone()).is_ok());
        assert!(CheckpointDigest::parse(s).is_ok());
    }
}
