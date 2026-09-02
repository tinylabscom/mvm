//! Wire-stable event names and label keys for checkpoint audit entries.
//!
//! Shared so the emitter and lineage chain-anchor cannot drift on a string and
//! silently defeat chain-anchored lineage verification.

/// Emitted when a VM's state is frozen into a checkpoint.
pub const CREATED_EVENT: &str = "checkpoint.created";
/// Emitted when a VM is resumed from a vm_full checkpoint (same identity).
pub const RESTORED_EVENT: &str = "checkpoint.restored";
/// Emitted when a new sandbox is branched from a checkpoint.
pub const FORKED_EVENT: &str = "checkpoint.forked";

/// Label: the checkpoint's own id (created/restored).
pub const LABEL_CHECKPOINT_ID: &str = "checkpoint_id";
/// Label: the checkpoint's content-address (created/restored).
pub const LABEL_META_DIGEST: &str = "meta_digest";
/// Label: the checkpoint class (created).
pub const LABEL_CLASS: &str = "class";
/// Label: the owning VM name (created/restored).
pub const LABEL_VM_NAME: &str = "vm_name";
/// Label: how a restore was initiated (`revert` / `rewind` / `advance`).
pub const LABEL_VIA: &str = "via";
/// Label: the parent checkpoint id (forked).
pub const LABEL_PARENT_ID: &str = "parent_id";
/// Label: the child (new) checkpoint id (forked).
pub const LABEL_CHILD_ID: &str = "child_id";
/// Label: the child VM name (forked).
pub const LABEL_CHILD_VM_NAME: &str = "child_vm_name";
/// Label: the parent's content-address, i.e. the child's hash-link (forked).
pub const LABEL_PARENT_DIGEST: &str = "parent_digest";
/// Label: the child's content-address (forked).
pub const LABEL_CHILD_DIGEST: &str = "child_digest";
/// Label: JSON array of child binding names and destination allow-lists.
/// This never contains keystore addresses, providers, or secret values.
pub const LABEL_SECRET_BINDINGS: &str = "secret_bindings";

/// Complete non-secret label payload for a `checkpoint.forked` event.
pub struct CheckpointForkedAudit<'a> {
    pub parent_id: &'a str,
    pub child_id: &'a str,
    pub child_vm_name: &'a str,
    pub parent_digest: &'a str,
    pub child_digest: &'a str,
    pub secret_bindings_json: &'a str,
}
