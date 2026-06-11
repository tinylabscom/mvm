//! Immutable, audit-bound records of frozen microVM state. A checkpoint is the
//! origin a `fork` clones a new sandbox instance from.

use serde::{Deserialize, Serialize};

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

/// On-disk metadata for one checkpoint (`<checkpoints_dir>/<id>/meta.json`).
/// `audit_ref` is a non-load-bearing back-pointer backfilled after the
/// chain-signed entry is emitted; integrity verification relies on
/// `content`, not on `audit_ref`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointMeta {
    pub id: CheckpointId,
    pub class: CheckpointClass,
    pub vm_name: String,
    pub tag: Option<String>,
    pub parent: Option<CheckpointId>,
    pub created_unix: u64,
    pub content: Vec<ContentBlob>,
    pub supervisor_config_digest: String,
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
            audit_ref: None,
        }
    }
}

/// Fluent builder for [`CheckpointMeta`]; obtain via [`CheckpointMeta::builder`].
///
/// Callers set only the fields they have; avoids a long positional constructor.
pub struct CheckpointMetaBuilder {
    id: CheckpointId,
    class: CheckpointClass,
    vm_name: String,
    tag: Option<String>,
    parent: Option<CheckpointId>,
    created_unix: u64,
    content: Vec<ContentBlob>,
    supervisor_config_digest: String,
    audit_ref: Option<String>,
}

impl CheckpointMetaBuilder {
    pub fn tag(mut self, tag: Option<String>) -> Self {
        self.tag = tag;
        self
    }
    pub fn parent(mut self, parent: Option<CheckpointId>) -> Self {
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
    pub fn audit_ref(mut self, r: Option<String>) -> Self {
        self.audit_ref = r;
        self
    }
    pub fn build(self) -> CheckpointMeta {
        CheckpointMeta {
            id: self.id,
            class: self.class,
            vm_name: self.vm_name,
            tag: self.tag,
            parent: self.parent,
            created_unix: self.created_unix,
            content: self.content,
            supervisor_config_digest: self.supervisor_config_digest,
            audit_ref: self.audit_ref,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        .parent(Some(CheckpointId::new("ckpt-parent")))
        .created_unix(1_700_000_000)
        .build();

        let json = serde_json::to_string(&meta).unwrap();
        let back: CheckpointMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
        assert_eq!(back.class, CheckpointClass::FsQuick);
        assert_eq!(back.parent.unwrap().as_str(), "ckpt-parent");
        assert_eq!(back.content[0].sha256, "deadbeef");
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
}
