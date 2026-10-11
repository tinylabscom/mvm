use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointClass, CheckpointDigest, CheckpointId, CheckpointMeta};
use mvm_runtime::agent_session::{AgentSessionStore, pinning_session};
use serde::{Deserialize, Serialize};

use super::{Checkpoints, validated_id};

/// How a content blob changed between two checkpoint manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BlobStatus {
    Unchanged,
    Changed,
    AddedInB,
    RemovedFromB,
}

/// A manifest delta; no checkpoint contents are decrypted to compute it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BlobDelta {
    pub name: String,
    pub status: BlobStatus,
    pub sha_a: Option<String>,
    pub sha_b: Option<String>,
}

/// Direct content-addressed relationship between two checkpoint records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum LineageRelation {
    BChildOfA,
    AChildOfB,
    Same,
    Unrelated,
}

/// Stable metadata comparison result, preserving the command JSON shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CheckpointDiff {
    pub a_id: CheckpointId,
    pub b_id: CheckpointId,
    pub class_a: CheckpointClass,
    pub class_b: CheckpointClass,
    pub vm_name_a: String,
    pub vm_name_b: String,
    pub tag_a: Option<String>,
    pub tag_b: Option<String>,
    pub created_unix_a: u64,
    pub created_unix_b: u64,
    pub supervisor_config_digest_same: bool,
    pub lineage: LineageRelation,
    pub blobs: Vec<BlobDelta>,
}

impl From<mvm_runtime::checkpoint::CheckpointDiff> for CheckpointDiff {
    fn from(diff: mvm_runtime::checkpoint::CheckpointDiff) -> Self {
        use mvm_runtime::checkpoint::{BlobStatus as Status, LineageRelation as Relation};
        Self {
            a_id: diff.a_id,
            b_id: diff.b_id,
            class_a: diff.class_a,
            class_b: diff.class_b,
            vm_name_a: diff.vm_name_a,
            vm_name_b: diff.vm_name_b,
            tag_a: diff.tag_a,
            tag_b: diff.tag_b,
            created_unix_a: diff.created_unix_a,
            created_unix_b: diff.created_unix_b,
            supervisor_config_digest_same: diff.supervisor_config_digest_same,
            lineage: match diff.lineage {
                Relation::BChildOfA => LineageRelation::BChildOfA,
                Relation::AChildOfB => LineageRelation::AChildOfB,
                Relation::Same => LineageRelation::Same,
                Relation::Unrelated => LineageRelation::Unrelated,
            },
            blobs: diff
                .blobs
                .into_iter()
                .map(|blob| BlobDelta {
                    name: blob.name,
                    status: match blob.status {
                        Status::Unchanged => BlobStatus::Unchanged,
                        Status::Changed => BlobStatus::Changed,
                        Status::AddedInB => BlobStatus::AddedInB,
                        Status::RemovedFromB => BlobStatus::RemovedFromB,
                    },
                    sha_a: blob.sha_a,
                    sha_b: blob.sha_b,
                })
                .collect(),
        }
    }
}

impl Checkpoints {
    /// List metadata, validating stored identifiers before exposing records.
    pub fn list(&self) -> Result<Vec<CheckpointMeta>> {
        let records = self.store.list()?;
        for record in &records {
            self.read(&record.id)?;
        }
        Ok(records)
    }

    /// Compare metadata and manifests without reading plaintext contents.
    pub fn diff(&self, a: &CheckpointId, b: &CheckpointId) -> Result<CheckpointDiff> {
        let a = validated_id(a.as_str())?;
        let b = validated_id(b.as_str())?;
        let left = self
            .read(&a)
            .with_context(|| format!("reading checkpoint {:?}", a.as_str()))?;
        let right = self
            .read(&b)
            .with_context(|| format!("reading checkpoint {:?}", b.as_str()))?;
        Ok(mvm_runtime::checkpoint::diff_checkpoints(&left, &right).into())
    }

    /// Find a live or hibernated session whose resume point holds this digest.
    pub fn pinning_session(&self, digest: &CheckpointDigest) -> Result<Option<String>> {
        pinning_session(&AgentSessionStore::open(), digest)
            .context("listing agent sessions")
            .map(|session| session.map(|id| id.as_str().to_owned()))
    }

    /// Find stored children that require this checkpoint to restore.
    pub fn dependents(&self, id: &CheckpointId) -> Result<Vec<CheckpointId>> {
        let meta = self.read(id)?;
        mvm_runtime::checkpoint::dependent_children(&self.store, &meta)
            .context("listing checkpoints that name this one as their parent")
    }

    /// Remove a leaf checkpoint only when no resumable session pins it.
    ///
    /// Missing checkpoints are an idempotent success. Unreadable metadata is
    /// not treated as absence: without it the pin guard cannot answer safely.
    pub fn remove(&self, id: &CheckpointId) -> Result<()> {
        self.remove_with_sessions(id, &AgentSessionStore::open())
    }

    fn remove_with_sessions(&self, id: &CheckpointId, sessions: &AgentSessionStore) -> Result<()> {
        let id = validated_id(id.as_str())?;
        if self.store.dir_for(&id).try_exists()? {
            let meta = self.read(&id)?;
            if let Some(session) =
                pinning_session(sessions, &meta.meta_digest).context("listing agent sessions")?
            {
                bail!(
                    "cannot remove checkpoint '{}': it is the resume point for agent session '{}'; \
                     close that session before removing the checkpoint",
                    id.as_str(),
                    session.as_str()
                );
            }
            let descendants = self.dependents(&id)?;
            if !descendants.is_empty() {
                bail!(
                    "cannot remove checkpoint '{}': {} through it; remove {} first",
                    id.as_str(),
                    descendants_restoring_through(&descendants),
                    if descendants.len() == 1 { "it" } else { "them" }
                );
            }
        }
        self.store.remove(&id)
    }
}

fn descendants_restoring_through(ids: &[CheckpointId]) -> String {
    let quoted: Vec<String> = ids.iter().map(|id| format!("'{}'", id.as_str())).collect();
    let (noun, verb) = if ids.len() == 1 {
        ("checkpoint", "restores")
    } else {
        ("checkpoints", "restore")
    };
    format!("{noun} {} {verb}", quoted.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "schema")]
    #[test]
    fn checkpoint_contract_schemas_match_the_wire_types() {
        use schemars::schema::{InstanceType, SingleOrVec};
        let string_type = Some(SingleOrVec::Single(Box::new(InstanceType::String)));
        assert_eq!(
            schemars::schema_for!(CheckpointId).schema.instance_type,
            string_type
        );
        assert_eq!(
            schemars::schema_for!(CheckpointDigest).schema.instance_type,
            string_type
        );
        // Documented unit variants are represented as oneOf string enums,
        // rather than one top-level enum, so each variant keeps its docs.
        let class_schema = schemars::schema_for!(CheckpointClass);
        let variants = class_schema
            .schema
            .subschemas
            .as_ref()
            .unwrap()
            .one_of
            .as_ref()
            .unwrap();
        let values: Vec<_> = variants
            .iter()
            .flat_map(|variant| {
                let variant = variant.clone().into_object();
                assert_eq!(variant.instance_type, string_type);
                variant.enum_values.unwrap()
            })
            .collect();
        assert_eq!(
            values,
            vec![serde_json::json!("fs_quick"), serde_json::json!("vm_full")]
        );
        let id = CheckpointId::new("safe");
        assert_eq!(
            serde_json::to_value(&id).unwrap(),
            serde_json::json!("safe")
        );
        let digest = CheckpointDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap();
        let json = serde_json::to_value(&digest).unwrap();
        assert_eq!(json, serde_json::json!(digest.as_str()));
        assert_eq!(
            serde_json::from_value::<CheckpointDigest>(json).unwrap(),
            digest
        );
        for class in [CheckpointClass::FsQuick, CheckpointClass::VmFull] {
            assert_eq!(
                serde_json::from_value::<CheckpointClass>(serde_json::to_value(class).unwrap())
                    .unwrap(),
                class
            );
        }
    }

    fn seed(service: &Checkpoints, id: &str, parent: Option<CheckpointDigest>) -> CheckpointMeta {
        let meta = CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .parent(parent)
            .build();
        service.store.write_meta(&meta).unwrap();
        meta
    }

    #[test]
    fn catalog_diff_preserves_wire_shape_and_roundtrips() {
        let root = tempfile::tempdir().unwrap();
        let service = Checkpoints::at(root.path());
        let parent = seed(&service, "parent", None);
        let child = seed(&service, "child", Some(parent.meta_digest.clone()));
        assert_eq!(service.list().unwrap().len(), 2);
        let diff = service.diff(&parent.id, &child.id).unwrap();
        assert_eq!(diff.lineage, LineageRelation::BChildOfA);
        let json = serde_json::to_value(&diff).unwrap();
        assert_eq!(
            json,
            serde_json::to_value(mvm_runtime::checkpoint::diff_checkpoints(&parent, &child))
                .unwrap()
        );
        assert_eq!(
            serde_json::from_value::<CheckpointDiff>(json).unwrap(),
            diff
        );
    }

    #[test]
    fn removal_is_leaf_first_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let service = Checkpoints::at(root.path().join("checkpoints"));
        let sessions = AgentSessionStore::at(root.path().join("sessions"));
        let parent = seed(&service, "parent", None);
        let child = seed(&service, "child", Some(parent.meta_digest));
        let error = service
            .remove_with_sessions(&parent.id, &sessions)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot remove checkpoint 'parent': checkpoint 'child' restores through it; remove it first"
        );
        service.remove_with_sessions(&child.id, &sessions).unwrap();
        service.remove_with_sessions(&parent.id, &sessions).unwrap();
        service.remove_with_sessions(&parent.id, &sessions).unwrap();
        assert!(service.list().unwrap().is_empty());
    }

    #[test]
    fn removing_an_absent_checkpoint_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let service = Checkpoints::at(root.path().join("checkpoints"));
        let sessions = AgentSessionStore::at(root.path().join("sessions"));
        let absent = CheckpointId::new("absent");
        service.remove_with_sessions(&absent, &sessions).unwrap();
        service.remove_with_sessions(&absent, &sessions).unwrap();
        assert!(!service.store.dir_for(&absent).exists());
    }

    #[test]
    fn catalog_operations_reject_unsafe_ids_and_corrupt_metadata() {
        let root = tempfile::tempdir().unwrap();
        let service = Checkpoints::at(root.path());
        let sessions = AgentSessionStore::at(root.path().join("sessions"));
        let meta = seed(&service, "safe", None);
        for raw in ["../escape", "a/b", "", "a\\b"] {
            let id = CheckpointId::new(raw);
            assert!(
                service
                    .diff(&id, &meta.id)
                    .unwrap_err()
                    .to_string()
                    .starts_with("invalid checkpoint id")
            );
            assert!(
                service
                    .remove_with_sessions(&id, &sessions)
                    .unwrap_err()
                    .to_string()
                    .starts_with("invalid checkpoint id")
            );
        }
        let path = service.store.dir_for(&meta.id).join("meta.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(service.remove_with_sessions(&meta.id, &sessions).is_err());
        assert!(path.exists());
    }
}
