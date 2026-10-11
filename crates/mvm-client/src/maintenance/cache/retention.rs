//! Seven-day checkpoint retention, followed by content GC. Session resume
//! points and the entire ancestry of every retained checkpoint remain intact.

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::CheckpointId;
use mvm_runtime::agent_session::{AgentSessionStore, pinned_checkpoints};
use mvm_runtime::checkpoint::{CheckpointStore, Retention, RetentionCut, retention_verdicts};
use serde::{Deserialize, Serialize};

use crate::checkpoint::Checkpoints;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRetentionRequest {
    #[serde(default)]
    pub apply: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedBy {
    Tagged,
    Young,
    SessionResumePoint,
    AncestorOf(CheckpointId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedCheckpoint {
    pub id: CheckpointId,
    pub reason: RetainedBy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointRetentionReport {
    pub inspected: usize,
    pub candidates: Vec<CheckpointId>,
    pub removed: Vec<CheckpointId>,
    pub retained: Vec<RetainedCheckpoint>,
    /// A partial sweep still reports its completed removals.
    pub warning: Option<String>,
}

pub fn prune(request: &CheckpointRetentionRequest) -> CheckpointRetentionReport {
    let mut report = CheckpointRetentionReport::default();
    if let Err(error) = sweep(
        &Checkpoints::open(),
        &AgentSessionStore::open(),
        request,
        mvm_core::time::now_unix_secs(),
        &mut report,
    ) {
        report.warning = Some(format!("{error:#}"));
    }
    report
}

fn sweep(
    catalog: &Checkpoints,
    sessions: &AgentSessionStore,
    request: &CheckpointRetentionRequest,
    now: u64,
    report: &mut CheckpointRetentionReport,
) -> Result<()> {
    let records = catalog.list()?;
    report.inspected = records.len();
    let pinned =
        pinned_checkpoints(sessions).context("could not determine session-pinned checkpoints")?;
    let cut = RetentionCut {
        now_unix: now,
        max_age_secs: 7 * 24 * 60 * 60,
        session_pinned: &pinned,
    };
    for verdict in retention_verdicts(records, &cut)? {
        let id = verdict.meta.id;
        if let Some(reason) = verdict.kept {
            report.retained.push(RetainedCheckpoint {
                id,
                reason: match reason {
                    Retention::Tagged => RetainedBy::Tagged,
                    Retention::Young => RetainedBy::Young,
                    Retention::SessionResumePoint => RetainedBy::SessionResumePoint,
                    Retention::AncestorOf(id) => RetainedBy::AncestorOf(id),
                },
            });
        } else {
            report.candidates.push(id);
        }
    }
    if !request.apply {
        return Ok(());
    }
    let mut pending = report.candidates.clone();
    // The catalog's removal guard requires children first. Re-read each leaf
    // through the catalog rather than bypassing pins/dependents with raw paths.
    while !pending.is_empty() {
        let mut progressed = false;
        for id in pending.clone() {
            if !catalog.dependents(&id)?.is_empty() {
                continue;
            }
            catalog.remove(&id)?;
            pending.retain(|candidate| candidate != &id);
            report.removed.push(id);
            progressed = true;
        }
        if !progressed {
            bail!(
                "checkpoint sweep retained remaining candidates: dependent checkpoints still exist"
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentPruneRequest {
    #[serde(default)]
    pub apply: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentPruneReport {
    pub abandoned_staging: usize,
    pub objects: usize,
    pub object_bytes: u64,
    pub materializations: usize,
    pub materialization_bytes: u64,
}

impl ContentPruneReport {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    pub fn entries(&self) -> u64 {
        (self.abandoned_staging + self.objects + self.materializations) as u64
    }

    pub fn bytes(&self) -> u64 {
        self.object_bytes.saturating_add(self.materialization_bytes)
    }
}

pub fn prune_content(request: &ContentPruneRequest) -> Result<ContentPruneReport> {
    // Validate the same catalog used by retention before letting content GC
    // classify references. A malformed stored identifier is not an orphan.
    Checkpoints::open().list()?;
    let report = mvm_runtime::checkpoint::prune_unreferenced_content(
        &CheckpointStore::open(),
        !request.apply,
    )?;
    Ok(ContentPruneReport {
        abandoned_staging: report.abandoned_staging,
        objects: report.objects,
        object_bytes: report.object_bytes,
        materializations: report.materializations,
        materialization_bytes: report.materialization_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointMeta};

    #[test]
    fn a_corrupt_catalog_refuses_retention_and_content_gc() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::open();
        let meta =
            CheckpointMeta::builder(CheckpointId::new("corrupt"), CheckpointClass::FsQuick, "vm")
                .build();
        store.write_meta(&meta).unwrap();
        std::fs::write(store.dir_for(&meta.id).join("meta.json"), b"{broken").unwrap();
        let report = prune(&CheckpointRetentionRequest { apply: true });
        assert!(report.warning.is_some());
        assert!(report.removed.is_empty());
        assert!(prune_content(&ContentPruneRequest { apply: true }).is_err());
        assert!(store.dir_for(&meta.id).exists());
    }

    #[test]
    fn a_real_parked_session_retains_its_resume_point_and_ancestry() {
        use mvm_contract::protocol::agent_session::AgentSessionId;
        use mvm_runtime::agent_session::{AgentSessionRecord, SandboxResidency};
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::open();
        let parent =
            CheckpointMeta::builder(CheckpointId::new("parent"), CheckpointClass::FsQuick, "vm")
                .created_unix(0)
                .build();
        let child =
            CheckpointMeta::builder(CheckpointId::new("child"), CheckpointClass::FsQuick, "vm")
                .created_unix(0)
                .parent(Some(parent.meta_digest.clone()))
                .build();
        store.write_meta(&parent).unwrap();
        store.write_meta(&child).unwrap();
        AgentSessionStore::open()
            .write(&AgentSessionRecord {
                session_id: AgentSessionId::parse("sess-parked").unwrap(),
                generation: 1,
                state: SandboxResidency::Hibernated,
                members: vec!["vm".to_owned()],
                parent_checkpoint: Some(child.meta_digest),
                created_unix: 0,
                updated_unix: 0,
                journal_cursor: 0,
                approval_head: None,
                storage_tier: None,
                park_reason: None,
                retain_until_unix: None,
                last_transition: None,
            })
            .unwrap();
        let report = prune(&CheckpointRetentionRequest { apply: true });
        assert!(report.warning.is_none(), "{:?}", report.warning);
        assert!(report.removed.is_empty());
        assert_eq!(report.retained.len(), 2);
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn defaults_preview_and_content_report_roundtrips() {
        assert!(
            !serde_json::from_str::<CheckpointRetentionRequest>("{}")
                .unwrap()
                .apply
        );
        assert!(
            !serde_json::from_str::<ContentPruneRequest>("{}")
                .unwrap()
                .apply
        );
        let report = ContentPruneReport {
            objects: 2,
            object_bytes: 10,
            ..Default::default()
        };
        assert_eq!(report.entries(), 2);
        assert_eq!(report.bytes(), 10);
        assert_eq!(
            serde_json::from_str::<ContentPruneReport>(&serde_json::to_string(&report).unwrap())
                .unwrap(),
            report
        );
    }

    #[test]
    fn retention_removes_children_first_and_retains_tagged_ancestry() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::open();
        for (parent_id, child_id, tagged) in [("parent", "child", false), ("kept", "tagged", true)]
        {
            let parent = CheckpointMeta::builder(
                CheckpointId::new(parent_id),
                CheckpointClass::FsQuick,
                "vm",
            )
            .created_unix(0)
            .build();
            store.write_meta(&parent).unwrap();
            let mut builder = CheckpointMeta::builder(
                CheckpointId::new(child_id),
                CheckpointClass::FsQuick,
                "vm",
            )
            .created_unix(0)
            .parent(Some(parent.meta_digest.clone()));
            if tagged {
                builder = builder.tag(Some("keep".to_owned()));
            }
            store.write_meta(&builder.build()).unwrap();
        }
        assert!(
            prune(&CheckpointRetentionRequest::default())
                .removed
                .is_empty()
        );
        assert_eq!(store.list().unwrap().len(), 4);
        let report = prune(&CheckpointRetentionRequest { apply: true });
        assert!(report.warning.is_none(), "{:?}", report.warning);
        assert_eq!(
            report.removed,
            vec![CheckpointId::new("child"), CheckpointId::new("parent")]
        );
        assert_eq!(store.list().unwrap().len(), 2);
        assert!(
            prune(&CheckpointRetentionRequest { apply: true })
                .removed
                .is_empty()
        );
    }
}
