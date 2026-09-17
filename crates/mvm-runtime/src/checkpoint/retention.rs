//! Which stored checkpoints a retention sweep must keep.
//!
//! Restoring or forking a checkpoint walks its whole parent chain and refuses
//! when any ancestor's record is gone, so a checkpoint is only as restorable as
//! its oldest ancestor. Retention is therefore decided by reachability: a
//! checkpoint kept for its own sake keeps every ancestor it restores through,
//! whatever their tag or age.

use std::collections::BTreeSet;

use anyhow::Result;
use mvm_core::checkpoint::{CheckpointDigest, CheckpointId, CheckpointMeta};

use super::CheckpointStore;
use crate::lineage::LineageGraph;

/// The inputs that decide whether a checkpoint is kept on its own account.
#[derive(Debug, Clone, Copy)]
pub struct RetentionCut<'a> {
    /// The sweep's clock.
    pub now_unix: u64,
    /// An untagged checkpoint no older than this is kept.
    pub max_age_secs: u64,
    /// Resume points of sessions that can still resume
    /// (`crate::agent_session::pinned_checkpoints`).
    pub session_pinned: &'a BTreeSet<CheckpointDigest>,
}

/// Why a sweep keeps a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retention {
    /// Tagged by the user; tags are never swept.
    Tagged,
    /// Untagged, but inside the age cut.
    Young,
    /// The resume point of a live or hibernated session.
    SessionResumePoint,
    /// Kept for no reason of its own, but the named retained checkpoint
    /// restores through it.
    AncestorOf(CheckpointId),
}

/// One stored checkpoint and the reason it survives, or `None` when a sweep
/// may reap it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionVerdict {
    pub meta: CheckpointMeta,
    pub kept: Option<Retention>,
}

/// The reason `meta` is kept on its own account, before lineage is considered.
pub fn direct_retention(meta: &CheckpointMeta, cut: &RetentionCut<'_>) -> Option<Retention> {
    if meta.tag.is_some() {
        return Some(Retention::Tagged);
    }
    if cut.now_unix.saturating_sub(meta.created_unix) <= cut.max_age_secs {
        return Some(Retention::Young);
    }
    if cut.session_pinned.contains(&meta.meta_digest) {
        return Some(Retention::SessionResumePoint);
    }
    None
}

/// Decide the fate of every checkpoint in `metas`: each is kept for a reason of
/// its own, kept because a checkpoint in the first group restores through it,
/// or reapable. Verdicts come back ordered by checkpoint id, so a sweep's
/// output is stable across runs.
///
/// Decided over one listing rather than by re-reading the store per hop, so
/// every verdict is made against the same view of the store. That view can go
/// stale: a checkpoint forked from a reapable one after the listing is not
/// seen, and nothing here stops the sweep removing its parent.
pub fn retention_verdicts(
    mut metas: Vec<CheckpointMeta>,
    cut: &RetentionCut<'_>,
) -> Result<Vec<RetentionVerdict>> {
    metas.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    let direct: Vec<Option<Retention>> = metas.iter().map(|m| direct_retention(m, cut)).collect();
    let roots = metas
        .iter()
        .zip(&direct)
        .filter_map(|(meta, kept)| kept.as_ref().map(|_| meta));
    let ancestors = crate::lineage::ancestors_of(&ListedCheckpoints(&metas), roots)?;
    Ok(metas
        .into_iter()
        .zip(direct)
        .map(|(meta, kept)| {
            let kept = kept.or_else(|| {
                ancestors
                    .get(&meta.meta_digest)
                    .map(|root| Retention::AncestorOf(CheckpointId::new(root.clone())))
            });
            RetentionVerdict { meta, kept }
        })
        .collect())
}

/// Every stored checkpoint that names `meta` as its parent, by id. Removing
/// `meta` while any exist leaves each of them unrestorable.
pub fn dependent_children(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
) -> Result<Vec<CheckpointId>> {
    let mut children: Vec<CheckpointId> = store
        .children_of(&meta.meta_digest)?
        .into_iter()
        .map(|child| child.id)
        .filter(|id| id != &meta.id)
        .collect();
    children.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    Ok(children)
}

/// A single listing of the store, read as a lineage graph.
struct ListedCheckpoints<'a>(&'a [CheckpointMeta]);

impl LineageGraph for ListedCheckpoints<'_> {
    type Record = CheckpointMeta;
    type Id = CheckpointId;
    fn read(&self, id: &CheckpointId) -> Result<CheckpointMeta> {
        self.0
            .iter()
            .find(|m| &m.id == id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("checkpoint '{id}' is not in this listing"))
    }
    fn by_digest(&self, digest: &CheckpointDigest) -> Result<Option<CheckpointMeta>> {
        Ok(self.0.iter().find(|m| &m.meta_digest == digest).cloned())
    }
    fn children_of(&self, parent_digest: &CheckpointDigest) -> Result<Vec<CheckpointMeta>> {
        Ok(self
            .0
            .iter()
            .filter(|m| m.parent.as_ref() == Some(parent_digest))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, ContentBlob};

    const NOW: u64 = 10_000_000;
    const AGED: u64 = 0;

    fn ckpt(
        id: &str,
        tag: Option<&str>,
        parent: Option<&CheckpointMeta>,
        created: u64,
    ) -> CheckpointMeta {
        CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .tag(tag.map(String::from))
            .parent(parent.map(|p| p.meta_digest.clone()))
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: "h".into(),
            }])
            .supervisor_config_digest("d")
            .created_unix(created)
            .build()
    }

    fn cut(pinned: &BTreeSet<CheckpointDigest>) -> RetentionCut<'_> {
        RetentionCut {
            now_unix: NOW,
            max_age_secs: 1,
            session_pinned: pinned,
        }
    }

    fn verdict_for<'v>(verdicts: &'v [RetentionVerdict], id: &str) -> &'v Option<Retention> {
        &verdicts
            .iter()
            .find(|v| v.meta.id.as_str() == id)
            .unwrap_or_else(|| panic!("no verdict for {id}"))
            .kept
    }

    #[test]
    fn a_tag_retains_regardless_of_age_or_pin() {
        let pinned = BTreeSet::new();
        let meta = ckpt("t", Some("gold"), None, AGED);
        assert_eq!(
            direct_retention(&meta, &cut(&pinned)),
            Some(Retention::Tagged)
        );
    }

    #[test]
    fn an_untagged_checkpoint_inside_the_cut_is_young() {
        let pinned = BTreeSet::new();
        let meta = ckpt("y", None, None, NOW);
        assert_eq!(
            direct_retention(&meta, &cut(&pinned)),
            Some(Retention::Young)
        );
    }

    #[test]
    fn a_session_resume_point_is_retained_past_the_cut() {
        let meta = ckpt("p", None, None, AGED);
        let pinned = BTreeSet::from([meta.meta_digest.clone()]);
        assert_eq!(
            direct_retention(&meta, &cut(&pinned)),
            Some(Retention::SessionResumePoint)
        );
    }

    #[test]
    fn an_aged_untagged_unpinned_checkpoint_has_no_reason_of_its_own() {
        let pinned = BTreeSet::new();
        let meta = ckpt("o", None, None, AGED);
        assert_eq!(direct_retention(&meta, &cut(&pinned)), None);
    }

    #[test]
    fn verdicts_keep_ancestors_of_retained_checkpoints_and_nothing_else() {
        let pinned = BTreeSet::new();
        let grandparent = ckpt("grandparent", None, None, AGED);
        let parent = ckpt("parent", None, Some(&grandparent), AGED);
        let tagged = ckpt("tagged", Some("gold"), Some(&parent), AGED);
        let stray = ckpt("stray", None, None, AGED);
        let verdicts =
            retention_verdicts(vec![stray, tagged, parent, grandparent], &cut(&pinned)).unwrap();

        assert_eq!(verdict_for(&verdicts, "tagged"), &Some(Retention::Tagged));
        for id in ["parent", "grandparent"] {
            assert_eq!(
                verdict_for(&verdicts, id),
                &Some(Retention::AncestorOf(CheckpointId::new("tagged")))
            );
        }
        assert_eq!(verdict_for(&verdicts, "stray"), &None);
    }

    #[test]
    fn a_direct_reason_outranks_being_an_ancestor() {
        let pinned = BTreeSet::new();
        let parent = ckpt("parent", Some("base"), None, AGED);
        let child = ckpt("child", Some("gold"), Some(&parent), AGED);
        let verdicts = retention_verdicts(vec![child, parent], &cut(&pinned)).unwrap();
        assert_eq!(verdict_for(&verdicts, "parent"), &Some(Retention::Tagged));
    }

    #[test]
    fn verdicts_are_ordered_by_id() {
        let pinned = BTreeSet::new();
        let verdicts = retention_verdicts(
            vec![
                ckpt("c", None, None, AGED),
                ckpt("a", None, None, AGED),
                ckpt("b", None, None, AGED),
            ],
            &cut(&pinned),
        )
        .unwrap();
        let ids: Vec<&str> = verdicts.iter().map(|v| v.meta.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn dependent_children_names_every_child_and_not_the_record_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        let parent = ckpt("parent", None, None, AGED);
        let first = ckpt("child-b", None, Some(&parent), AGED);
        let second = ckpt("child-a", None, Some(&parent), AGED);
        let unrelated = ckpt("unrelated", None, None, AGED);
        for m in [&parent, &first, &second, &unrelated] {
            store.write_meta(m).unwrap();
        }

        let children = dependent_children(&store, &parent).unwrap();
        let ids: Vec<&str> = children.iter().map(CheckpointId::as_str).collect();
        assert_eq!(ids, vec!["child-a", "child-b"]);
        assert!(dependent_children(&store, &first).unwrap().is_empty());
    }

    #[test]
    fn a_self_parented_record_is_not_its_own_dependent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        let mut looped = ckpt("looped", None, None, AGED);
        looped.parent = Some(looped.meta_digest.clone());
        store.write_meta(&looped).unwrap();
        assert!(dependent_children(&store, &looped).unwrap().is_empty());
    }
}
