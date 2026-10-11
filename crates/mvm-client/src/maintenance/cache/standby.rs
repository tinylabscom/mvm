//! Standby maintenance uses the launch path's TTL and reaper, including its
//! saved-state demotion and claimed-supervisor protection.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyPruneRequest {
    #[serde(default)]
    pub apply: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandbyPruneReport {
    /// Preview counts inspected entries, not removal candidates: the runtime
    /// owns liveness and saved-state transitions at apply time.
    pub inspected: usize,
    pub removed: usize,
}

pub fn prune(request: &StandbyPruneRequest) -> anyhow::Result<StandbyPruneReport> {
    prune_at(
        &mvm_runtime::standby_pool::SupervisorStandbyPool::open()?,
        request,
        mvm_core::time::now_unix_secs(),
    )
}

fn prune_at(
    pool: &mvm_runtime::standby_pool::SupervisorStandbyPool,
    request: &StandbyPruneRequest,
    now: u64,
) -> anyhow::Result<StandbyPruneReport> {
    if !request.apply {
        return Ok(StandbyPruneReport {
            inspected: pool.list()?.len(),
            removed: 0,
        });
    }
    let removed = pool
        .reap_stale(mvm_runtime::standby_pool::STANDBY_POOL_TTL, now)?
        .len();
    Ok(StandbyPruneReport {
        inspected: 0,
        removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_defaults_to_preview_and_rejects_unknown_fields() {
        let request: StandbyPruneRequest = serde_json::from_str("{}").unwrap();
        assert!(!request.apply);
        assert!(serde_json::from_str::<StandbyPruneRequest>(r#"{"root":"/"}"#).is_err());
    }

    #[test]
    fn preview_leaves_dead_entries_and_apply_spares_a_recent_live_standby() {
        use mvm_core::vm_backend::{StandbyHandle, StandbyState};
        let home = tempfile::tempdir().unwrap();
        let pool = mvm_runtime::standby_pool::SupervisorStandbyPool::at(home.path());
        for (id, pid) in [("dead", 999_999_999), ("live", std::process::id())] {
            pool.record(&StandbyHandle {
                id: id.into(),
                template_id: None,
                control_socket: format!("/unused/{id}"),
                pid,
                kernel_sha256: "aa".repeat(32),
                vcpus: 2,
                mem_mib: 1024,
                binding_nonce: "ab".repeat(32),
                spawned_unix_secs: 100,
                state: StandbyState::Idle,
                image_sha256: None,
                root_strategy: Default::default(),
                parent_checkpoint: None,
                preloaded_child_vm_name: None,
                vsock_egress: false,
            })
            .unwrap();
        }
        let preview = prune_at(&pool, &StandbyPruneRequest::default(), 101).unwrap();
        assert_eq!(preview.inspected, 2);
        assert_eq!(pool.list().unwrap().len(), 2);
        let applied = prune_at(&pool, &StandbyPruneRequest { apply: true }, 101).unwrap();
        assert_eq!(applied.removed, 1);
        assert_eq!(pool.list().unwrap()[0].id, "live");
    }

    #[test]
    fn absent_pool_preview_and_apply_are_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("pool");
        let pool = mvm_runtime::standby_pool::SupervisorStandbyPool::at(&root);
        for apply in [false, true, true] {
            let report = prune_at(&pool, &StandbyPruneRequest { apply }, 100).unwrap();
            assert_eq!(report, StandbyPruneReport::default());
            let json = serde_json::to_string(&report).unwrap();
            assert_eq!(
                serde_json::from_str::<StandbyPruneReport>(&json).unwrap(),
                report
            );
        }
        assert!(!root.exists());
    }
}
