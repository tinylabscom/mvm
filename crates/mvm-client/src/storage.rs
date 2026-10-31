//! dm-thin pool inspection and garbage collection behind `mvmctl storage`.

use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_runtime::storage::{
    DeviceMapperBackend, DmsetupBackend, MockBackend, PoolConfig, PoolStats, ThinPool,
    ThinPoolImpl, VolumeId, VolumeStats,
};

/// One volume and its usage, when the backend could report it.
#[derive(Debug, Clone)]
pub struct VolumeUsage {
    pub name: String,
    pub stats: Option<VolumeStats>,
}

/// Pool state for `storage info`; an unreachable pool is a report, not an error.
#[derive(Debug, Clone)]
pub enum PoolInfo {
    Unavailable {
        pool: String,
        reason: String,
    },
    Ready {
        pool: String,
        stats: PoolStats,
        volumes: Vec<VolumeUsage>,
    },
}

/// What a `gc --apply` attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcOutcome {
    Removed(Vec<String>),
    Empty,
    PoolUnavailable(String),
}

fn pool_for(mock: bool) -> ThinPoolImpl {
    let backend: Arc<dyn DeviceMapperBackend> = if mock {
        Arc::new(MockBackend::new())
    } else {
        Arc::new(DmsetupBackend::new())
    };
    ThinPoolImpl::new(PoolConfig::default(), backend)
}

/// Read pool utilization and per-volume stats.
pub fn info(mock: bool) -> PoolInfo {
    info_of(&pool_for(mock))
}

fn info_of(pool: &ThinPoolImpl) -> PoolInfo {
    let pool_name = pool.config().name.clone();
    let stats = match pool.stats() {
        Ok(stats) => stats,
        Err(e) => {
            return PoolInfo::Unavailable {
                pool: pool_name,
                reason: e.to_string(),
            };
        }
    };
    let volumes = pool
        .list_volumes()
        .unwrap_or_default()
        .into_iter()
        .map(|name| VolumeUsage {
            stats: pool.volume_stats(&VolumeId::new(&name)).ok(),
            name,
        })
        .collect();
    PoolInfo::Ready {
        pool: pool_name,
        stats,
        volumes,
    }
}

fn kept(name: &str, keep_prefix: &[String]) -> bool {
    keep_prefix.iter().any(|p| name.starts_with(p))
}

fn candidates_of(pool: &ThinPoolImpl, keep_prefix: &[String]) -> Result<Vec<String>, String> {
    let volumes = pool.list_volumes().map_err(|e| e.to_string())?;
    Ok(volumes
        .into_iter()
        .filter(|name| !kept(name, keep_prefix))
        .collect())
}

/// Volumes `gc` would remove; `Err` carries why the pool is unreachable.
pub fn gc_candidates(mock: bool, keep_prefix: &[String]) -> Result<Vec<String>, String> {
    candidates_of(&pool_for(mock), keep_prefix)
}

/// Remove every volume not matching `keep_prefix` and audit the attempt,
/// including the pool-unavailable and empty-pool no-ops.
pub fn gc_apply(mock: bool, keep_prefix: &[String]) -> Result<GcOutcome> {
    apply_to(&pool_for(mock), keep_prefix)
}

fn apply_to(pool: &ThinPoolImpl, keep_prefix: &[String]) -> Result<GcOutcome> {
    let outcome = match candidates_of(pool, keep_prefix) {
        Err(reason) => GcOutcome::PoolUnavailable(reason),
        Ok(c) if c.is_empty() => GcOutcome::Empty,
        Ok(_) => GcOutcome::Removed(
            pool.gc(|name| !kept(name, keep_prefix))
                .context("dmsetup gc failed")?,
        ),
    };
    let detail = match &outcome {
        GcOutcome::Removed(r) if r.len() <= 8 => format!("removed=[{}]", r.join(",")),
        GcOutcome::Removed(r) => format!("count={}", r.len()),
        GcOutcome::Empty => "count=0".to_string(),
        GcOutcome::PoolUnavailable(err) => format!("pool_unavailable={err}"),
    };
    mvm_core::audit_emit!(StorageGc, "{detail}");
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn seeded_pool() -> ThinPoolImpl {
        let pool = ThinPoolImpl::new(
            PoolConfig {
                size_bytes: 1_000_000,
                ..PoolConfig::default()
            },
            Arc::new(MockBackend::new()),
        );
        pool.ensure_initialized().unwrap();
        for name in ["keep-1", "orphan-1", "orphan-2"] {
            pool.register_base(&VolumeId::new(name), 100).unwrap();
        }
        pool
    }

    #[test]
    fn info_lists_volumes_and_an_uninitialised_pool_is_unavailable() {
        assert!(matches!(info(true), PoolInfo::Unavailable { .. }));
        let PoolInfo::Ready { volumes, .. } = info_of(&seeded_pool()) else {
            panic!("seeded pool must be ready");
        };
        assert_eq!(volumes.len(), 3);
    }

    #[test]
    fn gc_spares_kept_prefixes_and_audits_the_removal() {
        let temp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(temp.path());
        let pool = seeded_pool();
        let keep = vec!["keep-".to_string()];
        assert_eq!(candidates_of(&pool, &keep).unwrap().len(), 2);
        let outcome = apply_to(&pool, &keep).unwrap();
        assert_eq!(
            outcome,
            GcOutcome::Removed(vec!["orphan-1".into(), "orphan-2".into()])
        );
        assert_eq!(apply_to(&pool, &keep).unwrap(), GcOutcome::Empty);
    }
}
