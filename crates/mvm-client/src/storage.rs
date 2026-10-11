//! Thin-pool inspection and explicit garbage collection, without presentation.

use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_runtime::storage::{
    DeviceMapperBackend, DmsetupBackend, MockBackend, PoolConfig, ThinPool, ThinPoolImpl, VolumeId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct InfoRequest {
    #[serde(default)]
    pub mock: bool,
}

/// Collection is read-only unless `apply` is explicitly set. Prefixes are
/// retained live references, not a list of names authorized for deletion.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct GcRequest {
    #[serde(default)]
    pub apply: bool,
    #[serde(default)]
    pub mock: bool,
    #[serde(default)]
    pub keep_prefix: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PoolStats {
    pub used_bytes: u64,
    pub capacity_bytes: u64,
    pub volume_count: u32,
}

impl PoolStats {
    pub fn fill_fraction(&self) -> f32 {
        if self.capacity_bytes == 0 {
            return 0.0;
        }
        (self.used_bytes as f64 / self.capacity_bytes as f64).min(1.0) as f32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct VolumeStats {
    pub name: String,
    pub used_bytes: u64,
    pub virtual_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct InfoReport {
    pub pool: String,
    pub available: bool,
    pub reason: Option<String>,
    pub stats: Option<PoolStats>,
    pub volumes: Vec<String>,
    /// Best-effort statistics; unavailable individual volumes are omitted.
    pub volume_stats: Vec<VolumeStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct GcReport {
    pub applied: bool,
    pub candidates: Vec<String>,
    pub removed: Vec<String>,
    pub pool_unavailable: Option<String>,
}

fn pool(mock: bool) -> ThinPoolImpl {
    let backend: Arc<dyn DeviceMapperBackend> = if mock {
        Arc::new(MockBackend::new())
    } else {
        Arc::new(DmsetupBackend::new())
    };
    ThinPoolImpl::new(PoolConfig::default(), backend)
}

pub fn info(request: &InfoRequest) -> Result<InfoReport> {
    Ok(info_on(&pool(request.mock)))
}

fn info_on(pool: &impl ThinPool) -> InfoReport {
    let mut report = InfoReport {
        pool: pool.config().name.clone(),
        available: false,
        reason: None,
        stats: None,
        volumes: Vec::new(),
        volume_stats: Vec::new(),
    };
    let stats = match pool.stats() {
        Ok(stats) => stats,
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };
    report.available = true;
    report.stats = Some(PoolStats {
        used_bytes: stats.used_bytes,
        capacity_bytes: stats.capacity_bytes,
        volume_count: stats.volume_count,
    });
    report.volumes = pool.list_volumes().unwrap_or_default();
    report.volume_stats = report
        .volumes
        .iter()
        .filter(|name| valid_volume_name(name))
        .filter_map(|name| {
            pool.volume_stats(&VolumeId::new(name))
                .ok()
                .map(|stats| VolumeStats {
                    name: name.clone(),
                    used_bytes: stats.used_bytes,
                    virtual_size_bytes: stats.virtual_size_bytes,
                })
        })
        .collect();
    report
}

/// Re-enumerates at the mutation boundary; a preview is never authority to
/// remove a subsequently changed volume. The runtime backend owns busy-device
/// refusal and dependency handling.
pub fn gc(request: &GcRequest) -> Result<GcReport> {
    gc_on(request, &pool(request.mock))
}

fn valid_volume_name(name: &str) -> bool {
    name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn gc_on(request: &GcRequest, pool: &impl ThinPool) -> Result<GcReport> {
    let mut report = GcReport {
        applied: request.apply,
        candidates: Vec::new(),
        removed: Vec::new(),
        pool_unavailable: None,
    };
    match pool.list_volumes() {
        Ok(volumes) => {
            report.candidates = volumes
                .into_iter()
                .filter(|name| !request.keep_prefix.iter().any(|p| name.starts_with(p)))
                .collect();
            anyhow::ensure!(
                report.candidates.iter().all(|name| valid_volume_name(name)),
                "thin pool returned an invalid volume name"
            );
            if request.apply && !report.candidates.is_empty() {
                report.removed = pool
                    .gc(|name| {
                        valid_volume_name(name)
                            && report.candidates.iter().any(|candidate| candidate == name)
                            && !request.keep_prefix.iter().any(|p| name.starts_with(p))
                    })
                    .context("dmsetup gc failed")?;
            }
        }
        Err(error) => report.pool_unavailable = Some(error.to_string()),
    }
    if request.apply {
        let detail = match &report.pool_unavailable {
            Some(error) => format!("pool_unavailable={error}"),
            None if report.removed.is_empty() => "count=0".to_string(),
            None if report.removed.len() <= 8 => format!("removed=[{}]", report.removed.join(",")),
            None => format!("count={}", report.removed.len()),
        };
        mvm_core::audit_emit!(StorageGc, "{detail}");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_default_to_real_backend_and_read_only() {
        let request: GcRequest = serde_json::from_str("{}").unwrap();
        assert!(!request.apply);
        assert!(!request.mock);
        assert!(request.keep_prefix.is_empty());
        assert!(serde_json::from_str::<GcRequest>(r#"{"force":true}"#).is_err());
        let roundtrip: GcRequest =
            serde_json::from_value(serde_json::to_value(&request).unwrap()).unwrap();
        assert!(!roundtrip.apply);
    }

    #[test]
    fn stats_and_gc_preserve_live_prefixes() {
        let temp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(temp.path());
        let pool = pool(true);
        pool.ensure_initialized().unwrap();
        pool.register_base(&VolumeId::new("live-one"), 100).unwrap();
        pool.register_base(&VolumeId::new("orphan"), 200).unwrap();
        let info = info_on(&pool);
        assert!(info.available);
        assert_eq!(info.volume_stats.len(), 2);
        let mut request = GcRequest {
            keep_prefix: vec!["live-".into()],
            ..Default::default()
        };
        let preview = gc_on(&request, &pool).unwrap();
        assert_eq!(preview.candidates, ["orphan"]);
        assert!(preview.removed.is_empty());
        assert_eq!(pool.list_volumes().unwrap().len(), 2);
        request.apply = true;
        assert_eq!(gc_on(&request, &pool).unwrap().removed, ["orphan"]);
        assert_eq!(pool.list_volumes().unwrap(), ["live-one"]);
    }

    #[test]
    fn unavailable_pool_is_a_report_and_names_are_checked() {
        let report = info_on(&pool(true));
        assert!(!report.available);
        assert!(report.reason.is_some());
        for invalid in ["", "../escape", "-option", "a/b", "a\0b"] {
            assert!(!valid_volume_name(invalid));
        }
        assert!(valid_volume_name("base-abc_123"));
    }
}
