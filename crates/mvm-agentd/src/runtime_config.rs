//! Boot-time parse of `/etc/mvm/runtime.json` — function-entrypoint
//! workload metadata produced by mvmforge at image-build time.
//!
//! Two config files live under `/etc/mvm/`, owned by different
//! producers:
//!
//! - `agent.json` (mvm-owned, transport tuning) — read by
//!   `mvm-guest-agent`'s `parse_config`, exists today.
//! - `runtime.json` (mvmforge-owned, per-workload metadata) — this
//!   module. NEW.
//!
//! The two are kept separate because they have independent schemas
//! and release cadences. mvmforge writes `runtime.json` into the
//! rootfs via `mkGuest extraFiles`, owned root mode 0644, and the
//! verity initramfs prevents post-boot tampering.
//!
//! The agent reads this file once at boot. When `concurrency.kind =
//! "warm_process"` is present, it stands up a worker pool (see
//! `worker_pool` module). When the file or `concurrency` is absent,
//! the cold path handles `RunEntrypoint` exactly as before.
//!
//! Malformed JSON or a rejected `in_process` mode is fail-loud: the
//! agent exits non-zero at boot. mvmforge owns the file; a broken
//! one is a build bug, not a runtime fallback.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Default `runtime.json` location. Overridable via [`load_from`] for
/// tests.
pub const DEFAULT_PATH: &str = "/etc/mvm/runtime.json";

/// Sanity cap on `pool_size`. A misconfigured image with a huge
/// pool_size could exhaust VM memory before the first invoke; bound
/// it explicitly. mvmforge defaults are far below this.
pub const MAX_POOL_SIZE: usize = 64;

/// Per-workload metadata written by mvmforge at image-build time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub language: String,
    pub module: String,
    pub function: String,
    pub format: String,
    pub source_path: String,
    /// When absent, the agent serves `RunEntrypoint` via the cold
    /// path. When set to `WarmProcess`, the agent stands up a worker
    /// pool at boot.
    #[serde(default)]
    pub concurrency: Option<ConcurrencyConfig>,
}

/// Concurrency variant. Tagged enum so future tiers (e.g. async
/// in-process) extend the schema without breaking existing readers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ConcurrencyConfig {
    WarmProcess(WarmProcessConfig),
}

/// Warm-process tier knobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmProcessConfig {
    /// Recycle the worker after this many calls. mvmforge default 1000.
    pub max_calls_per_worker: u64,
    /// Recycle the worker if its RSS exceeds this many MiB at the
    /// post-call sample point. Sampled from `/proc/<pid>/statm`,
    /// never mid-dispatch. mvmforge default 512.
    pub max_rss_mb: u64,
    /// How many wrappers run concurrently. Bounded above by
    /// [`MAX_POOL_SIZE`].
    pub pool_size: usize,
    /// Per-worker concurrency. v0.2 supports `Serial` only.
    /// `Concurrent` is rejected at parse time.
    pub in_process: InProcessMode,
    /// FIFO queue cap when all workers are busy. Default = 2 *
    /// pool_size. Overflow returns `EntrypointEvent::Error { kind:
    /// Busy }` to the host — same envelope the cold path returns on
    /// contention.
    #[serde(default)]
    pub max_queue_depth: Option<usize>,
}

impl WarmProcessConfig {
    /// Resolve the queue depth: the explicit `max_queue_depth` if
    /// set, otherwise `2 * pool_size`.
    pub fn effective_queue_depth(&self) -> usize {
        self.max_queue_depth
            .unwrap_or(self.pool_size.saturating_mul(2))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum InProcessMode {
    /// One in-flight call per worker. Multiple workers run in
    /// parallel up to `pool_size`.
    Serial,
    /// Multiple in-flight calls per worker via async. Out of scope
    /// for v0.2; the loader rejects this value with
    /// [`RuntimeConfigError::ConcurrentNotSupported`].
    Concurrent,
}

/// Errors surfaced by [`load`] / [`load_from`]. Each variant
/// describes a fail-loud reason the agent refuses to start.
#[derive(Debug)]
pub enum RuntimeConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    PoolSizeOutOfRange {
        pool_size: usize,
        max: usize,
    },
    ConcurrentNotSupported,
}

impl std::fmt::Display for RuntimeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeConfigError::Read { path, source } => {
                write!(f, "read {}: {source}", path.display())
            }
            RuntimeConfigError::Parse { path, source } => {
                write!(f, "parse {}: {source}", path.display())
            }
            RuntimeConfigError::PoolSizeOutOfRange { pool_size, max } => write!(
                f,
                "pool_size {pool_size} out of range; must be in [1, {max}]"
            ),
            RuntimeConfigError::ConcurrentNotSupported => write!(
                f,
                "in_process = \"concurrent\" is not supported in v0.2 (ADR-0011)"
            ),
        }
    }
}

impl std::error::Error for RuntimeConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RuntimeConfigError::Read { source, .. } => Some(source),
            RuntimeConfigError::Parse { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Load `/etc/mvm/runtime.json` (or `Ok(None)` if the file is
/// absent). Wraps [`load_from`] with the production path.
pub fn load() -> Result<Option<RuntimeConfig>, RuntimeConfigError> {
    load_from(Path::new(DEFAULT_PATH))
}

/// Load runtime config from the given path. Missing file →
/// `Ok(None)`. Any other error is fail-loud; the agent should refuse
/// to start.
pub fn load_from(path: &Path) -> Result<Option<RuntimeConfig>, RuntimeConfigError> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(RuntimeConfigError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let config: RuntimeConfig =
        serde_json::from_str(&raw).map_err(|source| RuntimeConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    config.validate()?;
    Ok(Some(config))
}

impl RuntimeConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        if let Some(ConcurrencyConfig::WarmProcess(wp)) = &self.concurrency {
            if wp.pool_size < 1 || wp.pool_size > MAX_POOL_SIZE {
                return Err(RuntimeConfigError::PoolSizeOutOfRange {
                    pool_size: wp.pool_size,
                    max: MAX_POOL_SIZE,
                });
            }
            if wp.in_process == InProcessMode::Concurrent {
                return Err(RuntimeConfigError::ConcurrentNotSupported);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(s: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(s.as_bytes()).unwrap();
        f
    }

    #[test]
    fn missing_file_returns_ok_none() {
        let path = Path::new("/nonexistent/runtime.json");
        assert!(matches!(load_from(path), Ok(None)));
    }

    #[test]
    fn cold_tier_no_concurrency_field() {
        let json = r#"{
            "language": "python",
            "module": "app",
            "function": "handler",
            "format": "json",
            "source_path": "/app"
        }"#;
        let f = write_tmp(json);
        let cfg = load_from(f.path()).unwrap().unwrap();
        assert!(cfg.concurrency.is_none());
        assert_eq!(cfg.language, "python");
    }

    #[test]
    fn warm_process_serial_parses() {
        let json = r#"{
            "language": "python",
            "module": "app",
            "function": "handler",
            "format": "json",
            "source_path": "/app",
            "concurrency": {
                "kind": "warm_process",
                "max_calls_per_worker": 1000,
                "max_rss_mb": 512,
                "pool_size": 4,
                "in_process": "serial"
            }
        }"#;
        let f = write_tmp(json);
        let cfg = load_from(f.path()).unwrap().unwrap();
        let Some(ConcurrencyConfig::WarmProcess(wp)) = &cfg.concurrency else {
            panic!("expected WarmProcess");
        };
        assert_eq!(wp.pool_size, 4);
        assert_eq!(wp.max_calls_per_worker, 1000);
        assert_eq!(wp.max_rss_mb, 512);
        assert_eq!(wp.in_process, InProcessMode::Serial);
        assert_eq!(wp.effective_queue_depth(), 8);
    }

    #[test]
    fn explicit_max_queue_depth_overrides_default() {
        let json = r#"{
            "language": "python", "module": "app", "function": "handler",
            "format": "json", "source_path": "/app",
            "concurrency": {
                "kind": "warm_process",
                "max_calls_per_worker": 1, "max_rss_mb": 1, "pool_size": 2,
                "in_process": "serial",
                "max_queue_depth": 16
            }
        }"#;
        let f = write_tmp(json);
        let cfg = load_from(f.path()).unwrap().unwrap();
        let Some(ConcurrencyConfig::WarmProcess(wp)) = &cfg.concurrency else {
            unreachable!()
        };
        assert_eq!(wp.effective_queue_depth(), 16);
    }

    #[test]
    fn concurrent_mode_rejected() {
        let json = r#"{
            "language": "python", "module": "app", "function": "handler",
            "format": "json", "source_path": "/app",
            "concurrency": {
                "kind": "warm_process",
                "max_calls_per_worker": 1, "max_rss_mb": 1, "pool_size": 1,
                "in_process": "concurrent"
            }
        }"#;
        let f = write_tmp(json);
        let err = load_from(f.path()).unwrap_err();
        assert!(matches!(err, RuntimeConfigError::ConcurrentNotSupported));
    }

    #[test]
    fn pool_size_zero_rejected() {
        let json = r#"{
            "language": "python", "module": "app", "function": "handler",
            "format": "json", "source_path": "/app",
            "concurrency": {
                "kind": "warm_process",
                "max_calls_per_worker": 1, "max_rss_mb": 1, "pool_size": 0,
                "in_process": "serial"
            }
        }"#;
        let f = write_tmp(json);
        let err = load_from(f.path()).unwrap_err();
        assert!(matches!(err, RuntimeConfigError::PoolSizeOutOfRange { .. }));
    }

    #[test]
    fn pool_size_above_cap_rejected() {
        let json = format!(
            r#"{{
                "language": "python", "module": "app", "function": "handler",
                "format": "json", "source_path": "/app",
                "concurrency": {{
                    "kind": "warm_process",
                    "max_calls_per_worker": 1, "max_rss_mb": 1, "pool_size": {},
                    "in_process": "serial"
                }}
            }}"#,
            MAX_POOL_SIZE + 1
        );
        let f = write_tmp(&json);
        let err = load_from(f.path()).unwrap_err();
        assert!(matches!(err, RuntimeConfigError::PoolSizeOutOfRange { .. }));
    }

    #[test]
    fn unknown_field_at_top_level_rejected() {
        let json = r#"{
            "language": "python", "module": "app", "function": "handler",
            "format": "json", "source_path": "/app",
            "stowaway": "not allowed"
        }"#;
        let f = write_tmp(json);
        let err = load_from(f.path()).unwrap_err();
        assert!(matches!(err, RuntimeConfigError::Parse { .. }));
    }

    #[test]
    fn unknown_field_in_warm_process_rejected() {
        let json = r#"{
            "language": "python", "module": "app", "function": "handler",
            "format": "json", "source_path": "/app",
            "concurrency": {
                "kind": "warm_process",
                "max_calls_per_worker": 1, "max_rss_mb": 1, "pool_size": 1,
                "in_process": "serial",
                "extra": "deny"
            }
        }"#;
        let f = write_tmp(json);
        let err = load_from(f.path()).unwrap_err();
        assert!(matches!(err, RuntimeConfigError::Parse { .. }));
    }

    #[test]
    fn malformed_json_rejected() {
        let f = write_tmp("not-json");
        let err = load_from(f.path()).unwrap_err();
        assert!(matches!(err, RuntimeConfigError::Parse { .. }));
    }

    #[test]
    fn roundtrip_serialize_deserialize() {
        let cfg = RuntimeConfig {
            language: "python".into(),
            module: "app".into(),
            function: "handler".into(),
            format: "json".into(),
            source_path: "/app".into(),
            concurrency: Some(ConcurrencyConfig::WarmProcess(WarmProcessConfig {
                max_calls_per_worker: 1000,
                max_rss_mb: 512,
                pool_size: 1,
                in_process: InProcessMode::Serial,
                max_queue_depth: None,
            })),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: RuntimeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }
}
