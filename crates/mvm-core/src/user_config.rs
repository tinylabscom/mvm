use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Persistent operator configuration stored at `~/.mvm/config.toml`.
///
/// CLI flags always take precedence over these values. This config is
/// `mvmctl`-specific; `mvmd` maintains its own separate config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MvmConfig {
    /// vCPUs allocated to the dev VM (default: 8). macOS uses Apple
    /// Container; Linux uses native KVM.
    pub dev_vm_cpus: u32,
    /// Memory in GiB allocated to the dev VM (default: 16).
    pub dev_vm_mem_gib: u32,
    /// Default vCPU count for `mvmctl run` (default: 2)
    pub default_cpus: u32,
    /// Default memory in MiB for `mvmctl run` (default: 512)
    pub default_memory_mib: u32,
    /// Log format: "human" or "json". None means human.
    pub log_format: Option<String>,
    /// Port for the Prometheus metrics endpoint. None means disabled.
    pub metrics_port: Option<u16>,
    /// URL for remote image catalog. None means use bundled catalog only.
    pub catalog_url: Option<String>,
    /// Maximum wall-clock seconds `mvmctl up` waits for every guest
    /// integration's readiness probe to flip to `Active` before giving
    /// up and leaving `InstanceReadiness` at `ServicesStarting {
    /// pending }` (ADR-053 §3 / plan 74 W2). VMs with no integrations
    /// transition to `ServicesReady` immediately; this only matters
    /// for VMs that declare `after_start.sh` health hooks.
    ///
    /// Default: 30 seconds. Override via the `MVM_SERVICES_HEALTH_TIMEOUT_SECS`
    /// environment variable when ad-hoc tuning beats a config edit.
    pub services_health_timeout_secs: u64,
}

impl MvmConfig {
    /// Resolve the effective services-health timeout, honoring an
    /// `MVM_SERVICES_HEALTH_TIMEOUT_SECS` env-var override over the
    /// config field. Env-var takes precedence so a single shell
    /// session can stretch the wait without persisting a change.
    pub fn effective_services_health_timeout_secs(&self) -> u64 {
        if let Ok(raw) = std::env::var("MVM_SERVICES_HEALTH_TIMEOUT_SECS")
            && let Ok(n) = raw.trim().parse::<u64>()
        {
            return n;
        }
        self.services_health_timeout_secs
    }
}

impl Default for MvmConfig {
    fn default() -> Self {
        Self {
            dev_vm_cpus: 8,
            dev_vm_mem_gib: 16,
            default_cpus: 2,
            default_memory_mib: 512,
            log_format: None,
            metrics_port: None,
            catalog_url: None,
            services_health_timeout_secs: 30,
        }
    }
}

/// Resolve the config directory.
///
/// Uses `mvm_config_dir()` (XDG-compliant) by default, or `override_dir` for tests.
/// Falls back to `~/.mvm/` if an existing config lives there (migration compat).
fn config_dir(override_dir: Option<&Path>) -> PathBuf {
    if let Some(d) = override_dir {
        return d.to_path_buf();
    }

    // Check XDG location first
    let xdg_dir = PathBuf::from(crate::config::mvm_config_dir());
    if xdg_dir.join("config.toml").exists() {
        return xdg_dir;
    }

    // Fall back to the legacy data dir (`~/.mvm/`, or MVM_DATA_DIR) if a
    // config lives there.
    let legacy_dir = PathBuf::from(crate::config::mvm_data_dir());
    if legacy_dir.join("config.toml").exists() {
        return legacy_dir;
    }

    // New installs use XDG
    xdg_dir
}

fn config_path(dir: &Path) -> PathBuf {
    dir.join("config.toml")
}

/// Load `MvmConfig` from `~/.mvm/config.toml` (or `override_dir/config.toml` in tests).
///
/// If the file does not exist, it is created with defaults. If it cannot be
/// parsed, defaults are returned with a warning.
pub fn load(override_dir: Option<&Path>) -> MvmConfig {
    let dir = config_dir(override_dir);
    let path = config_path(&dir);

    if !path.exists() {
        let cfg = MvmConfig::default();
        if let Err(e) = save(&cfg, override_dir) {
            tracing::warn!("could not write default config to {}: {e}", path.display());
        }
        return cfg;
    }

    match std::fs::read_to_string(&path) {
        Ok(text) => match toml::from_str::<MvmConfig>(&text) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!("Failed to parse {}: {e}. Using defaults.", path.display());
                MvmConfig::default()
            }
        },
        Err(e) => {
            tracing::warn!("Failed to read {}: {e}. Using defaults.", path.display());
            MvmConfig::default()
        }
    }
}

/// Save `MvmConfig` to `~/.mvm/config.toml` (or `override_dir/config.toml` in tests).
pub fn save(cfg: &MvmConfig, override_dir: Option<&Path>) -> Result<()> {
    let dir = config_dir(override_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create config directory: {}", dir.display()))?;
    let path = config_path(&dir);
    let text = toml::to_string_pretty(cfg).context("Failed to serialize config")?;
    std::fs::write(&path, text)
        .with_context(|| format!("Failed to write config to {}", path.display()))
}

/// Update a single named field in `cfg` from a string value.
///
/// Returns `Err` for unknown keys or unparseable values.
pub fn set_key(cfg: &mut MvmConfig, key: &str, value: &str) -> Result<()> {
    match key {
        "dev_vm_cpus" => {
            cfg.dev_vm_cpus = value.parse().with_context(|| {
                format!("dev_vm_cpus must be a positive integer, got {:?}", value)
            })?;
        }
        "dev_vm_mem_gib" => {
            cfg.dev_vm_mem_gib = value.parse().with_context(|| {
                format!("dev_vm_mem_gib must be a positive integer, got {:?}", value)
            })?;
        }
        "default_cpus" => {
            cfg.default_cpus = value.parse().with_context(|| {
                format!("default_cpus must be a positive integer, got {:?}", value)
            })?;
        }
        "default_memory_mib" => {
            cfg.default_memory_mib = value.parse().with_context(|| {
                format!(
                    "default_memory_mib must be a positive integer, got {:?}",
                    value
                )
            })?;
        }
        "log_format" => {
            cfg.log_format = if value == "none" || value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
        }
        "metrics_port" => {
            cfg.metrics_port = if value == "none" || value == "0" || value.is_empty() {
                None
            } else {
                Some(value.parse().with_context(|| {
                    format!(
                        "metrics_port must be a port number (0-65535), got {:?}",
                        value
                    )
                })?)
            };
        }
        "catalog_url" => {
            cfg.catalog_url = if value == "none" || value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
        }
        other => {
            anyhow::bail!(
                "Unknown config key {:?}. Valid keys: dev_vm_cpus, dev_vm_mem_gib, \
                 default_cpus, default_memory_mib, log_format, metrics_port, catalog_url",
                other
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let cfg = MvmConfig::default();
        assert_eq!(cfg.dev_vm_cpus, 8);
        assert_eq!(cfg.dev_vm_mem_gib, 16);
        assert_eq!(cfg.default_cpus, 2);
        assert_eq!(cfg.default_memory_mib, 512);
        assert!(cfg.log_format.is_none());
        assert!(cfg.metrics_port.is_none());
        // ADR-053 §3 / plan 74 W2 default: 30 s services-health wait.
        assert_eq!(cfg.services_health_timeout_secs, 30);
    }

    #[test]
    fn test_effective_services_health_timeout_honors_env_var_override() {
        // Save + restore the env var so the test doesn't leak state.
        let saved = std::env::var("MVM_SERVICES_HEALTH_TIMEOUT_SECS").ok();

        // Clean slate: with no override, the config field wins.
        // SAFETY: tests are serial in this module and we restore below.
        unsafe { std::env::remove_var("MVM_SERVICES_HEALTH_TIMEOUT_SECS") };
        let cfg = MvmConfig {
            services_health_timeout_secs: 7,
            ..MvmConfig::default()
        };
        assert_eq!(cfg.effective_services_health_timeout_secs(), 7);

        // With a valid override, the env-var value wins.
        unsafe { std::env::set_var("MVM_SERVICES_HEALTH_TIMEOUT_SECS", "120") };
        assert_eq!(cfg.effective_services_health_timeout_secs(), 120);

        // Garbage in the env var falls back to the config field
        // rather than panicking — operator typos do not break boot.
        unsafe { std::env::set_var("MVM_SERVICES_HEALTH_TIMEOUT_SECS", "not-a-number") };
        assert_eq!(cfg.effective_services_health_timeout_secs(), 7);

        // Restore the original env value.
        match saved {
            Some(v) => unsafe { std::env::set_var("MVM_SERVICES_HEALTH_TIMEOUT_SECS", v) },
            None => unsafe { std::env::remove_var("MVM_SERVICES_HEALTH_TIMEOUT_SECS") },
        }
    }

    #[test]
    fn test_config_with_missing_optional_fields_loads_with_defaults() {
        // A config that omits optional fields must deserialize cleanly,
        // filling them from defaults. Serde's `#[serde(default)]` gives us
        // this — the seam that keeps older config files loading.
        let partial = r#"
            dev_vm_cpus = 4
            dev_vm_mem_gib = 8
            default_cpus = 2
            default_memory_mib = 512
        "#;
        let cfg: MvmConfig = toml::from_str(partial).unwrap();
        assert_eq!(cfg.dev_vm_cpus, 4);
        assert_eq!(cfg.services_health_timeout_secs, 30);
    }

    #[test]
    fn test_toml_roundtrip() {
        let cfg = MvmConfig {
            dev_vm_cpus: 4,
            metrics_port: Some(9091),
            ..MvmConfig::default()
        };

        let text = toml::to_string_pretty(&cfg).unwrap();
        let parsed: MvmConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.dev_vm_cpus, 4);
        assert_eq!(parsed.metrics_port, Some(9091));
        assert_eq!(parsed.dev_vm_mem_gib, 16);
    }

    #[test]
    fn test_load_from_empty_dir_returns_defaults_and_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = load(Some(tmp.path()));
        assert_eq!(cfg.dev_vm_cpus, 8);
        // File should have been created
        assert!(tmp.path().join("config.toml").exists());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = MvmConfig {
            dev_vm_cpus: 6,
            default_memory_mib: 1024,
            ..MvmConfig::default()
        };
        save(&cfg, Some(tmp.path())).unwrap();

        let loaded = load(Some(tmp.path()));
        assert_eq!(loaded.dev_vm_cpus, 6);
        assert_eq!(loaded.default_memory_mib, 1024);
    }

    #[test]
    fn test_set_key_known_key() {
        let mut cfg = MvmConfig::default();
        set_key(&mut cfg, "dev_vm_cpus", "4").unwrap();
        assert_eq!(cfg.dev_vm_cpus, 4);
    }

    #[test]
    fn test_set_key_unknown_key_error() {
        let mut cfg = MvmConfig::default();
        let err = set_key(&mut cfg, "not_a_key", "5").unwrap_err();
        assert!(err.to_string().contains("Unknown config key"));
        assert!(err.to_string().contains("dev_vm_cpus"));
    }

    #[test]
    fn test_set_key_catalog_url() {
        let mut cfg = MvmConfig::default();
        set_key(&mut cfg, "catalog_url", "https://example.com/catalog.json").unwrap();
        assert_eq!(
            cfg.catalog_url.as_deref(),
            Some("https://example.com/catalog.json")
        );
    }

    #[test]
    fn test_set_key_catalog_url_none() {
        let mut cfg = MvmConfig {
            catalog_url: Some("https://example.com".to_string()),
            ..MvmConfig::default()
        };
        set_key(&mut cfg, "catalog_url", "none").unwrap();
        assert!(cfg.catalog_url.is_none());
    }

    #[test]
    fn test_catalog_url_default_none() {
        let cfg = MvmConfig::default();
        assert!(cfg.catalog_url.is_none());
    }

    #[test]
    fn test_set_key_invalid_value_error() {
        let mut cfg = MvmConfig::default();
        let err = set_key(&mut cfg, "dev_vm_cpus", "not-a-number").unwrap_err();
        assert!(err.to_string().contains("integer"));
    }
}
