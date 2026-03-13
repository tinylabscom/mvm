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
    /// vCPUs allocated to the Lima VM (default: 8)
    pub lima_cpus: u32,
    /// Memory in GiB allocated to the Lima VM (default: 16)
    pub lima_mem_gib: u32,
    /// Default vCPU count for `mvmctl run` (default: 2)
    pub default_cpus: u32,
    /// Default memory in MiB for `mvmctl run` (default: 512)
    pub default_memory_mib: u32,
    /// Log format: "human" or "json". None means human.
    pub log_format: Option<String>,
    /// Port for the Prometheus metrics endpoint. None means disabled.
    pub metrics_port: Option<u16>,
}

impl Default for MvmConfig {
    fn default() -> Self {
        Self {
            lima_cpus: 8,
            lima_mem_gib: 16,
            default_cpus: 2,
            default_memory_mib: 512,
            log_format: None,
            metrics_port: None,
        }
    }
}

/// Resolve the config directory: `~/.mvm/` by default, or an override for tests.
fn config_dir(override_dir: Option<&Path>) -> PathBuf {
    if let Some(d) = override_dir {
        return d.to_path_buf();
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".mvm")
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
        "lima_cpus" => {
            cfg.lima_cpus = value.parse().with_context(|| {
                format!("lima_cpus must be a positive integer, got {:?}", value)
            })?;
        }
        "lima_mem_gib" => {
            cfg.lima_mem_gib = value.parse().with_context(|| {
                format!("lima_mem_gib must be a positive integer, got {:?}", value)
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
        other => {
            anyhow::bail!(
                "Unknown config key {:?}. Valid keys: lima_cpus, lima_mem_gib, \
                 default_cpus, default_memory_mib, log_format, metrics_port",
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
        assert_eq!(cfg.lima_cpus, 8);
        assert_eq!(cfg.lima_mem_gib, 16);
        assert_eq!(cfg.default_cpus, 2);
        assert_eq!(cfg.default_memory_mib, 512);
        assert!(cfg.log_format.is_none());
        assert!(cfg.metrics_port.is_none());
    }

    #[test]
    fn test_toml_roundtrip() {
        let mut cfg = MvmConfig::default();
        cfg.lima_cpus = 4;
        cfg.metrics_port = Some(9091);

        let text = toml::to_string_pretty(&cfg).unwrap();
        let parsed: MvmConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.lima_cpus, 4);
        assert_eq!(parsed.metrics_port, Some(9091));
        assert_eq!(parsed.lima_mem_gib, 16);
    }

    #[test]
    fn test_load_from_empty_dir_returns_defaults_and_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = load(Some(tmp.path()));
        assert_eq!(cfg.lima_cpus, 8);
        // File should have been created
        assert!(tmp.path().join("config.toml").exists());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = MvmConfig::default();
        cfg.lima_cpus = 6;
        cfg.default_memory_mib = 1024;
        save(&cfg, Some(tmp.path())).unwrap();

        let loaded = load(Some(tmp.path()));
        assert_eq!(loaded.lima_cpus, 6);
        assert_eq!(loaded.default_memory_mib, 1024);
    }

    #[test]
    fn test_set_key_known_key() {
        let mut cfg = MvmConfig::default();
        set_key(&mut cfg, "lima_cpus", "4").unwrap();
        assert_eq!(cfg.lima_cpus, 4);
    }

    #[test]
    fn test_set_key_unknown_key_error() {
        let mut cfg = MvmConfig::default();
        let err = set_key(&mut cfg, "not_a_key", "5").unwrap_err();
        assert!(err.to_string().contains("Unknown config key"));
        assert!(err.to_string().contains("lima_cpus"));
    }

    #[test]
    fn test_set_key_invalid_value_error() {
        let mut cfg = MvmConfig::default();
        let err = set_key(&mut cfg, "lima_cpus", "not-a-number").unwrap_err();
        assert!(err.to_string().contains("integer"));
    }
}
