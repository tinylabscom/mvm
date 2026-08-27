use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Persistent operator configuration stored at `~/.mvm/config/config.toml`.
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
    /// Optional mvmd endpoint used by `mvmctl deploy` after local recording.
    pub mvmd_url: Option<String>,
    /// Maximum wall-clock seconds `mvmctl up` waits for every guest
    /// integration's readiness probe to flip to `Active` before giving
    /// up and leaving `InstanceReadiness` at `ServicesStarting {
    /// pending }`. VMs with no integrations
    /// transition to `ServicesReady` immediately; this only matters
    /// for VMs that declare `after_start.sh` health hooks.
    ///
    /// Default: 30 seconds. Override via the `MVM_SERVICES_HEALTH_TIMEOUT_SECS`
    /// environment variable when ad-hoc tuning beats a config edit.
    pub services_health_timeout_secs: u64,
    /// Ceiling on the CPU share any workload on this host may be granted,
    /// in thousandths of one host core. `None` = unbounded in this dimension.
    ///
    /// This and its two siblings below are the host operator's bound on what a
    /// grant may *ask for*. They live in host config rather than in the plan
    /// precisely because a plan signer who is also the grant author would
    /// otherwise be able to grant itself the machine.
    pub max_cpu_millicores: Option<u32>,
    /// Ceiling on memory any workload on this host may be granted, in MiB.
    /// `None` = unbounded in this dimension.
    pub max_memory_mib: Option<u64>,
    /// Ceiling on wall-clock runtime any workload on this host may be granted,
    /// in seconds. `None` = unbounded in this dimension; note that a bounded
    /// value here refuses an explicitly unbounded grant rather than clamping
    /// it, so a caller learns the host forbids what it asked for.
    pub max_wall_clock_secs: Option<u32>,
    /// Default CPU share, in thousandths of one host core, for a workload no
    /// higher surface capped. `None` = uncapped.
    ///
    /// A default is not a ceiling. The three `max_*` keys above bound what a
    /// grant may *ask for* and no surface can exceed them; this one only fills
    /// in a dimension nobody else named, and any surface above host config
    /// overrides it freely.
    pub default_cpu_millicores: Option<u32>,
    /// Default wall-clock bound, in seconds, for a workload no higher surface
    /// bounded. `None` = unbounded. A configured `0` is ignored rather than
    /// read as "no time allowed": zero is not expressible as a wall-clock
    /// grant, and the legacy encoding it resembles means unbounded.
    pub default_wall_clock_secs: Option<u32>,
    /// Host-wide headroom for guest RAM, in MiB: the sum across every live
    /// machine plus a pending boot may not exceed it. `None` = unbounded.
    ///
    /// Distinct from `max_memory_mib`, which bounds one workload. Ten boots
    /// that each clear the per-workload ceiling can still exhaust the host,
    /// and only this key refuses the eleventh.
    pub host_budget_memory_mib: Option<u64>,
    /// Host-wide headroom for granted CPU share, in thousandths of one host
    /// core. `None` = unbounded.
    ///
    /// Sums only *granted* shares: a workload that declared no CPU grant is
    /// uncapped and contributes nothing, so this bounds the total of what was
    /// promised rather than the total of what can be consumed.
    pub host_budget_cpu_millicores: Option<u32>,
    /// External signers whose Ed25519-signed plans this host will admit.
    ///
    /// Empty by default, and the default is the security posture: a host that
    /// pins nobody refuses every externally-signed plan. Pinning an entry is
    /// the operator delegating plan authority to a fleet control plane's
    /// issuer key — the plan's grants are still measured against this host's
    /// ceiling and budget, which the signer cannot widen.
    pub trusted_plan_signers: Vec<TrustedPlanSigner>,
}

/// One external plan signer the operator has chosen to trust: the
/// `signer_id` a `SignedExecutionPlan` envelope names, pinned to the Ed25519
/// public key the signature must verify under.
///
/// The key is pinned, not looked up: the envelope's `signer_id` selects which
/// entry verifies it, so two entries must never share an id (the first match
/// wins, and a duplicated id would shadow the later pin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPlanSigner {
    /// The identifier the signed envelope carries and the verifier matches on.
    pub signer_id: String,
    /// The signer's Ed25519 public key, lowercase hex (64 chars, 32 bytes).
    pub ed25519_pubkey_hex: String,
}

impl TrustedPlanSigner {
    /// Parse the pinned public key into a verifying key.
    ///
    /// A malformed pin is an error, never a skipped entry: silently dropping
    /// an unparseable pin would admit nothing the operator meant to refuse,
    /// but surfacing it tells them the pin they wrote is not the pin in
    /// force.
    pub fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        let raw = hex::decode(&self.ed25519_pubkey_hex).with_context(|| {
            format!(
                "trusted plan signer {:?}: ed25519_pubkey_hex is not hex",
                self.signer_id
            )
        })?;
        let bytes: [u8; 32] = raw.try_into().map_err(|raw: Vec<u8>| {
            anyhow::anyhow!(
                "trusted plan signer {:?}: ed25519_pubkey_hex decodes to {} bytes, expected 32",
                self.signer_id,
                raw.len()
            )
        })?;
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).with_context(|| {
            format!(
                "trusted plan signer {:?}: ed25519_pubkey_hex is not a valid Ed25519 key",
                self.signer_id
            )
        })
    }
}

impl MvmConfig {
    /// The host's bound on what a workload may be granted.
    ///
    /// Read at admission, never from the plan being admitted: the ceiling and
    /// the grant have different trust roots, and collapsing them would make the
    /// bound writable by the party it exists to bound.
    #[must_use]
    pub fn grant_ceiling(&self) -> mvm_contract::grants::ceiling::GrantCeiling {
        mvm_contract::grants::ceiling::GrantCeiling {
            max_cpu_millicores: self.max_cpu_millicores,
            max_memory_mib: self.max_memory_mib,
            max_wall_clock_secs: self.max_wall_clock_secs,
        }
    }

    /// The host's headroom: what every live workload plus a pending boot may
    /// consume in total.
    ///
    /// Read at admission from the same operator config as the per-workload
    /// ceiling, and never from a plan. The two answer different questions —
    /// the ceiling bounds one workload, this bounds the sum — and a host can
    /// meaningfully configure either without the other.
    #[must_use]
    pub fn host_budget(&self) -> mvm_contract::grants::budget::HostBudget {
        mvm_contract::grants::budget::HostBudget {
            max_total_memory_mib: self.host_budget_memory_mib,
            max_total_cpu_millicores: self.host_budget_cpu_millicores,
        }
    }

    /// The host's default grant: the dimensions this operator wants applied to
    /// a workload that named none itself.
    ///
    /// Egress is deliberately absent and has no config key. A host-wide
    /// allow-list would open outbound access for every workload that never
    /// asked for any, which inverts default-deny — the one posture that has to
    /// hold without anyone opting into it. Egress is authored per workload or
    /// not at all.
    #[must_use]
    pub fn default_grants(&self) -> mvm_contract::grants::Grants {
        mvm_contract::grants::Grants {
            cpu: self
                .default_cpu_millicores
                .map(|millicores| mvm_contract::grants::CpuGrant::Share { millicores }),
            wall_clock: self
                .default_wall_clock_secs
                .and_then(std::num::NonZeroU32::new)
                .map(|secs| mvm_contract::grants::WallClockGrant::Secs { secs }),
            egress: None,
        }
    }

    /// The host's trusted external plan signers, parsed into verifying keys.
    ///
    /// Read at admission, never from the plan being admitted — same trust-root
    /// rule as the grant ceiling. An empty set is the fail-closed default:
    /// callers must treat it as "this host admits no externally-signed plans".
    /// A malformed pin fails the whole load rather than being skipped, so the
    /// set in force is exactly the set the operator wrote.
    pub fn trusted_plan_signer_keys(&self) -> Result<Vec<(String, ed25519_dalek::VerifyingKey)>> {
        self.trusted_plan_signers
            .iter()
            .map(|signer| Ok((signer.signer_id.clone(), signer.verifying_key()?)))
            .collect()
    }

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
            mvmd_url: None,
            services_health_timeout_secs: 30,
            // Unset by default: a single-user host is not multi-tenant, and a
            // ceiling invented here would refuse legitimate local runs while
            // protecting nobody. An operator who shares the host sets them.
            max_cpu_millicores: None,
            max_memory_mib: None,
            max_wall_clock_secs: None,
            // Also unset: a default invented here would cap every local run
            // with a number nobody chose.
            default_cpu_millicores: None,
            default_wall_clock_secs: None,
            // Unset for the same reason as the per-workload ceilings: a
            // headroom figure invented here would be a fraction of a host size
            // this code cannot see, and would refuse legitimate local runs on
            // a large machine while under-protecting a small one.
            host_budget_memory_mib: None,
            host_budget_cpu_millicores: None,
            // Empty = refuse every externally-signed plan. Trusting a fleet
            // issuer is a delegation of plan authority; it has to be written
            // by the operator, never defaulted into.
            trusted_plan_signers: Vec::new(),
        }
    }
}

/// Resolve the config directory: `mvm_config_dir()` (`<mvm_home>/config`)
/// by default, or `override_dir` for tests.
fn config_dir(override_dir: Option<&Path>) -> PathBuf {
    match override_dir {
        Some(d) => d.to_path_buf(),
        None => PathBuf::from(crate::config::mvm_config_dir()),
    }
}

fn config_path(dir: &Path) -> PathBuf {
    dir.join("config.toml")
}

/// Load `MvmConfig` from `<mvm_config_dir>/config.toml` (or `override_dir/config.toml` in tests).
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

/// Save `MvmConfig` to `<mvm_config_dir>/config.toml` (or `override_dir/config.toml` in tests).
pub fn save(cfg: &MvmConfig, override_dir: Option<&Path>) -> Result<()> {
    let dir = config_dir(override_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create config directory: {}", dir.display()))?;
    let path = config_path(&dir);
    let text = toml::to_string_pretty(cfg).context("Failed to serialize config")?;
    std::fs::write(&path, text)
        .with_context(|| format!("Failed to write config to {}", path.display()))
}

/// Parse a numeric setting that has an explicit "no bound" spelling.
///
/// `none` and the empty string clear the key. A ceiling is a bound, so
/// clearing it has to be something the operator writes on purpose — an
/// unparseable value is an error rather than a silent `None`, or a typo would
/// remove the bound it was meant to change.
fn optional_number<T: std::str::FromStr>(key: &str, value: &str) -> Result<Option<T>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "none" {
        return Ok(None);
    }
    trimmed.parse::<T>().map(Some).map_err(|_| {
        anyhow::anyhow!("{key} must be a non-negative integer or \"none\", got {value:?}")
    })
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
        "mvmd_url" => {
            cfg.mvmd_url = if value == "none" || value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
        }
        "max_cpu_millicores" => {
            cfg.max_cpu_millicores = optional_number(key, value)?;
        }
        "max_memory_mib" => {
            cfg.max_memory_mib = optional_number(key, value)?;
        }
        "max_wall_clock_secs" => {
            cfg.max_wall_clock_secs = optional_number(key, value)?;
        }
        other => {
            anyhow::bail!(
                "Unknown config key {:?}. Valid keys: dev_vm_cpus, dev_vm_mem_gib, \
                 default_cpus, default_memory_mib, log_format, metrics_port, catalog_url, \
                 mvmd_url, max_cpu_millicores, max_memory_mib, max_wall_clock_secs",
                other
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_env::TestEnv;

    #[test]
    fn test_default_values() {
        let cfg = MvmConfig::default();
        assert_eq!(cfg.dev_vm_cpus, 8);
        assert_eq!(cfg.dev_vm_mem_gib, 16);
        assert_eq!(cfg.default_cpus, 2);
        assert_eq!(cfg.default_memory_mib, 512);
        assert!(cfg.log_format.is_none());
        assert!(cfg.metrics_port.is_none());
        // Default: 30 s services-health wait.
        assert_eq!(cfg.services_health_timeout_secs, 30);
    }

    #[test]
    fn test_effective_services_health_timeout_honors_env_var_override() {
        let mut env = TestEnv::new();

        // Clean slate: with no override, the config field wins.
        env.remove("MVM_SERVICES_HEALTH_TIMEOUT_SECS");
        let cfg = MvmConfig {
            services_health_timeout_secs: 7,
            ..MvmConfig::default()
        };
        assert_eq!(cfg.effective_services_health_timeout_secs(), 7);

        // With a valid override, the env-var value wins.
        env.set("MVM_SERVICES_HEALTH_TIMEOUT_SECS", "120");
        assert_eq!(cfg.effective_services_health_timeout_secs(), 120);

        // Garbage in the env var falls back to the config field
        // rather than panicking — operator typos do not break boot.
        env.set("MVM_SERVICES_HEALTH_TIMEOUT_SECS", "not-a-number");
        assert_eq!(cfg.effective_services_health_timeout_secs(), 7);
        // `env` restores the original value on drop.
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
    fn test_set_key_mvmd_url() {
        let mut cfg = MvmConfig::default();
        set_key(&mut cfg, "mvmd_url", "https://mvmd.example").unwrap();
        assert_eq!(cfg.mvmd_url.as_deref(), Some("https://mvmd.example"));
        set_key(&mut cfg, "mvmd_url", "none").unwrap();
        assert!(cfg.mvmd_url.is_none());
    }

    #[test]
    fn test_catalog_url_default_none() {
        let cfg = MvmConfig::default();
        assert!(cfg.catalog_url.is_none());
    }

    #[test]
    fn an_unset_ceiling_bounds_nothing() {
        // A host with no ceiling configured must admit what it always did:
        // inventing a default here would refuse legitimate local runs.
        let ceiling = MvmConfig::default().grant_ceiling();
        assert_eq!(
            ceiling,
            mvm_contract::grants::ceiling::GrantCeiling::default()
        );
    }

    #[test]
    fn the_ceiling_is_read_from_the_configured_keys() {
        let mut cfg = MvmConfig::default();
        set_key(&mut cfg, "max_cpu_millicores", "4000").unwrap();
        set_key(&mut cfg, "max_memory_mib", "8192").unwrap();
        set_key(&mut cfg, "max_wall_clock_secs", "3600").unwrap();

        let ceiling = cfg.grant_ceiling();
        assert_eq!(ceiling.max_cpu_millicores, Some(4000));
        assert_eq!(ceiling.max_memory_mib, Some(8192));
        assert_eq!(ceiling.max_wall_clock_secs, Some(3600));

        // The config file is where an operator writes it, so it has to survive
        // the round trip that persists it.
        let parsed: MvmConfig = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(parsed.grant_ceiling(), ceiling);
    }

    #[test]
    fn a_typo_does_not_silently_remove_a_ceiling() {
        // Clearing a bound is an explicit `none`; anything else is an error,
        // because a mistyped ceiling that parses as "unbounded" is a security
        // control disabled by a spelling mistake.
        let mut cfg = MvmConfig {
            max_cpu_millicores: Some(4000),
            ..MvmConfig::default()
        };
        let err = set_key(&mut cfg, "max_cpu_millicores", "4o00").unwrap_err();
        assert!(err.to_string().contains("max_cpu_millicores"));
        assert_eq!(cfg.max_cpu_millicores, Some(4000), "the bound must survive");

        set_key(&mut cfg, "max_cpu_millicores", "none").unwrap();
        assert!(cfg.max_cpu_millicores.is_none());
    }

    #[test]
    fn test_set_key_invalid_value_error() {
        let mut cfg = MvmConfig::default();
        let err = set_key(&mut cfg, "dev_vm_cpus", "not-a-number").unwrap_err();
        assert!(err.to_string().contains("integer"));
    }

    #[test]
    fn trusted_plan_signers_default_empty() {
        // Fail closed: a host that pinned nobody admits no externally-signed
        // plan, and the empty default must survive a TOML round trip.
        let cfg = MvmConfig::default();
        assert!(cfg.trusted_plan_signers.is_empty());
        assert_eq!(cfg.trusted_plan_signer_keys().unwrap(), Vec::new());

        let parsed: MvmConfig = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert!(parsed.trusted_plan_signers.is_empty());
    }

    #[test]
    fn trusted_plan_signers_round_trip_and_parse() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let expected = signing.verifying_key();
        let cfg = MvmConfig {
            trusted_plan_signers: vec![TrustedPlanSigner {
                signer_id: "fleet-prod".to_string(),
                ed25519_pubkey_hex: hex::encode(expected.as_bytes()),
            }],
            ..MvmConfig::default()
        };

        // The operator writes this into config.toml, so the persisted form is
        // what must parse back into the same pin.
        let parsed: MvmConfig = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(parsed.trusted_plan_signers, cfg.trusted_plan_signers);

        let keys = parsed.trusted_plan_signer_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "fleet-prod");
        assert_eq!(keys[0].1, expected);
    }

    #[test]
    fn a_malformed_trusted_signer_pin_fails_the_load() {
        // Never skip an unparseable pin: the operator believes the key they
        // wrote is the one in force.
        let bad_pins = [
            "not-hex!".to_string(),
            "ab".repeat(16), // 16 bytes — wrong length
            "ab".repeat(64), // 64 bytes — wrong length
        ];
        for bad in &bad_pins {
            let signer = TrustedPlanSigner {
                signer_id: "fleet-prod".to_string(),
                ed25519_pubkey_hex: bad.clone(),
            };
            let err = signer.verifying_key().unwrap_err();
            assert!(
                err.to_string().contains("fleet-prod"),
                "the error must name the offending pin: {err:#}"
            );
        }

        // A real key's hex parses back to that key.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let expected = signing.verifying_key();
        let signer = TrustedPlanSigner {
            signer_id: "fleet-prod".to_string(),
            ed25519_pubkey_hex: hex::encode(expected.as_bytes()),
        };
        assert_eq!(signer.verifying_key().unwrap(), expected);
    }
}
