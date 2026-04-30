use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Project-level fleet configuration loaded from `mvm.toml`.
///
/// Defines a set of named VMs that share a Nix flake reference.
/// Each VM can override resource defaults (cpus, memory, profile).
#[derive(Debug, Deserialize)]
pub struct FleetConfig {
    /// Nix flake reference, shared across all VMs.
    pub flake: String,

    /// Default resource settings applied to all VMs unless overridden.
    #[serde(default)]
    pub defaults: FleetDefaults,

    /// Named VM definitions. BTreeMap for deterministic ordering.
    #[serde(default)]
    pub vms: BTreeMap<String, VmConfig>,
}

#[derive(Debug, Deserialize, Default)]
pub struct FleetDefaults {
    #[serde(default)]
    pub cpus: Option<u32>,

    #[serde(default)]
    pub memory: Option<u32>,

    #[serde(default)]
    pub profile: Option<String>,

    /// Default port mappings applied to all VMs (format: "HOST:GUEST" or "PORT").
    #[serde(default)]
    pub ports: Vec<String>,

    /// Default environment variables injected into all VMs (format: "KEY=VALUE").
    #[serde(default)]
    pub env: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct VmConfig {
    #[serde(default)]
    pub profile: Option<String>,

    #[serde(default)]
    pub cpus: Option<u32>,

    #[serde(default)]
    pub memory: Option<u32>,

    #[serde(default)]
    pub volumes: Vec<String>,

    /// Port mappings (format: "HOST:GUEST" or "PORT"). Replaces defaults if non-empty.
    #[serde(default)]
    pub ports: Vec<String>,

    /// Environment variables (format: "KEY=VALUE"). Replaces defaults if non-empty.
    #[serde(default)]
    pub env: Vec<String>,
}

const DEFAULT_CPUS: u32 = 2;
const DEFAULT_MEM: u32 = 1024;

/// Resolved VM configuration after merging VM-level > defaults > hardcoded.
pub struct ResolvedVm {
    pub name: String,
    pub profile: Option<String>,
    pub cpus: u32,
    pub memory: u32,
    pub volumes: Vec<String>,
    /// Merged port mappings (VM-specific replaces defaults).
    pub ports: Vec<String>,
    /// Merged environment variables (VM-specific replaces defaults).
    pub env: Vec<String>,
}

/// Search for `mvm.toml` starting from cwd, walking up the directory tree.
///
/// Returns `(config, directory_containing_mvm_toml)` so flake paths can be
/// resolved relative to the config file location.
pub fn find_fleet_config() -> Result<Option<(FleetConfig, PathBuf)>> {
    let mut dir = std::env::current_dir()?;
    loop {
        let candidate = dir.join("mvm.toml");
        if candidate.is_file() {
            let content = std::fs::read_to_string(&candidate)
                .with_context(|| format!("Failed to read {}", candidate.display()))?;
            let config: FleetConfig = toml::from_str(&content)
                .with_context(|| format!("Failed to parse {}", candidate.display()))?;
            return Ok(Some((config, dir)));
        }
        if !dir.pop() {
            return Ok(None);
        }
    }
}

/// Parse a fleet config from a TOML string.
pub fn parse_fleet_config(content: &str) -> Result<FleetConfig> {
    toml::from_str(content).context("Failed to parse fleet config")
}

/// Resolve a single VM's effective configuration by merging:
/// VM-specific > [defaults] > hardcoded defaults.
pub fn resolve_vm(fleet: &FleetConfig, name: &str) -> Result<ResolvedVm> {
    let vm = fleet
        .vms
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("VM '{}' not defined in fleet config", name))?;

    let profile = vm
        .profile
        .clone()
        .or_else(|| fleet.defaults.profile.clone());

    let cpus = vm.cpus.or(fleet.defaults.cpus).unwrap_or(DEFAULT_CPUS);

    let memory = vm.memory.or(fleet.defaults.memory).unwrap_or(DEFAULT_MEM);

    // Ports: VM-specific replaces defaults entirely (fall through if empty)
    let ports = if vm.ports.is_empty() {
        fleet.defaults.ports.clone()
    } else {
        vm.ports.clone()
    };

    // Env: VM-specific replaces defaults entirely (fall through if empty)
    let env = if vm.env.is_empty() {
        fleet.defaults.env.clone()
    } else {
        vm.env.clone()
    };

    Ok(ResolvedVm {
        name: name.to_string(),
        profile,
        cpus,
        memory,
        volumes: vm.volumes.clone(),
        ports,
        env,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
            flake = "./nix/images/examples/hello/"

            [defaults]
            cpus = 2
            memory = 1024

            [vms.gw]
            profile = "gateway"

            [vms.w1]
            profile = "worker"

            [vms.w2]
            profile = "worker"
            cpus = 4
            memory = 2048
            volumes = ["./data:/mnt/data:2G"]
        "#;

        let config = parse_fleet_config(toml).unwrap();
        assert_eq!(config.flake, "./nix/images/examples/hello/");
        assert_eq!(config.defaults.cpus, Some(2));
        assert_eq!(config.defaults.memory, Some(1024));
        assert_eq!(config.vms.len(), 3);

        let gw = &config.vms["gw"];
        assert_eq!(gw.profile.as_deref(), Some("gateway"));
        assert_eq!(gw.cpus, None);

        let w2 = &config.vms["w2"];
        assert_eq!(w2.cpus, Some(4));
        assert_eq!(w2.memory, Some(2048));
        assert_eq!(w2.volumes, vec!["./data:/mnt/data:2G"]);
    }

    #[test]
    fn test_parse_config_with_ports_and_env() {
        let toml = r#"
            flake = "."

            [defaults]
            ports = ["3333:3000", "3334:3002"]
            env = ["NODE_ENV=production"]

            [vms.oc]
            profile = "gateway"
            ports = ["8080:3000"]
            env = ["OPENCLAW_EXTERNAL_PORT=8080"]

            [vms.worker]
            profile = "worker"
        "#;

        let config = parse_fleet_config(toml).unwrap();
        assert_eq!(config.defaults.ports, vec!["3333:3000", "3334:3002"]);
        assert_eq!(config.defaults.env, vec!["NODE_ENV=production"]);

        let oc = &config.vms["oc"];
        assert_eq!(oc.ports, vec!["8080:3000"]);
        assert_eq!(oc.env, vec!["OPENCLAW_EXTERNAL_PORT=8080"]);

        let worker = &config.vms["worker"];
        assert!(worker.ports.is_empty());
        assert!(worker.env.is_empty());
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
            flake = "."

            [vms.dev]
            profile = "worker"
        "#;

        let config = parse_fleet_config(toml).unwrap();
        assert_eq!(config.flake, ".");
        assert_eq!(config.defaults.cpus, None);
        assert_eq!(config.defaults.memory, None);
        assert!(config.defaults.ports.is_empty());
        assert!(config.defaults.env.is_empty());
        assert_eq!(config.vms.len(), 1);
    }

    #[test]
    fn test_parse_no_vms() {
        let toml = r#"flake = ".""#;

        let config = parse_fleet_config(toml).unwrap();
        assert!(config.vms.is_empty());
    }

    #[test]
    fn test_parse_requires_flake() {
        let toml = r#"
            [vms.dev]
            profile = "worker"
        "#;

        let result = parse_fleet_config(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_vm_uses_vm_level_overrides() {
        let config = parse_fleet_config(
            r#"
            flake = "."
            [defaults]
            cpus = 2
            memory = 1024

            [vms.big]
            profile = "worker"
            cpus = 8
            memory = 4096
        "#,
        )
        .unwrap();

        let resolved = resolve_vm(&config, "big").unwrap();
        assert_eq!(resolved.cpus, 8);
        assert_eq!(resolved.memory, 4096);
        assert_eq!(resolved.profile.as_deref(), Some("worker"));
    }

    #[test]
    fn test_resolve_vm_falls_through_to_defaults() {
        let config = parse_fleet_config(
            r#"
            flake = "."
            [defaults]
            cpus = 4
            memory = 2048
            profile = "worker"

            [vms.small]
        "#,
        )
        .unwrap();

        let resolved = resolve_vm(&config, "small").unwrap();
        assert_eq!(resolved.cpus, 4);
        assert_eq!(resolved.memory, 2048);
        assert_eq!(resolved.profile.as_deref(), Some("worker"));
    }

    #[test]
    fn test_resolve_vm_falls_through_to_hardcoded() {
        let config = parse_fleet_config(
            r#"
            flake = "."
            [vms.bare]
        "#,
        )
        .unwrap();

        let resolved = resolve_vm(&config, "bare").unwrap();
        assert_eq!(resolved.cpus, DEFAULT_CPUS);
        assert_eq!(resolved.memory, DEFAULT_MEM);
        assert!(resolved.profile.is_none());
        assert!(resolved.ports.is_empty());
        assert!(resolved.env.is_empty());
    }

    #[test]
    fn test_resolve_vm_not_found() {
        let config = parse_fleet_config(r#"flake = ".""#).unwrap();
        let result = resolve_vm(&config, "missing");
        assert!(result.is_err());
    }

    #[test]
    fn test_vm_ordering_is_deterministic() {
        let config = parse_fleet_config(
            r#"
            flake = "."
            [vms.charlie]
            [vms.alpha]
            [vms.bravo]
        "#,
        )
        .unwrap();

        let names: Vec<&str> = config.vms.keys().map(|s| s.as_str()).collect();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn test_resolve_profile_priority() {
        // VM profile beats defaults profile
        let config = parse_fleet_config(
            r#"
            flake = "."
            [defaults]
            profile = "worker"

            [vms.gw]
            profile = "gateway"

            [vms.w1]
        "#,
        )
        .unwrap();

        let gw = resolve_vm(&config, "gw").unwrap();
        assert_eq!(gw.profile.as_deref(), Some("gateway"));

        let w1 = resolve_vm(&config, "w1").unwrap();
        assert_eq!(w1.profile.as_deref(), Some("worker"));
    }

    #[test]
    fn test_resolve_ports_vm_overrides_defaults() {
        let config = parse_fleet_config(
            r#"
            flake = "."
            [defaults]
            ports = ["3333:3000", "3334:3002"]

            [vms.oc]
            ports = ["8080:3000"]

            [vms.worker]
        "#,
        )
        .unwrap();

        // VM-level ports replace defaults entirely
        let oc = resolve_vm(&config, "oc").unwrap();
        assert_eq!(oc.ports, vec!["8080:3000"]);

        // No VM-level ports → fall through to defaults
        let worker = resolve_vm(&config, "worker").unwrap();
        assert_eq!(worker.ports, vec!["3333:3000", "3334:3002"]);
    }

    #[test]
    fn test_resolve_env_vm_overrides_defaults() {
        let config = parse_fleet_config(
            r#"
            flake = "."
            [defaults]
            env = ["NODE_ENV=production"]

            [vms.oc]
            env = ["NODE_ENV=development", "DEBUG=true"]

            [vms.worker]
        "#,
        )
        .unwrap();

        let oc = resolve_vm(&config, "oc").unwrap();
        assert_eq!(oc.env, vec!["NODE_ENV=development", "DEBUG=true"]);

        let worker = resolve_vm(&config, "worker").unwrap();
        assert_eq!(worker.env, vec!["NODE_ENV=production"]);
    }
}
