use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use mvm_core::pool::Role;

/// Manifest mapping (role, profile) → Nix module paths.
///
/// This file is placed at `<flake_ref>/mvm-profiles.toml` and describes
/// which .nix modules to compose for each role+profile combination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NixManifest {
    pub meta: ManifestMeta,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileEntry>,
    #[serde(default)]
    pub roles: HashMap<String, RoleEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestMeta {
    pub version: u32,
}

/// A guest profile (e.g., "minimal", "python") mapping to a .nix module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub module: String,
}

/// A role definition (e.g., "gateway", "worker") with its .nix module and drive requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleEntry {
    pub module: String,
    #[serde(default)]
    pub requires_config_drive: bool,
    #[serde(default)]
    pub requires_secrets_drive: bool,
}

impl NixManifest {
    /// Load a manifest from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).with_context(|| "Failed to parse mvm-profiles.toml")
    }

    /// Resolve a role+profile combination to their module paths.
    pub fn resolve(&self, role: &Role, profile: &str) -> Result<ResolvedModules> {
        let role_key = role.to_string();

        let role_entry = self
            .roles
            .get(&role_key)
            .ok_or_else(|| anyhow::anyhow!("Role '{}' not found in manifest", role_key))?;

        let profile_entry = self
            .profiles
            .get(profile)
            .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found in manifest", profile))?;

        Ok(ResolvedModules {
            role_module: role_entry.module.clone(),
            profile_module: profile_entry.module.clone(),
        })
    }

    /// Get drive requirements for a role, if defined.
    pub fn role_requirements(&self, role: &Role) -> Option<&RoleEntry> {
        self.roles.get(&role.to_string())
    }
}

/// Result of resolving a (role, profile) pair.
#[derive(Debug, Clone)]
pub struct ResolvedModules {
    pub role_module: String,
    pub profile_module: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
[meta]
version = 1

[profiles.minimal]
module = "guests/profiles/minimal.nix"

[profiles.python]
module = "guests/profiles/python.nix"

[roles.gateway]
module = "roles/gateway.nix"
requires_config_drive = true
requires_secrets_drive = true

[roles.worker]
module = "roles/worker.nix"
requires_config_drive = false
requires_secrets_drive = true

[roles.builder]
module = "roles/builder.nix"
requires_config_drive = false
requires_secrets_drive = false

[roles.capability-imessage]
module = "roles/capability-imessage.nix"
requires_config_drive = false
requires_secrets_drive = false

"#;

    #[test]
    fn test_parse_roundtrip() {
        let manifest = NixManifest::from_toml(SAMPLE_TOML).unwrap();
        assert_eq!(manifest.meta.version, 1);
        assert_eq!(manifest.profiles.len(), 2);
        assert_eq!(manifest.roles.len(), 4);

        let toml_str = toml::to_string(&manifest).unwrap();
        let reparsed = NixManifest::from_toml(&toml_str).unwrap();
        assert_eq!(reparsed.profiles.len(), 2);
    }

    #[test]
    fn test_resolve_valid() {
        let manifest = NixManifest::from_toml(SAMPLE_TOML).unwrap();
        let resolved = manifest.resolve(&Role::Gateway, "minimal").unwrap();
        assert_eq!(resolved.role_module, "roles/gateway.nix");
        assert_eq!(resolved.profile_module, "guests/profiles/minimal.nix");
    }

    #[test]
    fn test_resolve_worker_python() {
        let manifest = NixManifest::from_toml(SAMPLE_TOML).unwrap();
        let resolved = manifest.resolve(&Role::Worker, "python").unwrap();
        assert_eq!(resolved.role_module, "roles/worker.nix");
        assert_eq!(resolved.profile_module, "guests/profiles/python.nix");
    }

    #[test]
    fn test_resolve_unknown_role() {
        let toml = r#"
[meta]
version = 1

[profiles.minimal]
module = "guests/profiles/minimal.nix"

[roles.worker]
module = "roles/worker.nix"
"#;
        let manifest = NixManifest::from_toml(toml).unwrap();
        let result = manifest.resolve(&Role::Builder, "minimal");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("builder"));
    }

    #[test]
    fn test_resolve_unknown_profile() {
        let manifest = NixManifest::from_toml(SAMPLE_TOML).unwrap();
        let result = manifest.resolve(&Role::Worker, "nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonexistent"));
    }

    #[test]
    fn test_role_requirements_gateway() {
        let manifest = NixManifest::from_toml(SAMPLE_TOML).unwrap();
        let reqs = manifest.role_requirements(&Role::Gateway).unwrap();
        assert!(reqs.requires_config_drive);
        assert!(reqs.requires_secrets_drive);
    }

    #[test]
    fn test_role_requirements_builder() {
        let manifest = NixManifest::from_toml(SAMPLE_TOML).unwrap();
        let reqs = manifest.role_requirements(&Role::Builder).unwrap();
        assert!(!reqs.requires_config_drive);
        assert!(!reqs.requires_secrets_drive);
    }

    #[test]
    fn test_role_requirements_missing() {
        let toml = r#"
[meta]
version = 1
"#;
        let manifest = NixManifest::from_toml(toml).unwrap();
        assert!(manifest.role_requirements(&Role::Worker).is_none());
    }

    #[test]
    fn test_minimal_manifest() {
        let toml = r#"
[meta]
version = 1
"#;
        let manifest = NixManifest::from_toml(toml).unwrap();
        assert_eq!(manifest.meta.version, 1);
        assert!(manifest.profiles.is_empty());
        assert!(manifest.roles.is_empty());
    }
}
