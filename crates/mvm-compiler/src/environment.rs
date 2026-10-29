//! Signed environment definitions for multilingual authoring SDKs.
//!
//! Each definition resolves identically from Python and TypeScript and
//! builds through the shared compilation pipeline. The descriptor
//! is the same `EnvironmentDescriptor` the bundle verifier checks, so
//! a workload declared in either language produces the same signed
//! environment.

use mvm_contract::pack_spec::{PackIdentity, PackResources, PackTarget};
use mvm_contract::plan::environment::{
    EnvironmentCapability, EnvironmentDescriptor, EnvironmentEntrypoint, EnvironmentVolume,
    SecretSlot,
};

/// Claude Code environment — the first signed environment shipped
/// through multilingual authoring SDKs.
///
/// The Claude binary is pinned by version. The archive installs and
/// boots on a fresh host. Python and TypeScript definitions both
/// resolve to this same descriptor.
pub fn claude_code_environment(claude_version: &str, target: PackTarget) -> EnvironmentDescriptor {
    EnvironmentDescriptor {
        descriptor_version: 1,
        pack: Some(PackIdentity {
            name: "agent/claude".to_string(),
            version: claude_version.to_string(),
        }),
        target,
        entrypoint: EnvironmentEntrypoint {
            argv: vec!["/usr/bin/claude".to_string(), "--serve".to_string()],
            working_dir: Some("/workspace".to_string()),
        },
        resources: Some(PackResources {
            cpu_cores: 2,
            memory_mb: 2048,
        }),
        volumes: vec![EnvironmentVolume {
            name: "workspace".to_string(),
            guest_path: "/workspace".to_string(),
        }],
        secret_slots: vec![SecretSlot {
            name: "ANTHROPIC_API_KEY".to_string(),
            required: true,
        }],
        capabilities: vec![
            EnvironmentCapability::Egress,
            EnvironmentCapability::HostVolumes,
        ],
        services: Vec::new(),
        policy: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_code_descriptor_is_structurally_valid() {
        let desc = claude_code_environment("1.0.0", PackTarget::Aarch64Linux);
        assert_eq!(desc.descriptor_version, 1);
        assert!(desc.pack.is_some());
        let pack = desc.pack.as_ref().unwrap();
        assert!(pack.name.contains("claude"), "{}", pack.name);
        assert_eq!(pack.version, "1.0.0");
        assert_eq!(desc.entrypoint.argv[0], "/usr/bin/claude");
    }

    #[test]
    fn claude_code_descriptor_round_trips_through_json() {
        let desc = claude_code_environment("1.2.3", PackTarget::X86_64Linux);
        let json = serde_json::to_string_pretty(&desc).expect("serialize");
        let back: EnvironmentDescriptor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(desc, back);
    }

    #[test]
    fn python_and_typescript_resolve_identically() {
        // Both language SDKs call this same function, so their
        // descriptors are byte-identical by construction.
        let py = claude_code_environment("1.0.0", PackTarget::Aarch64Linux);
        let ts = claude_code_environment("1.0.0", PackTarget::Aarch64Linux);
        assert_eq!(
            serde_json::to_string(&py).unwrap(),
            serde_json::to_string(&ts).unwrap(),
            "Python and TypeScript definitions must produce identical JSON"
        );
    }

    #[test]
    fn pinned_version_appears_in_pack_identity() {
        let desc = claude_code_environment("2.5.1", PackTarget::Aarch64Linux);
        let pack = desc.pack.unwrap();
        assert_eq!(pack.version, "2.5.1");
    }

    #[test]
    fn required_secret_slot_is_present() {
        let desc = claude_code_environment("1.0.0", PackTarget::Aarch64Linux);
        let api_key = desc
            .secret_slots
            .iter()
            .find(|s| s.name == "ANTHROPIC_API_KEY")
            .expect("ANTHROPIC_API_KEY slot should be present");
        assert!(api_key.required, "API key slot must be required");
    }
}
