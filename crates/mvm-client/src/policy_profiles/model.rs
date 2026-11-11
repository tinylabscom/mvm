//! Host-side schema emission for the shared authored policy contract.

pub use mvm_contract::policy::authored::{
    EnvSection, GroupFile, GroupSelection, HostArch, HostOs, NetworkSection, OneOrMany, PolicyBody,
    ProfileFile, ResourcesSection, SecretGrant, SecretsSection, ShareGrant, SharesSection,
    WhenBlock,
};

/// The authored-policy documents' JSON Schemas, keyed by document kind.
#[cfg(feature = "schema")]
#[must_use]
pub fn json_schema_pretty() -> String {
    /// One root naming every document kind, so shared definitions are
    /// emitted once.
    #[derive(schemars::JsonSchema)]
    struct PolicyDocuments {
        #[schemars(rename = "profile")]
        _profile: ProfileFile,
        #[schemars(rename = "group")]
        _group: GroupFile,
        #[schemars(rename = "resolved_manifest")]
        _resolved_manifest: super::manifest::ResolvedManifest,
    }
    let schema = schemars::schema_for!(PolicyDocuments);
    serde_json::to_string_pretty(&schema).expect("a JSON Schema always serializes")
}

/// Where the committed schema lives, relative to the workspace root.
pub const SCHEMA_PATH: &str = "schema/policy-profiles-v0.json";
