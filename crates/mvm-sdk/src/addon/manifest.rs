//! `addon.toml` manifest schema.
//!
//! Authoritative shape. The generated `schema/addon-manifest-v0.json`
//! is emitted from these types via `schemars` and committed; CI rejects
//! drift. SDK lower layers (`sdks/python/mvm/_addon/`,
//! `sdks/typescript/src/addon/`) are generated from the JSON Schema
//! and committed as well.
//!
//! Round-trip discipline: a manifest parsed and re-serialized via
//! `mvm_ir::canonicalize` must produce the registry's canonical
//! bytes. The signature payload is over those canonical bytes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Top-level manifest. Stored as `addon.toml` in the addon's root
/// directory alongside the inner workload definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddonManifest {
    /// Schema version of the manifest itself. Mirrors workload IR's
    /// `schema_version` discipline so manifest-schema evolution doesn't
    /// break older addons. `"0"` at v1.
    pub manifest_version: String,
    /// Addon-level metadata + composition policy.
    pub addon: AddonSection,
    /// Security posture defaults (trust tier, seccomp profile).
    #[serde(default)]
    pub security: SecuritySection,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddonSection {
    /// Addon name. Pattern `^[a-z][a-z0-9-]{1,63}$`. Reserved names
    /// (`core`, `mvm`, `mvmd`) are blocked at the registry.
    pub name: String,
    /// SemVer 2.0.0 version string.
    pub version: String,
    /// Short human-readable description; <= 200 chars.
    pub description: String,
    /// Composition tier. v1 only `"separate"` is valid; `"in_vm"` is
    /// reserved for the in-VM addon tier (future plan).
    pub tier: ManifestTier,
    /// Persistent storage requested by the addon-instance (gibibytes).
    /// Allocated by mvmd at instantiation. Default 0 (ephemeral).
    #[serde(default)]
    pub persistent_storage_gb: u32,
    /// Network egress allowlist (deny-default). Each entry is
    /// `host:port`. Empty = no egress. Wildcards rejected.
    #[serde(default)]
    pub egress_allowlist: Vec<String>,
    /// SLSA-style provenance attestation pointer. Optional v1; becomes
    /// required for community-tier addons (future plan).
    #[serde(default)]
    pub provenance_url: String,
    /// Graceful-shutdown drain window in seconds. Bounded [0, 300];
    /// default 30. mvmd applies SIGTERM, waits, then SIGKILL.
    #[serde(default = "default_graceful_shutdown_seconds")]
    pub graceful_shutdown_seconds: u32,
    /// Parameters the addon accepts. Validated against consumer-side
    /// `AddonUse.params` at lockfile time and at compile time.
    #[serde(default)]
    pub params: Vec<AddonParam>,
    /// Service exports the addon provides. At least one required.
    pub exports: Vec<AddonExport>,
}

fn default_graceful_shutdown_seconds() -> u32 {
    30
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManifestTier {
    Separate,
    InVm,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddonParam {
    /// Parameter name. ASCII identifier matching `^[a-z][a-z0-9_]*$`.
    pub name: String,
    /// Parameter type. Closed enum: string / integer / boolean.
    pub r#type: AddonParamType,
    /// Default value. JSON-shaped; type must match `type`.
    pub default: serde_json::Value,
    /// Optional enum constraint for string params.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#enum: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddonParamType {
    String,
    Integer,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddonExport {
    /// Logical name within this addon. Unique per manifest.
    pub logical_name: String,
    /// Canonical protocol identifier (e.g. `postgres`, `redis`,
    /// `http`, `mqtt`). Drives credential-format selection.
    pub protocol: String,
    /// Default port the addon listens on inside its microVM.
    /// 1..=65535.
    pub default_port: u16,
    /// ASCII env var name mvmd injects into the consumer with the
    /// rendered connection string. Aliasing prefixes apply.
    pub env_var: String,
    /// Optional file path inside the consumer's microVM where mvmd
    /// writes the credential as a 0400 file (recommended over env-var
    /// delivery; reduces `/proc/<pid>/environ` exposure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_path: Option<String>,
    /// How credentials are produced.
    pub credentials: CredentialsKind,
    /// Canonical credential format per protocol (e.g.
    /// `scram-sha-256` for postgres). Required when
    /// `credentials = "generated"`. mvmd validates the addon image
    /// supports the declared format at publish/contract-test time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_format: Option<String>,
    /// Credential TTL in hours. mvmd auto-rotates at expiry.
    /// Default 24.
    #[serde(default = "default_credential_ttl_hours")]
    pub credential_ttl_hours: u32,
}

fn default_credential_ttl_hours() -> u32 {
    24
}

/// How credentials are produced.
///
/// `#[non_exhaustive]` is the forward-compat hook: future variants
/// (`Static` — manifest-shipped credentials, publish-time secret
/// hazard; `UserSupplied` — consumer passes the value as a param) can
/// be added in a non-breaking minor release. Today only `Generated`
/// is shipped; the registry rejects manifests that try to use any
/// other variant at publish time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialsKind {
    /// mvmd generates credentials per `credential_format` at instance
    /// start; rotates per `credential_ttl_hours`.
    Generated,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecuritySection {
    /// Trust tier — drives mvmd's SMT-affinity scheduler matrix.
    /// Default `high` (most protective; addon co-located with consumer
    /// requires separate physical cores when consumer is `untrusted`).
    #[serde(default)]
    pub trust_tier: TrustTier,
    /// Seccomp profile applied to the addon-instance microVM.
    /// `strict` (default) | `moderate`. `permissive` is rejected for
    /// the official namespace (`E_ADDON_SECCOMP_PROFILE_DENIED`).
    #[serde(default)]
    pub seccomp_profile: SeccompProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Holds secrets at rest (DB passwords, encryption keys, customer
    /// PII). Default. Forces strict scheduler isolation against
    /// untrusted consumers.
    #[default]
    High,
    /// Handles user data but doesn't aggregate secrets (caches, queues
    /// with TTL'd tokens).
    Medium,
    /// Ephemeral, non-secret-handling (stateless transformers, log
    /// shippers). Packs freely.
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SeccompProfile {
    /// Strictest profile (default). Maps onto `mvm-security`'s
    /// existing `SecurityProfile::Strict` enum.
    #[default]
    Strict,
    /// Looser profile. Allowed for non-official namespaces; in the
    /// official namespace, requires audit-trail justification at
    /// publish time.
    Moderate,
    /// Permissive. **Rejected** for the official namespace
    /// (`E_ADDON_SECCOMP_PROFILE_DENIED`); allowed only in
    /// development / private namespaces.
    Permissive,
}

/// Parse an `addon.toml` from a string. Returns a [`ParseError`] with
/// the underlying TOML error preserved for diagnostic surfaces.
pub fn parse(s: &str) -> Result<AddonManifest, ParseError> {
    toml::from_str(s).map_err(ParseError::Toml)
}

/// Serialize a manifest back to TOML. Output is deterministic given
/// the input (the canonical-bytes guarantee is established by routing
/// the parsed value through `mvm_ir::canonicalize` at the
/// registry/lockfile boundary).
pub fn to_toml(manifest: &AddonManifest) -> Result<String, ParseError> {
    toml::to_string_pretty(manifest).map_err(ParseError::Serialize)
}

#[derive(Debug)]
pub enum ParseError {
    Toml(toml::de::Error),
    Serialize(toml::ser::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Toml(e) => write!(f, "addon.toml parse error: {e}"),
            Self::Serialize(e) => write!(f, "addon.toml serialize error: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest_toml() -> &'static str {
        r#"
manifest_version = "0"

[addon]
name = "postgres"
version = "16.1.0"
description = "Postgres 16 with pgvector"
tier = "separate"
persistent_storage_gb = 10

[[addon.params]]
name = "version"
type = "string"
default = "16"

[[addon.exports]]
logical_name = "main"
protocol = "postgres"
default_port = 5432
env_var = "DATABASE_URL"
credentials_path = "/run/secrets/database_url"
credentials = "generated"
credential_format = "scram-sha-256"
"#
    }

    #[test]
    fn parses_minimal_manifest() {
        let manifest = parse(sample_manifest_toml()).expect("parse");
        assert_eq!(manifest.manifest_version, "0");
        assert_eq!(manifest.addon.name, "postgres");
        assert_eq!(manifest.addon.version, "16.1.0");
        assert!(matches!(manifest.addon.tier, ManifestTier::Separate));
        assert_eq!(manifest.addon.persistent_storage_gb, 10);
        assert_eq!(manifest.addon.graceful_shutdown_seconds, 30);
        assert_eq!(manifest.security.trust_tier, TrustTier::High);
        assert_eq!(manifest.security.seccomp_profile, SeccompProfile::Strict);

        let export = &manifest.addon.exports[0];
        assert_eq!(export.logical_name, "main");
        assert_eq!(export.protocol, "postgres");
        assert_eq!(export.default_port, 5432);
        assert_eq!(export.env_var, "DATABASE_URL");
        assert_eq!(
            export.credentials_path.as_deref(),
            Some("/run/secrets/database_url")
        );
        assert!(matches!(export.credentials, CredentialsKind::Generated));
        assert_eq!(export.credential_ttl_hours, 24);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let bad = format!("{}\nbogus = true\n", sample_manifest_toml());
        let err = parse(&bad).unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }

    #[test]
    fn round_trips_through_toml() {
        let parsed = parse(sample_manifest_toml()).expect("parse");
        let emitted = to_toml(&parsed).expect("serialize");
        let reparsed = parse(&emitted).expect("re-parse");
        assert_eq!(parsed, reparsed);
    }
}
