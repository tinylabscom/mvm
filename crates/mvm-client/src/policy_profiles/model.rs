//! The authored policy documents, exactly as written.
//!
//! Three shapes, all TOML, all `deny_unknown_fields` so a misspelt key is an
//! error rather than a silently absent restriction:
//!
//! - a **group** ([`GroupFile`]): a named, reusable fragment of policy;
//! - a **profile** ([`ProfileFile`]): `extends`, `groups.include/exclude`,
//!   `[[when]]` platform blocks, and `[overrides]`;
//! - the **body** ([`PolicyBody`]) both of them carry, which is also what a
//!   resolved policy is expressed in.

use std::collections::BTreeMap;

use mvm_contract::policy::routes::EgressRoute;
use mvm_contract::protocol::vm_backend::BackendKind;
use serde::{Deserialize, Serialize};

/// The policy dimensions a group, a profile's overrides, or a `[[when]]`
/// block may speak to. Every section is optional; an absent one says nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PolicyBody {
    /// Outbound network.
    #[serde(default, skip_serializing_if = "NetworkSection::is_empty")]
    pub network: NetworkSection,
    /// Stored secrets the workload may use, and where.
    #[serde(default, skip_serializing_if = "SecretsSection::is_empty")]
    pub secrets: SecretsSection,
    /// Host directories copied into the guest.
    #[serde(default, skip_serializing_if = "SharesSection::is_empty")]
    pub shares: SharesSection,
    /// Environment variables the workload may be handed.
    #[serde(default, skip_serializing_if = "EnvSection::is_empty")]
    pub env: EnvSection,
    /// Per-tool privileges. Recorded, not yet enforced.
    #[serde(default, skip_serializing_if = "ToolsSection::is_empty")]
    pub tools: ToolsSection,
    /// Resource bounds.
    #[serde(default, skip_serializing_if = "ResourcesSection::is_empty")]
    pub resources: ResourcesSection,
}

impl PolicyBody {
    /// Whether no section says anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.network.is_empty()
            && self.secrets.is_empty()
            && self.shares.is_empty()
            && self.env.is_empty()
            && self.tools.is_empty()
            && self.resources.is_empty()
    }
}

/// `[network]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NetworkSection {
    /// Destinations as `HOST[:PORT]`, port defaulting to 443.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Destinations refused whatever allows them: `HOST[:PORT]` or
    /// `*.suffix`. A deny without a port matches every port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// `true` turns all egress off. Once any layer sets it, no later layer
    /// can turn it back on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<bool>,
    /// Endpoint routes (method and path rules at a destination).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<EgressRoute>,
}

impl NetworkSection {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
            && self.deny.is_empty()
            && self.block.is_none()
            && self.routes.is_empty()
    }
}

/// `[secrets]`.
// allow(secret-debug): secret names and destination hosts only; the schema has no field a value can occupy
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SecretsSection {
    /// Stored secrets (`mvmctl secret set`) to bind, by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bind: Vec<SecretGrant>,
    /// Secret names refused whatever binds them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

impl SecretsSection {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bind.is_empty() && self.deny.is_empty()
    }
}

/// One `[[secrets.bind]]` entry.
// allow(secret-debug): secret names and destination hosts only; the schema has no field a value can occupy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SecretGrant {
    /// The stored secret's name.
    pub name: String,
    /// Hosts the credential may be sent to. Empty keeps the stored
    /// allow-list whole; a list may only narrow it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

/// `[shares]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SharesSection {
    /// Host directories to copy into the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mount: Vec<ShareGrant>,
    /// Host path prefixes no share may come from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

impl SharesSection {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mount.is_empty() && self.deny.is_empty()
    }
}

/// One `[[shares.mount]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ShareGrant {
    /// Host directory. Relative paths resolve against the file declaring it.
    pub host: String,
    /// Absolute guest mount point.
    pub guest: String,
    /// Writable inside the guest (default read-only). Two layers naming the
    /// same share resolve to read-only unless both ask for writable.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub writable: bool,
}

/// `[env]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EnvSection {
    /// Exact variable names the workload may be handed. When any layer
    /// declares an allow-list, an `--env` outside it is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Exact variable names refused whatever allows them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Re-admit variables the built-in hygiene denylist refuses (loader,
    /// shell, interpreter, password-manager session variables). An escape
    /// hatch: honoured only in a user-authored profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readmit: Vec<String>,
}

impl EnvSection {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && self.readmit.is_empty()
    }
}

/// `[tools]` — per-tool privileges. Parsed, merged and shown so profiles can
/// be written ahead of enforcement; nothing enforces it yet, and
/// `mvmctl policy validate --strict` refuses a policy that relies on it.
///
/// Composition only narrows. Whole-tool lists union (`deny` beats `ask`
/// beats `allow`); per-tool detail is first-defined-then-narrowed: a later
/// layer may repeat or restrict the `argv`, `routes` and `secrets` an
/// earlier layer set for a tool, never extend them, and `deny` argv
/// patterns union.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ToolsSection {
    /// Tool names allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Tool names where every call asks the runtime approver first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<String>,
    /// Tool names refused whatever allows them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Per-tool argv, route and secret restrictions, keyed by tool name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub detail: BTreeMap<String, ToolDetail>,
}

impl ToolsSection {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
            && self.ask.is_empty()
            && self.deny.is_empty()
            && self.detail.is_empty()
    }
}

/// Per-tool detail under `[tools.detail.<name>]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ToolDetail {
    /// Argv patterns permitted for this tool, glob-style and matched against
    /// the command line (`git *`). An empty list means any argv the tool is
    /// invoked with. Composition narrows: a later layer may only name
    /// patterns an earlier layer set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// Argv patterns refused whatever `argv` allows. Unions across layers
    /// and beats `argv` on conflict.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Destinations (`HOST[:PORT]`) this tool may reach through the one host
    /// egress gate. Composition narrows like secret destinations: a later
    /// layer may list a subset, never a destination outside them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    /// Secret names bound to this tool; the binding is enforced where the
    /// secret is substituted. Composition narrows like `routes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
}

/// `[resources]` — bounds. Every value is a ceiling: across layers the
/// smallest wins, so no layer can raise one another set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ResourcesSection {
    /// Share of host CPU time in thousandths of a core (`--cpu-limit`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millicores: Option<u32>,
    /// Wall-clock bound in seconds (`--timeout`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_secs: Option<u32>,
    /// Most vCPUs a run may ask for (`--cpus`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpus: Option<u32>,
    /// Most guest memory a run may ask for, e.g. `2G` (`--memory`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory: Option<String>,
}

impl ResourcesSection {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cpu_millicores.is_none()
            && self.wall_clock_secs.is_none()
            && self.max_cpus.is_none()
            && self.max_memory.is_none()
    }
}

/// A policy group file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct GroupFile {
    /// What the group is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Once included, no profile below may exclude it.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "NetworkSection::is_empty")]
    pub network: NetworkSection,
    #[serde(default, skip_serializing_if = "SecretsSection::is_empty")]
    pub secrets: SecretsSection,
    #[serde(default, skip_serializing_if = "SharesSection::is_empty")]
    pub shares: SharesSection,
    #[serde(default, skip_serializing_if = "EnvSection::is_empty")]
    pub env: EnvSection,
    #[serde(default, skip_serializing_if = "ToolsSection::is_empty")]
    pub tools: ToolsSection,
    #[serde(default, skip_serializing_if = "ResourcesSection::is_empty")]
    pub resources: ResourcesSection,
}

impl GroupFile {
    /// The policy the group contributes.
    #[must_use]
    pub fn body(&self) -> PolicyBody {
        PolicyBody {
            network: self.network.clone(),
            secrets: self.secrets.clone(),
            shares: self.shares.clone(),
            env: self.env.clone(),
            tools: self.tools.clone(),
            resources: self.resources.clone(),
        }
    }
}

/// One name or several.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        OneOrMany::Many(Vec::new())
    }
}

impl<T: Clone> OneOrMany<T> {
    /// Every value, in order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            OneOrMany::One(value) => vec![value.clone()],
            OneOrMany::Many(values) => values.clone(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        matches!(self, OneOrMany::Many(values) if values.is_empty())
    }
}

/// `[groups]` in a profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct GroupSelection {
    /// Groups to add, by name or path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    /// Groups a parent included, to drop. A required group cannot be dropped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

impl GroupSelection {
    fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }
}

/// Host operating systems a `[[when]]` block can match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum HostOs {
    Linux,
    Macos,
}

impl HostOs {
    /// The operating system this binary runs on, when it is one a policy can
    /// name.
    #[must_use]
    pub fn current() -> Option<Self> {
        match std::env::consts::OS {
            "linux" => Some(HostOs::Linux),
            "macos" => Some(HostOs::Macos),
            _ => None,
        }
    }
}

/// Host architectures a `[[when]]` block can match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum HostArch {
    X86_64,
    Aarch64,
}

impl HostArch {
    /// The architecture this binary runs on, when it is one a policy can name.
    #[must_use]
    pub fn current() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(HostArch::X86_64),
            "aarch64" => Some(HostArch::Aarch64),
            _ => None,
        }
    }
}

/// A `[[when]]` block: groups and overrides that apply only on matching
/// platforms. Each listed predicate must match (any of its values); an
/// omitted predicate matches everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct WhenBlock {
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub os: OneOrMany<HostOs>,
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub arch: OneOrMany<HostArch>,
    /// The backend the run boots on: `--hypervisor`, or the host's default.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub backend: OneOrMany<BackendKind>,
    /// Groups to add when matched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    /// Groups to drop when matched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    /// Policy applied when matched.
    #[serde(default, skip_serializing_if = "PolicyBody::is_empty")]
    pub overrides: PolicyBody,
}

/// A policy profile file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProfileFile {
    /// What the profile is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Profiles this one builds on, by name or path, applied in order.
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub extends: OneOrMany<String>,
    /// Groups to add and drop.
    #[serde(default, skip_serializing_if = "GroupSelection::is_empty")]
    pub groups: GroupSelection,
    /// Platform-conditional groups and overrides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<WhenBlock>,
    /// This profile's own policy, applied after its groups.
    #[serde(default, skip_serializing_if = "PolicyBody::is_empty")]
    pub overrides: PolicyBody,
}

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
