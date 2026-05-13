//! Addon types for the workload IR (ADR-0018 / schema 0.2+).
//!
//! An addon is a sha-attested, parameterized service definition another
//! developer publishes. Consumers reference addons via `App.addons`; mvmd
//! instantiates each addon-use as a separate microVM and bridges it to the
//! consumer over the workload mesh (ADR-0020).
//!
//! The shape here is the *consumer-side* IR slice. Author-side concerns
//! (manifest schema `addon.toml`, registry API, lockfile) live in
//! `crates/mvm-sdk-addon`.

use crate::hooks::Hooks;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One use of an addon by the consuming app.
///
/// The triple `(name, ref, sha256)` uniquely identifies the addon
/// artifact; `alias` disambiguates env-var prefixes when the same addon
/// is used multiple times. `params` are validated against the manifest's
/// `[[addon.params]]` table at compile time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddonUse {
    /// Bare addon name (matches the manifest's `[addon].name`). Pattern
    /// `^[a-z][a-z0-9-]{1,63}$`. Reserved names (`core`, `mvm`,
    /// `mvm`, `mvmd`) blocked at the registry side.
    pub name: String,

    /// Optional alias. When present, every env var the addon exports is
    /// prefixed `<ALIAS_UPPER>_` verbatim (per ADR-0018). When absent,
    /// exports use their bare names. Two `AddonUse`s with the same
    /// `name` must use distinct aliases (validated mvm-side).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,

    /// Composition tier — currently only `Separate` (a separate
    /// addon-microVM bridged via the mesh). `InVm` is reserved by
    /// `specs/plans/0012-in-vm-addon-tier.md` and rejected by
    /// `validate.rs` until that plan lands.
    pub tier: AddonTier,

    /// Pointer to the addon's published artifact. Either a registry
    /// reference (`Registry { url, version }`) or a local-path reference
    /// (`Local { path }`) for development. Local-path uses are gated:
    /// `mvm addon publish` rejects a workload that contains any.
    pub r#ref: AddonRef,

    /// sha256 of the canonical-form addon artifact. Matches the
    /// `sha256` in `mvm.lock` for the resolved version. Verified
    /// at compile time against the cached artifact bytes (no network).
    pub sha256: String,

    /// Param values the consumer passes to the addon. Keys must match a
    /// `[[addon.params]]` entry in the manifest at the resolved
    /// version; values must match the declared `type` (validated at
    /// `addon::resolve_and_validate` time).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, serde_json::Value>,
    /// Hooks bundled by this addon (SDK port Phase 1a — IR field
    /// reserved; consumers in Phase 10). The compiler concatenates each
    /// addon's hook vecs in attachment order, then appends the
    /// consuming app's own hooks. Empty `Hooks` is the default and is
    /// skip-serialized so v0 addon-use entries stay byte-identical.
    #[serde(default, skip_serializing_if = "Hooks::is_empty")]
    pub hooks: Hooks,
}

/// Addon composition tier.
///
/// `Separate` is the v1 shape — the addon runs as its own microVM and
/// the consumer reaches it over the mesh. `InVm` is reserved for the
/// future in-VM addon tier where small Nix fragments compose directly
/// into the consumer's `mkGuest` flake (see
/// `specs/plans/0012-in-vm-addon-tier.md`); it is rejected by the
/// validator with `E_ADDON_TIER_NOT_IMPLEMENTED` until that plan lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddonTier {
    Separate,
    InVm,
}

/// Resolution kind for an addon — registry-published or local-path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AddonRef {
    /// Registry-resolved addon. `url` is the canonical registry URL
    /// (e.g. `addons.mvm.io/postgres`); `version` is the SemVer
    /// the consumer locked against.
    Registry { url: String, version: String },
    /// Local-path addon (development). Path is relative to the
    /// workload manifest. `mvm compile` re-hashes the directory
    /// and rejects on `content_sha256` drift; `mvm addon publish`
    /// rejects any workload that includes a local-path use.
    Local { path: String },
}

/// Threat-tier label on the *consumer* (App). Combines with the addon's
/// `[security].trust_tier` to drive mvmd's SMT-affinity scheduler matrix
/// per ADR-0018 §"Trust-tier labeling and SMT-affinity policy".
///
/// Defaults to `Untrusted` (most protective). Workloads that run only
/// first-party reviewed code can opt into `Trusted` for finer packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreatTier {
    /// Runs user-provided / sandboxed code. Default. Forces strictest
    /// scheduler isolation against High-trust addons.
    #[default]
    Untrusted,
    /// First-party app code reviewed by the workload owner. Allows
    /// finer packing in mvmd's scheduler matrix.
    Trusted,
}

impl ThreatTier {
    /// Whether this is the default variant. Used by `App`'s
    /// `skip_serializing_if` so legacy IR (no threat_tier) stays
    /// byte-identical after this field was added.
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Untrusted)
    }
}
