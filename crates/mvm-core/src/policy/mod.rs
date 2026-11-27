//! Security policy, audit log, secret bindings and network policy.

pub mod audit;
/// Authored workload policy: profiles, groups, and their composition.
#[cfg(feature = "host-state")]
pub mod authored;
/// Strict DNS answer filtering for SSRF and rebinding defense. Lives in
/// `mvm-contract` so the registry client in `mvm-fs` can share it.
pub use mvm_contract::policy::dns_guard;
/// DNS admission-time pin data model. State-only slice (types +
/// tests, no resolver / no enforcement / no audit emission).
pub mod dns_pin;
pub mod network_policy;
pub mod security_profile;

// `security`, `reversible_replacement`, `policies`, `redaction`, and
// `bundle` are pure-DTO leaves that now live in `mvm-contract`, and
// `projection` is the pure egress-decision core alongside them; re-exported
// here as module aliases so every existing
// `crate::policy::{security,reversible_replacement,policies,redaction,bundle,projection}::X`
// path keeps resolving unchanged.
pub use mvm_contract::policy::{
    action_budget, approval, bundle, policies, projection, protected_paths, redaction, resolver,
    reversible_replacement, security,
};

pub use action_budget::ActionBudget;
pub use bundle::PolicyId;
pub use policies::{
    ArtifactPolicy, AuditPolicy, BundleNetworkPolicy, DEFAULT_BODY_CAP_BYTES, EgressPolicy,
    FlowByteLogDirections, FlowByteLogSpec, FsGrantSpec, KeyPolicy, L4RuleSpec, PiiPolicy,
    WasiCapPolicy,
};
pub use projection::{CanonicalEgress, CanonicalRule, ProjectionError, Proto};
pub use protected_paths::{
    ProtectedPath, ProtectedPathSet, ProtectedPathsMode, ProtectedPathsPolicy,
};
pub use redaction::{
    EntropyMode, NameMode, RedactionAction, RedactionPolicy, RedactionProfile, SecretAction,
};
pub use resolver::EffectivePolicy;
pub use reversible_replacement::{
    OpaqueRewriteToken, ReversibleFallback, ReversibleReplacementAction,
    ReversibleReplacementPolicy, ReversibleReplacementProfile, RewriteFlowId, RewriteProofRecord,
    RewriteSurface, SensitiveClass,
};
