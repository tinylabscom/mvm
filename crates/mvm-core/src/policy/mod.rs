//! Security policy, audit log, secret bindings, network policy, plus
//! the tenant policy-bundle authoring/resolution/signing surface folded
//! in from the former `mvm-policy` crate (plan 121 B2).

pub mod audit;
/// Plan 74 W2 / mvmd ADR 0022 §"Layer 3 — DNS pinning" — DNS
/// admission-time pin data model. State-only slice (types +
/// tests, no resolver / no enforcement / no audit emission).
pub mod dns_pin;
pub mod network_policy;
pub mod secret_binding;
pub mod security;

// Tenant policy bundles — authoring, resolution, signing, TOML loading.
// Folded in from the former `mvm-policy` crate (plan 121 B2). mvmd
// consumes the resolver + bundle types via the facade.
pub mod bundle;
pub mod policies;
pub mod redaction;
pub mod resolver;
pub mod signing;
pub mod toml_loader;

pub use bundle::{PolicyBundle, PolicyId, SCHEMA_VERSION, TenantOverlay};
pub use policies::{
    ArtifactPolicy, AuditPolicy, DEFAULT_BODY_CAP_BYTES, EgressPolicy, FlowByteLogDirections,
    FlowByteLogSpec, KeyPolicy, L4RuleSpec, NetworkPolicy, PiiPolicy, ToolPolicy,
};
pub use redaction::{
    EntropyMode, NameMode, RedactionAction, RedactionPolicy, RedactionProfile, SecretAction,
};
pub use resolver::{EffectivePolicy, EmergencyDeny, resolve};
pub use signing::{BundleVerifyError, SignedPolicyBundle, sign_bundle, verify_bundle};
