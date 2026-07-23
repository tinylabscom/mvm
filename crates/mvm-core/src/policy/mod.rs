//! Security policy, audit log, secret bindings, network policy, plus
//! the tenant policy-bundle authoring/resolution/signing surface folded
//! in from the former `mvm-policy` crate.

pub mod audit;
/// Strict DNS answer filtering for SSRF and rebinding defense.
pub mod dns_guard;
/// DNS admission-time pin data model. State-only slice (types +
/// tests, no resolver / no enforcement / no audit emission).
pub mod dns_pin;
pub mod network_policy;
pub mod secret_binding;
pub mod security_profile;

// Tenant policy bundles — authoring, resolution, signing, TOML loading.
// Folded in from the former `mvm-policy` crate. mvmd consumes the
// resolver + bundle types via the facade.
pub mod projection;
pub mod projection_fs_env;
pub mod resolver;
pub mod signing;
pub mod toml_loader;

// `security`, `reversible_replacement`, `policies`, `redaction`, and
// `bundle` are pure-DTO leaves that now live in `mvm-protocol`; re-exported
// here as module aliases so every existing
// `crate::policy::{security,reversible_replacement,policies,redaction,bundle}::X`
// path keeps resolving unchanged.
pub use mvm_protocol::policy::{bundle, policies, redaction, reversible_replacement, security};

pub use bundle::{PolicyBundle, PolicyId, SCHEMA_VERSION, TenantOverlay};
pub use policies::{
    ArtifactPolicy, AuditPolicy, BundleNetworkPolicy, DEFAULT_BODY_CAP_BYTES, EgressPolicy,
    FlowByteLogDirections, FlowByteLogSpec, FsGrantSpec, KeyPolicy, L4RuleSpec, PiiPolicy,
    ToolPolicy, WasiCapPolicy,
};
pub use projection::{
    CanonicalEgress, CanonicalRule, ProjectionError, Proto, WasiEgress, WasiOutboundGrant,
    WasiTarget, canonicalize_effective, canonicalize_l4, clamp, to_wasi_grants, wasi_allows,
};
pub use projection_fs_env::{
    CanonicalEnv, CanonicalFs, FsAccess, FsEnvError, FsGrant, WasiPreopen, canonicalize_env,
    canonicalize_fs, clamp_env, clamp_fs, to_wasi_env_names, to_wasi_preopens,
};
pub use redaction::{
    EntropyMode, NameMode, RedactionAction, RedactionPolicy, RedactionProfile, SecretAction,
};
pub use resolver::{EffectivePolicy, EmergencyDeny, resolve};
pub use reversible_replacement::{
    OpaqueRewriteToken, ReversibleFallback, ReversibleReplacementAction,
    ReversibleReplacementPolicy, ReversibleReplacementProfile, RewriteFlowId, RewriteProofRecord,
    RewriteSurface, SensitiveClass,
};
pub use signing::{BundleVerifyError, SignedPolicyBundle, sign_bundle, verify_bundle};
