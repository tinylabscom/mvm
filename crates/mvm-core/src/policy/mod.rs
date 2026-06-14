//! Security policy, audit log, secret bindings, network policy, plus
//! the tenant policy-bundle authoring/resolution/signing surface folded
//! in from the former `mvm-policy` crate.

pub mod audit;
/// DNS admission-time pin data model. State-only slice (types +
/// tests, no resolver / no enforcement / no audit emission).
pub mod dns_pin;
pub mod network_policy;
pub mod secret_binding;
pub mod security;

// Tenant policy bundles — authoring, resolution, signing, TOML loading.
// Folded in from the former `mvm-policy` crate. mvmd consumes the
// resolver + bundle types via the facade.
pub mod bundle;
pub mod policies;
pub mod projection;
pub mod projection_fs_env;
pub mod redaction;
pub mod resolver;
pub mod signing;
pub mod toml_loader;

pub use bundle::{PolicyBundle, PolicyId, SCHEMA_VERSION, TenantOverlay};
pub use policies::{
    ArtifactPolicy, AuditPolicy, DEFAULT_BODY_CAP_BYTES, EgressPolicy, FlowByteLogDirections,
    FlowByteLogSpec, FsGrantSpec, KeyPolicy, L4RuleSpec, NetworkPolicy, PiiPolicy, ToolPolicy,
    WasiCapPolicy,
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
pub use signing::{BundleVerifyError, SignedPolicyBundle, sign_bundle, verify_bundle};
