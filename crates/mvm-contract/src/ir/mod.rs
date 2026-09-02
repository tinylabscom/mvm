//! Workload IR for the mvm toolchain.
//!
//! The data model here is the single source of truth for every downstream
//! artifact: per-language SDK types are generated from the JSON Schema this
//! crate emits; the host toolchain consumes instances of these types to
//! produce Nix flakes and launch plans.
//!
//! Two invariants govern the shape: declaration and execution stay separate,
//! and the JSON Schema emitted here is the single source of truth that every
//! per-language SDK conforms to.

mod addon;
mod canonicalize;
mod data;
mod error_codes;
mod hash;
mod hooks;
mod validate;
mod version;
mod workload;

pub use addon::{AddonRef, AddonTier, AddonUse, ThreatTier};
pub use canonicalize::canonicalize;
pub use error_codes::ErrorCode;
pub use hash::ir_hash;
pub use hooks::{HookCmd, Hooks};
pub use validate::{ValidationError, validate};
pub use version::{IR_MAJOR, IR_MINOR, VersionError, validate_schema_version};
pub use workload::{
    App, AuthType, Concurrency, Dependencies, Entrypoint, EnvValue, Format, HealthCheck, HostPort,
    Image, InProcessMode, JsonSchemaShape, MaterializedFile, Mount, MountMode, MountSource,
    Network, NetworkDns, NetworkEgress, NetworkMode, NodeTool, PortForward, PortProto,
    PortTransform, PythonTool, Resources, SecretMount, SecretRef, Sigv4Params, Source, Volume,
    WarmProcessConfig, Workload, host_is_bound, host_matches,
};
