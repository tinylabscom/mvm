//! Workload IR for the mvm toolchain.
//!
//! The data model here is the single source of truth for every downstream
//! artifact: per-language SDK types are generated from the JSON Schema this
//! crate emits; the host toolchain consumes instances of these types to
//! produce Nix flakes and launch plans.
//!
//! Governing ADRs: ADR-0002 (declaration/execution separation), ADR-0003
//! (schema source of truth and SDK conformance model). Field shapes follow
//! Plan-0002 Appendix A.

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
    App, Concurrency, Dependencies, Entrypoint, EnvValue, Format, HostPort, Image, InProcessMode,
    JsonSchemaShape, Mount, MountMode, MountSource, Network, NetworkDns, NetworkEgress,
    NetworkMode, NodeTool, PortForward, PortProto, PythonTool, Resources, SecretMount, SecretRef,
    Source, Volume, WarmProcessConfig, Workload,
};
