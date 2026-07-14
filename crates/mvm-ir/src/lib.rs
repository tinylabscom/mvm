//! Canonical workload IR for the mvm toolchain.
//!
//! The data model here is the single source of truth for downstream SDK type
//! generation and for the host toolchain's compile/admission paths.

pub mod ir;

pub use ir::{
    AddonRef, AddonTier, AddonUse, App, AuthType, Concurrency, Dependencies, Entrypoint, EnvValue,
    ErrorCode, Format, HealthCheck, HookCmd, Hooks, HostPort, IR_MAJOR, IR_MINOR, Image,
    InProcessMode, JsonSchemaShape, MaterializedFile, Mount, MountMode, MountSource, Network,
    NetworkDns, NetworkEgress, NetworkMode, NodeTool, PortForward, PortProto, PythonTool,
    Resources, SecretMount, SecretRef, Sigv4Params, Source, ThreatTier, ValidationError,
    VersionError, Volume, WarmProcessConfig, Workload, canonicalize, host_matches, ir_hash,
    validate, validate_schema_version,
};
