//! Portable backend capability dimensions and lifecycle protocol DTOs.
//!
//! These types are deliberately separate from the coarse bool matrix in
//! [`VmCapabilities`](super::VmCapabilities) so the browser build can consume
//! the same identity/capability truth without native runtime dependencies.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::{VmId, VmStatus};

// Backend capability dimensions — honest, portable backend identity
// ---------------------------------------------------------------------------

/// What kind of guest environment a backend runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestEnvironment {
    /// Not declared — treat as unknown rather than assuming Linux.
    #[default]
    Unknown,
    /// A real Linux kernel and userspace.
    Linux,
    /// A direct WASI module with no Linux kernel.
    Wasi,
}

/// How the backend executes guest code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuExecution {
    /// Not declared.
    #[default]
    Unknown,
    /// Hardware virtualization (KVM, Hypervisor.framework).
    HardwareVirtualized,
    /// Software emulation inside a host process.
    SoftwareEmulated,
    /// Wasm runtime (browser or host Wasmtime/WAMR).
    WasmNative,
}

/// What isolation boundary sits between the workload and the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationBoundary {
    /// Not declared.
    #[default]
    Unknown,
    /// Hardware-assisted VM boundary.
    HardwareVm,
    /// Browser sandbox / process isolation.
    BrowserSandbox,
    /// Ordinary host process.
    HostProcess,
}

/// How long a VM lifecycle is expected to survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleScope {
    /// Not declared.
    #[default]
    Unknown,
    /// Bound to a single host process (e.g. `WasmBackend` module run).
    Process,
    /// Bound to a browser document / workbench session.
    Document,
    /// Survives as a node-level resource (hardware microVMs).
    DurableNode,
}

/// What attestation tier, if any, the backend can provide for the workload
/// and its boot artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationTier {
    /// Not declared.
    #[default]
    Unknown,
    /// No attestation; claim-free dev/demo tier.
    None,
    /// Attestation derived from builder-signed manifests and digest sidecars.
    BuilderSigned,
    /// Hardware-rooted attestation (TPM, TEE, secure enclave, etc.).
    HardwareRooted,
}

/// Portable, typed backend capability dimensions. These are deliberately
/// separate from the coarse bool matrix in [`VmCapabilities`] so the browser
/// build can consume the same identity/capability truth without native runtime
/// dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BackendCapabilityDimensions {
    pub guest_environment: GuestEnvironment,
    pub cpu_execution: CpuExecution,
    pub isolation_boundary: IsolationBoundary,
    pub lifecycle_scope: LifecycleScope,
    pub attestation_tier: AttestationTier,
}
// ---------------------------------------------------------------------------
// Portable artifact references and lifecycle protocol skeleton
// ---------------------------------------------------------------------------

/// Digest-addressed reference to an immutable artifact at the portable
/// boundary. Host paths, OPFS handles, and JavaScript objects must be resolved
/// below this layer; the shared DTO carries only content identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    /// Content digest, e.g. `sha256:<hex>`.
    pub digest: String,
    /// IANA media type.
    pub media_type: String,
    /// Size in bytes.
    pub size: u64,
}

/// A set of artifacts addressed by manifest digest.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSetRef {
    /// Digest of the signed manifest that lists this set.
    pub manifest_digest: String,
    /// Objects reachable from the manifest.
    pub objects: Vec<ArtifactRef>,
}

/// Versioned backend lifecycle request at the portable boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendRequest {
    /// Start a VM from the given artifact set.
    Start {
        /// Caller-generated id for audit correlation and idempotency.
        request_id: String,
        /// Artifact set describing the runtime pack / workload to boot.
        artifact: ArtifactSetRef,
    },
    /// Stop a running VM.
    Stop { request_id: String, vm_id: VmId },
    /// Query VM status.
    Status { request_id: String, vm_id: VmId },
    /// Retrieve recent log lines.
    Logs {
        request_id: String,
        vm_id: VmId,
        /// Maximum number of lines to return.
        max_lines: u32,
    },
}

/// Versioned backend lifecycle response at the portable boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendResponse {
    /// VM started.
    Started { request_id: String, vm_id: VmId },
    /// VM stopped.
    Stopped { request_id: String, vm_id: VmId },
    /// Current VM status.
    Status {
        request_id: String,
        vm_id: VmId,
        status: VmStatus,
    },
    /// Log lines.
    Logs {
        request_id: String,
        vm_id: VmId,
        lines: Vec<String>,
    },
    /// Operation failed with an actionable reason.
    Failed { request_id: String, reason: String },
}
