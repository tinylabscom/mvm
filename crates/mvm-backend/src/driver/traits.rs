//! The `VmmDriver` seam: pure VMM mechanics, written once per VMM. Role policy
//! (workload admission/egress/audit, builder orchestration) lives in the role
//! runners above this trait, never here. The driver carries no workload
//! permission and never sees an admitted plan — it boots what the spec
//! describes and nothing more.

use anyhow::Result;
use mvm_core::vm_backend::{SnapshotCapability, VmCapabilities, VmExitStatus, VmId, VmStatus};

use crate::driver::spec::VmmSpec;

/// A bidirectional, owned guest channel (a connected vsock stream).
pub trait DuplexStream: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send> DuplexStream for T {}

/// VMM mechanics, written once per VMM.
pub trait VmmDriver: Send + Sync {
    /// Stable backend token (`"libkrun"`, `"vz"`, `"firecracker"`, `"in-house"`, `"mock"`).
    fn name(&self) -> &str;
    /// Whether this VMM can run on the current host.
    fn is_available(&self) -> Result<bool>;
    /// Coarse capability flags.
    fn capabilities(&self) -> VmCapabilities;
    /// Honest warm-start tier.
    fn snapshot_capability(&self) -> SnapshotCapability;
    /// Boot the VM described by `spec`, returning a live handle.
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>>;
}

/// A live VM handle. Launch-model-agnostic: an in-process VMM, a subprocess,
/// and an external supervisor all present the same surface.
pub trait RunningVm: Send {
    fn id(&self) -> &VmId;
    /// Block until the VM exits; returns its status.
    fn wait(&self) -> Result<VmExitStatus>;
    /// Force-terminate the VM.
    fn kill(&self) -> Result<()>;
    fn pause(&self) -> Result<()>;
    fn resume(&self) -> Result<()>;
    fn status(&self) -> Result<VmStatus>;
    /// Open a host->guest vsock connection to `guest_port`.
    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>>;
}
