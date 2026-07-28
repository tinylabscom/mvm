//! The `VmmDriver` seam: pure VMM mechanics, written once per VMM. Role policy
//! (workload admission/egress/audit, builder orchestration) lives in the role
//! runners above this trait, never here. The driver carries no workload
//! permission and never sees an admitted plan — it boots what the spec
//! describes and nothing more.

use std::path::Path;

use anyhow::Result;
use mvm_core::crypto::vmgenid::{GENID_BYTES, GenerationToken};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, GuestChannelInfo, SnapshotCapability, StandbyError,
    StandbyHandle, StandbySpec, VmCapabilities, VmExitStatus, VmId, VmStatus,
};

use crate::driver::spec::VmmSpec;
use crate::vm::instance_snapshot::PostRestoreOutcome;

/// What a driver needs to fork a materialized standby parent into a fresh child
/// VMM. Grouped so the seam takes one value instead of a positional list.
pub struct ChildForkRequest<'a> {
    /// The child's fresh, registry-unique name (its `~/.mvm/vms/<name>` key).
    pub child_vm_name: &'a str,
    /// The child's state dir, already holding the copy-on-write clone of the
    /// verified parent's own content.
    pub child_dir: &'a Path,
    /// Fresh VMGenID token, bound to the child's content-address, that the
    /// child must adopt so its CSPRNG diverges from the parent's.
    ///
    /// A fork restores a *running* guest out of saved memory rather than
    /// booting one, so there is no boot to hand the token to: the fork brings
    /// the child up carrying the parent's random state, and the role layer
    /// above closes that window by delivering this token over vsock through
    /// [`VmmDriver::deliver_child_identity`] before the claim is admissible.
    /// The request carries it so both halves read the same value.
    pub genid: GenerationToken,
}

/// A bidirectional, owned guest channel (a connected vsock stream).
pub trait DuplexStream: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send> DuplexStream for T {}

/// VMM mechanics, written once per VMM.
pub trait VmmDriver: Send + Sync {
    /// Stable backend token (`"libkrun"`, `"firecracker"`, `"hvf"`, `"mock"`).
    fn name(&self) -> &str;
    /// The typed discriminant; branch on this, never on `name()`.
    fn kind(&self) -> BackendKind;
    /// Whether this VMM can run on the current host.
    fn is_available(&self) -> Result<bool>;
    /// Coarse capability flags.
    fn capabilities(&self) -> VmCapabilities;
    /// Honest warm-start tier. The capability descriptor is authoritative;
    /// this method remains as a compatibility accessor for driver callers.
    fn snapshot_capability(&self) -> SnapshotCapability {
        self.capabilities().snapshot_capability
    }
    /// Which of the CI-enforced security claims this VMM's boot path holds.
    fn security_profile(&self) -> BackendSecurityProfile;
    /// Boot the VM described by `spec`, returning a live handle.
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>>;

    /// Boot a clean, pre-workload standby parent from `spec` and capture it into
    /// a claimable resource. The parent runs no entrypoint and holds no secret or
    /// plan — nothing on this seam (`StandbySpec` in, `StandbyHandle` out) has a
    /// field to carry one, so a parent is structurally incapable of holding
    /// workload authority. The driver owns the whole boot-to-ready-plus-capture
    /// sequence; the role layer above only ever sees the resulting handle and
    /// never boots a VMM directly for this path.
    ///
    /// Fail-closed default: a driver opts in explicitly, mirroring
    /// `VmBackend::spawn_standby`'s own fail-closed default.
    fn spawn_standby_parent(
        &self,
        _spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        Err(StandbyError::Unsupported {
            backend: self.name().to_string(),
        })
    }

    /// Fork a clean standby parent — already materialized into `req.child_dir` as
    /// a copy-on-write clone of its verified content — into a fresh child VMM
    /// identity, resumed from the parent's saved memory. The driver owns the VMM
    /// fork/restore mechanics only: the role layer above has already admitted the
    /// plan, bound it to the parent, materialized the rootfs, and scrubbed the
    /// identity.
    ///
    /// The child comes back **still carrying the parent's random state**: a
    /// restore has no boot at which to seed it, and the guest is not reachable
    /// until it is running. Delivering `req.genid` is therefore a separate step
    /// the caller runs immediately afterwards, through
    /// [`deliver_child_identity`](Self::deliver_child_identity), and a child that
    /// cannot prove it adopted the token is never admitted.
    ///
    /// Fail-closed default: a driver opts in explicitly, mirroring
    /// [`spawn_standby_parent`](Self::spawn_standby_parent).
    fn fork_standby_child(
        &self,
        _req: &ChildForkRequest<'_>,
    ) -> std::result::Result<(), StandbyError> {
        Err(StandbyError::Unsupported {
            backend: self.name().to_string(),
        })
    }

    /// Hand a freshly forked child its own generation token and report, verbatim,
    /// what the guest agent says it did with it — whether it acknowledged the
    /// signal, rotated its generation identity (reseeding its CSPRNG off the
    /// parent's cloned state), and resynchronized its wall clock off the host's.
    ///
    /// The reported flags are the guest's own claims, not a verdict: judging them
    /// is the role layer's job, so a driver never decides whether a child is
    /// admissible.
    ///
    /// The default is the real host→guest RPC over the backend-agnostic vsock
    /// dispatcher, so every VMM shares one delivery path and inherits its connect
    /// retry and read deadline — a guest that never answers surfaces as an error
    /// rather than an unbounded wait. A driver overrides this only to run
    /// hypervisor-free.
    fn deliver_child_identity(
        &self,
        child_vm_name: &str,
        token: [u8; GENID_BYTES],
    ) -> Result<PostRestoreOutcome> {
        crate::vm::instance_snapshot::signal_post_restore(
            child_vm_name,
            &crate::vm::instance_snapshot::VsockPostRestoreSignal { token },
        )
    }

    /// Backend-specific control over a running VM named `vm_name` that lets the
    /// caller pause it, save its live memory, and resume it — the mechanics
    /// [`crate::checkpoint::capture_vm_full`] needs to capture a spawned standby
    /// parent. `None` by default: a backend that cannot pause-and-save-memory
    /// cannot back a warm pool, so it simply has nothing to offer here rather
    /// than a control whose methods would all fail.
    fn vm_full_control(&self, vm_name: &str) -> Option<Box<dyn crate::checkpoint::VmFullControl>> {
        let _ = vm_name;
        None
    }

    /// The VMM-specific base kernel bootargs (console, earlycon, root/init
    /// selection) for a workload boot with the given root/disk shape. The
    /// shared cmdline assembler (`workload_runner::cmdline`) layers every
    /// other token — verity, grants, egress, uvols — on top of this.
    fn workload_base_bootargs(&self, virtiofs_root: bool, has_disk: bool) -> String;

    /// Reconstruct a live handle for an already-running VM by id — the stateless
    /// lifecycle entry (stop/status/wait from a process that didn't boot it). The
    /// handle is disk-backed (pid file + exit record), so no in-memory boot state
    /// is needed; a returned handle whose VM has since exited reports `Stopped`.
    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>>;

    /// Guest communication channel info for VM `id`. Errors when the VMM has
    /// none to report.
    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo>;
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
