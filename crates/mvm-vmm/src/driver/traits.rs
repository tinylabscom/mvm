//! The `VmmDriver` seam: pure VMM mechanics, written once per VMM. Role policy
//! (workload admission/egress/audit, builder orchestration) lives in the role
//! runners above this trait, never here. The driver carries no workload
//! permission and never sees an admitted plan — it boots what the spec
//! describes and nothing more.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use mvm_core::crypto::vmgenid::{GENID_BYTES, GenerationToken};
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, GuestChannelInfo, SnapshotCapability, StandbyError,
    StandbyHandle, StandbySpec, VmCapabilities, VmExitStatus, VmId, VmStatus,
};

use crate::driver::spec::{VmmSpec, VsockPort};
use crate::post_restore::{PostRestoreOutcome, VsockPostRestoreSignal, signal_post_restore};

/// What a driver needs to fork a materialized standby parent into a fresh child
/// VMM. Grouped so the seam takes one value instead of a positional list.
pub struct ChildForkRequest<'a> {
    /// The verified standby parent that is being handed off to this child.
    /// Saved-state drivers use the checkpoint in `child_dir`; live standby
    /// drivers use this name to transfer their paused resident VM.
    pub parent_vm_name: Option<&'a str>,
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
    /// The host end of every vsock channel the child is entitled to: the agent
    /// RPC the host dials, the gated egress endpoint, the workload-exit report
    /// and — for an admitted child — the host-services broker.
    ///
    /// This is not a boot recipe. A restored child inherits its device model
    /// and kernel cmdline from the parent's saved memory, so the guest is
    /// already configured to dial these ports; what is missing on the host is
    /// something listening on the other end. The driver puts that in place
    /// **before** it resumes the child: a restore brings back an already-booted
    /// guest, so there is no kernel boot to cover the gap the way a cold boot's
    /// does.
    ///
    /// The list is assembled by the role layer from the same mapper a workload
    /// boot's channel set comes from, never derived here — a second derivation
    /// is free to drift, and a claimed child that dials a channel nobody bound
    /// is silently less capable than a cold-booted one.
    pub channels: &'a [VsockPort],
    /// The CPU share the claim's admitted plan grants this child — the same
    /// value the parent-subset comparison cleared.
    ///
    /// A driver that starts a fresh VMM for the child binds it on that spawn,
    /// exactly as a cold boot binds `VmmSpec.cpu_grant`. A driver that hands
    /// over an already-running machine (a resident parent, a preloaded child)
    /// has no spawn left to bind and leaves the child on whatever bound that
    /// machine was started with.
    pub cpu_grant: Option<mvm_contract::grants::CpuGrant>,
}

/// What a driver needs to boot a warm-pool factory parent. Grouped so the seam
/// takes one value instead of a positional list.
pub struct StandbyParentSpawn<'a> {
    /// The parent's pool record: its identity, state dir, and the compat key a
    /// later claim matches on. It has no plan, secret or entrypoint field, so a
    /// parent is structurally incapable of holding workload authority.
    pub spec: &'a StandbySpec,
    /// The parent's boot inputs, assembled by the role layer from the launch
    /// the parent will serve, through the same mappers a workload boot uses.
    /// The driver boots this verbatim: it must not derive a parent's device
    /// model or cmdline itself, because a second recipe is free to drift from
    /// the workload's, and every child restored from this parent inherits both
    /// out of its saved memory.
    pub boot: &'a VmmSpec,
}

/// A verified checkpoint materialized into a child state directory before a
/// warm claim. The driver loads it and leaves the child VMM paused; the claim
/// path wires authority-bearing channels before resuming it.
pub struct PreloadChildRequest<'a> {
    /// Fresh VM identity reserved for this one-shot preloaded child.
    pub child_vm_name: &'a str,
    /// Canonical child state directory containing the materialized snapshot.
    pub child_dir: &'a Path,
}

/// The process identity and control endpoint of a paused preloaded child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreloadedChild {
    /// The VMM process that remains paused in the pool.
    pub pid: u32,
    /// Backend control socket used for diagnostics and teardown.
    pub control_socket: String,
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
    /// Whether this VMM can attach live read-only host-directory shares.
    /// Unsupported drivers must fail closed before boot.
    fn supports_directory_shares(&self) -> bool {
        false
    }
    /// Whether a standby claim can hand a resident VMM directly to the child
    /// identity without starting a separate saved-state restore.
    fn supports_resident_handoff(&self) -> bool {
        false
    }
    /// Whether pool refill may load a saved child VMM and keep it paused until
    /// the claim wires its authority-bearing channels.
    fn supports_preloaded_standby(&self) -> bool {
        false
    }
    /// Boot the VM described by `spec`, returning a live handle.
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>>;

    /// Boot the clean, pre-workload standby parent `req` describes and return
    /// its pool record. The parent runs no entrypoint and holds no secret or
    /// plan — nothing on this seam (`StandbyParentSpawn` in, `StandbyHandle`
    /// out) has a field to carry one, so a parent is structurally incapable of
    /// holding workload authority.
    ///
    /// The driver boots `req.boot` as given and reports the live process; it
    /// does not assemble the parent's boot inputs. Those come from the role
    /// layer, which derives them from the launch the parent will serve using
    /// the same mappers a workload boot uses — the only way a parent's device
    /// model and cmdline stay in step with a workload's. The parent is left
    /// **running**: the caller captures its live memory next.
    ///
    /// Fail-closed default: a driver opts in explicitly, mirroring
    /// `VmBackend::spawn_standby`'s own fail-closed default.
    fn spawn_standby_parent(
        &self,
        _req: &StandbyParentSpawn<'_>,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        Err(StandbyError::Unsupported {
            backend: self.name().to_string(),
        })
    }

    /// Fork a clean standby parent — already materialized into `req.child_dir`
    /// as a copy-on-write clone of its verified content — into a fresh child
    /// VMM identity, resumed from the parent's saved memory. The driver owns
    /// the VMM fork/restore mechanics only: the role layer above has already
    /// admitted the plan, bound it to the parent, materialized the rootfs, and
    /// scrubbed the identity.
    ///
    /// Before it resumes anything the driver wires `req.channels` — the host
    /// end of the channels the restored guest dials. A cold boot does the
    /// equivalent before `InstanceStart`; a fork has a tighter window, because
    /// the guest it brings back is already past its own boot and can dial the
    /// moment its vCPUs run.
    ///
    /// The child comes back **still carrying the parent's random state**: a
    /// restore has no boot at which to seed it, and the guest is not reachable
    /// until it is running. Delivering `req.genid` is therefore a separate step
    /// the caller runs immediately afterwards, through
    /// [`deliver_child_identity`](Self::deliver_child_identity), and a child
    /// that cannot prove it adopted the token is never admitted.
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

    /// Load a materialized standby child into a fresh VMM and leave it paused.
    /// Pool refill uses this before a claim has authority-bearing channels.
    fn preload_standby_child(
        &self,
        _req: &PreloadChildRequest<'_>,
    ) -> std::result::Result<PreloadedChild, StandbyError> {
        Err(StandbyError::Unsupported {
            backend: self.name().to_string(),
        })
    }

    /// Resume a child previously returned by [`preload_standby_child`](Self::preload_standby_child).
    /// The caller wires all claim-specific channels before invoking this method.
    fn resume_preloaded_child(
        &self,
        _req: &ChildForkRequest<'_>,
    ) -> std::result::Result<(), StandbyError> {
        Err(StandbyError::Unsupported {
            backend: self.name().to_string(),
        })
    }

    /// Hand a freshly forked child its generation token and optional signed
    /// verb grant, then report verbatim what the guest agent says it did with
    /// them — whether it acknowledged the signal, rotated its generation
    /// identity (reseeding its CSPRNG off the parent's cloned state), and
    /// resynchronized its wall clock off the host's.
    ///
    /// The reported flags are the guest's own claims, not a verdict: judging
    /// them is the role layer's job, so a driver never decides whether a child
    /// is admissible.
    ///
    /// The default is the real host→guest RPC over the backend-agnostic vsock
    /// dispatcher, so every VMM shares one delivery path and inherits its
    /// connect retry and read deadline — a guest that never answers surfaces as
    /// an error rather than an unbounded wait. A driver overrides this only to
    /// run hypervisor-free.
    fn deliver_child_identity(
        &self,
        child_vm_name: &str,
        token: [u8; GENID_BYTES],
        grant_envelope: Option<VerbGrantEnvelope>,
    ) -> Result<PostRestoreOutcome> {
        signal_post_restore(
            child_vm_name,
            &VsockPostRestoreSignal {
                token,
                hostname: Some(child_vm_name.to_string()),
                grant_envelope,
            },
            crate::post_restore::POST_RESTORE_READY_TIMEOUT,
        )
    }

    /// Backend-specific control over a running VM named `vm_name` that lets
    /// the caller pause it, save its live memory, and resume it — the mechanics
    /// a checkpoint capture needs to capture a spawned standby parent. `None`
    /// by default: a backend that cannot pause-and-save-memory cannot back a
    /// warm pool, so it simply has nothing to offer here rather than a control
    /// whose methods would all fail.
    fn vm_full_control(&self, vm_name: &str) -> Option<Box<dyn crate::checkpoint::VmFullControl>> {
        let _ = vm_name;
        None
    }

    /// Whether a standby parent stays resident and is handed off in place.
    ///
    /// This is distinct from a saved-state snapshot: a live handoff must
    /// rewire every host channel while the parent is paused and must never be
    /// selected by a driver that has not implemented that protocol.
    fn standby_parent_is_live(&self) -> bool {
        false
    }

    /// The VMM-specific base kernel bootargs (console, earlycon, root/init
    /// selection) for a workload boot with the given root/disk shape. The
    /// shared cmdline assembler (`workload_runner::cmdline`) layers every
    /// other token — verity, grants, egress, uvols — on top of this.
    fn workload_base_bootargs(&self, virtiofs_root: bool, has_disk: bool) -> String;

    /// Reconstruct a live handle for an already-running VM by id — the stateless
    /// lifecycle entry (stop/status/wait from a process that didn't boot it).
    /// The handle is disk-backed (pid file + exit record), so no in-memory boot
    /// state is needed; a returned handle whose VM has since exited reports
    /// `Stopped`.
    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>>;

    /// Guest communication channel info for VM `id`. Errors when the VMM has
    /// none to report.
    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo>;
}

/// A live VM handle. Launch-model-agnostic: an in-process VMM, a subprocess,
/// and an external supervisor all present the same surface.
pub trait RunningVm: Send {
    fn id(&self) -> &VmId;
    /// Host process that owns this VM's address space, when the driver can
    /// identify it. This is an observation surface for diagnostics and
    /// benchmarks, not a lifecycle handle; callers must tolerate process exit.
    fn host_process_id(&self) -> Option<u32> {
        None
    }
    /// Block until the VM exits; returns its status.
    fn wait(&self) -> Result<VmExitStatus>;
    /// Force-terminate the VM.
    fn kill(&self) -> Result<()>;
    /// Force-terminate the VM and report backend-specific teardown phases when
    /// the implementation can observe them.
    fn kill_with_timing(&self) -> Result<Option<RunningVmStopTiming>> {
        self.kill().map(|_| None)
    }
    fn pause(&self) -> Result<()>;
    fn resume(&self) -> Result<()>;
    fn status(&self) -> Result<VmStatus>;
    /// Open a host->guest vsock connection to `guest_port`.
    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>>;
}

/// Backend-specific phases observed while terminating a running VM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunningVmStopTiming {
    /// Time spent issuing the supervisor termination signal.
    pub supervisor_signal: Duration,
    /// Time spent waiting for the supervisor process to disappear after the
    /// graceful termination request.
    pub pid_disappearance: Duration,
    /// Time spent on forced termination and its follow-up wait, if needed.
    pub force_kill_wait: Duration,
    /// Time spent removing the backend's live-process state marker.
    pub state_cleanup: Duration,
}
