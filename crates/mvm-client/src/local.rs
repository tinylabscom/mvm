//! `LocalBackend` — the `MvmClient` over this host's microVMs, in-process.
//!
//! Lives here rather than in `mvm-core` because it links the runtime backend
//! (`mvm-backend`); keeping that edge above the foundation crate is what lets
//! `mvm-sdk` enable `mvm-core/client` for the trait without a dependency cycle.
//!
//! `list`/`stop`/`logs` go straight to the backend dispatch (they act on VMs
//! that already exist, so they carry no admission concern). `run` boots through
//! the signed-plan admission gate in-process — no subprocess, no CLI. It
//! resolves the spec's image to a host-materialized rootfs — a ready
//! `rootfs.ext4`, an unpacked OCI directory (inject runtime + pure-materialize),
//! or a registry ref (pull + unpack + inject + materialize) — reusing the exact
//! `mvm_build::run_image` orchestration the CLI's `run --image` uses, then hands
//! it to `mvm_hostd::run::admit_and_boot_local`. A workload never boots on a
//! path that skipped admission.

use std::collections::HashSet;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use flate2::read::GzDecoder;
use mvm_core::protocol::vm_backend::{BackendKind, VmId, VmInfo, VmStatus};
use mvm_core::rootfs_source::RootfsSource;
use mvm_fs::oci::{
    ImageReference, LayerDescriptor, LayerFetchOptions, OciLayerFetcher, OciManifestFetcher,
    UnpackOptions, UnpackReport, current_linux_platform, unpack_layer_with_prior_paths,
};
use mvm_runtime::AnyBackend;

use mvm_core::client::dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus,
    PauseOpts, PauseOutcome, PortMapping, ResumeOpts, ResumeOutcome,
};
use mvm_core::client::{BackendCapabilityReport, ClientOperationCapabilities};
use mvm_core::client::{MvmClient, MvmError, Result};
use mvm_core::config::vm_state_dir;
use mvm_core::vm_backend::{SnapshotCapability, VmStartConfig, WarmStartError};
#[cfg(feature = "test-support")]
use mvm_runtime::vm::instance_snapshot::CannedIO;
use mvm_runtime::vm::instance_snapshot::{
    FirecrackerIO, POST_RESTORE_READY_TIMEOUT, PostRestoreOutcome, PostRestoreSignal, SnapshotIO,
    VsockPostRestoreSignal, VsockPrimedSignalSource, await_primed_barrier, describe_missing_reseed,
    pause_and_seal, signal_post_restore, verify_and_resume,
};
use mvm_runtime::vm::name_registry::{VmNameRegistry, VmRegistration};

/// Drives the host's VM backend directly. Construct with [`LocalBackend::new`]
/// (auto-selected backend) or [`LocalBackend::with_hypervisor`].
pub struct LocalBackend {
    pub(crate) backend: AnyBackend,
    /// Injected secret lifecycle service for launch-time reference
    /// validation/recording. `None` builds the production-wired
    /// [`crate::secret::SecretService::local`] on first use.
    pub(crate) secret_service: Option<std::sync::Arc<crate::secret::SecretService>>,
}

/// vCPUs to give a guest when the caller does not say.
///
/// A plain constant again. It was briefly resolved per backend, because HVF
/// accepted exactly one vCPU and refused anything else while being the macOS
/// default — so the default configuration and the default backend were
/// mutually exclusive there. HVF has real SMP now, which removes the ceiling
/// and with it the reason to vary the default by backend. Varying it anyway
/// would quietly hand a macOS caller half the CPUs everyone else gets.
#[must_use]
pub fn default_vcpus() -> u32 {
    2
}

/// Name of the workload backend selected by the canonical host ladder.
///
/// Keeps callers on the client facade instead of coupling them to the runtime
/// backend enum merely to resolve the standard platform default.
#[must_use]
pub fn auto_selected_backend_name() -> String {
    AnyBackend::auto_select().name().to_string()
}

impl LocalBackend {
    pub fn new() -> Self {
        Self {
            backend: AnyBackend::auto_select(),
            secret_service: None,
        }
    }

    pub fn with_hypervisor(name: &str) -> Self {
        Self {
            backend: AnyBackend::from_hypervisor(name),
            secret_service: None,
        }
    }

    /// Client bound to the backend that actually started `vm`, falling back to
    /// the host default when the VM has left no marker.
    ///
    /// A verb operating an *existing* machine must reach the VMM that owns it.
    /// Choosing from a flag default instead sent `pause` at Firecracker for a
    /// guest running on HVF, which failed on a socket that was never going to
    /// exist.
    #[must_use]
    pub fn for_started_vm(vm: &str) -> Self {
        Self {
            backend: AnyBackend::for_started_vm(vm).unwrap_or_else(AnyBackend::auto_select),
            secret_service: None,
        }
    }

    /// Replace the secret lifecycle service this client validates and
    /// records machine secret references through (tests inject a fixture
    /// store; production uses the default).
    #[must_use]
    pub fn with_secret_service(
        mut self,
        service: std::sync::Arc<crate::secret::SecretService>,
    ) -> Self {
        self.secret_service = Some(service);
        self
    }

    /// The backend-observed VMs on this host — every VMM's live listing plus this
    /// client's own backend, deduped by name — as the target set for a bulk stop.
    ///
    /// This is deliberately NOT [`list_machines`](MvmClient::list_machines): it
    /// omits the registry-only rows that call folds in (a stopped registration
    /// with no backend process), which must never be swept by `down`, and it
    /// KEEPS a crashed VM that still holds a pid marker — reported `Stopped` by
    /// its backend — so [`stop_machine`](MvmClient::stop_machine) can reap that
    /// VM's orphaned per-VM subprocesses (secret substitution, broker, …).
    ///
    /// Infallible: a per-backend listing error degrades to fewer rows rather than
    /// aborting a host-wide stop before it can reap anything.
    pub fn list_stop_targets(&self) -> Vec<MachineState> {
        let mut infos: Vec<VmInfo> = AnyBackend::list_all();
        for vm in self.backend.list().unwrap_or_default() {
            if !infos.iter().any(|existing| existing.name == vm.name) {
                infos.push(vm);
            }
        }
        infos.into_iter().map(|i| to_state(i, None)).collect()
    }

    /// Resolve an existing machine's owning backend from its live marker. A
    /// marker-less machine falls back to the backend explicitly carried by this
    /// client, preserving the hermetic mock path and explicit CLI overrides.
    fn lifecycle_backend_for(&self, vm_name: &str) -> AnyBackend {
        AnyBackend::for_started_vm(vm_name)
            .unwrap_or_else(|| AnyBackend::from_hypervisor(self.backend.name()))
    }

    /// Firecracker and the hermetic mock use the sealed snapshot lifecycle.
    /// Other backends own their pause/resume mechanics directly.
    fn uses_sealed_snapshot(backend: &AnyBackend) -> bool {
        matches!(backend.kind(), BackendKind::Firecracker | BackendKind::Mock)
    }

    fn is_mock_backend(backend: &AnyBackend) -> bool {
        backend.kind() == BackendKind::Mock
    }

    /// Pick the `SnapshotIO` matching the resolved machine owner. The mock writes
    /// deterministic `CannedIO` stub bytes so the seal/verify round-trip runs
    /// without a real Firecracker socket; every other backend drives
    /// `FirecrackerIO` against the running Firecracker VM's UDS control socket.
    /// Backend-native lifecycle paths never call this helper. The mock
    /// arm is gated behind `test-support` along with `is_mock()`'s only
    /// possible `true` outcome — outside that feature `AnyBackend::Mock`
    /// doesn't exist, so `is_mock()` is always `false` and this falls
    /// straight through to the real Firecracker path.
    fn snapshot_io_for(&self, backend: &AnyBackend, vm_name: &str) -> Result<Box<dyn SnapshotIO>> {
        #[cfg(feature = "test-support")]
        if Self::is_mock_backend(backend) {
            let dir = mvm_runtime::MockBackend::vm_dir(vm_name);
            if !dir.exists() {
                return Err(backend_err(format!(
                    "mock VM {vm_name:?} is not running (no directory at {})",
                    dir.display()
                )));
            }
            return Ok(Box::new(CannedIO::new(
                b"mock-vmstate".to_vec(),
                b"mock-mem".to_vec(),
            )));
        }
        debug_assert_eq!(
            backend.kind(),
            BackendKind::Firecracker,
            "only Firecracker reaches the production sealed-snapshot transport"
        );
        let vm_dir = mvm_runtime::microvm::resolve_running_vm_dir(vm_name)
            .map_err(|e| backend_err(format!("VM {vm_name:?} is not running: {e:#}")))?;
        mvm_runtime::microvm::ensure_fc_sockets_in_state_dir(&vm_dir, "a sealed snapshot")
            .map_err(|e| backend_err(format!("{e:#}")))?;
        Ok(Box::new(FirecrackerIO::new(firecracker_socket(&vm_dir))))
    }

    /// Warm-resume through the backend's live-memory `warm_start` path: mint a
    /// fresh VMGenID, load + resume live memory, reseed. Fails closed with the
    /// typed `WarmStartError::Unsupported` recovery hint on a disk-only backend
    /// rather than silently cold-booting.
    fn warm_resume(&self, backend: &AnyBackend, name: &str) -> Result<ResumeOutcome> {
        require_registry_paused(name)?;
        let config = VmStartConfig {
            name: name.to_string(),
            ..Default::default()
        };
        match backend.warm_start(&config, SnapshotCapability::LiveMemory) {
            Ok(outcome) => {
                let reseed = match warm_resume_reseed_verdict(outcome.reseed) {
                    Ok(summary) => summary,
                    Err(why) => {
                        return Err(refuse_resume(name, &why, || {
                            backend.stop(&VmId(name.to_string()))
                        }));
                    }
                };
                // A warm start resumes the paused process itself, so the pause
                // marker still names it and would keep reporting it paused.
                if let Err(error) = mvm_runtime::vm::admission::clear_paused(&vm_state_dir(name)) {
                    tracing::warn!(vm = %name, error = %format!("{error:#}"), "could not clear the pause marker");
                }
                mark_resumed_after_restore(name, "")?;
                // A warm resume restores live memory, not a sealed snapshot, so it
                // carries no epoch/lengths — only the reseed summary.
                Ok(ResumeOutcome {
                    reseed: Some(reseed),
                    ..Default::default()
                })
            }
            // Name the tier mismatch + recovery hint verbatim (its `Display` is
            // the actionable message); other failures keep a locating context.
            Err(e @ WarmStartError::Unsupported { .. }) => Err(backend_err(format!("{e}"))),
            Err(e) => Err(backend_err(format!("warm-starting VM {name:?}: {e}"))),
        }
    }

    /// Plain resume: verify the sealed snapshot envelope — **refusing a replayed
    /// older-epoch snapshot** — load it back and resume vCPUs, then finish
    /// bringing the guest back with a fresh-VMGenID PostRestore (skipped for the
    /// mock, which has no guest agent).
    fn plain_resume(&self, backend: &AnyBackend, name: &str) -> Result<ResumeOutcome> {
        require_registry_paused(name)?;
        if !Self::uses_sealed_snapshot(backend) {
            backend
                .resume(&VmId(name.to_string()))
                .map_err(|e| backend_err(format!("resuming VM {name:?}: {e:#}")))?;
            mark_resumed_after_restore(name, "")?;
            return Ok(ResumeOutcome::default());
        }

        let io = self.snapshot_io_for(backend, name)?;
        if !Self::is_mock_backend(backend) {
            let (sidecar, reseed) =
                resume_sealed(name, &*io, post_restore_signal(name), RESUME_ADMISSION)?;
            // Report the verified snapshot's epoch + artifact lengths so the
            // caller's WorkloadWake audit entry carries the same detail the
            // pause did.
            return Ok(ResumeOutcome {
                epoch: sidecar.epoch,
                vmstate_len: sidecar.vmstate_len,
                mem_len: sidecar.mem_len,
                reseed: Some(reseed),
            });
        }
        // The mock has no guest agent to reseed, so its restore is the whole
        // resume.
        let sidecar = verify_and_resume(name, &*io)
            .map_err(|e| backend_err(format!("resuming VM {name:?}: {e:#}")))?;
        let reseed = None;
        mark_resumed_after_restore(name, "")?;
        // Report the verified snapshot's epoch + artifact lengths so the caller's
        // WorkloadWake audit entry carries the same detail the pause did.
        Ok(ResumeOutcome {
            epoch: sidecar.epoch,
            vmstate_len: sidecar.vmstate_len,
            mem_len: sidecar.mem_len,
            reseed,
        })
    }
}

/// Restore a machine's sealed snapshot and admit its guest, or refuse it.
///
/// From just before the restore until the guest is admitted or refused, an
/// interrupt runs a cleanup that stops the restored VMM and records the
/// refusal. The guest is admitted by recording `fc.admitted` next to its
/// `fc.pid`, and only then is the machine marked resumed; the admission record
/// is what reconcile trusts, so a failed registry write cannot make an admitted
/// guest look unadmitted.
fn resume_sealed<S: PostRestoreSignal + Send + 'static>(
    name: &str,
    io: &dyn SnapshotIO,
    signal: S,
    timeouts: AdmissionTimeouts,
) -> Result<(mvm_core::crypto::snapshot_hmac::IntegritySidecar, String)> {
    // Only a machine the registry records as paused is restored. A running
    // machine would lose everything since its last pause to an old snapshot,
    // and a machine reconcile cannot see as paused could not be found and
    // stopped if this process died before admitting its guest.
    require_registry_paused(name)?;
    let claim = AdmissionClaim::default();
    let _interrupt = arm_interrupted_admission(name, &claim);
    // The replay-refusal gate: `verify_and_resume` rejects a snapshot whose
    // epoch is below the persisted high-water mark before restoring anything.
    // Called unchanged — this is the security property of resume.
    let sidecar = verify_and_resume(name, io)
        .map_err(|e| backend_err(format!("resuming VM {name:?}: {e:#}")))?;

    let state_dir = vm_state_dir(name);
    // The pause marker names the process the restore just replaced; it no
    // longer describes this VM.
    if let Err(error) = mvm_runtime::vm::admission::clear_paused(&state_dir) {
        tracing::warn!(vm = %name, error = %format!("{error:#}"), "could not clear the pause marker");
    }
    let reseed = admit_resumed_guest(
        name,
        signal,
        timeouts,
        &claim,
        || mvm_runtime::vm::admission::record_admitted(&state_dir),
        || io.teardown_paused(),
    )?;
    mark_resumed_after_restore(name, " and its guest reseeded and was admitted")?;
    Ok((sidecar, reseed))
}

/// Mark `name` resumed after its restore, naming the running guest and the
/// recovery path if the registry write fails once the guest is already
/// running. `detail` names what already succeeded beyond the restore itself.
fn mark_resumed_after_restore(name: &str, detail: &str) -> Result<()> {
    set_registry_resumed(name).map_err(|e| {
        backend_err(format!(
            "VM {name:?} resumed{detail}, but {e}. \
             The guest is running. Do not run resume again: the registry still \
             says paused, so another resume would restore over the running guest \
             and discard what it has done since. Fix the registry, then pause or \
             stop the machine as usual."
        ))
    })
}

/// Refuse to restore `name` unless the registry records it as paused.
///
/// The `paused` flag is load-bearing here: it must mean this machine was
/// sealed by a real pause, with its current snapshot beside it. Anything else
/// that parks a machine — the host idle-sleep reaper, for one — must not set
/// it without also discarding or invalidating the sealed snapshot, or a
/// resume of the parked machine would restore a stale snapshot over it.
fn require_registry_paused(name: &str) -> Result<()> {
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    let paused = {
        let _lock = mvm_runtime::vm::name_registry::acquire_registry_lock(&registry_path)
            .map_err(|e| backend_err(format!("{e:#}")))?;
        VmNameRegistry::load(&registry_path)
            .map_err(|e| backend_err(format!("{e:#}")))?
            .lookup(name)
            .map(|record| record.paused)
    };
    match paused {
        Some(true) => Ok(()),
        Some(false) => Err(backend_err(format!(
            "VM {name:?} is not paused; resume restores its sealed snapshot and would \
             discard everything the running machine has done since that pause. If a pause \
             of it was interrupted, run the pause again first"
        ))),
        None => Err(backend_err(format!(
            "VM {name:?} has no registry record, so a resume of it could not be tracked \
             or recovered; refusing to restore it"
        ))),
    }
}

/// Who settled a resume's admission first: the resume, or an interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Pending,
    Admitted,
    Refused,
}

/// The one decision a resume's admission ends in, shared between the resume
/// and its interrupt cleanup so exactly one of them acts: an interrupt after
/// the admission stops nothing, and a refusal is recorded once.
#[derive(Clone)]
struct AdmissionClaim(std::sync::Arc<std::sync::Mutex<Decision>>);

impl Default for AdmissionClaim {
    fn default() -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(
            Decision::Pending,
        )))
    }
}

impl AdmissionClaim {
    fn decision(&self) -> std::sync::MutexGuard<'_, Decision> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Settle the admission as refused. `true` if this call settled it, and
    /// its caller now owns stopping the VMM and recording the refusal.
    fn refuse(&self) -> bool {
        let mut decision = self.decision();
        if *decision != Decision::Pending {
            return false;
        }
        *decision = Decision::Refused;
        true
    }

    /// Settle the admission as admitted once `record` has recorded it.
    /// `Ok(false)` if an interrupt refused it first. A failed `record` leaves
    /// it pending and returns the error. The decision is held while `record`
    /// runs, so an interrupt cannot land between the record and the decision.
    fn admit(&self, record: impl FnOnce() -> anyhow::Result<()>) -> anyhow::Result<bool> {
        let mut decision = self.decision();
        if *decision != Decision::Pending {
            return Ok(false);
        }
        record()?;
        *decision = Decision::Admitted;
        Ok(true)
    }
}

/// Register the interrupt cleanup for a resume whose admission `claim`
/// tracks. It stops the restored VMM and records the refusal only if the
/// admission is still pending when the interrupt arrives.
fn arm_interrupted_admission(
    name: &str,
    claim: &AdmissionClaim,
) -> mvm_runtime::interrupt_cleanup::InterruptCleanup {
    let owned = name.to_string();
    let claim = claim.clone();
    mvm_runtime::interrupt_cleanup::on_interrupt(&format!("resume of {name}"), move || {
        if claim.refuse() {
            stop_interrupted_admission(&owned);
        }
    })
}

/// Deliver the post-restore signal to a resumed guest and admit the resume only
/// if the guest confirms it reseeded; otherwise stop its VMM and refuse.
///
/// A plain resume can restore the same sealed memory image more than once:
/// the epoch check refuses only an older snapshot, and resume reloads the
/// snapshot into a fresh VMM whether or not the last one is still running. A
/// guest that did not reseed would draw again on random state it has already
/// used, nonces and keys included — the clone problem in time rather than in
/// space. So every way of not confirming a reseed is refused the same way: a
/// reported shortfall, an agent that never became reachable, a failed or
/// unacknowledged signal, and a clock that did not resync. The workload shares
/// its agent's uid, so it can stall the agent on purpose; a refusal is what
/// keeps that from leaving it running on reused state.
///
/// The whole exchange is held to `timeouts`: the signal runs on its own thread,
/// and a guest that has not answered by the deadline is refused, so the time
/// an unadmitted guest runs is bounded by the deadline rather than by the
/// transport's own connect retries and read timeouts. That thread is then
/// abandoned: it ends when its own connect retries and read timeout run out, or
/// sooner if stopping the VMM closes a connection it is reading from, and its
/// late answer is dropped.
fn admit_resumed_guest<S: PostRestoreSignal + Send + 'static>(
    name: &str,
    signal: S,
    timeouts: AdmissionTimeouts,
    claim: &AdmissionClaim,
    record_admission: impl FnOnce() -> anyhow::Result<()>,
    stop: impl FnOnce() -> anyhow::Result<()>,
) -> Result<String> {
    // The verb-emits-at-least-one-audit invariant extends to the vsock messages a
    // verb dispatches; this records the PostRestore RPC alongside where it fires.
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: name,
        "scope=rpc,direction=in,kind=vsock,verb={verb}",
        verb = "post-restore",
    );
    let delivered = signal_within(name, signal, timeouts);
    let why = match resume_reseed_verdict(delivered) {
        Ok(summary) => match claim.admit(record_admission) {
            Ok(true) => return Ok(summary),
            Ok(false) => return Err(interrupted_resume(name)),
            Err(error) => {
                format!("the guest reseeded, but its admission could not be recorded ({error:#})")
            }
        },
        Err(why) => why,
    };
    if claim.refuse() {
        Err(refuse_resume(name, &why, stop))
    } else {
        Err(interrupted_resume(name))
    }
}

/// The error a resume returns when its interrupt cleanup settled the
/// admission first; that cleanup already stopped the VMM and recorded it.
fn interrupted_resume(name: &str) -> MvmError {
    backend_err(format!(
        "the resume of VM {name:?} was interrupted; its VMM was stopped and the refusal recorded"
    ))
}

/// How long a resumed guest has to confirm its reseed: `ready` for its agent
/// to become reachable, then `reply` for the post-restore exchange itself.
#[derive(Debug, Clone, Copy)]
struct AdmissionTimeouts {
    ready: std::time::Duration,
    reply: std::time::Duration,
}

impl AdmissionTimeouts {
    /// The most time a resumed guest runs before it is admitted or refused.
    fn deadline(self) -> std::time::Duration {
        self.ready + self.reply
    }
}

/// The production admission budget: five seconds for the agent to come up,
/// ten for the exchange. Fifteen seconds is the bound the documentation
/// states for how long a refused guest can have run.
const RESUME_ADMISSION: AdmissionTimeouts = AdmissionTimeouts {
    ready: POST_RESTORE_READY_TIMEOUT,
    reply: std::time::Duration::from_secs(10),
};

/// Deliver the post-restore signal on a separate thread and wait for its
/// outcome no longer than `timeouts` allows.
fn signal_within<S: PostRestoreSignal + Send + 'static>(
    name: &str,
    signal: S,
    timeouts: AdmissionTimeouts,
) -> anyhow::Result<PostRestoreOutcome> {
    let (sender, outcome) = std::sync::mpsc::channel();
    let owned = name.to_string();
    std::thread::Builder::new()
        .name("post-restore".to_string())
        .spawn(move || {
            // The receiver is gone once the deadline has passed; the late
            // outcome has nowhere to go and is dropped.
            let _ = sender.send(signal_post_restore(&owned, &signal, timeouts.ready));
        })
        .map_err(|error| anyhow::anyhow!("starting the post-restore exchange: {error}"))?;
    let deadline = timeouts.deadline();
    outcome.recv_timeout(deadline).unwrap_or_else(|_| {
        Err(anyhow::anyhow!(
            "the guest did not answer the post-restore signal within {deadline:?}"
        ))
    })
}

/// The interrupt cleanup for a resume in flight: stop the restored VMM, keep
/// the machine paused, and record the refusal, as a refused admission does.
fn stop_interrupted_admission(name: &str) {
    let stop = || -> anyhow::Result<()> {
        let vm_dir = mvm_runtime::microvm::resolve_running_vm_dir(name)?;
        FirecrackerIO::new(firecracker_socket(&vm_dir)).teardown_paused()
    };
    let _ = refuse_resume(
        name,
        "the resume was interrupted before the guest confirmed a reseed",
        stop,
    );
}

/// The resume summary if the guest confirmed a reseed, or why it did not.
fn resume_reseed_verdict(
    delivered: anyhow::Result<PostRestoreOutcome>,
) -> std::result::Result<String, String> {
    use mvm_core::vm_backend::ReseedStatus;
    match delivered {
        Ok(outcome) if outcome.reseeded => Ok(ReseedStatus::Rotated.resume_summary().to_string()),
        Ok(outcome) => Err(describe_missing_reseed(
            outcome.reseed_shortfall,
            outcome.detail.as_deref(),
        )),
        Err(error) => Err(format!(
            "the guest did not confirm a reseed ({error:#}); retry the resume"
        )),
    }
}

/// Refuse a resume whose guest did not reseed: stop its VMM with `stop`, mark
/// the machine paused again, and record the refusal under its own audit kind.
///
/// The sealed snapshot is not touched, so the resume can be retried; the retry
/// restores the snapshot into a fresh VMM and must reseed in turn.
fn refuse_resume(name: &str, why: &str, stop: impl FnOnce() -> anyhow::Result<()>) -> MvmError {
    let stopped = match stop() {
        Ok(()) => "its VMM was stopped".to_string(),
        Err(error) => format!("stopping its VMM also failed ({error:#}); stop it before retrying"),
    };
    let kept_paused = match set_registry_paused(name, true) {
        Ok(()) => String::new(),
        Err(error) => format!(" (marking it paused also failed: {error})"),
    };
    let refusal = format!(
        "refusing to resume VM {name:?}: {why}; {stopped}, and its sealed snapshot is kept{kept_paused}"
    );
    tracing::warn!(vm = %name, detail = %refusal, "refused a resume whose guest did not reseed");
    mvm_core::audit_emit!(ResumeRefused, vm: name, "{refusal}");
    backend_err(refusal)
}

/// Admit a warm resume only if the guest rotated its generation identity, or
/// the backend's warm start involves no restored memory to rotate from; the
/// reason for a refusal otherwise.
///
/// Refused on the same ground as a plain resume: live memory restored without
/// a reseed repeats random state the guest has already used. An undelivered
/// token is refused too, since nothing says the guest rotated.
fn warm_resume_reseed_verdict(
    reseed: mvm_core::vm_backend::ReseedStatus,
) -> std::result::Result<String, String> {
    use mvm_core::vm_backend::ReseedStatus;
    match reseed {
        ReseedStatus::Rotated | ReseedStatus::NotApplicable => {
            Ok(reseed.resume_summary().to_string())
        }
        ReseedStatus::NotRotated | ReseedStatus::Undelivered => Err(format!(
            "the warm start did not reseed the guest ({}); retry the resume",
            reseed.resume_summary()
        )),
    }
}

/// The detail of the `WorkloadWake` entry an admitted resume records: the
/// verified snapshot's epoch and lengths for a plain resume, the backend for a
/// warm one, and in both cases what happened to the guest's random state.
fn wake_audit_detail(warm: bool, backend: &str, outcome: &ResumeOutcome) -> String {
    let reseed = outcome.reseed.as_deref().unwrap_or("no reseed requested");
    if warm {
        format!("warm_start backend={backend} {reseed}")
    } else {
        format!(
            "epoch={} vmstate={} mem={} {reseed}",
            outcome.epoch, outcome.vmstate_len, outcome.mem_len
        )
    }
}

/// The production post-restore signal for a resume: a fresh generation token,
/// so the guest rotates its VMGenID and reseeds its CSPRNG, and the machine's
/// name as the guest hostname.
fn post_restore_signal(name: &str) -> VsockPostRestoreSignal {
    VsockPostRestoreSignal {
        token: mvm_core::crypto::vmgenid::fresh_generation_token(name).token,
        hostname: Some(name.to_string()),
        grant_envelope: None,
    }
}

/// The primed-barrier timeout to enforce before sealing, or `None` when the
/// barrier is not requested (or the backend is the hermetic mock, which has no
/// live guest agent to answer). Pure so the opt-in gating is unit-tested.
fn primed_barrier_timeout(opts: &PauseOpts, is_mock: bool) -> Option<std::time::Duration> {
    if opts.primed_barrier && !is_mock {
        Some(std::time::Duration::from_secs(opts.primed_timeout_secs))
    } else {
        None
    }
}

/// The Firecracker control socket path inside a running VM's state dir — the
/// `fc.socket` the start path actually creates.
fn firecracker_socket(vm_dir: &str) -> PathBuf {
    PathBuf::from(format!("{vm_dir}/fc.socket"))
}

/// Record the pause in the VM's state directory: stamp the live Firecracker
/// pid into `fc.paused`, so the quiesce gate can tell paused from running (FC
/// keeps its pid across a pause, so liveness alone cannot) and reconcile can
/// tell a paused VMM from an unadmitted resume, and withdraw the previous
/// admission. A VM with no `fc.pid` is not Firecracker and gets no marker. A
/// failure is an error: reconcile acts on this marker's absence.
fn write_fc_paused_marker(name: &str) -> Result<()> {
    mvm_runtime::vm::admission::record_paused(&vm_state_dir(name)).map_err(|e| {
        backend_err(format!(
            "VM {name:?} was paused and sealed, but recording the pause failed: {e:#}"
        ))
    })
}

/// Flip the persistent name-registry `paused` flag for `name`, under the
/// registry lock. A machine with no entry (a direct-boot VM) is not an error;
/// a registry that cannot be locked, read or written is, since reconcile acts
/// on this flag.
fn set_registry_paused(name: &str, paused: bool) -> Result<()> {
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    mvm_runtime::vm::name_registry::update_registry(&registry_path, |registry| {
        registry.set_paused(name, paused).map(|_| ())
    })
    .map_err(|e| backend_err(format!("updating the registry for VM {name:?}: {e:#}")))
}

/// Mark `name` resumed in the name registry and refresh its idle tracking so the
/// freshly-woken VM isn't immediately re-slept by the idle reaper. Same locking
/// and error rules as [`set_registry_paused`].
fn set_registry_resumed(name: &str) -> Result<()> {
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    mvm_runtime::vm::name_registry::update_registry(&registry_path, |registry| {
        registry.set_paused(name, false)?;
        registry.touch_last_active(name, mvm_core::time::utc_now())?;
        Ok(())
    })
    .map_err(|e| backend_err(format!("updating the registry for VM {name:?}: {e:#}")))
}

impl Default for LocalBackend {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn map_status(s: &VmStatus) -> MachineStatus {
    match s {
        VmStatus::Running => MachineStatus::Running,
        VmStatus::Starting => MachineStatus::Starting,
        VmStatus::Stopped => MachineStatus::Stopped,
        // A paused VM stays distinct from stopped so it remains visible in a
        // default listing rather than folding away.
        VmStatus::Paused => MachineStatus::Paused,
        VmStatus::Failed { .. } => MachineStatus::Failed,
    }
}

/// The detail behind a non-happy status — currently the failure reason, which
/// rides on [`MachineState::status_detail`] because [`MachineStatus::Failed`] is
/// a unit variant.
fn status_detail(s: &VmStatus) -> Option<String> {
    match s {
        VmStatus::Failed { reason } => Some(reason.clone()),
        VmStatus::Running | VmStatus::Starting | VmStatus::Stopped | VmStatus::Paused => None,
    }
}

/// Resolve the backend that owns a started VM by its state-dir marker, falling
/// back to the platform default so the column is accurate for a marker-less VM.
fn resolve_backend_name(vm_name: &str) -> String {
    AnyBackend::for_started_vm(vm_name)
        .map(|b| b.name().to_string())
        .unwrap_or_else(|| {
            if mvm_core::platform::current().is_hvf_default_tier() {
                "hvf".to_string()
            } else {
                "firecracker".to_string()
            }
        })
}

/// Load the persistent VM name registry, degrading to empty when absent or
/// unreadable so a listing falls back to backend-only rows rather than failing.
fn load_name_registry() -> VmNameRegistry {
    let path = mvm_runtime::vm::name_registry::registry_path();
    VmNameRegistry::load(&path).unwrap_or_default()
}

/// Best-effort removal of a machine name from the persistent VM name registry
/// after a successful stop, so it stops showing as registered. A load or save
/// failure is ignored — a direct-boot VM carries no registry entry, and the
/// stop this follows already succeeded regardless.
pub(crate) fn deregister_from_name_registry(name: &str) {
    let path = mvm_runtime::vm::name_registry::registry_path();
    if let Ok(mut registry) = VmNameRegistry::load(&path) {
        registry.deregister(name);
        let _ = registry.save(&path);
    }
}

/// Build a [`MachineState`] from a backend `VmInfo` joined with its optional
/// registry entry (tags / TTL / readiness) and its resolved owning backend.
fn to_state(info: VmInfo, reg: Option<&VmRegistration>) -> MachineState {
    let backend = resolve_backend_name(&info.name);
    MachineState {
        id: MachineId(info.id.0),
        status: map_status(&info.status),
        status_detail: status_detail(&info.status),
        backend,
        guest_ip: info.guest_ip,
        cpus: info.cpus,
        memory_mib: info.memory_mib,
        profile: info.profile,
        revision: info.revision,
        flake_ref: info.flake_ref,
        ports: info
            .ports
            .into_iter()
            .map(|p| PortMapping {
                host: p.host,
                guest: p.guest,
            })
            .collect(),
        tags: reg.map(|r| r.tags.clone()).unwrap_or_default(),
        expires_at: reg.and_then(|r| r.expires_at.clone()),
        auto_resume: reg.map(|r| r.auto_resume).unwrap_or(true),
        readiness: reg.and_then(|r| r.readiness.clone()),
        last_readiness_change_at: reg.and_then(|r| r.last_readiness_change_at.clone()),
        name: info.name,
    }
}

pub(crate) fn backend_err(e: impl std::fmt::Display) -> MvmError {
    MvmError::Backend {
        reason: e.to_string(),
    }
}

/// The work a declared rootfs source implies. One variant per verification
/// path: a materialized blob is booted as-is, a tree is injected and
/// materialized, and a reference is fetched from a registry first.
#[derive(Debug, PartialEq, Eq)]
enum RootfsPlan {
    /// An already-materialized `rootfs.ext4` — boot it directly.
    Materialized(PathBuf),
    /// An unpacked OCI rootfs directory — inject runtime + materialize.
    UnpackedDir(PathBuf),
    /// A registry reference — pull + unpack + inject + materialize.
    Pull(ImageReference),
}

/// Turn a caller-declared rootfs source into the work it implies.
///
/// The declaration arrives parsed, so a mistyped path stops here instead of
/// falling through to the registry arm: the arms differ in how the bytes they
/// produce are verified, and which one runs must not depend on the caller's
/// working directory.
fn plan_rootfs_source(source: RootfsSource) -> Result<RootfsPlan> {
    match source {
        // The filesystem is consulted only to tell a blob from a tree, and
        // only once the caller has declared the source local.
        RootfsSource::LocalPath(path) if path.is_file() => Ok(RootfsPlan::Materialized(path)),
        RootfsSource::LocalPath(path) if path.is_dir() => Ok(RootfsPlan::UnpackedDir(path)),
        RootfsSource::LocalPath(path) => Err(MvmError::InvalidSpec {
            reason: format!(
                "declared local rootfs path does not exist: {} — no registry fetch was \
                 attempted; write `oci:<reference>` to boot a registry image instead",
                path.display()
            ),
        }),
        RootfsSource::Oci { image_ref } => image_ref
            .parse::<ImageReference>()
            .map(RootfsPlan::Pull)
            .map_err(|e| MvmError::InvalidSpec {
                reason: format!(
                    "not a usable OCI reference: {image_ref:?}: {e}{}",
                    path_collision_hint(&image_ref)
                ),
            }),
        RootfsSource::Flake { flake_ref, attr } => Err(MvmError::InvalidSpec {
            reason: format!(
                "a flake source is built, not booted: build {flake_ref}#{attr} first, then \
                 declare the resulting rootfs path"
            ),
        }),
    }
}

/// A bare name is a registry reference by declaration, so a same-named file in
/// the caller's working directory is not silently preferred — but it is almost
/// certainly what they meant, so say so once the reference has failed to parse.
fn path_collision_hint(image_ref: &str) -> String {
    if Path::new(image_ref).exists() {
        format!(
            " (a filesystem entry named {image_ref:?} exists — write `./{image_ref}` or `path:{image_ref}` to boot it)"
        )
    } else {
        String::new()
    }
}

/// Materialize an OCI reference into a host `rootfs.ext4`, for a caller that
/// wants the artifact rather than a running machine.
///
/// The build path uses this so an image-backed `mvm.toml` is materialized by
/// exactly the code a `run --image` boots through — same pull, same hardened
/// unpack, same runtime injection, and the same `mvm-meta.json` sidecar written
/// beside the rootfs. A second materializer would be a second answer to "what
/// does this image become", and the two would drift.
///
/// `cache_key` names the cache slot under `~/.mvm/cache/local-run/`.
pub async fn materialize_image_rootfs(image_ref: &str, cache_key: &str) -> Result<PathBuf> {
    resolve_local_rootfs(
        &RootfsSource::Oci {
            image_ref: image_ref.to_string(),
        },
        cache_key,
    )
    .await
}

/// Resolve `spec.image` to a host `rootfs.ext4` path, materializing in-process
/// as needed (no subprocess, no CLI). Registry pulls are async; the dir +
/// pre-materialized cases are synchronous.
pub(crate) async fn resolve_local_rootfs(image: &RootfsSource, name: &str) -> Result<PathBuf> {
    match plan_rootfs_source(image.clone())? {
        RootfsPlan::Materialized(path) => Ok(path),
        // An already-unpacked tree carries no unpack report, so there is
        // nothing the host filesystem deferred to merge back in.
        RootfsPlan::UnpackedDir(dir) => materialize_from_dir(&dir, name, UnpackedLayers::default()),
        RootfsPlan::Pull(image_ref) => {
            let staging = tempfile::tempdir().map_err(backend_err)?;
            let layers = pull_image_to_dir(&image_ref, staging.path()).await?;
            materialize_from_dir(staging.path(), name, layers)
        }
    }
}

/// Cache location for a locally-materialized run rootfs, keyed by machine name.
fn run_rootfs_output(name: &str) -> PathBuf {
    let key: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    PathBuf::from(mvm_core::config::mvm_cache_dir())
        .join("local-run")
        .join(key)
        .join("rootfs.ext4")
}

/// What unpacking an image's layers produced beyond the host tree: the nodes
/// the host filesystem could not hold, and the owners it could not apply.
#[derive(Default)]
struct UnpackedLayers {
    deferred_nodes: Vec<mvm_fs::ext4::Node>,
    owners: mvm_fs::ownership::OwnerTable,
}

/// Inject the mvm runtime into an unpacked tree and materialize it into the
/// run-rootfs cache, reusing the CLI's shared `run_image` orchestration.
fn materialize_from_dir(dir: &Path, name: &str, layers: UnpackedLayers) -> Result<PathBuf> {
    let output = run_rootfs_output(name);
    let cache_root = PathBuf::from(mvm_core::config::mvm_cache_dir());
    // The library carries no guest binaries; remaining legacy injection needs
    // a source checkout or a complete compatibility cache.
    mvm_build::run_image::inject_and_materialize(
        mvm_build::run_image::InjectAndMaterializeRequest::builder(&cache_root, dir, &output, name)
            .sealed(false)
            .deferred_nodes(layers.deferred_nodes)
            .owners(layers.owners)
            .build(),
    )
    .map_err(|e| backend_err(format!("{e:#}")))?;
    Ok(output)
}

/// Pull a public OCI registry reference and unpack every layer into `dest`,
/// reusing mvm-oci's fetch + hardened unpacker (gzip is decoded here, at the
/// crate boundary, keeping mvm-oci decompressor-free by design).
async fn pull_image_to_dir(image_ref: &ImageReference, dest: &Path) -> Result<UnpackedLayers> {
    let reference = image_ref.canonical();
    let manifest_fetcher = OciManifestFetcher::new();
    let manifest = manifest_fetcher
        .fetch_linux_platform_manifest(image_ref, &current_linux_platform())
        .await
        .map_err(|e| backend_err(format!("fetch manifest for {reference}: {e}")))?;
    let layers = manifest
        .layers()
        .map_err(|e| backend_err(format!("parse layers for {reference}: {e}")))?;
    if layers.is_empty() {
        return Err(backend_err(format!("OCI image {reference} has no layers")));
    }
    let layer_fetcher =
        OciLayerFetcher::from_manifest_fetcher(&manifest_fetcher, LayerFetchOptions::default());
    let mut prior_layer_paths = std::collections::HashSet::new();
    let mut unpacked = UnpackedLayers::default();
    for layer in &layers {
        let mut bytes = Vec::new();
        layer_fetcher
            .fetch_layer(image_ref, layer, &mut bytes)
            .await
            .map_err(|e| backend_err(format!("fetch layer {}: {e}", layer.digest)))?;
        let report = unpack_one_layer(layer, &bytes, dest, &prior_layer_paths)?;
        unpacked.owners.absorb(&report.ownership);
        prior_layer_paths.extend(report.paths_written);
        unpacked.deferred_nodes.extend(report.deferred_nodes);
    }
    Ok(unpacked)
}

/// Unpack one layer's bytes into `dest`, decompressing gzip layers first.
fn unpack_one_layer(
    layer: &LayerDescriptor,
    bytes: &[u8],
    dest: &Path,
    prior_layer_paths: &HashSet<PathBuf>,
) -> Result<UnpackReport> {
    let mt = &layer.media_type;
    let report = if mt.ends_with("+gzip") || mt.ends_with(".gzip") || mt.contains("tar.gzip") {
        unpack_layer_with_prior_paths(
            GzDecoder::new(Cursor::new(bytes)),
            dest,
            &UnpackOptions::default(),
            prior_layer_paths,
        )
    } else {
        unpack_layer_with_prior_paths(
            Cursor::new(bytes),
            dest,
            &UnpackOptions::default(),
            prior_layer_paths,
        )
    }
    .map_err(|e| backend_err(format!("unpack layer {}: {e}", layer.digest)))?;
    if !report.refused.is_empty() {
        return Err(backend_err(format!(
            "layer {} unpack refused entries: {:?}",
            layer.digest, report.refused
        )));
    }
    Ok(report)
}

/// Probe the dm-verity sidecars the pure materializer writes beside the image
/// (`rootfs.verity` + `rootfs.roothash`) from the host filesystem. Returns
/// `(verity_path, roothash)` when both are present and the hash is well-formed
/// (64-hex); `(None, None)` for an unverified image. A `&Path` adapter over
/// `mvm_runtime::microvm::probe_verity_sidecar`, which does the host-side read.
pub(crate) fn host_verity_sidecars(rootfs: &Path) -> (Option<String>, Option<String>) {
    mvm_runtime::microvm::probe_verity_sidecar(&rootfs.to_string_lossy())
}

#[async_trait]
impl MvmClient for LocalBackend {
    async fn backend_capabilities(&self) -> Result<BackendCapabilityReport> {
        // Straight from the backend that will actually run the workload, so
        // the report cannot drift from the thing it describes.
        let capabilities = self.backend.capabilities();
        Ok(
            BackendCapabilityReport::new(self.backend.kind(), capabilities.clone())
                .with_operations(
                    ClientOperationCapabilities::builder()
                        .list(true)
                        .inspect(true)
                        .create(true)
                        .run(true)
                        .start(true)
                        .stop(true)
                        .pause(capabilities.pause_resume)
                        .resume(capabilities.pause_resume)
                        .remove(true)
                        .logs(true)
                        .reconfigure(true)
                        .set_ttl(true)
                        .build(),
                ),
        )
    }

    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>> {
        let registry = load_name_registry();

        // Aggregate every backend's live VMs (the host-wide view `mvmctl ls`
        // shows), then fold in this backend's own listing — the in-process mock
        // is excluded from `list_all`, so a single-backend caller (tests, a
        // mock-driven consumer) would otherwise see nothing. Dedup by name.
        let mut infos: Vec<VmInfo> = AnyBackend::list_all();
        for vm in self.backend.list().map_err(backend_err)? {
            if !infos.iter().any(|existing| existing.name == vm.name) {
                infos.push(vm);
            }
        }

        // Fold in registered-but-not-running machines as stopped rows so the
        // registry's TTL/tag metadata is listable; the CLI hides these unless
        // `--all` is asked.
        let listed: std::collections::BTreeSet<&str> =
            infos.iter().map(|i| i.name.as_str()).collect();
        let registry_only: Vec<VmInfo> = registry
            .vms
            .iter()
            .filter(|(name, _)| !listed.contains(name.as_str()))
            .map(|(name, reg)| VmInfo {
                id: VmId(name.clone()),
                name: name.clone(),
                status: VmStatus::Stopped,
                guest_ip: reg.guest_ip.clone(),
                cpus: 0,
                memory_mib: 0,
                profile: None,
                revision: None,
                flake_ref: None,
                ports: Vec::new(),
            })
            .collect();
        infos.extend(registry_only);

        Ok(infos
            .into_iter()
            .map(|info| {
                let reg = registry.lookup(&info.name);
                to_state(info, reg)
            })
            .filter(|m| filter.matches(m))
            .collect())
    }

    async fn inspect_machine(&self, id: &MachineId) -> Result<MachineState> {
        let registry = load_name_registry();
        self.backend
            .list()
            .map_err(backend_err)?
            .into_iter()
            .find(|v| v.id.0 == id.0)
            .map(|info| {
                let reg = registry.lookup(&info.name);
                to_state(info, reg)
            })
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })
    }

    async fn create_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        if !spec.env.is_empty() {
            return Err(MvmError::InvalidSpec {
                reason: "the persisted machine definition carries no environment variables; \
                         refusing to silently drop them (use the CLI run path)"
                    .into(),
            });
        }
        let mut builder = crate::launch::LaunchRequest::builder(
            crate::launch::LifecycleMode::Persistent,
            spec.image,
        )
        .name(spec.name)
        .cpus(spec.cpus)
        .memory_mib(spec.memory_mib);
        // Carried, never dropped — the same reason the env refusal above
        // exists. A permission set the caller believes is in force and is not
        // is worse than none at all, because it is believed. This is also the
        // only way a library caller expresses an egress allow-list.
        if let Some(grants) = spec.grants {
            builder = builder.grants(grants);
        }
        if let Some(path) = spec.assurance_campaign {
            builder = builder.assurance_campaign(path);
        }
        self.create_from_request(&builder.build()?)
    }

    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        // Env vars have no delivery seam on the in-process boot path; refuse
        // rather than silently drop values the caller believes were set.
        if !spec.env.is_empty() {
            return Err(MvmError::InvalidSpec {
                reason: "guest environment variables are not supported by the in-process \
                         local backend (no delivery seam); use the CLI run path"
                    .into(),
            });
        }
        let mut builder = crate::launch::LaunchRequest::builder(
            crate::launch::LifecycleMode::Transient,
            spec.image,
        )
        .name(spec.name)
        .cpus(spec.cpus)
        .memory_mib(spec.memory_mib);
        if let Some(grants) = spec.grants {
            builder = builder.grants(grants);
        }
        if let Some(path) = spec.assurance_campaign {
            builder = builder.assurance_campaign(path);
        }
        let outcome = self.launch(builder.build()?).await?;
        Ok(outcome.machine)
    }

    async fn start_machine(&self, id: &MachineId) -> Result<MachineState> {
        self.start_persistent(&id.0).await
    }

    async fn stop_machine(&self, id: &MachineId) -> Result<()> {
        let vid = VmId(id.0.clone());
        // Stop via the VMM that actually started this VM (resolved from its
        // per-VM state-dir pid marker) so a QEMU/libkrun VM is torn down by its
        // own hypervisor, not this client's default. A marker-less VM (mock or
        // direct-boot) has no owning marker, so fall back to this client's
        // configured backend — which keeps a `with_hypervisor("mock")` client
        // hermetic rather than reaching a platform default.
        let result = match AnyBackend::for_started_vm(&id.0) {
            Some(owner) => owner.stop(&vid),
            None => self.backend.stop(&vid),
        };
        // Deregister from the name registry only on a successful stop; on
        // failure the entry (and any readiness the caller recorded) stays so
        // the user can see what happened. A persistent machine's spec is
        // never touched by stop — only remove deletes a definition.
        if result.is_ok() {
            deregister_from_name_registry(&id.0);
            // Release the stopped owner's volume-attachment leases (re-sealing
            // any just-in-time unlocked volume). Best-effort: the stop itself
            // already succeeded.
            use crate::volume::VolumeService as _;
            if let Err(e) = crate::volume::LocalVolumeService::new().release_owner_leases(&id.0) {
                tracing::warn!(error = %e, machine = %id.0, "releasing volume leases after stop failed");
            }
        }
        result.map_err(backend_err)
    }

    async fn pause_machine(&self, id: &MachineId, opts: PauseOpts) -> Result<PauseOutcome> {
        let name = &id.0;
        let backend = self.lifecycle_backend_for(name);
        // The same per-machine lock a resume holds: a pause racing a resume
        // would otherwise seal and mark paused a machine the resume then marks
        // resumed, or the reverse.
        let _lifecycle = mvm_runtime::vm::instance_snapshot::lock_resume(name)
            .map_err(|e| backend_err(format!("{e:#}")))?;

        // Opt-in warm-base barrier: wait for the workload to signal "primed"
        // before sealing. Fails closed — a timeout propagates so no half-warmed
        // snapshot is sealed. Skipped for the mock (no guest agent to answer).
        if let Some(timeout) = primed_barrier_timeout(&opts, Self::is_mock_backend(&backend)) {
            let source = VsockPrimedSignalSource {
                vm_name: name.clone(),
                poll_interval: std::time::Duration::from_millis(500),
            };
            await_primed_barrier(&source, timeout)
                .map_err(|e| backend_err(format!("primed barrier for VM {name:?}: {e:#}")))?;
        }

        if !Self::uses_sealed_snapshot(&backend) {
            backend
                .pause(&VmId(name.clone()))
                .map_err(|e| backend_err(format!("pausing VM {name:?}: {e:#}")))?;
            set_registry_paused(name, true)?;
            return Ok(PauseOutcome::default());
        }

        let io = self.snapshot_io_for(&backend, name)?;
        let sidecar = pause_and_seal(name, &*io)
            .map_err(|e| backend_err(format!("pausing VM {name:?}: {e:#}")))?;

        write_fc_paused_marker(name)?;
        set_registry_paused(name, true)?;

        Ok(PauseOutcome {
            epoch: sidecar.epoch,
            vmstate_len: sidecar.vmstate_len,
            mem_len: sidecar.mem_len,
        })
    }

    async fn resume_machine(&self, id: &MachineId, opts: ResumeOpts) -> Result<ResumeOutcome> {
        let backend = self.lifecycle_backend_for(&id.0);
        // One resume of a machine at a time, held until its guest is admitted
        // or refused: a second resume must not restore over a guest the first
        // is still admitting, or stop the VMM the first is waiting on.
        let _resuming = mvm_runtime::vm::instance_snapshot::lock_resume(&id.0)
            .map_err(|e| backend_err(format!("{e:#}")))?;
        // `warm` routes through the backend's live-memory warm-start path (fails
        // closed on a disk-only backend); the default plain path verifies +
        // restores the sealed snapshot and signals the guest.
        let outcome = if opts.warm {
            self.warm_resume(&backend, &id.0)
        } else {
            self.plain_resume(&backend, &id.0)
        }?;
        // Recorded here rather than by each caller, so a resume from any
        // surface leaves the same entry, carrying the reseed outcome.
        let detail = wake_audit_detail(opts.warm, backend.kind().as_str(), &outcome);
        mvm_core::audit_emit!(WorkloadWake, vm: &id.0, "{detail}");
        Ok(outcome)
    }

    async fn set_ttl(&self, id: &MachineId, expires_at: Option<String>) -> Result<()> {
        let path = mvm_runtime::vm::name_registry::registry_path();
        let mut registry = VmNameRegistry::load(&path).map_err(|e| {
            backend_err(format!(
                "loading VM name registry at {}: {e}",
                path.display()
            ))
        })?;
        let updated = registry
            .set_expires_at(&id.0, expires_at)
            .map_err(|e| backend_err(format!("updating registry record: {e}")))?;
        if !updated {
            return Err(MvmError::NotFound { id: id.0.clone() });
        }
        registry.save(&path).map_err(|e| {
            backend_err(format!(
                "saving VM name registry at {}: {e}",
                path.display()
            ))
        })
    }

    async fn remove_machine(&self, id: &MachineId) -> Result<()> {
        // The non-forced flow: a RUNNING persistent machine is refused (the
        // reviewed force flow is `remove_machine_with`); a stopped persistent
        // definition is deleted; a spec-less name gets idempotent transient
        // cleanup. Removing an absent machine is `Ok` (trait contract).
        self.remove_machine_with(id, crate::launch::RemoveOptions::default())
            .await
    }

    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>> {
        let lines = opts.tail_lines.unwrap_or(200);
        let text = self
            .backend
            .logs(&VmId(id.0.clone()), lines, false)
            .map_err(backend_err)?;
        Ok(text.into_bytes())
    }

    async fn exec_machine(&self, _id: &MachineId, _command: Vec<String>) -> Result<ExecResult> {
        // The backend dispatch (`AnyBackend`) exposes no exec seam; in-guest exec
        // goes through the agent RPC path, which is not wired here.
        Err(MvmError::Backend {
            reason: "local exec requires the guest-agent exec seam (not wired)".into(),
        })
    }

    async fn reconfigure_machine(
        &self,
        id: &MachineId,
        cfg: mvm_core::client::dto::ReconfigureRequest,
    ) -> Result<MachineState> {
        use mvm_runtime::machine::persist as mp;

        // Claim-10: this backend's in-process boot does not enforce network
        // policy, so a net/allow_host change would persist-but-not-enforce.
        // Refuse rather than silently fail open.
        if cfg.net.is_some() || cfg.allow_host.is_some() {
            return Err(MvmError::InvalidSpec {
                reason: "changing network policy (net/allow_host) via reconfigure is not \
                         supported on the in-process local backend (its boot path does not \
                         enforce egress policy); use the CLI verb or the gateway backend"
                    .into(),
            });
        }

        // A microVM with 0 vCPUs is invalid; the CLI create path already
        // rejects it — don't apply/persist/relaunch a 0-cpu spec here either.
        if cfg.cpus == Some(0) {
            return Err(MvmError::InvalidSpec {
                reason: "cpus must be >= 1".into(),
            });
        }

        let existing = mp::load_machine_spec(&id.0).map_err(backend_err)?;

        let patch = mp::ReconfigurePatch {
            net: None,
            allow_host: None,
            cpus: cfg.cpus,
            memory: cfg.memory_mib.map(|m| format!("{m}M")),
            mem_initial: None,
        };
        let desired = mp::apply_patch(existing.clone(), &patch);

        mp::validate_machine_memory(&desired.memory, desired.mem_initial.as_deref())
            .map_err(backend_err)?;

        let changed = mp::machine_config_diff(&existing, &desired);
        if changed.is_empty() {
            // Report the machine's actual status rather than assuming
            // Stopped — a no-op reconfigure on a running machine should
            // still say Running.
            let status = match self.backend.status(&VmId(id.0.clone())) {
                Ok(s) => map_status(&s),
                Err(_) => MachineStatus::Stopped,
            };
            return Ok(MachineState {
                id: id.clone(),
                name: existing.name,
                status,
                ..Default::default()
            });
        }

        mp::overwrite_machine_spec(&desired).map_err(backend_err)?;

        // Relaunch if running: stop then in-process admitted boot with the new resources.
        let vid = VmId(id.0.clone());
        let was_running = matches!(self.backend.status(&vid), Ok(VmStatus::Running));
        if was_running {
            self.backend.stop(&vid).map_err(backend_err)?;
            // Relaunch the persisted definition through the persistent start
            // path — the same admitted boot every lifecycle verb uses.
            return self.start_persistent(&desired.name).await;
        }

        Ok(MachineState {
            id: id.clone(),
            name: desired.name,
            status: MachineStatus::Stopped,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "test-support")]
    use mvm_core::util::test_env::TestEnv;

    use mvm_runtime::vm::instance_snapshot::ReseedShortfall;

    /// How a fake resumed guest answers the post-restore signal.
    #[derive(Clone, Copy)]
    enum Guest {
        /// The agent never becomes reachable (stopped, wedged, or slow).
        Unreachable,
        /// The signal is sent and the RPC fails.
        RpcFails,
        /// The guest answers but does not acknowledge the restore.
        NoAck,
        /// The guest acknowledges but did not resync its wall clock.
        ClockNotResynced,
        /// The guest acknowledges and reports it did not reseed.
        NotReseeded(ReseedShortfall),
        /// The guest acknowledges and reseeded.
        Reseeded,
        /// The exchange hangs well past any admission budget.
        Hangs,
    }

    impl PostRestoreSignal for Guest {
        fn probe_ready(&self, _: &str) -> bool {
            !matches!(self, Guest::Unreachable)
        }

        fn post_restore(&self, _: &str) -> anyhow::Result<PostRestoreOutcome> {
            let replied = |acknowledged, clock_resynced, reseeded, reseed_shortfall| {
                Ok(PostRestoreOutcome {
                    acknowledged,
                    detail: Some("from the fake guest".to_string()),
                    reseeded,
                    clock_resynced,
                    reseed_shortfall,
                })
            };
            match *self {
                Guest::Unreachable => unreachable!("never probed ready"),
                Guest::RpcFails => anyhow::bail!("vsock connection reset"),
                Guest::NoAck => replied(false, true, false, None),
                Guest::ClockNotResynced => replied(true, false, true, None),
                Guest::NotReseeded(shortfall) => replied(true, true, false, Some(shortfall)),
                Guest::Reseeded => replied(true, true, true, None),
                Guest::Hangs => {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    replied(true, true, true, None)
                }
            }
        }
    }

    const QUICK: AdmissionTimeouts = AdmissionTimeouts {
        ready: std::time::Duration::from_millis(20),
        reply: std::time::Duration::from_millis(200),
    };

    fn verdict(guest: Guest) -> std::result::Result<String, String> {
        resume_reseed_verdict(signal_within("vm-a", guest, QUICK))
    }

    /// A guest whose exchange never finishes is refused at the admission
    /// deadline, not after the transport's own timeouts.
    #[test]
    fn a_guest_that_does_not_answer_is_refused_at_the_deadline() {
        let started = std::time::Instant::now();
        let why = verdict(Guest::Hangs).expect_err("refused");
        assert!(why.contains("did not answer"), "{why}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(4),
            "refused after {:?}, not at the deadline",
            started.elapsed()
        );
    }

    #[test]
    fn the_production_admission_deadline_is_the_documented_fifteen_seconds() {
        assert_eq!(
            RESUME_ADMISSION.deadline(),
            std::time::Duration::from_secs(15)
        );
    }

    /// Every way a resumed guest can fail to confirm a reseed is a refusal,
    /// not only a reported shortfall: a stalled agent, a failed RPC, an
    /// unacknowledged signal and an unsynced clock included.
    #[test]
    fn every_unconfirmed_reseed_is_refused() {
        for (guest, expect) in [
            (Guest::Unreachable, "did not become reachable"),
            (Guest::RpcFails, "vsock connection reset"),
            (Guest::NoAck, "did not acknowledge"),
            (Guest::ClockNotResynced, "wall clock"),
            (
                Guest::NotReseeded(ReseedShortfall::HelperMissing),
                "rebuild the image",
            ),
            (
                Guest::NotReseeded(ReseedShortfall::Failed),
                "retry the restore",
            ),
        ] {
            let why = verdict(guest).expect_err("refused");
            assert!(why.contains(expect), "{why}");
        }
    }

    /// A reported shortfall is refused with the fork path's own words.
    #[test]
    fn a_reported_shortfall_uses_the_fork_paths_guidance() {
        let why = verdict(Guest::NotReseeded(ReseedShortfall::HelperMissing)).unwrap_err();
        assert_eq!(
            why,
            describe_missing_reseed(
                Some(ReseedShortfall::HelperMissing),
                Some("from the fake guest")
            )
        );
    }

    #[test]
    fn a_confirmed_reseed_is_admitted() {
        assert_eq!(verdict(Guest::Reseeded).as_deref(), Ok("VMGenID rotated"));
    }

    #[test]
    fn a_warm_resume_without_a_rotation_is_refused() {
        use mvm_core::vm_backend::ReseedStatus;
        for admitted in [ReseedStatus::Rotated, ReseedStatus::NotApplicable] {
            assert!(warm_resume_reseed_verdict(admitted).is_ok());
        }
        for refused in [ReseedStatus::NotRotated, ReseedStatus::Undelivered] {
            let why = warm_resume_reseed_verdict(refused).unwrap_err();
            assert!(why.contains("did not reseed"), "{why}");
        }
    }

    #[test]
    fn the_wake_entry_carries_the_reseed_outcome() {
        let plain = ResumeOutcome {
            epoch: 3,
            vmstate_len: 12,
            mem_len: 8,
            reseed: Some("VMGenID rotated".to_string()),
        };
        assert_eq!(
            wake_audit_detail(false, "firecracker", &plain),
            "epoch=3 vmstate=12 mem=8 VMGenID rotated"
        );
        let warm = ResumeOutcome {
            reseed: Some("VMGenID rotated".to_string()),
            ..Default::default()
        };
        assert_eq!(
            wake_audit_detail(true, "hvf", &warm),
            "warm_start backend=hvf VMGenID rotated"
        );
        assert!(
            wake_audit_detail(false, "firecracker", &ResumeOutcome::default())
                .ends_with("no reseed requested")
        );
    }

    /// The side effects of a refusal, against an isolated `MVM_HOME`: the VMM
    /// is stopped, the machine is paused in the registry rather than resumed,
    /// and the refusal is audited under its own kind.
    #[cfg(feature = "test-support")]
    fn refusal_side_effects(guest: Guest) -> (bool, String, String) {
        let data = IsolatedDataDir::new();
        let registry_path = mvm_runtime::vm::name_registry::registry_path();
        let mut registry = VmNameRegistry::default();
        registry
            .register("vm-a", "/vms/vm-a", "default", None, 0)
            .expect("register");
        registry.save(&registry_path).expect("save registry");

        let stopped = std::cell::Cell::new(false);
        let refusal = admit_resumed_guest(
            "vm-a",
            guest,
            QUICK,
            &AdmissionClaim::default(),
            || Ok(()),
            || {
                stopped.set(true);
                Ok(())
            },
        )
        .expect_err("refused")
        .to_string();

        let paused = VmNameRegistry::load(&registry_path)
            .expect("registry")
            .lookup("vm-a")
            .map(|record| record.paused)
            .unwrap_or(false);
        assert!(paused, "a refused machine is paused, not resumed");
        let log = std::fs::read_to_string(mvm_core::policy::audit::default_audit_log())
            .unwrap_or_default();
        drop(data);
        (stopped.get(), refusal, log)
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn a_refused_resume_stops_the_vmm_pauses_the_machine_and_is_audited() {
        for guest in [
            Guest::Unreachable,
            Guest::RpcFails,
            Guest::NoAck,
            Guest::ClockNotResynced,
            Guest::NotReseeded(ReseedShortfall::Failed),
            Guest::Hangs,
        ] {
            let (stopped, refusal, log) = refusal_side_effects(guest);
            assert!(stopped, "the VMM must not keep running: {refusal}");
            assert!(refusal.contains("its VMM was stopped"), "{refusal}");
            assert!(refusal.contains("sealed snapshot is kept"), "{refusal}");
            assert!(log.contains("\"resume_refused\""), "{log}");
            assert!(!log.contains("\"vm_stop\""), "not an ordinary stop: {log}");
        }
    }

    /// Registers `name` in the isolated registry, unpaused.
    #[cfg(feature = "test-support")]
    fn register(name: &str) -> std::path::PathBuf {
        let registry_path = mvm_runtime::vm::name_registry::registry_path();
        let mut registry = VmNameRegistry::load(&registry_path).expect("registry");
        registry
            .register(name, &format!("/vms/{name}"), "default", None, 0)
            .expect("register");
        registry.save(&registry_path).expect("save registry");
        registry_path
    }

    #[cfg(feature = "test-support")]
    fn is_paused(registry_path: &std::path::Path, name: &str) -> bool {
        VmNameRegistry::load(registry_path)
            .expect("registry")
            .lookup(name)
            .is_some_and(|record| record.paused)
    }

    #[cfg(feature = "test-support")]
    fn audit_log() -> String {
        std::fs::read_to_string(mvm_core::policy::audit::default_audit_log()).unwrap_or_default()
    }

    /// An interrupt while a resume is admitting its guest runs the cleanup
    /// the resume armed: the machine is left paused and the refusal is
    /// recorded, exactly as a refused admission would be.
    #[test]
    #[cfg(feature = "test-support")]
    fn an_interrupt_during_admission_stops_and_records_the_resume() {
        let _data = IsolatedDataDir::new();
        let registry_path = register("vm-int");
        let claim = AdmissionClaim::default();
        let _armed = arm_interrupted_admission("vm-int", &claim);
        let processed = mvm_runtime::interrupt_cleanup::run_all();
        assert!(processed.contains(&"resume of vm-int".to_string()));
        assert!(is_paused(&registry_path, "vm-int"), "left paused");
        let log = audit_log();
        assert!(log.contains("\"resume_refused\""), "{log}");
        assert!(log.contains("interrupted"), "{log}");
        assert!(
            !claim.refuse(),
            "the interrupt settled it; no second refusal"
        );
    }

    /// An interrupt that lands after the guest was admitted, but before the
    /// resume withdrew its cleanup, stops nothing and records nothing.
    #[test]
    #[cfg(feature = "test-support")]
    fn an_interrupt_after_admission_leaves_the_guest_running() {
        let _data = IsolatedDataDir::new();
        let registry_path = register("vm-late");
        let claim = AdmissionClaim::default();
        let _armed = arm_interrupted_admission("vm-late", &claim);
        assert!(claim.admit(|| Ok(())).expect("admitted"));
        mvm_runtime::interrupt_cleanup::run_all();
        assert!(!is_paused(&registry_path, "vm-late"), "not refused");
        assert!(!audit_log().contains("\"resume_refused\""));
    }

    #[test]
    fn an_admission_is_settled_exactly_once() {
        let claim = AdmissionClaim::default();
        assert!(claim.refuse(), "the first refusal settles it");
        assert!(!claim.refuse(), "a second refusal is not recorded again");
        assert!(
            !claim.admit(|| Ok(())).expect("no error"),
            "refused stays refused"
        );

        let admitted = AdmissionClaim::default();
        assert!(admitted.admit(|| Ok(())).expect("admitted"));
        assert!(!admitted.refuse(), "an admitted guest is not refused");

        let unrecorded = AdmissionClaim::default();
        unrecorded
            .admit(|| anyhow::bail!("disk full"))
            .expect_err("a failed record is not an admission");
        assert!(unrecorded.refuse(), "and it can still be refused");
    }

    /// A guest that reseeded but whose admission could not be recorded is
    /// refused, and the reason says so rather than blaming the guest.
    #[test]
    #[cfg(feature = "test-support")]
    fn an_admission_that_cannot_be_recorded_is_refused_for_that_reason() {
        let _data = IsolatedDataDir::new();
        register("vm-rec");
        let refusal = admit_resumed_guest(
            "vm-rec",
            Guest::Reseeded,
            QUICK,
            &AdmissionClaim::default(),
            || anyhow::bail!("no space left on device"),
            || Ok(()),
        )
        .expect_err("refused")
        .to_string();
        assert!(refusal.contains("could not be recorded"), "{refusal}");
        assert!(refusal.contains("no space left"), "{refusal}");
    }

    /// A sealed resume restores only a machine the registry records as
    /// paused, and refuses before it loads anything otherwise.
    #[test]
    #[cfg(feature = "test-support")]
    fn a_sealed_resume_refuses_a_machine_that_is_not_paused() {
        let _data = IsolatedDataDir::new();
        let canned = CannedIO::new(b"vmstate".to_vec(), b"mem".to_vec());
        mvm_runtime::vm::instance_snapshot::pause_and_seal("vm-run", &canned).expect("sealed");
        let before = canned.calls().len();

        let unregistered = resume_sealed("vm-run", &canned, Guest::Reseeded, QUICK)
            .expect_err("no record")
            .to_string();
        assert!(
            unregistered.contains("no registry record"),
            "{unregistered}"
        );

        register("vm-run");
        let running = resume_sealed("vm-run", &canned, Guest::Reseeded, QUICK)
            .expect_err("not paused")
            .to_string();
        assert!(running.contains("is not paused"), "{running}");
        assert_eq!(canned.calls().len(), before, "nothing was loaded");
    }

    /// A pause waits for a resume of the same machine to finish.
    #[test]
    #[cfg(feature = "test-support")]
    fn a_pause_waits_for_a_resume_in_progress() {
        let _data = IsolatedDataDir::new();
        std::fs::create_dir_all(mvm_runtime::MockBackend::vm_dir("vm-race")).unwrap();
        let resuming = mvm_runtime::vm::instance_snapshot::lock_resume("vm-race").expect("lock");
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished = std::sync::Arc::clone(&done);
        let pause = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime.block_on(
                LocalBackend::with_hypervisor("mock")
                    .pause_machine(&MachineId("vm-race".into()), PauseOpts::default()),
            );
            finished.store(true, std::sync::atomic::Ordering::SeqCst);
            result
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            !done.load(std::sync::atomic::Ordering::SeqCst),
            "the pause must wait while a resume holds the machine"
        );
        drop(resuming);
        pause
            .join()
            .unwrap()
            .expect("the pause completes once the resume is done");
    }

    /// Answers the post-restore signal as a guest that reseeded, recording
    /// which interrupt cleanups were registered while it was being asked.
    #[cfg(feature = "test-support")]
    struct CleanupObservingGuest(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    #[cfg(feature = "test-support")]
    impl PostRestoreSignal for CleanupObservingGuest {
        fn probe_ready(&self, _: &str) -> bool {
            true
        }
        fn post_restore(&self, _: &str) -> anyhow::Result<PostRestoreOutcome> {
            *self.0.lock().unwrap() = mvm_runtime::interrupt_cleanup::pending();
            Guest::Reseeded.post_restore("")
        }
    }

    /// A sealed resume keeps its interrupt cleanup armed while the guest is
    /// being admitted, records the admission next to `fc.pid`, marks the
    /// machine resumed, and withdraws the cleanup once it returns.
    #[test]
    #[cfg(feature = "test-support")]
    fn a_sealed_resume_is_interruptible_until_it_admits_its_guest() {
        let _data = IsolatedDataDir::new();
        let registry_path = register("vm-seal");
        let canned = CannedIO::new(b"vmstate".to_vec(), b"mem".to_vec());
        mvm_runtime::vm::instance_snapshot::pause_and_seal("vm-seal", &canned).expect("sealed");
        let state_dir = vm_state_dir("vm-seal");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("fc.pid"), std::process::id().to_string()).unwrap();
        set_registry_paused("vm-seal", true).unwrap();

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (_, reseed) = resume_sealed(
            "vm-seal",
            &canned,
            CleanupObservingGuest(std::sync::Arc::clone(&seen)),
            QUICK,
        )
        .expect("admitted");
        assert_eq!(reseed, "VMGenID rotated");
        assert!(
            seen.lock()
                .unwrap()
                .contains(&"resume of vm-seal".to_string()),
            "an interrupt during admission would have stopped the VMM"
        );
        assert!(
            !mvm_runtime::interrupt_cleanup::pending().contains(&"resume of vm-seal".to_string()),
            "the cleanup is withdrawn once the guest is admitted"
        );
        assert!(
            state_dir.join("fc.admitted").exists(),
            "the admission is recorded"
        );
        assert!(
            !is_paused(&registry_path, "vm-seal"),
            "and the machine is resumed"
        );
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn a_refusal_whose_stop_fails_says_so() {
        let _data = IsolatedDataDir::new();
        let refusal = admit_resumed_guest(
            "vm-a",
            Guest::NoAck,
            QUICK,
            &AdmissionClaim::default(),
            || Ok(()),
            || anyhow::bail!("still running after SIGTERM and SIGKILL"),
        )
        .expect_err("refused")
        .to_string();
        assert!(
            refusal.contains("stopping its VMM also failed"),
            "{refusal}"
        );
        assert!(refusal.contains("still running"), "{refusal}");
        assert!(!refusal.contains("its VMM was stopped"), "{refusal}");
    }

    #[test]
    fn auto_selected_backend_name_exposes_only_standard_backends() {
        assert!(
            matches!(auto_selected_backend_name().as_str(), "firecracker" | "hvf"),
            "automatic selection must never expose an opt-in backend"
        );
    }

    // Only the mock-driven `LocalBackend` tests below need an isolated
    // `MVM_HOME` (they boot/list/stop machines against real on-disk state);
    // gated together with the mock backend those tests exercise.
    #[cfg(feature = "test-support")]
    static DATA_DIR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(feature = "test-support")]
    struct IsolatedDataDir {
        _lock: std::sync::MutexGuard<'static, ()>,
        _env: TestEnv,
        dir: tempfile::TempDir,
    }

    #[cfg(feature = "test-support")]
    impl IsolatedDataDir {
        fn new() -> Self {
            let lock = DATA_DIR_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let dir = tempfile::tempdir().unwrap();
            let mut env = TestEnv::new();
            env.set("MVM_HOME", dir.path());
            Self {
                _lock: lock,
                _env: env,
                dir,
            }
        }

        fn path(&self) -> &std::path::Path {
            self.dir.path()
        }
    }

    #[test]
    fn status_maps_all_variants() {
        assert_eq!(map_status(&VmStatus::Running), MachineStatus::Running);
        assert_eq!(map_status(&VmStatus::Starting), MachineStatus::Starting);
        assert_eq!(map_status(&VmStatus::Stopped), MachineStatus::Stopped);
        // Paused stays distinct from Stopped (it must remain visible by default).
        assert_eq!(map_status(&VmStatus::Paused), MachineStatus::Paused);
        assert_eq!(
            map_status(&VmStatus::Failed {
                reason: "boom".into()
            }),
            MachineStatus::Failed
        );
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn local_operation_report_omits_the_unwired_exec_seam() {
        let operations = LocalBackend::with_hypervisor("mock")
            .backend_capabilities()
            .await
            .expect("local capabilities")
            .operations;
        assert!(operations.list && operations.inspect && operations.run);
        assert!(operations.create && operations.start && operations.stop);
        assert!(operations.remove && operations.logs && operations.reconfigure);
        assert!(operations.set_ttl);
        assert!(!operations.exec);
    }

    #[test]
    fn status_detail_carries_only_failure_reason() {
        assert_eq!(
            status_detail(&VmStatus::Failed {
                reason: "boom".into()
            }),
            Some("boom".to_string())
        );
        assert_eq!(status_detail(&VmStatus::Running), None);
        assert_eq!(status_detail(&VmStatus::Paused), None);
    }

    #[test]
    fn to_state_joins_backend_info_with_registry_metadata() {
        let info = VmInfo {
            id: VmId("vm-1".into()),
            name: "web".into(),
            status: VmStatus::Running,
            guest_ip: Some("172.16.0.2".into()),
            cpus: 2,
            memory_mib: 512,
            profile: Some("worker".into()),
            revision: None,
            flake_ref: Some(".#worker".into()),
            ports: vec![mvm_core::protocol::vm_backend::VmPortMapping {
                host: 8080,
                guest: 80,
            }],
        };
        let mut registry = VmNameRegistry::default();
        let mut tags = std::collections::BTreeMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        registry
            .register_with_metadata(mvm_runtime::vm::name_registry::RegisterParams {
                name: "web",
                vm_dir: "/tmp/web",
                network: "default",
                guest_ip: Some("172.16.0.2"),
                slot_index: 0,
                tags,
                expires_at: Some("2099-01-01T00:00:00Z".into()),
                auto_resume: false,
            })
            .unwrap();

        let state = to_state(info, registry.lookup("web"));
        assert_eq!(state.name, "web");
        assert_eq!(state.status, MachineStatus::Running);
        assert_eq!(state.cpus, 2);
        assert_eq!(state.memory_mib, 512);
        assert_eq!(state.flake_ref.as_deref(), Some(".#worker"));
        assert_eq!(
            state.ports,
            vec![PortMapping {
                host: 8080,
                guest: 80
            }]
        );
        assert_eq!(state.tags.get("env").map(String::as_str), Some("prod"));
        assert_eq!(state.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert!(!state.auto_resume);
        // No registry entry → metadata defaults (auto_resume true).
        let bare = to_state(
            VmInfo {
                id: VmId("vm-2".into()),
                name: "solo".into(),
                status: VmStatus::Stopped,
                guest_ip: None,
                cpus: 0,
                memory_mib: 0,
                profile: None,
                revision: None,
                flake_ref: None,
                ports: Vec::new(),
            },
            None,
        );
        assert!(bare.tags.is_empty() && bare.auto_resume && bare.expires_at.is_none());
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn list_over_mock_backend_succeeds() {
        // `list_machines` unions the host-wide backend scan + name registry, so
        // isolate the data dir or leftover real `~/.mvm/vms` state leaks in.
        let _data = IsolatedDataDir::new();
        let be = LocalBackend::with_hypervisor("mock");
        let machines = be.list_machines(MachineFilter::all()).await.unwrap();
        let none = be
            .list_machines(MachineFilter {
                name: Some("definitely-not-present-xyz".into()),
                status: None,
            })
            .await
            .unwrap();
        assert!(none.len() <= machines.len());
    }

    /// `std::env::set_current_dir` is process-wide; this Mutex stops
    /// `cargo test`'s thread pool from racing between two cwd-mutating tests.
    /// The lock is held for the lifetime of [`CwdGuard`].
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct CwdGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: PathBuf,
    }

    impl CwdGuard {
        fn enter(dir: &Path) -> Self {
            let guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::current_dir().expect("cwd");
            std::env::set_current_dir(dir).expect("chdir");
            CwdGuard {
                _guard: guard,
                prev,
            }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev);
        }
    }

    fn reference(s: &str) -> ImageReference {
        s.parse().expect("parses as an OCI reference")
    }

    /// Both steps a caller takes with a declaration string — parse it, then
    /// plan the work — so these tests keep exercising the grammar rather than
    /// hand-building the parsed value.
    fn plan_rootfs(image: &str) -> Result<RootfsPlan> {
        let source: RootfsSource = image.parse().map_err(|e| MvmError::InvalidSpec {
            reason: format!("{e}"),
        })?;
        plan_rootfs_source(source)
    }

    #[test]
    fn plan_rootfs_routes_file_dir_and_registry() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("rootfs.ext4");
        std::fs::write(&file, b"x").unwrap();

        // An existing file → a materialized rootfs.
        assert_eq!(
            plan_rootfs(&file.to_string_lossy()).unwrap(),
            RootfsPlan::Materialized(file.clone())
        );
        // An existing directory → an unpacked tree.
        assert_eq!(
            plan_rootfs(&dir.path().to_string_lossy()).unwrap(),
            RootfsPlan::UnpackedDir(dir.path().to_path_buf())
        );
        // A reference → a pull (no network touched here).
        assert_eq!(
            plan_rootfs("docker.io/library/alpine:3.20").unwrap(),
            RootfsPlan::Pull(reference("docker.io/library/alpine:3.20"))
        );
    }

    #[test]
    fn a_mistyped_local_path_is_refused_and_never_planned_as_a_pull() {
        let dir = tempfile::tempdir().unwrap();
        // The user meant `rootfs.ext4`; nothing exists at what they typed.
        let typo = dir.path().join("rootfs.ext5");

        let planned = plan_rootfs(&typo.to_string_lossy());

        // `Pull` is the only variant that reaches a registry, so refusing to
        // produce one is what "no fetch was attempted" means here.
        assert!(
            !matches!(planned, Ok(RootfsPlan::Pull(_))),
            "a typo'd local path must not be planned as a registry pull: {planned:?}"
        );
        let err = planned.expect_err("an absent declared path is an error");
        assert!(
            matches!(err, MvmError::InvalidSpec { .. }),
            "expected a spec error naming the path, got {err:?}"
        );
        assert!(
            err.to_string().contains(&typo.display().to_string()),
            "the error must name the path the caller typed: {err}"
        );
    }

    #[tokio::test]
    async fn resolve_local_rootfs_refuses_a_mistyped_path_before_any_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let typo = dir.path().join("rootfs.ext5");

        let declared: RootfsSource = typo.to_string_lossy().parse().expect("a path parses");
        let err = crate::local::resolve_local_rootfs(&declared, "m")
            .await
            .expect_err("an absent declared path is an error");

        assert!(matches!(err, MvmError::InvalidSpec { .. }), "got {err:?}");
        assert!(err.to_string().contains(&typo.display().to_string()));
    }

    #[test]
    fn a_registry_reference_survives_a_colliding_working_directory_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("alpine:3.20"), b"decoy").unwrap();
        std::fs::create_dir(dir.path().join("busybox")).unwrap();
        let _cwd = CwdGuard::enter(dir.path());

        // Both names exist in the cwd; neither is a declared path, so both
        // stay references.
        assert_eq!(
            plan_rootfs("alpine:3.20").unwrap(),
            RootfsPlan::Pull(reference("alpine:3.20"))
        );
        assert_eq!(
            plan_rootfs("busybox").unwrap(),
            RootfsPlan::Pull(reference("busybox"))
        );
        // The explicitly-relative form is how the caller asks for the file.
        assert_eq!(
            plan_rootfs("./alpine:3.20").unwrap(),
            RootfsPlan::Materialized(PathBuf::from("./alpine:3.20"))
        );
    }

    #[test]
    fn an_unbootable_declaration_names_what_is_wrong() {
        let empty = plan_rootfs("").expect_err("empty is not a source");
        assert!(matches!(empty, MvmError::InvalidSpec { .. }), "{empty:?}");

        let flake = plan_rootfs_source(RootfsSource::Flake {
            flake_ref: "./nix".into(),
            attr: "rootfs".into(),
        })
        .expect_err("a flake is built, not booted");
        assert!(flake.to_string().contains("./nix#rootfs"), "{flake}");
    }

    #[test]
    fn run_rootfs_output_is_name_sanitized_and_under_cache() {
        let out = run_rootfs_output("my/app:1.2");
        assert!(out.ends_with("rootfs.ext4"));
        let s = out.to_string_lossy();
        assert!(s.contains("local-run"));
        // Path-hostile characters in the name are replaced.
        assert!(s.contains("my_app_1_2"));
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn run_boots_admitted_plan_from_materialized_rootfs() {
        let data = IsolatedDataDir::new();
        let rootfs = data.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"hashable-rootfs-bytes\n").unwrap();

        let be = LocalBackend::with_hypervisor("mock");
        let spec = MachineSpec {
            name: "local-boot-from-image-path".into(),
            image: rootfs.to_string_lossy().parse().expect("a path parses"),
            cpus: 1,
            memory_mib: 128,
            env: vec![],
            grants: None,
            assurance_campaign: None,
        };
        let state = be
            .run_machine(spec)
            .await
            .expect("in-process admitted boot");
        assert_eq!(state.name, "local-boot-from-image-path");
        assert_eq!(state.status, MachineStatus::Running);
        // The boot really landed a VM: it shows up in the backend listing.
        let listed = be.list_machines(MachineFilter::all()).await.unwrap();
        assert!(
            listed
                .iter()
                .any(|m| m.name == "local-boot-from-image-path")
        );
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn remove_drops_the_machine_from_list_and_is_idempotent() {
        let data = IsolatedDataDir::new();
        let rootfs = data.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"hashable-rootfs-bytes\n").unwrap();

        let be = LocalBackend::with_hypervisor("mock");
        let spec = MachineSpec {
            name: "local-remove-target".into(),
            image: rootfs.to_string_lossy().parse().expect("a path parses"),
            cpus: 1,
            memory_mib: 128,
            env: vec![],
            grants: None,
            assurance_campaign: None,
        };
        let state = be.run_machine(spec).await.expect("boot");
        assert!(
            be.list_machines(MachineFilter::all())
                .await
                .unwrap()
                .iter()
                .any(|m| m.id == state.id),
            "the booted machine should list before removal"
        );

        // Remove drops it from the backend's view.
        be.remove_machine(&state.id).await.expect("remove");
        assert!(
            !be.list_machines(MachineFilter::all())
                .await
                .unwrap()
                .iter()
                .any(|m| m.id == state.id),
            "removed machine must not list"
        );

        // Idempotent: removing the now-absent machine, and a never-existed id,
        // both succeed rather than erroring.
        be.remove_machine(&state.id).await.expect("re-remove is Ok");
        be.remove_machine(&MachineId("never-existed-xyz".into()))
            .await
            .expect("removing an absent machine is Ok");
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn stop_machine_falls_back_to_configured_backend_and_is_idempotent() {
        // A mock-driven VM writes no pid marker, so `for_started_vm` finds no
        // owning VMM and the stop must fall back to this client's configured
        // backend (mock). That fallback is what keeps `with_hypervisor("mock")`
        // hermetic — no platform default, no real VMM reached.
        let data = IsolatedDataDir::new();
        let rootfs = data.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"hashable-rootfs-bytes\n").unwrap();

        let be = LocalBackend::with_hypervisor("mock");
        let spec = MachineSpec {
            name: "local-stop-target".into(),
            image: rootfs.to_string_lossy().parse().expect("a path parses"),
            cpus: 1,
            memory_mib: 128,
            env: vec![],
            grants: None,
            assurance_campaign: None,
        };
        let state = be.run_machine(spec).await.expect("boot");
        assert!(
            be.list_machines(MachineFilter::all())
                .await
                .unwrap()
                .iter()
                .any(|m| m.id == state.id),
            "the booted machine should list before the stop"
        );

        // Stop drops it from the backend's live view.
        be.stop_machine(&state.id).await.expect("stop");
        assert!(
            !be.list_machines(MachineFilter::all())
                .await
                .unwrap()
                .iter()
                .any(|m| m.id == state.id),
            "stopped machine must not list as running"
        );

        // Idempotent: stopping the now-stopped machine, and a never-existed id,
        // both succeed rather than erroring.
        be.stop_machine(&state.id).await.expect("re-stop is Ok");
        be.stop_machine(&MachineId("never-existed-xyz".into()))
            .await
            .expect("stopping an absent machine is Ok");
    }

    #[test]
    fn host_verity_sidecars_reads_well_formed_pair() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"x").unwrap();
        // No sidecars yet → unverified.
        assert_eq!(host_verity_sidecars(&rootfs), (None, None));

        std::fs::write(dir.path().join("rootfs.verity"), b"tree").unwrap();
        let hex = "a".repeat(64);
        std::fs::write(dir.path().join("rootfs.roothash"), format!("{hex}\n")).unwrap();
        let (v, h) = host_verity_sidecars(&rootfs);
        assert!(v.unwrap().ends_with("rootfs.verity"));
        assert_eq!(h.unwrap(), hex);

        // A malformed (non-hex / wrong-length) roothash is rejected.
        std::fs::write(dir.path().join("rootfs.roothash"), "nothex\n").unwrap();
        assert_eq!(host_verity_sidecars(&rootfs), (None, None));
    }

    // ---------------------------------------------------------------------------
    // pause / resume tests
    // ---------------------------------------------------------------------------

    #[test]
    fn primed_barrier_timeout_is_opt_in_and_skips_mock() {
        // Default off → no barrier.
        assert!(primed_barrier_timeout(&PauseOpts::default(), false).is_none());
        // Opt-in on a real backend → barrier with the requested timeout.
        let on = PauseOpts {
            primed_barrier: true,
            primed_timeout_secs: 30,
        };
        assert_eq!(
            primed_barrier_timeout(&on, false),
            Some(std::time::Duration::from_secs(30))
        );
        // The hermetic mock has no live guest agent — never gate it.
        assert!(primed_barrier_timeout(&on, true).is_none());
    }

    #[test]
    fn firecracker_socket_is_fc_socket_in_vm_dir() {
        assert_eq!(
            firecracker_socket("/tmp/vms/web"),
            std::path::PathBuf::from("/tmp/vms/web/fc.socket")
        );
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn lifecycle_backend_prefers_the_started_vm_marker() {
        let _data = IsolatedDataDir::new();
        let state_dir = mvm_core::config::vm_state_dir("hvf-owned");
        std::fs::create_dir_all(&state_dir).expect("create VM state directory");
        std::fs::write(state_dir.join("hvf.pid"), "123").expect("write HVF owner marker");

        let firecracker_client = LocalBackend::with_hypervisor("firecracker");
        let owner = firecracker_client.lifecycle_backend_for("hvf-owned");

        assert_eq!(owner.kind(), BackendKind::Hvf);
        assert!(!LocalBackend::uses_sealed_snapshot(&owner));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn lifecycle_backend_falls_back_to_the_explicit_test_backend_without_a_marker() {
        let _data = IsolatedDataDir::new();
        let mock_client = LocalBackend::with_hypervisor("mock");

        let owner = mock_client.lifecycle_backend_for("marker-less");

        assert_eq!(owner.kind(), BackendKind::Mock);
        assert!(LocalBackend::uses_sealed_snapshot(&owner));
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn pause_seals_and_resume_verifies_over_mock_canned_io() {
        // The mock snapshot transport keys off the mock VM's per-VM dir existing.
        let _data = IsolatedDataDir::new();
        let vm_dir = mvm_runtime::MockBackend::vm_dir("snap-roundtrip");
        std::fs::create_dir_all(&vm_dir).unwrap();

        let be = LocalBackend::with_hypervisor("mock");
        let id = MachineId("snap-roundtrip".into());

        // A resume is admitted only for a machine the registry records as
        // paused; this test drives the backend directly, so it records that
        // itself.
        let registry_path = register("snap-roundtrip");
        let mut registry = VmNameRegistry::load(&registry_path).expect("registry");
        assert!(
            registry
                .set_paused("snap-roundtrip", true)
                .expect("pause flag")
        );
        registry.save(&registry_path).expect("save registry");

        let outcome = be
            .pause_machine(&id, PauseOpts::default())
            .await
            .expect("pause seals the canned snapshot");
        // CannedIO writes 12-byte vmstate + 8-byte mem stubs and seals epoch 1.
        assert_eq!(outcome.vmstate_len, b"mock-vmstate".len() as u64);
        assert_eq!(outcome.mem_len, b"mock-mem".len() as u64);
        assert!(outcome.epoch >= 1);

        // Plain resume drives the replay-refusal gate (`verify_and_resume`) and,
        // for the mock, skips the guest PostRestore signal.
        be.resume_machine(&id, ResumeOpts::default())
            .await
            .expect("resume verifies the sealed envelope and restores");
    }

    /// A plain resume restores only a machine the registry records as paused,
    /// on the non-sealed and mock paths exactly as on the sealed one.
    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn a_plain_resume_refuses_a_machine_the_registry_does_not_record_paused() {
        let _data = IsolatedDataDir::new();
        let be = LocalBackend::with_hypervisor("mock");
        let id = MachineId("vm-plain".into());

        let missing = be
            .resume_machine(&id, ResumeOpts::default())
            .await
            .expect_err("no record")
            .to_string();
        assert!(missing.contains("no registry record"), "{missing}");

        let registry_path = register("vm-plain");
        let mut registry = VmNameRegistry::load(&registry_path).expect("registry");
        registry
            .set_paused("vm-plain", false)
            .expect("recorded running");
        registry.save(&registry_path).expect("save registry");

        let running = be
            .resume_machine(&id, ResumeOpts::default())
            .await
            .expect_err("running")
            .to_string();
        assert!(running.contains("is not paused"), "{running}");
    }

    /// A warm resume is held to the same paused-record precondition, before it
    /// touches the backend at all.
    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn a_warm_resume_refuses_a_machine_the_registry_does_not_record_paused() {
        let _data = IsolatedDataDir::new();
        let be = LocalBackend::with_hypervisor("mock");
        let id = MachineId("vm-warm".into());

        let missing = be
            .resume_machine(&id, ResumeOpts { warm: true })
            .await
            .expect_err("no record")
            .to_string();
        assert!(missing.contains("no registry record"), "{missing}");

        let registry_path = register("vm-warm");
        let mut registry = VmNameRegistry::load(&registry_path).expect("registry");
        registry
            .set_paused("vm-warm", false)
            .expect("recorded running");
        registry.save(&registry_path).expect("save registry");

        let running = be
            .resume_machine(&id, ResumeOpts { warm: true })
            .await
            .expect_err("running")
            .to_string();
        assert!(running.contains("is not paused"), "{running}");
    }

    /// A registry write that fails after the restore names the running guest
    /// and tells the operator not to resume it again.
    #[test]
    #[cfg(feature = "test-support")]
    fn a_failed_resume_mark_warns_against_resuming_again() {
        let _data = IsolatedDataDir::new();
        let registry_path = register("vm-mark");
        std::fs::write(&registry_path, "not a registry").expect("corrupt the registry");

        let error = mark_resumed_after_restore("vm-mark", "").expect_err("corrupt registry");
        let msg = error.to_string();
        assert!(msg.contains("Do not run resume again"), "{msg}");
        assert!(msg.contains("guest is running"), "{msg}");
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn pause_on_absent_mock_vm_is_error() {
        let _data = IsolatedDataDir::new();
        let be = LocalBackend::with_hypervisor("mock");
        let err = be
            .pause_machine(&MachineId("never-brought-up".into()), PauseOpts::default())
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("is not running"),
            "absent mock VM must fail with 'is not running'; got: {msg}"
        );
    }

    // ---------------------------------------------------------------------------
    // reconfigure_machine tests
    // ---------------------------------------------------------------------------

    /// Persist a minimal image-backed spec named `name` into the current
    /// `MVM_HOME`-derived machine state dir. Only used by the
    /// `reconfigure_*` tests below, which all drive the mock backend.
    #[cfg(feature = "test-support")]
    fn persist_test_spec(name: &str) {
        use mvm_runtime::machine::persist::{
            MACHINE_SPEC_SCHEMA_VERSION, MachineSpec as PersistSpec, save_machine_spec,
        };
        let spec = PersistSpec {
            caller_commitment: None,
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: name.to_string(),
            image: Some("alpine:latest".to_string()),
            manifest: None,
            runtime_pack: false,
            resolved_digest: None,
            net: false,
            allow_host: vec![],
            peer: vec![],
            cpus: 2,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: vec![],
            init: vec![],
            agent_verb: vec![],
            created_at: None,
            last_started_at: None,
            health_check: None,
            deployment: None,
            grants: None,
            gpu: false,
            gpu_device: None,
            ports: vec![],
            ai: None,
        };
        save_machine_spec(&spec, false).expect("persist_test_spec: save failed");
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn reconfigure_refuses_network_changes_on_local_backend() {
        let _data = IsolatedDataDir::new();
        persist_test_spec("web");
        let be = LocalBackend::with_hypervisor("mock");
        let err = be
            .reconfigure_machine(
                &MachineId("web".into()),
                mvm_core::client::dto::ReconfigureRequest {
                    net: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("network"),
            "must refuse net on local backend; got: {msg}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn reconfigure_refuses_allow_host_changes_on_local_backend() {
        let _data = IsolatedDataDir::new();
        persist_test_spec("web2");
        let be = LocalBackend::with_hypervisor("mock");
        let err = be
            .reconfigure_machine(
                &MachineId("web2".into()),
                mvm_core::client::dto::ReconfigureRequest {
                    allow_host: Some(vec!["api.example.com:443".into()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("network"),
            "must refuse allow_host on local backend; got: {msg}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn reconfigure_unknown_machine_is_error() {
        let _data = IsolatedDataDir::new();
        let be = LocalBackend::with_hypervisor("mock");
        let err = be
            .reconfigure_machine(
                &MachineId("nope".into()),
                mvm_core::client::dto::ReconfigureRequest {
                    cpus: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        let msg = format!("{err}").to_lowercase();
        assert!(
            msg.contains("does not exist") || msg.contains("not found"),
            "expected 'does not exist' or 'not found'; got: {msg}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn reconfigure_stopped_machine_updates_spec_and_returns_stopped() {
        let _data = IsolatedDataDir::new();
        persist_test_spec("myapp");
        let be = LocalBackend::with_hypervisor("mock");
        // Machine is not running in the mock backend — just patching the spec.
        let state = be
            .reconfigure_machine(
                &MachineId("myapp".into()),
                mvm_core::client::dto::ReconfigureRequest {
                    cpus: Some(4),
                    ..Default::default()
                },
            )
            .await
            .expect("reconfigure stopped machine");
        assert_eq!(state.name, "myapp");
        assert_eq!(state.status, MachineStatus::Stopped);

        // The spec was actually persisted: load it back and confirm cpus updated.
        let loaded =
            mvm_runtime::machine::persist::load_machine_spec("myapp").expect("load patched spec");
        assert_eq!(loaded.cpus, 4, "persisted cpus should be 4");
        assert_eq!(loaded.memory, "512M", "memory should be unchanged");
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn reconfigure_rejects_zero_cpus() {
        let _data = IsolatedDataDir::new();
        persist_test_spec("zero-cpu-machine");
        let be = LocalBackend::with_hypervisor("mock");
        let err = be
            .reconfigure_machine(
                &MachineId("zero-cpu-machine".into()),
                mvm_core::client::dto::ReconfigureRequest {
                    cpus: Some(0),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("cpus"),
            "must refuse cpus=0 with a message mentioning cpus; got: {msg}"
        );

        // The spec must not have been overwritten.
        let loaded = mvm_runtime::machine::persist::load_machine_spec("zero-cpu-machine")
            .expect("load spec");
        assert_eq!(loaded.cpus, 2, "cpus must remain unchanged after refusal");
    }

    #[tokio::test]
    #[cfg(feature = "test-support")]
    async fn reconfigure_noop_returns_stopped_without_overwriting_spec() {
        let _data = IsolatedDataDir::new();
        persist_test_spec("noop-machine");
        let be = LocalBackend::with_hypervisor("mock");
        // No fields changed → should short-circuit, not error.
        let state = be
            .reconfigure_machine(
                &MachineId("noop-machine".into()),
                mvm_core::client::dto::ReconfigureRequest::default(),
            )
            .await
            .expect("noop reconfigure should succeed");
        assert_eq!(state.status, MachineStatus::Stopped);
    }
}
