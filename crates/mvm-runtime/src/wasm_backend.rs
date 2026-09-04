//! Host-`wasmtime` backend running a user-supplied WASI module.
//!
//! `WasmBackend` is the claim-free portability/demo tier: it runs a WASI
//! Preview 1 module under host `wasmtime` instead of booting a Linux
//! microVM. It has no hardware isolation boundary — no KVM/HVF, no guest
//! kernel, no TAP/virtio/vsock, no verified boot, no snapshot — and its
//! `capabilities()`/`security_profile()` say so plainly. It exists for
//! demos, docs playgrounds, and hosts with no real microVM substrate, never
//! for a production or untrusted-workload path.
//!
//! Opt-in and never auto-selected: `AnyBackend::auto_select` never returns
//! this kind, and the real `wasmtime` engine only compiles in behind the
//! `wasm-backend` Cargo feature (off by default, so the default workspace
//! build carries no `wasmtime` dependency). `WasmBackend` itself is always
//! constructible — construction does no I/O and touches no engine state —
//! so the catalog/dispatch machinery every other backend goes through stays
//! uniform. Without the feature, every operation that would need the real
//! engine fails closed with [`WasmBackendError::NotCompiledIn`] instead of
//! silently falling back to a different backend or panicking; this mirrors
//! how every other backend surfaces "not available" at first use rather
//! than at construction.
//!
//! Governed egress, not raw networking: a module is never granted a WASI
//! socket capability directly, so it cannot dial the network on its own.
//! Instead, a run whose policy allows egress gets a host-mediated
//! `mvm:egress` import that relays each request through the same
//! substitution-endpoint seam every other backend uses — default-deny,
//! `${NAME}` secret substitution on a bound destination, and a
//! chain-signed audit entry, with the module never holding the real
//! secret. A launch config that instead asks for a kernel/verified boot, a
//! snapshot, or an interactive console still fails closed with a typed
//! error naming the supported alternative.
//!
//! The capability handshake: every run also receives the same environment
//! description the microVM/container tiers deliver as
//! `ActivateEnvironment`, adapted to WASI — preopened directories instead
//! of block mounts (the runtime overlay read-only at `/mvm/runtime`,
//! directory-share volumes at their guest mountpoints), and policy/grant
//! delivery as an `activation.json` plus `MVM_ACTIVATION_FILE` env instead
//! of a vsock verb. WASI has no mountable root: the module's filesystem
//! view IS its root, the in-place analog of the container tier's
//! already-owned `/`. The WASI capability model is the gate — the module
//! receives exactly the preopens, env, and host imports the plan admits
//! and nothing else; no signature verification happens in-guest because
//! the WASI host itself is the trust boundary (which is precisely why
//! this tier stays claim-free and dev/demo-only).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::workload_backend::{EgressSubstitutionTransport, WorkloadBackend};
use anyhow::{Context, Result};
use mvm_contract::grants::{CpuGrant, Grants, WallClockGrant};
use mvm_contract::protocol::resource_controls::EnforcedGrants;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, LayerCoverage, ResourceControls,
    SnapshotCapability, StartMode, VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo,
    VmStartConfig, VmStatus,
};
use thiserror::Error;

/// Typed, fail-closed errors for requests this tier cannot satisfy. Every
/// variant names the supported alternative rather than silently dropping
/// the request — see the module docs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WasmBackendError {
    /// Selected via `--backend wasm` / `MVM_BACKEND=wasm`, but `mvm-runtime`
    /// was built without the `wasm-backend` feature.
    #[error(
        "wasm backend was not compiled in — rebuild with `cargo build -p mvm-runtime \
         --features wasm-backend`, or select a real backend (firecracker, libkrun, hvf, qemu)"
    )]
    NotCompiledIn,

    /// `VmStartConfig::rootfs_path` — reused here to name the `.wasm`/`.wat`
    /// module to instantiate, since this tier has no root filesystem — is
    /// empty.
    #[error(
        "wasm backend has no module to run — set VmStartConfig::rootfs_path to the \
         .wasm/.wat module path"
    )]
    ModulePathMissing,

    #[error(
        "wasm backend has no kernel/initrd boot path — it instantiates a WASI module \
         directly; drop --kernel/--initrd or select a microVM backend"
    )]
    KernelBootNotSupported,

    #[error(
        "wasm backend has no dm-verity verified boot — select a microVM backend \
         (firecracker, libkrun, hvf) for a verified rootfs"
    )]
    VerifiedBootNotSupported,

    #[error(
        "wasm backend has no interactive console — a WASI instance has no PTY; select a \
         microVM backend for `mvmctl console`"
    )]
    ConsoleNotSupported,

    #[error(
        "wasm backend does not support pause/resume — a WASI instance runs to completion or traps; there is no vCPU to suspend"
    )]
    PauseResumeNotSupported,

    #[error("failed to load wasm module {path:?}: {reason}")]
    ModuleLoadFailed { path: String, reason: String },

    #[error("wasm module {path:?} does not export a WASI `_start` entrypoint: {reason}")]
    NoStartExport { path: String, reason: String },

    #[error("wasm module {path:?} trapped: {reason}")]
    ModuleTrapped { path: String, reason: String },

    #[error(
        "wasm backend cannot attach block volume '{host}' — a WASI instance has no block \
         devices; use `machine run --mount` with a host directory instead"
    )]
    DiskVolumeNotSupported { host: String },

    #[error(
        "wasm backend cannot resolve the runtime-overlay guest binaries: {reason}. They \
         cross-compile from a source checkout (or a warm cache) — populate the cache with a \
         build first, or drop the runtime-overlay requirement"
    )]
    RuntimeOverlayUnavailable { reason: String },

    #[error("wasm backend volume mountpoint {guest_path:?} is denied: {reason}")]
    VolumePathDenied { guest_path: String, reason: String },

    #[error(
        "the wasm tier cannot bound a CPU share — a share is a fraction of host CPU time and \
         this tier counts instructions; express it as fuel (a deterministic instruction budget)"
    )]
    CpuShareNotSupported,

    #[error(
        "a fuel grant needs a bounded wall_clock grant: fuel does not tick inside a host call, \
         so a module parked in one would be bounded by the instruction budget by nothing"
    )]
    FuelWithoutWallClock,

    #[error(
        "wasm tier could not confirm {control} is live on the engine that compiled this module, \
         so it refuses to run a workload it would have to report as bounded without evidence"
    )]
    ControlNotConfirmed { control: &'static str },

    #[error("wasm backend has no completed run recorded for '{name}'")]
    NoRunRecorded { name: String },
}

/// What the wasm tier will accept as a grant, refusing anything it could only
/// half-enforce.
///
/// Shared by `start` (which installs the bounds) and `apply_grants` (which
/// reports them) so the two cannot drift apart on what they admit.
fn validate_wasm_grants(grants: &Grants) -> std::result::Result<(), WasmBackendError> {
    // Different units, and no conversion between them exists. The capability
    // negotiation already names fuel as the substitute; this is the same
    // refusal at the point the control would have been installed.
    if matches!(grants.cpu, Some(CpuGrant::Share { .. })) {
        return Err(WasmBackendError::CpuShareNotSupported);
    }
    // Fuel is consumed by executed wasm instructions only. A module blocked in
    // the `mvm:egress` host import executes none, so a fuel budget alone would
    // let it park there forever. Epoch interruption is what preempts it, and it
    // is driven by the wall-clock grant — so accepting fuel without one would
    // record a bound that a hostile module trivially escapes.
    if matches!(grants.cpu, Some(CpuGrant::Fuel { .. }))
        && !matches!(grants.wall_clock, Some(WallClockGrant::Secs { .. }))
    {
        return Err(WasmBackendError::FuelWithoutWallClock);
    }
    Ok(())
}

/// Linear memory a wasm run may grow into when the launch config declares no
/// memory of its own. A microVM's memory is committed at creation; a wasm
/// memory grows on demand, so "unset" would otherwise mean "as much as the
/// host has".
const DEFAULT_WASM_MEMORY_MIB: u32 = 256;

/// How long a single `mvm:egress` host call may block before the import gives
/// up on the endpoint.
///
/// Epoch interruption cannot preempt host code — the instrumentation lives in
/// compiled wasm — so time spent inside this import is time the wall-clock
/// bound cannot reclaim. The timeout is what keeps a slow or hostile endpoint
/// from stalling the tier indefinitely, and it is clamped to the run's own
/// wall-clock grant so a 5-second run cannot be held open for 30.
const MAX_EGRESS_CALL_SECS: u64 = 30;

/// The bounds one wasm run is born inside, resolved from the admitted plan
/// before any engine exists.
///
/// Every field is a bound that will be *installed*, not a request: `start`
/// refuses the run outright rather than dropping one it cannot confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmBounds {
    /// Executed-instruction budget, or `None` for an uncapped run.
    pub fuel: Option<u64>,
    /// Wall-clock ceiling in seconds, enforced by epoch interruption.
    pub wall_clock_secs: Option<u32>,
    /// Linear-memory ceiling in bytes. Always set: see [`DEFAULT_WASM_MEMORY_MIB`].
    pub memory_bytes: usize,
}

impl WasmBounds {
    /// The shape a run with no admitted grants gets: no CPU or wall-clock
    /// bound, and the tier's default memory ceiling.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            fuel: None,
            wall_clock_secs: None,
            memory_bytes: (DEFAULT_WASM_MEMORY_MIB as usize) * 1024 * 1024,
        }
    }

    /// The memory ceiling rounded back to whole MiB, for `VmInfo`.
    #[must_use]
    pub const fn memory_mib(&self) -> u32 {
        (self.memory_bytes / (1024 * 1024)) as u32
    }

    /// How long one `mvm:egress` host call may block. Clamped to the run's own
    /// wall-clock grant, because a host call that outlives the whole run's
    /// budget defeats the bound it sits inside.
    #[must_use]
    pub fn egress_call_timeout(&self) -> std::time::Duration {
        let secs = match self.wall_clock_secs {
            Some(secs) => u64::from(secs).min(MAX_EGRESS_CALL_SECS),
            None => MAX_EGRESS_CALL_SECS,
        };
        std::time::Duration::from_secs(secs)
    }
}

/// One finished wasm run: how it exited, and what was confirmed to have
/// bounded it while it did.
#[derive(Debug, Clone)]
pub struct CompletedRun {
    pub exit: VmExitStatus,
    pub enforced: EnforcedGrants,
}

/// The grants this launch was admitted under.
///
/// The signed plan on `plan_json` is authoritative. Without one, the only
/// grant threaded onto a launch config is `cpu_grant` — and a CPU bound with
/// no wall-clock companion is refused by [`validate_wasm_grants`] rather than
/// half-applied, which is the correct outcome for a launch that reached this
/// tier without an admitted plan behind it.
fn wasm_grants_from_config(config: &VmStartConfig) -> Result<Grants> {
    match config.plan_json.as_deref() {
        Some(json) => {
            let plan = mvm_core::plan::plan_from_admitted_json(json)
                .map_err(|e| anyhow::anyhow!("decoding the admitted plan for its grants: {e}"))?;
            Ok(plan.grants.unwrap_or_default())
        }
        None => Ok(Grants {
            cpu: config.cpu_grant,
            wall_clock: None,
            egress: None,
        }),
    }
}

/// Turn admitted grants plus the launch config's memory declaration into the
/// bounds the engine and store are built with.
fn wasm_bounds_for(config: &VmStartConfig, grants: &Grants) -> WasmBounds {
    let memory_mib = if config.memory_mib == 0 {
        DEFAULT_WASM_MEMORY_MIB
    } else {
        config.memory_mib
    };
    WasmBounds {
        fuel: match grants.cpu {
            Some(CpuGrant::Fuel { instructions }) => Some(instructions),
            // A share never reaches here: `validate_wasm_grants` refuses it.
            Some(CpuGrant::Share { .. }) | None => None,
        },
        wall_clock_secs: match grants.wall_clock {
            Some(WallClockGrant::Secs { secs }) => Some(secs.get()),
            Some(WallClockGrant::Unbounded) | None => None,
        },
        memory_bytes: (memory_mib as usize) * 1024 * 1024,
    }
}

/// Reject every launch request this tier cannot honestly satisfy before
/// touching the engine. Each check names the supported alternative.
fn reject_unsupported_start_config(
    config: &VmStartConfig,
) -> std::result::Result<(), WasmBackendError> {
    if config.kernel_path.is_some() || config.initrd_path.is_some() {
        return Err(WasmBackendError::KernelBootNotSupported);
    }
    if config.verity_path.is_some() || config.roothash.is_some() {
        return Err(WasmBackendError::VerifiedBootNotSupported);
    }
    if config.dev_console {
        return Err(WasmBackendError::ConsoleNotSupported);
    }
    if let Some(volume) = config
        .volumes
        .iter()
        .find(|v| v.materialized_image.is_none())
    {
        return Err(WasmBackendError::DiskVolumeNotSupported {
            host: volume.host.clone(),
        });
    }
    // Every materialized directory grant becomes a WASI preopen of its
    // original host path, so its guest mountpoint must pass the mount-path
    // policy before any of it starts.
    for volume in &config.volumes {
        crate::wasm_activation::validate_wasm_volume_guest_path(&volume.guest)?;
    }
    if config.rootfs_path.trim().is_empty() {
        return Err(WasmBackendError::ModulePathMissing);
    }
    Ok(())
}

/// Record of a WASI module run to completion by [`WasmBackend::start`].
/// There is no "running" state to observe: a module runs synchronously
/// inside `start`, so by the time any other trait method can see it, it has
/// already exited.
#[derive(Debug, Clone)]
struct WasmRun {
    exit: VmExitStatus,
    /// The bounds that were installed on the store this module ran in.
    bounds: WasmBounds,
    /// What each control was *confirmed* to be doing on that store, read back
    /// off the live engine at construction — never derived from the request.
    enforced: EnforcedGrants,
}

/// Host-`wasmtime` backend. See module docs for the tier's scope and the
/// opt-in/fail-closed contract.
#[derive(Debug, Default, Clone)]
pub struct WasmBackend {
    runs: std::sync::Arc<Mutex<HashMap<String, WasmRun>>>,
    /// Substitution-endpoint UDS the `mvm:egress` host-import relays
    /// egress requests through. Host state, never guest-controlled input:
    /// `None` until an endpoint is spawned and wired in, in which case the
    /// import fails closed with `NoEndpointConfigured` rather than
    /// silently allowing (or dropping) egress.
    egress_endpoint: Option<PathBuf>,
}

impl WasmBackend {
    /// Construct an empty backend. Side-effect free — no engine is created
    /// and no `wasmtime` symbol is touched until a module actually runs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Point this backend's `mvm:egress` host-import at a substitution
    /// endpoint UDS. Builder-style; mainly a test seam — production `start`
    /// spawns and wires its own endpoint (see [`spawn_wasm_egress_endpoint_if_needed`])
    /// and only falls back to this manually-configured path when a run has
    /// nothing to mediate.
    pub fn with_egress_endpoint(mut self, path: PathBuf) -> Self {
        self.egress_endpoint = Some(path);
        self
    }
}

/// Owned inputs for a wasm run's per-VM substitution-endpoint spawn, decided
/// once by [`wasm_endpoint_plan`] so the skip/spawn branch is unit-testable
/// without touching a subprocess. Kept separate from
/// `crate::network_endpoint_spawn::SubstitutionSpawnParams` (which borrows) so
/// the decided values can be asserted directly in a test.
struct WasmEndpointPlan {
    vm_name: String,
    state_dir: PathBuf,
    tenant: String,
    secrets: Vec<mvm_core::plan::SecretBinding>,
    redaction: mvm_core::policy::RedactionPolicy,
    network_limits: mvm_core::plan::NetworkLimits,
    socket_path: PathBuf,
}

/// Decide whether a wasm run needs the per-VM substitution endpoint, and if
/// so, the owned inputs the spawn needs. Mirrors libkrun's
/// `spawn_libkrun_egress_endpoint_if_needed` skip logic exactly: nothing to
/// mediate — no bound secrets and the resolved policy denies egress — is a
/// no-op, returning `None`. `start()` then leaves the `mvm:egress`
/// host-import unconfigured, so every egress call fails closed with
/// `NoEndpointConfigured` (correct: no policy/secrets ⇒ no egress).
fn wasm_endpoint_plan(
    config: &VmStartConfig,
    state_dir: &std::path::Path,
) -> Result<Option<WasmEndpointPlan>> {
    let default_redaction = mvm_core::policy::RedactionPolicy::default();
    let decoded = mvm_vmm::host::egress_shared::decode_plan_secrets_from_state(state_dir)?;
    let (secrets, redaction, tenant) = match decoded {
        Some((secrets, redaction, tenant)) => (secrets, redaction, tenant),
        None => (
            Vec::new(),
            default_redaction,
            match config.tenant_id.as_deref() {
                Some(t) if !t.is_empty() => t.to_string(),
                _ => "local".to_string(),
            },
        ),
    };
    if secrets.is_empty() && !config.network_policy.allows_egress() {
        return Ok(None);
    }
    let network_limits = config
        .plan_json
        .as_deref()
        .map(mvm_core::plan::plan_from_admitted_json)
        .transpose()
        .context("parse admitted plan network limits")?
        .map(|plan| plan.effective_network_limits())
        .transpose()
        .context("validate admitted plan network limits")?
        .unwrap_or_default();
    Ok(Some(WasmEndpointPlan {
        vm_name: config.name.clone(),
        state_dir: state_dir.to_path_buf(),
        tenant,
        secrets,
        redaction,
        network_limits,
        socket_path: mvm_core::config::vm_network_endpoint_socket(&config.name),
    }))
}

/// Build the [`network_endpoint_spawn::SubstitutionSpawnParams`] a wasm run's
/// endpoint spawn needs from a decided [`WasmEndpointPlan`]. Pure (no I/O)
/// so the wasm-specific literal fields are unit-testable without a spawn:
/// always `Uds` (the host-import connects to the endpoint directly — wasm has
/// no VMM to proxy a per-port vsock socket), no terminator (no TAP/nft
/// REDIRECT to feed), no TLS intermediate (http-only POC; HTTPS termination
/// is a later phase), and — unlike libkrun/hvf, which serve raw pass-through
/// when a run carries no secrets — the wasm tier mints no FlowMux identity:
/// the `mvm:egress` host-import always speaks the `WireRequest` wire
/// protocol, never a raw byte relay.
fn wasm_network_endpoint_spawn_params<'a>(
    plan: &'a WasmEndpointPlan,
    network_policy: &'a mvm_core::network_policy::NetworkPolicy,
) -> crate::network_endpoint_spawn::SubstitutionSpawnParams<'a> {
    crate::network_endpoint_spawn::SubstitutionSpawnParams {
        vm_name: &plan.vm_name,
        state_dir: &plan.state_dir,
        tenant: &plan.tenant,
        secrets: &plan.secrets,
        redaction: &plan.redaction,
        transport: crate::network_endpoint_spawn::EndpointTransport::Uds {
            path: plan.socket_path.clone(),
        },
        terminator_listen: None,
        egress_proxy: None,
        tls_intermediate: None,
        network_policy: Some(network_policy),
        network_limits: plan.network_limits,
        ingress: &[],
        resolver_remote: None,
        binding_store_dir: None,
        flowmux_identity: None,
        session_marker: None,
    }
}

/// Spawn the per-VM substitution endpoint for a wasm run — mirroring
/// libkrun's `spawn_libkrun_egress_endpoint_if_needed` — and return the UDS
/// path to wire into the `mvm:egress` host-import. `None` when
/// [`wasm_endpoint_plan`] finds nothing to mediate; the caller then leaves
/// the host-import unconfigured rather than spawning a needless endpoint.
/// Creating `state_dir` is deferred to this Some-branch so a run that spawns
/// nothing touches no filesystem state.
fn spawn_wasm_egress_endpoint_if_needed(
    config: &VmStartConfig,
    state_dir: &std::path::Path,
) -> Result<Option<PathBuf>> {
    let Some(plan) = wasm_endpoint_plan(config, state_dir)? else {
        return Ok(None);
    };
    std::fs::create_dir_all(state_dir)
        .map_err(|e| anyhow::anyhow!("create per-VM state dir {}: {e}", state_dir.display()))?;
    let params = wasm_network_endpoint_spawn_params(&plan, &config.network_policy);
    crate::network_endpoint_spawn::spawn_network_endpoint(params)?;
    Ok(Some(plan.socket_path))
}

impl VmBackend for WasmBackend {
    fn name(&self) -> &str {
        "wasm"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Wasm
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            // Nothing in a WASI module can reach the network by IP — there
            // is no guest NIC, no socket capability granted, no device at
            // all. Egress, when a later phase adds it, rides host-provided
            // WASI imports, not a routable NIC.
            no_routable_guest_nic: true,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            // Named explicitly: wasmtime's fuel/epoch mechanisms bound this
            // tier's CPU and wall clock, unlike the all-`None` struct-update
            // default. This field declares what the mechanisms *could* bound;
            // `apply_grants` reports what one particular run confirmed.
            resource_controls: ResourceControls::for_backend(BackendKind::Wasm),
            ..VmCapabilities::default()
        }
    }

    fn start_with_mode(&self, config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        reject_unsupported_start_config(config)?;

        // Admission for this tier's resource controls happens here, not in
        // `apply_grants`. A wasm module runs to completion inside `start`, so a
        // bound installed afterwards would bound the run that already finished
        // by nothing. Refusals therefore have to land before the engine exists.
        let grants = wasm_grants_from_config(config)?;
        validate_wasm_grants(&grants)?;
        let bounds = wasm_bounds_for(config, &grants);

        let state_dir = mvm_core::config::vm_state_dir(&config.name);

        // Resolve the environment-activation inputs BEFORE spawning
        // anything: a launch whose declared overlay can't resolve fails
        // closed here, leaving no side effects behind.
        let overlay_bins_dir = crate::wasm_activation::resolve_wasm_overlay_bins_dir(config)?;
        let grant_present = crate::microvm::read_verb_grant_envelope(&config.name)?.is_some();

        let spawned_endpoint = spawn_wasm_egress_endpoint_if_needed(config, &state_dir)?;
        let egress_endpoint = spawned_endpoint
            .clone()
            .or_else(|| self.egress_endpoint.clone());

        // The capability handshake: activation file + preopen plan the
        // engine translates into WASI preopens and env (see
        // `crate::wasm_activation`).
        let activation = crate::wasm_activation::prepare_wasm_activation(
            config,
            &state_dir,
            overlay_bins_dir.as_deref(),
            grant_present,
        )?;

        let result = engine::run_module_to_completion(
            &config.rootfs_path,
            egress_endpoint,
            Some(&activation),
            bounds,
        );
        if spawned_endpoint.is_some() {
            // A wasm run is synchronous end-to-end inside `start` — there is
            // no later `stop()` boundary to reap the endpoint at, so its
            // decrypted secrets must not outlive this call either way.
            crate::network_endpoint_spawn::reap_network_endpoint(&state_dir, &config.name);
        }
        let completed = result?;

        let mut runs = self
            .runs
            .lock()
            .map_err(|_| anyhow::anyhow!("wasm backend state mutex poisoned"))?;
        runs.insert(
            config.name.clone(),
            WasmRun {
                exit: completed.exit,
                bounds,
                enforced: completed.enforced,
            },
        );
        Ok(VmId(config.name.clone()))
    }

    /// Report what actually bounded this run, by reading back the controls the
    /// store it ran in carried.
    ///
    /// The tier is recorded at engine construction from a live read-back —
    /// `Store::get_fuel` for the instruction budget, and a probe that trips
    /// epoch interruption on the very engine the module was compiled with —
    /// never from the fact that a setter returned `Ok`.
    ///
    /// Called after `start` like every other backend's, but with a different
    /// meaning: the module is already finished, so this reports a fact rather
    /// than installing one. That is why the refusal rules also run in `start`,
    /// where they can still stop an unenforceable launch.
    fn apply_grants(&self, id: &VmId, grants: &Grants) -> Result<EnforcedGrants> {
        validate_wasm_grants(grants)?;
        let runs = self
            .runs
            .lock()
            .map_err(|_| anyhow::anyhow!("wasm backend state mutex poisoned"))?;
        runs.get(&id.0)
            .map(|run| run.enforced.clone())
            .ok_or_else(|| WasmBackendError::NoRunRecorded { name: id.0.clone() }.into())
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        let runs = self
            .runs
            .lock()
            .map_err(|_| anyhow::anyhow!("wasm backend state mutex poisoned"))?;
        runs.get(&id.0)
            .map(|run| run.exit)
            .ok_or_else(|| anyhow::anyhow!("wasm: no completed run recorded for '{}'", id.0))
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        Err(WasmBackendError::PauseResumeNotSupported.into())
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        Err(WasmBackendError::PauseResumeNotSupported.into())
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let mut runs = self
            .runs
            .lock()
            .map_err(|_| anyhow::anyhow!("wasm backend state mutex poisoned"))?;
        runs.remove(&id.0);
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        let mut runs = self
            .runs
            .lock()
            .map_err(|_| anyhow::anyhow!("wasm backend state mutex poisoned"))?;
        runs.clear();
        Ok(())
    }

    fn status(&self, _id: &VmId) -> Result<VmStatus> {
        // A module runs to completion inside `start` — there is no
        // observable "running" state, recorded or not.
        Ok(VmStatus::Stopped)
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let runs = self
            .runs
            .lock()
            .map_err(|_| anyhow::anyhow!("wasm backend state mutex poisoned"))?;
        Ok(runs
            .iter()
            .map(|(name, run)| VmInfo {
                id: VmId(name.clone()),
                name: name.clone(),
                status: VmStatus::Stopped,
                guest_ip: None,
                // A WASI instance is single-threaded by construction — one
                // `_start` on one host thread, no vCPU to add a second to. The
                // count is the parallelism actually in force, not a zero
                // standing in for "this tier has no CPUs".
                cpus: 1,
                // The linear-memory ceiling the store's limiter enforced, which
                // is what "how much memory could this have used" means here.
                memory_mib: run.bounds.memory_mib(),
                profile: None,
                revision: None,
                flake_ref: None,
                ports: Vec::new(),
            })
            .collect())
    }

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        let runs = self
            .runs
            .lock()
            .map_err(|_| anyhow::anyhow!("wasm backend state mutex poisoned"))?;
        match runs.get(&id.0) {
            Some(run) => Ok(format!(
                "[wasm] module '{}' exited with code {:?} (success={})",
                id.0, run.exit.code, run.exit.success
            )),
            None => anyhow::bail!("wasm: no completed run recorded for '{}'", id.0),
        }
    }

    fn is_available(&self) -> Result<bool> {
        Ok(engine::is_compiled_in())
    }

    fn install(&self) -> Result<()> {
        if engine::is_compiled_in() {
            Ok(())
        } else {
            Err(WasmBackendError::NotCompiledIn.into())
        }
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Claim-free portability tier: every numbered claim is
        // `DoesNotHold`, matching the mock test double's framing rather
        // than a real microVM's partial-claim profile. There is no
        // guest, no rootfs block device, and no hardware isolation
        // boundary — nothing here approximates the security posture's threat model.
        BackendSecurityProfile {
            claims: [ClaimStatus::DoesNotHold; 7],
            layer_coverage: LayerCoverage::default(),
            tier: "Tier 3 (portability, claim-free)",
            notes: &[
                "Runs a user-supplied WASI module under host wasmtime — no hardware virt, \
                 no guest kernel, no TAP/virtio/vsock, no verified boot, no snapshot.",
                "Opt-in only; never selected by auto-detect.",
                "Carries none of the numbered security claims; never a production or \
                 untrusted-workload path.",
            ],
        }
    }
}

impl WorkloadBackend for WasmBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        // The wasm tier mediates egress through a host import that speaks the
        // same substitution-endpoint wire protocol the vsock-backed tiers use.
        EgressSubstitutionTransport::WasmHostImport
    }
}

/// The `wasmtime`-touching internals, split so the outer `WasmBackend` type
/// and its `VmBackend` impl compile identically with or without the
/// `wasm-backend` feature. Only this inner module references `wasmtime` —
/// with the feature off, `cargo tree` shows no `wasmtime` anywhere in the
/// dependency graph.
#[cfg(feature = "wasm-backend")]
mod engine {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::{CompletedRun, WasmBackendError, WasmBounds};
    use crate::wasm_activation::WasmPreopenPlan;
    use mvm_contract::protocol::resource_controls::{EnforcedGrants, EnforcedTier};
    use mvm_core::substitution_wire::{WireRequest, WireResponse};
    use mvm_core::vm_backend::VmExitStatus;
    use wasmtime::{
        Caller, Engine, Extern, FuncType, Linker, Memory, Module, Store, StoreLimits, Val, ValType,
    };
    use wasmtime_wasi::p1::{self, WasiP1Ctx};
    use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

    pub fn is_compiled_in() -> bool {
        true
    }

    /// Host state carried in the wasmtime `Store` for a `WasmBackend` run:
    /// the WASI Preview 1 context, the linear-memory limiter, and the bits of
    /// state the `mvm:egress` host-import needs. `egress_endpoint` is
    /// host-supplied — never guest-controlled — and names the
    /// substitution-endpoint UDS the import relays each request to. `None`
    /// until an endpoint is spawned and wired in, in which case the import
    /// fails closed rather than silently allowing egress.
    pub(super) struct WasmHostState {
        wasi: WasiP1Ctx,
        egress_endpoint: Option<PathBuf>,
        /// Bounds the linear memory a module may grow into. A wasm memory
        /// grows on demand, so unlike a microVM it has no allocation fixed at
        /// creation and needs a limiter consulted on every `memory.grow`.
        limits: StoreLimits,
        /// Ceiling on one `mvm:egress` call. Epoch interruption cannot preempt
        /// host code, so this is the only thing bounding time spent in the
        /// import.
        egress_timeout: Duration,
    }

    /// How often the epoch is advanced while a bounded run is in flight.
    ///
    /// Epoch interruption fires when the engine's counter passes the store's
    /// deadline, and nothing advances that counter on its own. The period sets
    /// the granularity of the wall-clock bound: a run granted N seconds is
    /// stopped somewhere in `[N, N + one period)`.
    const EPOCH_TICKS_PER_SEC: u64 = 10;
    const EPOCH_TICK: Duration = Duration::from_millis(1000 / EPOCH_TICKS_PER_SEC);

    /// Advances an engine's epoch on a fixed cadence for as long as a run is in
    /// flight, and stops on drop.
    ///
    /// Without this an epoch deadline is a number nothing ever reaches. Drop
    /// rather than an explicit stop call so an early return or a trap on the
    /// run path cannot leave the thread ticking behind it.
    pub(super) struct EpochTicker {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl EpochTicker {
        fn spawn(engine: &Engine) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let engine = engine.clone();
            let flag = Arc::clone(&stop);
            let handle = std::thread::spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    std::thread::sleep(EPOCH_TICK);
                    engine.increment_epoch();
                }
            });
            Self {
                stop,
                handle: Some(handle),
            }
        }
    }

    impl Drop for EpochTicker {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                // Bounded by one tick period: the thread checks the flag on
                // every wake.
                let _ = handle.join();
            }
        }
    }

    /// Prove epoch interruption actually preempts wasm on `engine` before a
    /// workload is compiled on it.
    ///
    /// wasmtime exposes no getter for `Config::epoch_interruption` and none for
    /// a store's epoch deadline, so the only way to know the control is live is
    /// to trip it. A tiny loop is compiled on this very engine, given a
    /// deadline that has already elapsed, and called: epoch checks sit on loop
    /// back-edges, so a working control traps on the first one.
    ///
    /// The probe loop is finite on purpose. An engine that silently dropped the
    /// instrumentation must return `false`, not spin — a hang here would be a
    /// worse failure than the misreport it exists to prevent.
    fn epoch_interruption_fires(engine: &Engine) -> bool {
        const PROBE_WAT: &str = r#"(module (func (export "spin") (local $i i32)
  (loop $l
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br_if $l (i32.lt_u (local.get $i) (i32.const 1024))))))"#;

        let Ok(module) = Module::new(engine, PROBE_WAT) else {
            return false;
        };
        let mut store = Store::new(engine, ());
        store.set_epoch_deadline(1);
        // Push the engine past the deadline before entering wasm, so the trap
        // is taken at the first check rather than after an unpredictable wait.
        engine.increment_epoch();
        let Ok(instance) = wasmtime::Instance::new(&mut store, &module, &[]) else {
            return false;
        };
        let Ok(spin) = instance.get_typed_func::<(), ()>(&mut store, "spin") else {
            return false;
        };
        spin.call(&mut store, ()).is_err()
    }

    /// Run the epoch read-back against an engine built with the control
    /// deliberately on or off, so a test can prove the probe distinguishes the
    /// two rather than always answering yes.
    #[cfg(test)]
    pub(super) fn probe_epoch_for_test(enabled: bool) -> bool {
        let mut cfg = wasmtime::Config::new();
        cfg.epoch_interruption(enabled);
        let engine = Engine::new(&cfg).expect("engine config is valid either way");
        epoch_interruption_fires(&engine)
    }

    /// Build the engine a run's module will be compiled on, turning on exactly
    /// the controls `bounds` asks for.
    ///
    /// Each mechanism is enabled only when a grant needs it: fuel accounting
    /// instruments every compiled block, so switching it on for an uncapped run
    /// would charge that run for a bound it does not have.
    fn wasm_engine(bounds: &WasmBounds) -> std::result::Result<Engine, WasmBackendError> {
        let mut cfg = wasmtime::Config::new();
        cfg.consume_fuel(bounds.fuel.is_some());
        cfg.epoch_interruption(bounds.wall_clock_secs.is_some());
        Engine::new(&cfg).map_err(|e| WasmBackendError::ModuleLoadFailed {
            path: String::new(),
            reason: format!("failed to configure the wasm engine: {e}"),
        })
    }

    /// Maximum `WireRequest` JSON a guest module may hand the `mvm:egress`
    /// import in one call. Guest-controlled, so bounded to keep a
    /// malicious length from forcing an oversized host allocation.
    const MAX_REQUEST_BYTES: usize = 64 * 1024;

    /// Maximum `WireResponse` JSON the import will write back into guest
    /// memory in one call.
    const MAX_RESPONSE_BYTES: usize = 256 * 1024;

    /// Negative status codes the `mvm:egress` host-import returns instead
    /// of trapping the guest. Every branch that would otherwise reach for
    /// `unwrap`/`panic` on guest-controlled input returns one of these and
    /// logs the reason host-side.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(i32)]
    enum EgressImportError {
        NoMemoryExport = -1,
        RequestOutOfBounds = -2,
        RequestTooLarge = -3,
        MalformedRequest = -4,
        NoEndpointConfigured = -5,
        ConnectFailed = -6,
        RelayFailed = -7,
        ResponseSerializeFailed = -8,
        ResponseTooLargeForBuffer = -9,
        ResponseWriteOutOfBounds = -10,
        HostOutOfBounds = -11,
        BodyOutOfBounds = -12,
        PortInvalid = -13,
        ResponseDecodeFailed = -14,
        EgressRefused = -15,
        InvalidArguments = -16,
    }

    impl std::fmt::Display for EgressImportError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let msg = match self {
                Self::NoMemoryExport => "module does not export \"memory\"",
                Self::RequestOutOfBounds => "request ptr/len out of bounds",
                Self::RequestTooLarge => "request exceeds the maximum egress request size",
                Self::MalformedRequest => "request is not a valid WireRequest",
                Self::NoEndpointConfigured => "no egress endpoint configured for this backend",
                Self::ConnectFailed => "failed to connect to the egress endpoint",
                Self::RelayFailed => "failed to relay the request to the egress endpoint",
                Self::ResponseSerializeFailed => "failed to serialize the endpoint response",
                Self::ResponseTooLargeForBuffer => {
                    "response does not fit in the guest-provided buffer"
                }
                Self::ResponseWriteOutOfBounds => "response ptr/cap out of bounds",
                Self::HostOutOfBounds => "egress host ptr/len out of bounds",
                Self::BodyOutOfBounds => "egress body ptr/len out of bounds",
                Self::PortInvalid => "egress port is not a valid 16-bit value",
                Self::ResponseDecodeFailed => "failed to decode the endpoint response body",
                Self::EgressRefused => "egress refused by policy or endpoint",
                Self::InvalidArguments => "mvm:egress called with wrong argument types/count",
            };
            f.write_str(msg)
        }
    }

    /// Read `len` guest-controlled bytes at `ptr` out of `memory`. Bounds
    /// and size are validated before any allocation or memory access —
    /// out-of-range or oversized input returns an error, never panics.
    fn read_request_bytes(
        memory: &Memory,
        store: impl wasmtime::AsContext,
        ptr: i32,
        len: i32,
    ) -> std::result::Result<Vec<u8>, EgressImportError> {
        read_bytes(
            memory,
            store,
            ptr,
            len,
            EgressImportError::RequestOutOfBounds,
            EgressImportError::RequestTooLarge,
            MAX_REQUEST_BYTES,
        )
    }

    /// Write `bytes` into `memory` at `ptr`, refusing to write beyond the
    /// guest-provided `cap`. Returns the written length as `i32`.
    fn write_response_bytes(
        memory: &Memory,
        store: impl wasmtime::AsContextMut,
        ptr: i32,
        cap: i32,
        bytes: &[u8],
    ) -> std::result::Result<i32, EgressImportError> {
        let ptr = usize::try_from(ptr).map_err(|_| EgressImportError::ResponseWriteOutOfBounds)?;
        let cap = usize::try_from(cap).map_err(|_| EgressImportError::ResponseWriteOutOfBounds)?;
        if bytes.len() > cap {
            return Err(EgressImportError::ResponseTooLargeForBuffer);
        }
        memory
            .write(store, ptr, bytes)
            .map_err(|_| EgressImportError::ResponseWriteOutOfBounds)?;
        i32::try_from(bytes.len()).map_err(|_| EgressImportError::ResponseTooLargeForBuffer)
    }

    /// Read `len` guest-controlled bytes at `ptr` out of `memory`, using
    /// `bounds_err` and `too_large_err` instead of the JSON-request codes.
    fn read_bytes(
        memory: &Memory,
        store: impl wasmtime::AsContext,
        ptr: i32,
        len: i32,
        bounds_err: EgressImportError,
        too_large_err: EgressImportError,
        max_len: usize,
    ) -> std::result::Result<Vec<u8>, EgressImportError> {
        let ptr = usize::try_from(ptr).map_err(|_| bounds_err)?;
        let len = usize::try_from(len).map_err(|_| bounds_err)?;
        if len > max_len {
            return Err(too_large_err);
        }
        let mut buf = vec![0u8; len];
        memory.read(store, ptr, &mut buf).map_err(|_| bounds_err)?;
        Ok(buf)
    }

    /// Connect to the substitution endpoint at `endpoint` and relay one
    /// `WireRequest`. Reuses `mvm_agentd::substitution_client::relay` — the
    /// same framed-JSON round-trip the in-guest substitution leg uses —
    /// rather than a second frame codec.
    fn call_egress_endpoint(
        endpoint: &Path,
        req: &WireRequest,
        timeout: Duration,
    ) -> std::result::Result<WireResponse, EgressImportError> {
        let mut stream = std::os::unix::net::UnixStream::connect(endpoint).map_err(|e| {
            tracing::warn!(
                endpoint = %endpoint.display(),
                error = %e,
                "mvm:egress: connect to substitution endpoint failed"
            );
            EgressImportError::ConnectFailed
        })?;
        // Time inside this call is time epoch interruption cannot reclaim: the
        // deadline check lives in compiled wasm, and this thread is in host
        // code. Without a socket timeout a hostile or wedged endpoint parks the
        // module here for as long as it likes, which is exactly the hole a fuel
        // budget alone leaves open.
        let deadline = |result: std::io::Result<()>| {
            result.map_err(|e| {
                tracing::warn!(error = %e, "mvm:egress: setting the endpoint call timeout failed");
                EgressImportError::ConnectFailed
            })
        };
        deadline(stream.set_read_timeout(Some(timeout)))?;
        deadline(stream.set_write_timeout(Some(timeout)))?;
        mvm_agentd::substitution_client::relay(&mut stream, req).map_err(|e| {
            tracing::warn!(error = %e, "mvm:egress: relay to substitution endpoint failed");
            EgressImportError::RelayFailed
        })
    }

    fn mvm_egress_import_inner(
        caller: &mut Caller<'_, WasmHostState>,
        req_ptr: i32,
        req_len: i32,
        resp_ptr: i32,
        resp_cap: i32,
    ) -> std::result::Result<i32, EgressImportError> {
        let memory = match caller.get_export("memory") {
            Some(Extern::Memory(mem)) => mem,
            _ => return Err(EgressImportError::NoMemoryExport),
        };

        let req_bytes = read_request_bytes(&memory, &*caller, req_ptr, req_len)?;
        let req: WireRequest =
            serde_json::from_slice(&req_bytes).map_err(|_| EgressImportError::MalformedRequest)?;

        let endpoint = caller
            .data()
            .egress_endpoint
            .clone()
            .ok_or(EgressImportError::NoEndpointConfigured)?;
        let timeout = caller.data().egress_timeout;

        let resp = call_egress_endpoint(&endpoint, &req, timeout)?;
        let resp_bytes =
            serde_json::to_vec(&resp).map_err(|_| EgressImportError::ResponseSerializeFailed)?;
        if resp_bytes.len() > MAX_RESPONSE_BYTES {
            return Err(EgressImportError::ResponseTooLargeForBuffer);
        }
        write_response_bytes(&memory, caller, resp_ptr, resp_cap, &resp_bytes)
    }

    /// The `"mvm"`/`"egress_json"` host-import:
    /// `(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_cap: i32) -> i32`.
    ///
    /// Reads a `WireRequest` JSON blob from `req_len` bytes at `req_ptr` in
    /// the calling module's exported `memory`, relays it to the configured
    /// substitution-endpoint UDS, and writes the `WireResponse` JSON back
    /// at `resp_ptr` (up to `resp_cap` bytes), returning its length. Never
    /// panics or traps the host on guest-controlled input: every failure
    /// returns a negative [`EgressImportError`] code and is logged
    /// host-side instead.
    fn mvm_egress_json_import(
        mut caller: Caller<'_, WasmHostState>,
        req_ptr: i32,
        req_len: i32,
        resp_ptr: i32,
        resp_cap: i32,
    ) -> i32 {
        match mvm_egress_import_inner(&mut caller, req_ptr, req_len, resp_ptr, resp_cap) {
            Ok(len) => len,
            Err(err) => {
                tracing::warn!(error = %err, "mvm:egress_json host-import failed closed");
                err as i32
            }
        }
    }

    /// Maximum host name length the browser-style `mvm:egress` import will
    /// accept. Public DNS names are short; this keeps a malicious length from
    /// forcing an oversized host allocation.
    const MAX_EGRESS_HOST_BYTES: usize = 1024;

    /// Maximum body length the browser-style `mvm:egress` import will accept.
    const MAX_EGRESS_BODY_BYTES: usize = 64 * 1024;

    /// Arguments to the browser-style `mvm:egress` host-import:
    /// `(host_ptr, host_len, port, body_ptr, body_len, out_ptr, out_cap)`.
    ///
    /// Grouping them keeps the import callback's parameter count small and
    /// makes the validated, parsed shape explicit.
    struct BrowserEgressArgs {
        host_ptr: i32,
        host_len: i32,
        port: i32,
        body_ptr: i32,
        body_len: i32,
        out_ptr: i32,
        out_cap: i32,
    }

    impl BrowserEgressArgs {
        fn from_params(params: &[Val]) -> std::result::Result<Self, EgressImportError> {
            let get = |i: usize| {
                params
                    .get(i)
                    .and_then(Val::i32)
                    .ok_or(EgressImportError::InvalidArguments)
            };
            Ok(Self {
                host_ptr: get(0)?,
                host_len: get(1)?,
                port: get(2)?,
                body_ptr: get(3)?,
                body_len: get(4)?,
                out_ptr: get(5)?,
                out_cap: get(6)?,
            })
        }
    }

    /// The `"mvm"`/`"egress"` host-import (browser-style ABI):
    /// `(host_ptr: i32, host_len: i32, port: i32, body_ptr: i32, body_len: i32,
    ///   out_ptr: i32, out_cap: i32) -> i32`.
    ///
    /// Builds a `WireRequest` from `host`, `port`, and `body`, relays it to
    /// the configured substitution-endpoint UDS, and writes the decoded
    /// response body into `out_ptr` (up to `out_cap` bytes). On refusal the
    /// refusal message is written to `out_ptr` and a negative code is
    /// returned. This ABI matches the browser-tier demo guest so the same
    /// module can run under host `wasmtime` and in a browser Worker.
    fn mvm_egress_browser_import(
        caller: &mut Caller<'_, WasmHostState>,
        args: BrowserEgressArgs,
    ) -> std::result::Result<i32, EgressImportError> {
        let memory = match caller.get_export("memory") {
            Some(Extern::Memory(mem)) => mem,
            _ => return Err(EgressImportError::NoMemoryExport),
        };

        let host_bytes = read_bytes(
            &memory,
            &*caller,
            args.host_ptr,
            args.host_len,
            EgressImportError::HostOutOfBounds,
            EgressImportError::HostOutOfBounds,
            MAX_EGRESS_HOST_BYTES,
        )?;
        let host = String::from_utf8_lossy(&host_bytes);
        let port = u16::try_from(args.port).map_err(|_| EgressImportError::PortInvalid)?;

        let body = read_bytes(
            &memory,
            &*caller,
            args.body_ptr,
            args.body_len,
            EgressImportError::BodyOutOfBounds,
            EgressImportError::BodyOutOfBounds,
            MAX_EGRESS_BODY_BYTES,
        )?;

        let url = format!("https://{host}:{port}/");
        let method = if body.is_empty() { "GET" } else { "POST" };
        let req = WireRequest {
            method: method.to_string(),
            url,
            headers: Vec::new(),
            body_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &body),
        };

        let endpoint = caller
            .data()
            .egress_endpoint
            .clone()
            .ok_or(EgressImportError::NoEndpointConfigured)?;
        let timeout = caller.data().egress_timeout;

        let resp = call_egress_endpoint(&endpoint, &req, timeout)?;
        let out_bytes = match resp {
            WireResponse::Ok { body_b64, .. } => {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body_b64)
                    .map_err(|_| EgressImportError::ResponseDecodeFailed)?
            }
            WireResponse::Refused { message } => {
                let bytes = message.into_bytes();
                write_response_bytes(&memory, caller, args.out_ptr, args.out_cap, &bytes)?;
                return Err(EgressImportError::EgressRefused);
            }
        };
        write_response_bytes(&memory, caller, args.out_ptr, args.out_cap, &out_bytes)
    }

    fn install_egress_import(
        linker: &mut Linker<WasmHostState>,
    ) -> std::result::Result<(), wasmtime::Error> {
        let ty = FuncType::new(
            linker.engine(),
            vec![
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
            ],
            vec![ValType::I32],
        );
        linker.func_new("mvm", "egress", ty, |mut caller, params, results| {
            let args = match BrowserEgressArgs::from_params(params) {
                Ok(args) => args,
                Err(err) => {
                    tracing::warn!(error = %err, "mvm:egress host-import failed closed (bad args)");
                    results[0] = Val::I32(err as i32);
                    return Ok(());
                }
            };
            match mvm_egress_browser_import(&mut caller, args) {
                Ok(len) => results[0] = Val::I32(len),
                Err(err) => {
                    tracing::warn!(error = %err, "mvm:egress host-import failed closed");
                    results[0] = Val::I32(err as i32);
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Everything one run needs, plus the read-back of what is bounding it.
    ///
    /// The ticker is carried here rather than spawned at the call site so it
    /// lives exactly as long as the store whose deadline it drives.
    pub(super) struct WasmRuntime {
        pub engine: Engine,
        pub linker: Linker<WasmHostState>,
        pub store: Store<WasmHostState>,
        pub enforced: EnforcedGrants,
        _ticker: Option<EpochTicker>,
    }

    /// Build a fresh engine + linker wired with WASI Preview 1 and the
    /// `mvm:egress` host-import, and a `Store` carrying `egress_endpoint`
    /// as host state. The instance's filesystem and environment come
    /// exclusively from `activation`: every preopen is applied with its
    /// read-only marking and every env entry is set, and nothing beyond
    /// them is reachable. The one wiring path both [`run_module_to_completion`]
    /// and the test-only [`instantiate_for_test`] go through, so the
    /// import can't drift between the production and test instantiation
    /// paths.
    ///
    /// `bounds` are installed here and read back before the caller gets the
    /// store: a control that could not be confirmed live fails the whole
    /// construction rather than downgrading into a run that would be reported
    /// as bounded on a setter's say-so.
    fn new_engine_linker_store(
        egress_endpoint: Option<PathBuf>,
        activation: Option<&WasmPreopenPlan>,
        bounds: WasmBounds,
    ) -> std::result::Result<WasmRuntime, WasmBackendError> {
        let engine = wasm_engine(&bounds)?;
        let mut linker: Linker<WasmHostState> = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |state: &mut WasmHostState| &mut state.wasi).map_err(
            |e| WasmBackendError::ModuleLoadFailed {
                path: String::new(),
                reason: format!("failed to wire WASI imports: {e}"),
            },
        )?;
        install_egress_import(&mut linker).map_err(|e| WasmBackendError::ModuleLoadFailed {
            path: String::new(),
            reason: format!("failed to wire the mvm:egress host-import: {e}"),
        })?;
        linker
            .func_wrap("mvm", "egress_json", mvm_egress_json_import)
            .map_err(|e| WasmBackendError::ModuleLoadFailed {
                path: String::new(),
                reason: format!("failed to wire the mvm:egress_json host-import: {e}"),
            })?;

        let mut wasi_builder = WasiCtxBuilder::new();
        wasi_builder.inherit_stdio();
        if let Some(plan) = activation {
            for preopen in &plan.preopens {
                let (dir_perms, file_perms) = if preopen.read_only {
                    (DirPerms::READ, FilePerms::READ)
                } else {
                    (
                        DirPerms::READ | DirPerms::MUTATE,
                        FilePerms::READ | FilePerms::WRITE,
                    )
                };
                wasi_builder
                    .preopened_dir(
                        &preopen.host_dir,
                        &preopen.guest_path,
                        dir_perms,
                        file_perms,
                    )
                    .map_err(|e| WasmBackendError::ModuleLoadFailed {
                        path: String::new(),
                        reason: format!(
                            "preopen {} at {}: {e}",
                            preopen.host_dir.display(),
                            preopen.guest_path
                        ),
                    })?;
            }
            for (key, value) in &plan.env {
                wasi_builder.env(key, value);
            }
        }
        let wasi_ctx = wasi_builder.build_p1();
        let mut store = Store::new(
            &engine,
            WasmHostState {
                wasi: wasi_ctx,
                egress_endpoint,
                limits: wasmtime::StoreLimitsBuilder::new()
                    .memory_size(bounds.memory_bytes)
                    .build(),
                egress_timeout: bounds.egress_call_timeout(),
            },
        );
        store.limiter(|state| &mut state.limits);

        // Wall clock first: the probe advances the engine's epoch, and
        // `set_epoch_deadline` is relative to whatever the counter reads when
        // it is called.
        let mut ticker = None;
        let wall_clock = match bounds.wall_clock_secs {
            Some(secs) => {
                if !epoch_interruption_fires(&engine) {
                    return Err(WasmBackendError::ControlNotConfirmed {
                        control: "epoch interruption",
                    });
                }
                store.set_epoch_deadline(u64::from(secs) * EPOCH_TICKS_PER_SEC);
                ticker = Some(EpochTicker::spawn(&engine));
                EnforcedTier::WasmEpoch
            }
            None => EnforcedTier::Declared,
        };

        let cpu = match bounds.fuel {
            Some(instructions) => {
                let installed = store.set_fuel(instructions).is_ok()
                    && store.get_fuel().is_ok_and(|got| got == instructions);
                if !installed {
                    // `get_fuel` errors unless the engine was configured to
                    // consume fuel, so this is a read of the live control and
                    // not a restatement of the value just written.
                    return Err(WasmBackendError::ControlNotConfirmed {
                        control: "fuel accounting",
                    });
                }
                EnforcedTier::WasmFuel
            }
            None => EnforcedTier::Declared,
        };

        Ok(WasmRuntime {
            engine,
            linker,
            store,
            enforced: EnforcedGrants { cpu, wall_clock },
            _ticker: ticker,
        })
    }

    /// Instantiate the WASI module at `path` and run its `_start` export to
    /// completion. The instance receives exactly the capabilities
    /// `activation` admits: its preopens are the only directories the
    /// module can see (read-only where marked), its env entries the only
    /// ones set — no filesystem preopens and no socket capability are ever
    /// granted beyond that, so the instance is network- and
    /// host-fs-isolated by construction beyond the explicit `mvm:egress`
    /// import; a module with no `egress_endpoint` configured gets
    /// `NoEndpointConfigured` on every `mvm:egress` call.
    pub fn run_module_to_completion(
        path: &str,
        egress_endpoint: Option<PathBuf>,
        activation: Option<&WasmPreopenPlan>,
        bounds: WasmBounds,
    ) -> std::result::Result<CompletedRun, WasmBackendError> {
        let WasmRuntime {
            engine,
            linker,
            mut store,
            enforced,
            _ticker,
        } = new_engine_linker_store(egress_endpoint, activation, bounds)?;
        let module =
            Module::from_file(&engine, path).map_err(|e| WasmBackendError::ModuleLoadFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;
        let instance = linker.instantiate(&mut store, &module).map_err(|e| {
            WasmBackendError::ModuleLoadFailed {
                path: path.to_string(),
                reason: e.to_string(),
            }
        })?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| WasmBackendError::NoStartExport {
                path: path.to_string(),
                reason: e.to_string(),
            })?;

        let exit = match start.call(&mut store, ()) {
            Ok(()) => VmExitStatus {
                code: Some(0),
                success: true,
            },
            Err(err) => match err.downcast::<wasmtime_wasi::I32Exit>() {
                Ok(exit) => VmExitStatus {
                    code: Some(exit.0),
                    success: exit.0 == 0,
                },
                Err(err) => {
                    return Err(WasmBackendError::ModuleTrapped {
                        path: path.to_string(),
                        reason: trap_reason(&err),
                    });
                }
            },
        };
        Ok(CompletedRun { exit, enforced })
    }

    /// Render a trap so the *reason* survives into the error message.
    ///
    /// wasmtime's own `Display` for an execution failure is the wasm backtrace;
    /// the trap kind — "all fuel consumed by WebAssembly", "interrupt" — is one
    /// level down the cause chain. Which control stopped a run is the whole
    /// point of bounding it, so it belongs in the message rather than only in a
    /// debug-formatted chain nobody prints.
    fn trap_reason(err: &wasmtime::Error) -> String {
        match err.downcast_ref::<wasmtime::Trap>() {
            Some(trap) => format!("{trap}: {err}"),
            None => err.to_string(),
        }
    }

    /// Instantiate the module at `path` through the exact wiring
    /// [`run_module_to_completion`] uses, without calling any exported
    /// function — so a test can call an arbitrary export (not just
    /// `_start`) and inspect the resulting `Store`/`Instance` afterward.
    /// Test-only surface: production code always goes through
    /// [`run_module_to_completion`].
    #[cfg(test)]
    pub(super) fn instantiate_for_test(
        path: &str,
        egress_endpoint: Option<PathBuf>,
        activation: Option<&WasmPreopenPlan>,
        bounds: WasmBounds,
    ) -> std::result::Result<InstantiatedForTest, WasmBackendError> {
        let WasmRuntime {
            engine,
            linker,
            mut store,
            // The tier report belongs to a run; this helper deliberately calls
            // no export, so there is nothing yet to report on.
            enforced: _,
            _ticker,
        } = new_engine_linker_store(egress_endpoint, activation, bounds)?;
        let module =
            Module::from_file(&engine, path).map_err(|e| WasmBackendError::ModuleLoadFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;
        let instance = linker.instantiate(&mut store, &module).map_err(|e| {
            WasmBackendError::ModuleLoadFailed {
                path: path.to_string(),
                reason: e.to_string(),
            }
        })?;
        Ok(InstantiatedForTest {
            store,
            instance,
            _ticker,
        })
    }

    /// What [`instantiate_for_test`] hands back. The ticker rides along
    /// because dropping it would silently stop advancing the epoch, leaving a
    /// caller holding a wall-clock-bounded store whose deadline nothing
    /// reaches.
    #[cfg(test)]
    pub(super) struct InstantiatedForTest {
        pub store: Store<WasmHostState>,
        pub instance: wasmtime::Instance,
        pub _ticker: Option<EpochTicker>,
    }
}

#[cfg(not(feature = "wasm-backend"))]
mod engine {
    use std::path::PathBuf;

    use super::{CompletedRun, WasmBackendError, WasmBounds};
    use crate::wasm_activation::WasmPreopenPlan;

    pub fn is_compiled_in() -> bool {
        false
    }

    pub fn run_module_to_completion(
        _path: &str,
        _egress_endpoint: Option<PathBuf>,
        _activation: Option<&WasmPreopenPlan>,
        _bounds: WasmBounds,
    ) -> std::result::Result<CompletedRun, WasmBackendError> {
        Err(WasmBackendError::NotCompiledIn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The uniform negotiation entry point, exercised through the real trait
    /// on a real backend rather than a hand-built capability matrix. This is
    /// what a library consumer holding an `AnyBackend` actually calls.
    #[test]
    fn negotiating_unsupported_capabilities_names_the_wasm_alternatives() {
        use mvm_core::protocol::vm_backend::{CapabilityAlternative, RequiredCapabilities};

        let backend = WasmBackend::new();
        let required = RequiredCapabilities {
            vsock: true,
            pty_exec: true,
            vcpu_state_snapshot: true,
            ..RequiredCapabilities::default()
        };

        let gaps = backend
            .negotiate(&required)
            .expect_err("the wasm tier serves none of these");

        let by_name = |want: &str| {
            gaps.iter()
                .find(|g| g.capability == want)
                .unwrap_or_else(|| panic!("no gap reported for {want}: {gaps:?}"))
                .clone()
        };

        // Egress still reaches the same substitution endpoint, just through
        // the host import rather than a vsock device.
        assert_eq!(
            by_name("vsock").alternative,
            CapabilityAlternative::NetworkEndpointOverWasmImport
        );
        // No vCPU state to restore, so the substitute is a cold start driven
        // by the same signed plan.
        assert_eq!(
            by_name("vcpu_state_snapshot").alternative,
            CapabilityAlternative::ColdStartFromSignedPlan
        );
        // No PTY, and the stdin route is explicitly not one.
        assert_eq!(
            by_name("pty_exec").alternative,
            CapabilityAlternative::WorkloadStdinRoute
        );

        assert!(
            gaps.iter().all(|g| g.is_actionable()),
            "every gap here has a real substitute: {gaps:?}"
        );
    }

    /// A backend that serves the request must not manufacture gaps.
    #[test]
    fn negotiating_a_request_the_backend_serves_returns_ok() {
        use mvm_core::protocol::vm_backend::RequiredCapabilities;

        let backend = WasmBackend::new();
        assert_eq!(
            backend.negotiate(&RequiredCapabilities::default()),
            Ok(()),
            "an empty requirement set is served by every backend"
        );
    }

    fn cfg(name: &str, module_path: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.to_string(),
            rootfs_path: module_path.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn kind_and_name_are_wasm() {
        let b = WasmBackend::new();
        assert_eq!(b.name(), "wasm");
        assert_eq!(b.kind(), BackendKind::Wasm);
    }

    #[test]
    fn capabilities_are_honest_about_lacking_isolation() {
        let caps = WasmBackend::new().capabilities();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(!caps.vsock);
        assert!(!caps.tap_networking);
        assert!(!caps.balloon);
        assert!(!caps.fs_quick_checkpoint);
        assert!(!caps.host_vsock_proxy);
        assert!(!caps.pty_exec);
        assert!(!caps.production_ssh);
        assert!(caps.no_routable_guest_nic);
    }

    #[test]
    fn security_profile_carries_zero_numbered_claims() {
        let profile = WasmBackend::new().security_profile();
        assert!(
            profile
                .claims
                .iter()
                .all(|c| matches!(c, ClaimStatus::DoesNotHold)),
            "wasm tier must not claim any numbered security guarantee"
        );
        assert_eq!(profile.dropped_claims(), vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(profile.layer_coverage, LayerCoverage::default());
    }

    #[test]
    fn snapshot_capability_defaults_to_unsupported() {
        use mvm_core::vm_backend::SnapshotCapability;
        assert_eq!(
            WasmBackend::new().snapshot_capability(),
            SnapshotCapability::Unsupported
        );
    }

    #[test]
    fn warm_start_fails_closed() {
        use mvm_core::vm_backend::{SnapshotCapability, WarmStartError};
        let b = WasmBackend::new();
        match b.warm_start(&VmStartConfig::default(), SnapshotCapability::DiskOnly) {
            Err(WarmStartError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn standby_pool_fails_closed() {
        assert!(!WasmBackend::new().supports_standby_pool());
    }

    #[test]
    fn pause_resume_fail_closed_with_typed_error() {
        let b = WasmBackend::new();
        let id = VmId("x".to_string());
        let err = b.pause(&id).unwrap_err();
        assert!(err.to_string().contains("pause/resume"));
        let err = b.resume(&id).unwrap_err();
        assert!(err.to_string().contains("pause/resume"));
    }

    #[test]
    fn kernel_request_fails_closed() {
        let mut config = cfg("x", "/tmp/does-not-matter.wasm");
        config.kernel_path = Some("/some/vmlinux".to_string());
        let err = reject_unsupported_start_config(&config).unwrap_err();
        assert_eq!(err, WasmBackendError::KernelBootNotSupported);
    }

    #[test]
    fn verified_boot_request_fails_closed() {
        let mut config = cfg("x", "/tmp/does-not-matter.wasm");
        config.roothash = Some("a".repeat(64));
        let err = reject_unsupported_start_config(&config).unwrap_err();
        assert_eq!(err, WasmBackendError::VerifiedBootNotSupported);
    }

    #[test]
    fn start_config_with_egress_policy_is_now_allowed() {
        // A policy that allows egress must NOT be rejected: egress is
        // governed (the substitution endpoint mediates it), not unsupported.
        let mut config = cfg("x", "/tmp/does-not-matter.wasm");
        config.network_policy = mvm_core::network_policy::NetworkPolicy::unrestricted();
        assert!(reject_unsupported_start_config(&config).is_ok());
    }

    #[test]
    fn start_config_still_rejects_kernel_and_console() {
        let mut config = cfg("x", "/tmp/does-not-matter.wasm");
        config.kernel_path = Some("/x".to_string());
        assert_eq!(
            reject_unsupported_start_config(&config),
            Err(WasmBackendError::KernelBootNotSupported)
        );
    }

    #[test]
    fn console_request_fails_closed() {
        let mut config = cfg("x", "/tmp/does-not-matter.wasm");
        config.dev_console = true;
        let err = reject_unsupported_start_config(&config).unwrap_err();
        assert_eq!(err, WasmBackendError::ConsoleNotSupported);
    }

    #[test]
    fn deny_all_default_network_policy_is_accepted() {
        let config = cfg("x", "/tmp/does-not-matter.wasm");
        assert!(reject_unsupported_start_config(&config).is_ok());
    }

    #[test]
    fn missing_module_path_fails_closed() {
        let config = cfg("x", "   ");
        let err = reject_unsupported_start_config(&config).unwrap_err();
        assert_eq!(err, WasmBackendError::ModulePathMissing);
    }

    #[test]
    fn disk_volume_fails_closed_materialized_directory_grant_passes() {
        let mut config = cfg("x", "/tmp/mod.wasm");
        config.volumes = vec![mvm_core::vm_backend::VmVolume {
            materialized_image: None,
            volume_label: None,
            host: "/host/disk.img".into(),
            guest: "/data/disk".into(),
            size: "1G".into(),
            read_only: false,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        }];
        assert_eq!(
            reject_unsupported_start_config(&config),
            Err(WasmBackendError::DiskVolumeNotSupported {
                host: "/host/disk.img".into()
            })
        );

        config.volumes[0].materialized_image = Some("/state/mount.ext4".to_string());
        assert!(reject_unsupported_start_config(&config).is_ok());
    }

    #[test]
    fn volume_mountpoint_shadowing_the_handshake_fails_closed() {
        for bad in ["mnt/relative", "/run/mvm", "/mvm/runtime"] {
            let mut config = cfg("x", "/tmp/mod.wasm");
            config.volumes = vec![mvm_core::vm_backend::VmVolume {
                materialized_image: Some("/state/mount.ext4".to_string()),
                volume_label: None,
                host: "/host/share".into(),
                guest: bad.into(),
                size: String::new(),
                read_only: true,
                kind: mvm_core::vm_backend::VmVolumeKind::Disk,
                encrypted: false,
            }];
            assert!(
                matches!(
                    reject_unsupported_start_config(&config),
                    Err(WasmBackendError::VolumePathDenied { .. })
                ),
                "guest path {bad:?} must be refused"
            );
        }
    }

    // ── resource bounds: what this tier admits, and what it installs ──

    fn secs(n: u32) -> WallClockGrant {
        WallClockGrant::Secs {
            secs: std::num::NonZeroU32::new(n).expect("nonzero"),
        }
    }

    /// A bounded grant set the tier accepts: fuel with the wall clock that
    /// makes it a real bound.
    fn bounded_grants(instructions: u64, wall_clock_secs: u32) -> Grants {
        Grants {
            cpu: Some(CpuGrant::Fuel { instructions }),
            wall_clock: Some(secs(wall_clock_secs)),
            ..Default::default()
        }
    }

    /// Serialize an admitted plan carrying `grants`, in the bare-`ExecutionPlan`
    /// shape `plan_from_admitted_json` accepts.
    fn plan_json_with(grants: Grants) -> String {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.grants = Some(grants);
        serde_json::to_string(&plan).expect("plan serializes")
    }

    #[test]
    fn a_fuel_only_grant_is_refused() {
        // Fuel does not tick inside a host call, so fuel without a wall-clock
        // bound leaves a module that parks in `mvm:egress` bounded by nothing.
        // Accepting it would be partial enforcement reported as complete.
        let grants = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 10_000,
            }),
            wall_clock: None,
            ..Default::default()
        };
        assert_eq!(
            validate_wasm_grants(&grants),
            Err(WasmBackendError::FuelWithoutWallClock)
        );

        let err = WasmBackend::new()
            .apply_grants(&VmId("wasm-test".to_string()), &grants)
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("wall_clock"),
            "the refusal must name the missing grant: {err}"
        );
    }

    #[test]
    fn an_unbounded_wall_clock_does_not_satisfy_a_fuel_grant() {
        // `Unbounded` is an explicit "no ceiling", so it leaves exactly the
        // hole an absent grant does.
        let grants = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 10_000,
            }),
            wall_clock: Some(WallClockGrant::Unbounded),
            ..Default::default()
        };
        assert_eq!(
            validate_wasm_grants(&grants),
            Err(WasmBackendError::FuelWithoutWallClock)
        );
    }

    #[test]
    fn a_share_grant_is_refused_with_fuel_named_as_the_substitute() {
        let grants = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Default::default()
        };
        let err = WasmBackend::new()
            .apply_grants(&VmId("wasm-test".to_string()), &grants)
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("fuel"),
            "the refusal must name the substitute: {err}"
        );
    }

    #[test]
    fn a_wall_clock_grant_alone_is_accepted() {
        // Only the fuel direction is unsound. Epoch interruption bounds a run
        // whether or not an instruction budget accompanies it.
        let grants = Grants {
            wall_clock: Some(secs(30)),
            ..Default::default()
        };
        assert_eq!(validate_wasm_grants(&grants), Ok(()));
    }

    #[test]
    fn apply_grants_will_not_report_a_tier_for_a_vm_that_never_ran() {
        // The tier is a read-back off the store a module actually ran in.
        // With no run there is nothing to read, and answering `Declared` would
        // be indistinguishable from an unbounded run that did happen.
        let err = WasmBackend::new()
            .apply_grants(&VmId("never-ran".to_string()), &Grants::default())
            .expect_err("no run, no report");
        assert!(err.to_string().contains("no completed run recorded"));
    }

    #[test]
    fn the_signed_plan_is_where_grants_come_from() {
        let mut config = cfg("x", "/tmp/mod.wasm");
        // A CPU grant threaded onto the launch config is ignored when a signed
        // plan is present: the plan is what admission checked.
        config.cpu_grant = Some(CpuGrant::Fuel { instructions: 7 });
        config.plan_json = Some(plan_json_with(bounded_grants(4_242, 30)));

        let grants = wasm_grants_from_config(&config).expect("decodes");
        assert_eq!(
            grants.cpu,
            Some(CpuGrant::Fuel {
                instructions: 4_242
            })
        );
        assert_eq!(grants.wall_clock, Some(secs(30)));
    }

    #[test]
    fn a_launch_with_no_signed_plan_carries_only_its_cpu_grant() {
        // Which makes it fuel-without-wall-clock, and therefore refused —
        // the correct outcome for a bound that reached this tier without an
        // admission behind it.
        let mut config = cfg("x", "/tmp/mod.wasm");
        config.cpu_grant = Some(CpuGrant::Fuel { instructions: 7 });
        let grants = wasm_grants_from_config(&config).expect("no plan is not an error");
        assert_eq!(
            validate_wasm_grants(&grants),
            Err(WasmBackendError::FuelWithoutWallClock)
        );
    }

    #[test]
    fn a_launch_declaring_no_memory_still_gets_a_ceiling() {
        // A wasm memory grows on demand: "unset" would otherwise mean "as much
        // as the host has".
        let config = cfg("x", "/tmp/mod.wasm");
        assert_eq!(config.memory_mib, 0, "fixture declares no memory");
        let bounds = wasm_bounds_for(&config, &Grants::default());
        assert_eq!(bounds.memory_mib(), DEFAULT_WASM_MEMORY_MIB);
        assert_eq!(bounds.fuel, None);
        assert_eq!(bounds.wall_clock_secs, None);
    }

    #[test]
    fn a_declared_memory_is_the_ceiling_that_gets_installed() {
        let mut config = cfg("x", "/tmp/mod.wasm");
        config.memory_mib = 64;
        let bounds = wasm_bounds_for(&config, &bounded_grants(1_000, 5));
        assert_eq!(bounds.memory_mib(), 64);
        assert_eq!(bounds.fuel, Some(1_000));
        assert_eq!(bounds.wall_clock_secs, Some(5));
    }

    #[test]
    fn an_egress_call_cannot_outlive_the_runs_wall_clock_budget() {
        // Epoch interruption cannot preempt host code, so a host call longer
        // than the whole run's budget would defeat the bound it sits inside.
        let config = cfg("x", "/tmp/mod.wasm");
        let bounds = wasm_bounds_for(&config, &bounded_grants(1_000, 2));
        assert_eq!(
            bounds.egress_call_timeout(),
            std::time::Duration::from_secs(2)
        );

        // An unbounded run still gets a ceiling, so a wedged endpoint cannot
        // park the tier forever.
        let unbounded = wasm_bounds_for(&config, &Grants::default());
        assert_eq!(
            unbounded.egress_call_timeout(),
            std::time::Duration::from_secs(MAX_EGRESS_CALL_SECS)
        );

        // A generous grant is clamped to the tier's own ceiling rather than
        // inherited verbatim.
        let generous = wasm_bounds_for(&config, &bounded_grants(1_000, 3_600));
        assert_eq!(
            generous.egress_call_timeout(),
            std::time::Duration::from_secs(MAX_EGRESS_CALL_SECS)
        );
    }

    // ── P3b.1: wasm_endpoint_plan / wasm_network_endpoint_spawn_params ──
    // Decision + params only — no subprocess is ever spawned in this module.

    // Mirrors `libkrun_substitution_not_spawned_when_no_secrets_and_no_egress`:
    // a fresh state dir (no plan.json) plus the default deny-all policy has
    // nothing to mediate, so the plan must skip.
    #[test]
    fn wasm_endpoint_plan_is_none_when_no_secrets_and_no_egress() {
        let dir = tempfile::tempdir().unwrap();
        let config = VmStartConfig {
            name: "no-secrets-wasm-vm".to_string(),
            ..Default::default()
        };
        let plan = wasm_endpoint_plan(&config, dir.path()).unwrap();
        assert!(
            plan.is_none(),
            "deny-all policy with no bound secrets must skip the endpoint spawn"
        );
    }

    // A policy that allows egress must still produce a spawn plan even with
    // no bound secrets — the endpoint runs in wire mode regardless and gates
    // the destination itself, mirroring libkrun's own skip condition.
    #[test]
    fn wasm_endpoint_plan_is_some_when_policy_allows_egress_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let config = VmStartConfig {
            name: "policy-allow-wasm-vm".to_string(),
            network_policy: mvm_core::network_policy::NetworkPolicy::preset(
                mvm_core::network_policy::NetworkPreset::Dev,
            ),
            ..Default::default()
        };
        let plan = wasm_endpoint_plan(&config, dir.path())
            .unwrap()
            .expect("a policy allowing egress must produce a spawn plan");
        assert!(plan.secrets.is_empty());
        assert_eq!(plan.tenant, "local");
    }

    // Secrets present (even under a deny-all `VmStartConfig::network_policy`,
    // since the endpoint itself gates per-destination) must produce a spawn
    // plan whose params mirror libkrun/hvf except for the wasm-only
    // deviations: always `Uds`, no terminator, no TLS, and — the one field
    // that must NOT mirror libkrun — the wasm tier never carries an identity.
    #[test]
    fn wasm_endpoint_plan_params_mirror_libkrun_with_wasm_deviations() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let secret = mvm_core::plan::SecretBinding {
            name: "API_KEY".to_string(),
            source: mvm_core::plan::SecretSource::Keystore {
                address: "addr".to_string(),
            },
        };
        let admitted = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("acme")
            .secrets(vec![secret.clone()])
            .build();
        std::fs::write(
            dir.path().join("plan.json"),
            serde_json::to_string(&admitted).unwrap(),
        )
        .unwrap();

        let config = VmStartConfig {
            name: "secret-wasm-vm".to_string(),
            ..Default::default()
        };
        let plan = wasm_endpoint_plan(&config, dir.path())
            .unwrap()
            .expect("bound secrets must produce a spawn plan");

        assert_eq!(plan.vm_name, "secret-wasm-vm");
        assert_eq!(plan.state_dir, dir.path().to_path_buf());
        assert_eq!(plan.tenant, "acme");
        assert_eq!(plan.secrets, vec![secret]);
        assert_eq!(
            plan.socket_path,
            mvm_core::config::vm_network_endpoint_socket("secret-wasm-vm")
        );

        let params = wasm_network_endpoint_spawn_params(&plan, &config.network_policy);
        assert_eq!(params.vm_name, "secret-wasm-vm");
        assert_eq!(
            params.transport,
            crate::network_endpoint_spawn::EndpointTransport::Uds {
                path: plan.socket_path.clone(),
            }
        );
        assert!(
            params.terminator_listen.is_none(),
            "wasm has no TAP/nft REDIRECT to feed a terminator"
        );
        assert!(
            params.tls_intermediate.is_none(),
            "http-only POC; HTTPS termination is a later phase"
        );
        assert!(
            params.network_policy.is_some(),
            "the endpoint must gate the destination itself"
        );
        assert!(
            params.flowmux_identity.is_none(),
            "wasm always speaks WireRequest wire mode, never libkrun's raw pass-through"
        );
    }

    #[test]
    fn network_info_and_guest_channel_info_fail_closed_by_default() {
        let b = WasmBackend::new();
        let id = VmId("x".to_string());
        assert!(b.network_info(&id).is_err());
        assert!(b.guest_channel_info(&id).is_err());
    }

    #[test]
    fn balloon_ops_fail_closed_by_default() {
        let b = WasmBackend::new();
        let id = VmId("x".to_string());
        assert!(b.balloon_set_target(&id, 64).is_err());
        assert!(b.balloon_state(&id).is_err());
    }

    #[test]
    fn is_available_without_feature_reflects_engine_compiled_in() {
        // Cheap, tautological-looking, but pins the contract: `is_available`
        // must track whether the real engine module compiled in, not a
        // hardcoded `true`.
        assert_eq!(
            WasmBackend::new().is_available().unwrap(),
            engine::is_compiled_in()
        );
    }

    #[cfg(not(feature = "wasm-backend"))]
    #[test]
    fn start_without_feature_fails_closed_not_panics() {
        // Isolate MVM_HOME: `start` materializes the activation run dir
        // before the engine's fail-closed error, and must not write into
        // the developer's real `~/.mvm`.
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let b = WasmBackend::new();
        let config = cfg("x", "/tmp/does-not-matter.wasm");
        let err = b.start(&config).unwrap_err();
        assert!(err.to_string().contains("not compiled in"));
    }

    #[cfg(not(feature = "wasm-backend"))]
    #[test]
    fn install_without_feature_fails_closed() {
        assert!(WasmBackend::new().install().is_err());
    }

    #[cfg(feature = "wasm-backend")]
    mod wasm_backend_engine_tests {
        use super::*;
        use mvm_contract::protocol::resource_controls::EnforcedTier;
        use mvm_core::substitution_wire::WireRequest;
        use std::io::Write;

        /// Escape a string for embedding as a WAT string-literal data
        /// segment: backslash and double-quote are the only two bytes WAT
        /// string syntax requires escaped for otherwise-printable JSON text.
        fn wat_escape(s: &str) -> String {
            s.replace('\\', "\\\\").replace('"', "\\\"")
        }

        /// Isolate MVM_HOME: every `start` materializes the activation run
        /// dir under the per-VM state dir, and these tests must not write
        // into the developer's real `~/.mvm`.
        fn isolated_home() -> (
            mvm_core::util::test_env::TestEnv,
            tempfile::TempDir,
            std::sync::MutexGuard<'static, ()>,
        ) {
            let guard = crate::base::runtime_meta::HOME_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let dir = tempfile::tempdir().unwrap();
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.set("MVM_HOME", dir.path());
            (env, dir, guard)
        }

        /// Write `wat` to a temp `.wat` file `wasmtime::Module::from_file`
        /// can parse (it text-parses `.wat` and auto-detects binary wasm).
        fn wat_module(wat: &str) -> tempfile::NamedTempFile {
            let mut f = tempfile::Builder::new().suffix(".wat").tempfile().unwrap();
            f.write_all(wat.as_bytes()).unwrap();
            f.flush().unwrap();
            f
        }

        #[test]
        fn runs_a_trivial_module_to_completion_with_exit_zero() {
            // No imports beyond the linked WASI basics; `_start` just
            // returns, which this backend treats as a clean exit(0).
            let (_env, _home, _guard) = isolated_home();
            let module = wat_module("(module (func) (export \"_start\" (func 0)))");
            let b = WasmBackend::new();
            let config = cfg("trivial", module.path().to_str().unwrap());

            let id = b
                .start(&config)
                .expect("trivial module must run to completion");
            assert_eq!(id.0, "trivial");

            let status = b
                .wait(&id)
                .expect("wait must return the captured exit status");
            assert_eq!(status.code, Some(0));
            assert!(status.success);

            // The capability handshake was materialized: the activation run
            // dir + file exist under this VM's isolated state dir.
            let run_dir = mvm_core::config::vm_state_dir("trivial").join("wasm-activation");
            assert!(run_dir.join("activation.json").is_file());
            let written: crate::wasm_activation::WasmActivation =
                serde_json::from_slice(&std::fs::read(run_dir.join("activation.json")).unwrap())
                    .unwrap();
            assert_eq!(written.runtime_overlay, None);
            assert!(!written.grant_present);
        }

        #[test]
        fn module_sees_the_activation_env_and_the_runtime_preopen() {
            let (_env, home, _guard) = isolated_home();
            // Seed an overlay-bins dir so the activation carries a runtime
            // preopen the module can enumerate.
            let overlay = home.path().join("runtime-overlay-bins");
            std::fs::create_dir_all(&overlay).unwrap();
            let config = cfg("activated", "/tmp/does-not-matter.wasm");
            let run_dir = mvm_core::config::vm_state_dir("activated").join("wasm-activation");
            std::fs::create_dir_all(&run_dir).unwrap();
            std::fs::write(run_dir.join("activation.json"), "{}").unwrap();
            let plan = crate::wasm_activation::build_wasm_preopen_plan(
                &config,
                &run_dir,
                Some(overlay.as_path()),
            );

            // A fixture that reads MVM_ACTIVATION_FILE via WASI environ and
            // exits 0 only when it matches, and lists the overlay preopen.
            let wat = r#"
                (module
                  (import "wasi_snapshot_preview1" "environ_sizes_get" (func $esizes (param i32 i32) (result i32)))
                  (import "wasi_snapshot_preview1" "environ_get" (func $eget (param i32 i32) (result i32)))
                  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
                  (memory (export "memory") 1)
                  (data (i32.const 512) "MVM_ACTIVATION_FILE=/run/mvm/activation.json")
                  (func $memcmp (param $a i32) (param $b i32) (param $len i32) (result i32)
                    (local $i i32)
                    (block $done
                      (loop $loop
                        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
                        (if (i32.ne (i32.load8_u (i32.add (local.get $a) (local.get $i)))
                                    (i32.load8_u (i32.add (local.get $b) (local.get $i))))
                          (then (return (i32.const 0))))
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br $loop)))
                    (i32.const 1))
                  (func (export "_start")
                    (local $count i32) (local $i i32) (local $ptr i32)
                    (if (i32.ne (call $esizes (i32.const 0) (i32.const 4)) (i32.const 0))
                      (then (call $proc_exit (i32.const 2))))
                    (local.set $count (i32.load (i32.const 0)))
                    (if (i32.ne (call $eget (i32.const 16) (i32.const 1024)) (i32.const 0))
                      (then (call $proc_exit (i32.const 3))))
                    (block $done
                      (loop $scan
                        (br_if $done (i32.ge_u (local.get $i) (local.get $count)))
                        (local.set $ptr (i32.load (i32.add (i32.const 16) (i32.mul (local.get $i) (i32.const 4)))))
                        (if (call $memcmp (local.get $ptr) (i32.const 512) (i32.const 44))
                          (then (call $proc_exit (i32.const 0))))
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br $scan)))
                    (call $proc_exit (i32.const 7))))
            "#;
            let module = wat_module(wat);
            let run = engine::run_module_to_completion(
                module.path().to_str().unwrap(),
                None,
                Some(&plan),
                WasmBounds::unbounded(),
            )
            .expect("module with the activation env must run to completion");
            assert_eq!(run.exit.code, Some(0), "activation env must be visible");

            // Without the activation plan the same module must NOT see the env.
            let run = engine::run_module_to_completion(
                module.path().to_str().unwrap(),
                None,
                None,
                WasmBounds::unbounded(),
            )
            .expect("module without the activation plan must still run");
            assert_eq!(run.exit.code, Some(7), "no env without the handshake");
        }

        #[test]
        fn runs_a_module_that_calls_proc_exit_with_a_nonzero_code() {
            let (_env, _home, _guard) = isolated_home();
            let wat = r#"
                (module
                  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
                  (memory (export "memory") 1)
                  (func $_start
                    i32.const 7
                    call $proc_exit)
                  (export "_start" (func $_start)))
            "#;
            let module = wat_module(wat);
            let b = WasmBackend::new();
            let config = cfg("exit-seven", module.path().to_str().unwrap());

            let id = b
                .start(&config)
                .expect("proc_exit module must run to completion");
            let status = b
                .wait(&id)
                .expect("wait must return the captured exit status");
            assert_eq!(status.code, Some(7));
            assert!(!status.success);
        }

        /// A launch config carrying `grants` on a signed plan, plus whatever
        /// memory the caller wants bounded.
        fn bounded_cfg(
            name: &str,
            module_path: &str,
            grants: Grants,
            memory_mib: u32,
        ) -> VmStartConfig {
            let mut config = cfg(name, module_path);
            config.plan_json = Some(plan_json_with(grants));
            config.memory_mib = memory_mib;
            config
        }

        #[test]
        fn a_fuel_grant_halts_a_runaway_module() {
            // An infinite loop must be stopped by the instruction budget rather
            // than running until the test harness gives up. The wall clock is
            // generous on purpose: if epoch were the thing that fired, the
            // assertion below would catch it.
            let (_env, _home, _guard) = isolated_home();
            let module = wat_module(r#"(module (func (export "_start") (loop br 0)))"#);
            let config = bounded_cfg(
                "runaway",
                module.path().to_str().unwrap(),
                bounded_grants(10_000, 300),
                64,
            );

            let err = WasmBackend::new()
                .start(&config)
                .expect_err("a runaway module must not complete");
            // The exact trap text, not merely the word "fuel": the tier's own
            // "could not confirm fuel accounting" refusal also contains it, and
            // that failure must not be able to satisfy this witness.
            assert!(
                err.to_string().contains("all fuel consumed by WebAssembly"),
                "expected fuel exhaustion, got: {err}"
            );
        }

        #[test]
        fn a_module_parked_in_a_host_call_is_stopped_by_epoch() {
            // The joint-requirement witness. This module spends essentially all
            // its time blocked inside `mvm:egress` against an endpoint that
            // accepts and never answers, so it burns a handful of instructions
            // per iteration. The fuel budget below is large enough that it can
            // never be the thing that stops the run — only epoch interruption
            // can, which is exactly why a fuel-only grant is refused.
            let (_env, _home, _guard) = isolated_home();
            let dir = tempfile::tempdir().unwrap();
            let socket_path = dir.path().join("blackhole.sock");
            let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let server_stop = std::sync::Arc::clone(&stop);
            let server = std::thread::spawn(move || {
                // Hold every accepted connection open without replying.
                let mut held = Vec::new();
                while !server_stop.load(std::sync::atomic::Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => held.push(stream),
                        Err(_) => break,
                    }
                }
            });

            let request_json = serde_json::to_string(&WireRequest {
                method: "GET".into(),
                url: "https://example.test/".into(),
                headers: vec![],
                body_b64: String::new(),
            })
            .unwrap();
            let wat = format!(
                r#"(module
  (import "mvm" "egress_json" (func $mvm_egress (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "{escaped}")
  (func (export "_start")
    (loop $l
      (drop (call $mvm_egress (i32.const 0) (i32.const {req_len}) (i32.const 4096) (i32.const 4096)))
      (br $l))))
"#,
                escaped = wat_escape(&request_json),
                req_len = request_json.len(),
            );
            let module = wat_module(&wat);

            // One second of wall clock, which also clamps each egress call to
            // one second, against a billion instructions of fuel.
            let config = bounded_cfg(
                "parked",
                module.path().to_str().unwrap(),
                bounded_grants(1_000_000_000, 1),
                64,
            );
            let backend = WasmBackend::new().with_egress_endpoint(socket_path);

            let started = std::time::Instant::now();
            let err = backend
                .start(&config)
                .expect_err("a module parked in a host call must not run forever");
            let elapsed = started.elapsed();

            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = std::os::unix::net::UnixStream::connect(dir.path().join("blackhole.sock"));
            let _ = server.join();

            let message = err.to_string();
            assert!(
                !message.contains("fuel"),
                "fuel must not be what stopped this run — it barely ticked: {message}"
            );
            // The trap text specifically. "epoch" alone would also match the
            // tier's own "could not confirm epoch interruption" refusal, which
            // is a different outcome and must not pass for this one.
            assert!(
                message.contains("interrupt"),
                "expected an epoch interruption, got: {message}"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(60),
                "the bound must fire promptly, took {elapsed:?}"
            );
        }

        #[test]
        fn store_limits_refuse_a_module_that_grows_past_its_memory_bound() {
            // `memory.grow` returns -1 when the limiter refuses, which is the
            // conforming wasm signal for "that allocation is not available".
            // The module traps itself if the grow is *allowed*, so a missing
            // limiter turns this test red rather than silently passing.
            let (_env, _home, _guard) = isolated_home();
            let wat = r#"(module
  (memory (export "memory") 1)
  (func (export "_start")
    (if (i32.ne (memory.grow (i32.const 512)) (i32.const -1))
      (then (unreachable)))))
"#;
            let module = wat_module(wat);

            // 1 MiB ceiling; the module asks for 512 pages (32 MiB) on top of
            // the one it starts with.
            let bounded = bounded_cfg(
                "mem-bounded",
                module.path().to_str().unwrap(),
                Grants::default(),
                1,
            );
            let backend = WasmBackend::new();
            let id = backend
                .start(&bounded)
                .expect("a refused grow is not a failure — the module handles it");
            assert_eq!(backend.wait(&id).unwrap().code, Some(0));
            assert_eq!(
                backend.list().unwrap()[0].memory_mib,
                1,
                "the reported memory is the ceiling that was enforced"
            );

            // The control: raise the ceiling above what the module asks for and
            // the same grow succeeds, tripping the module's own `unreachable`.
            // This is what proves the refusal above came from the bound.
            let roomy = bounded_cfg(
                "mem-roomy",
                module.path().to_str().unwrap(),
                Grants::default(),
                128,
            );
            let err = WasmBackend::new()
                .start(&roomy)
                .expect_err("with room to grow, the module trips its own unreachable");
            assert!(err.to_string().contains("trapped"), "got: {err}");
        }

        #[test]
        fn a_bounded_run_reports_the_mechanisms_that_bounded_it() {
            let (_env, _home, _guard) = isolated_home();
            let module = wat_module("(module (func) (export \"_start\" (func 0)))");
            let grants = bounded_grants(1_000_000, 30);
            let config = bounded_cfg(
                "bounded-report",
                module.path().to_str().unwrap(),
                grants.clone(),
                64,
            );

            let backend = WasmBackend::new();
            let id = backend.start(&config).expect("bounded module runs");
            let enforced = backend.apply_grants(&id, &grants).expect("reports");
            assert_eq!(enforced.cpu, EnforcedTier::WasmFuel);
            assert_eq!(enforced.wall_clock, EnforcedTier::WasmEpoch);
            assert!(enforced.cpu.is_enforced() && enforced.wall_clock.is_enforced());
        }

        #[test]
        fn an_unbounded_run_reports_declared_on_both_dimensions() {
            let (_env, _home, _guard) = isolated_home();
            let module = wat_module("(module (func) (export \"_start\" (func 0)))");
            let config = bounded_cfg(
                "unbounded-report",
                module.path().to_str().unwrap(),
                Grants::default(),
                64,
            );

            let backend = WasmBackend::new();
            let id = backend.start(&config).expect("unbounded module runs");
            let enforced = backend
                .apply_grants(&id, &Grants::default())
                .expect("reports");
            assert_eq!(enforced.cpu, EnforcedTier::Declared);
            assert_eq!(enforced.wall_clock, EnforcedTier::Declared);
        }

        #[test]
        fn a_share_grant_never_reaches_the_engine() {
            // The refusal lands before anything is compiled, so a launch that
            // asked for an unenforceable bound leaves no VM behind.
            let (_env, _home, _guard) = isolated_home();
            let module = wat_module("(module (func) (export \"_start\" (func 0)))");
            let config = bounded_cfg(
                "share-refused",
                module.path().to_str().unwrap(),
                Grants {
                    cpu: Some(CpuGrant::Share { millicores: 1500 }),
                    wall_clock: Some(secs(30)),
                    ..Default::default()
                },
                64,
            );

            let backend = WasmBackend::new();
            let err = backend.start(&config).expect_err("must refuse");
            assert!(err.to_string().contains("fuel"), "got: {err}");
            assert!(
                backend.list().unwrap().is_empty(),
                "a refused launch must record no run"
            );
        }

        #[test]
        fn epoch_interruption_is_confirmed_on_an_engine_that_has_it() {
            // The read-back itself. An engine built without the control must
            // fail the same probe the bounded path gates on, or the probe is
            // asserting nothing.
            let with_epoch = super::super::engine::probe_epoch_for_test(true);
            let without_epoch = super::super::engine::probe_epoch_for_test(false);
            assert!(with_epoch, "epoch interruption must be observable when on");
            assert!(
                !without_epoch,
                "the probe must fail when the control is absent, or it proves nothing"
            );
        }

        #[test]
        fn is_available_and_install_succeed_with_the_feature_compiled_in() {
            let b = WasmBackend::new();
            assert!(b.is_available().unwrap());
            assert!(b.install().is_ok());
        }

        #[test]
        fn missing_module_file_fails_closed_with_typed_error() {
            let (_env, _home, _guard) = isolated_home();
            let b = WasmBackend::new();
            let config = cfg("missing", "/nonexistent/path/does-not-exist.wasm");
            let err = b.start(&config).unwrap_err();
            assert!(err.to_string().contains("failed to load wasm module"));
        }

        /// The capability handshake end to end: a module built from a
        /// `WasmPreopenPlan` sees exactly the admitted preopens (the run dir
        /// at /run/mvm with the activation file, an overlay dir at
        /// /mvm/runtime read-only) and the `MVM_ACTIVATION_FILE` env — and
        /// nothing beyond them (a path outside the preopens is not openable,
        /// and a read-only preopen refuses writes).
        #[test]
        fn activation_preopens_and_env_are_exactly_what_the_module_sees() {
            use crate::wasm_activation::{WasmPreopen, WasmPreopenPlan};

            let run_dir = tempfile::tempdir().unwrap();
            std::fs::write(run_dir.path().join("activation.json"), b"{}").unwrap();
            let overlay_dir = tempfile::tempdir().unwrap();
            std::fs::write(overlay_dir.path().join("agent"), b"bin").unwrap();

            let plan = WasmPreopenPlan {
                preopens: vec![
                    WasmPreopen {
                        host_dir: run_dir.path().to_path_buf(),
                        guest_path: "/run/mvm".into(),
                        read_only: true,
                    },
                    WasmPreopen {
                        host_dir: overlay_dir.path().to_path_buf(),
                        guest_path: "/mvm/runtime".into(),
                        read_only: true,
                    },
                ],
                env: vec![(
                    "MVM_ACTIVATION_FILE".to_string(),
                    "/run/mvm/activation.json".to_string(),
                )],
            };

            // dirfd 3 = first preopen (/run/mvm), dirfd 4 = second
            // (/mvm/runtime). path_open returns a WASI errno (0 = success);
            // environ_sizes_get writes the env count at addr 0.
            let wat = r#"(module
  (import "wasi_snapshot_preview1" "path_open" (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_sizes_get" (func $esg (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 100) "activation.json")
  (data (i32.const 200) "agent")
  (func (export "open_activation") (result i32)
    (call $path_open (i32.const 3) (i32.const 0) (i32.const 100) (i32.const 15) (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 500)))
  (func (export "open_overlay_bin") (result i32)
    (call $path_open (i32.const 4) (i32.const 0) (i32.const 200) (i32.const 5) (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 500)))
  (func (export "open_shadow_escape") (result i32)
    (call $path_open (i32.const 3) (i32.const 0) (i32.const 200) (i32.const 5) (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 500)))
  (func (export "env_count") (result i32)
    (drop (call $esg (i32.const 0) (i32.const 4)))
    (i32.load (i32.const 0)))
  (func (export "_start")))
"#;
            let module = wat_module(wat);
            let engine::InstantiatedForTest {
                mut store,
                instance,
                ..
            } = engine::instantiate_for_test(
                module.path().to_str().unwrap(),
                None,
                Some(&plan),
                WasmBounds::unbounded(),
            )
            .expect("module with WASI imports must instantiate");

            let errno = |name: &str, store: &mut wasmtime::Store<engine::WasmHostState>| {
                instance
                    .get_typed_func::<(), i32>(&mut *store, name)
                    .unwrap_or_else(|_| panic!("fixture must export {name}"))
                    .call(store, ())
                    .unwrap_or_else(|_| panic!("{name} must not trap"))
            };

            // The admitted files open.
            assert_eq!(errno("open_activation", &mut store), 0);
            assert_eq!(errno("open_overlay_bin", &mut store), 0);
            // `agent` does not exist under /run/mvm — the preopen boundary
            // is real (nothing outside the admitted dirs is reachable).
            assert_ne!(errno("open_shadow_escape", &mut store), 0);
            // The one admitted env entry is present.
            let env_count = instance
                .get_typed_func::<(), i32>(&mut store, "env_count")
                .unwrap()
                .call(&mut store, ())
                .unwrap();
            assert_eq!(env_count, 1);
        }

        mod mvm_egress_import_tests {
            use super::*;
            use base64::Engine;
            use base64::engine::general_purpose::STANDARD as B64;
            use mvm_core::substitution_wire::WireResponse;
            use std::os::unix::net::UnixListener;
            use std::thread;

            /// A fixture module that writes `request_json` into memory at
            /// offset 0, calls `mvm:egress` with it, and exports the raw
            /// `i32` the import returns (the `WireResponse` length, or a
            /// negative `EgressImportError` code) as `run_egress`. The
            /// response bytes the import wrote land at `resp_ptr`, which
            /// the test reads directly out of the instantiated module's
            /// exported memory.
            fn egress_fixture_wat(request_json: &str, resp_ptr: i32, resp_cap: i32) -> String {
                format!(
                    r#"(module
  (import "mvm" "egress_json" (func $mvm_egress (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "{escaped}")
  (func (export "run_egress") (result i32)
    (call $mvm_egress
      (i32.const 0)
      (i32.const {req_len})
      (i32.const {resp_ptr})
      (i32.const {resp_cap})))
  (func (export "_start")))
"#,
                    escaped = wat_escape(request_json),
                    req_len = request_json.len(),
                )
            }

            /// Bind a `UnixListener` at `socket_path`, accept exactly one
            /// connection, read one framed `WireRequest` off it, reply with
            /// `canned_response`, and hand the received request back on the
            /// join handle — the stub substitution endpoint the P3a gate
            /// proves the wasm round-trip against.
            fn spawn_stub_network_endpoint(
                socket_path: std::path::PathBuf,
                canned_response: WireResponse,
            ) -> thread::JoinHandle<WireRequest> {
                let listener = UnixListener::bind(&socket_path).unwrap();
                thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let got: WireRequest = mvm_agentd::vsock::read_frame(&mut stream).unwrap();
                    mvm_agentd::vsock::write_frame(&mut stream, &canned_response).unwrap();
                    got
                })
            }

            #[test]
            fn round_trips_a_wire_request_over_a_stub_uds_endpoint() {
                let dir = tempfile::tempdir().unwrap();
                let socket_path = dir.path().join("egress.sock");

                let canned_response = WireResponse::Ok {
                    status: 200,
                    headers: vec![],
                    body_b64: B64.encode(b"pong"),
                };
                let expected_request = WireRequest {
                    method: "GET".into(),
                    url: "https://example.test/v1/status".into(),
                    headers: vec![("authorization".into(), "Bearer ${API_KEY}".into())],
                    body_b64: String::new(),
                };

                let server =
                    spawn_stub_network_endpoint(socket_path.clone(), canned_response.clone());

                let request_json = serde_json::to_string(&expected_request).unwrap();
                let resp_ptr: i32 = 4096;
                let resp_cap: i32 = 4096;
                let wat = egress_fixture_wat(&request_json, resp_ptr, resp_cap);
                let module = wat_module(&wat);

                let backend = WasmBackend::new().with_egress_endpoint(socket_path);
                let engine::InstantiatedForTest {
                    mut store,
                    instance,
                    ..
                } = engine::instantiate_for_test(
                    module.path().to_str().unwrap(),
                    backend.egress_endpoint.clone(),
                    None,
                    WasmBounds::unbounded(),
                )
                .expect("module with the mvm:egress import must instantiate");

                let run_egress = instance
                    .get_typed_func::<(), i32>(&mut store, "run_egress")
                    .expect("fixture must export run_egress");
                let len = run_egress
                    .call(&mut store, ())
                    .expect("run_egress must not trap");
                assert!(
                    len > 0,
                    "expected a positive WireResponse length, got {len}"
                );

                let memory = instance.get_memory(&mut store, "memory").unwrap();
                let mut resp_bytes = vec![0u8; len as usize];
                memory
                    .read(&store, resp_ptr as usize, &mut resp_bytes)
                    .unwrap();
                let observed: WireResponse = serde_json::from_slice(&resp_bytes).unwrap();
                assert_eq!(observed, canned_response);

                let got_request = server.join().unwrap();
                assert_eq!(got_request, expected_request);
            }

            #[test]
            fn fails_closed_with_negative_code_when_no_endpoint_is_configured() {
                let request_json = serde_json::to_string(&WireRequest {
                    method: "GET".into(),
                    url: "https://example.test/".into(),
                    headers: vec![],
                    body_b64: String::new(),
                })
                .unwrap();
                let wat = egress_fixture_wat(&request_json, 4096, 4096);
                let module = wat_module(&wat);

                // No `with_egress_endpoint` call: the backend has nothing
                // configured, so the import must fail closed rather than
                // panic or trap the host.
                let engine::InstantiatedForTest {
                    mut store,
                    instance,
                    ..
                } = engine::instantiate_for_test(
                    module.path().to_str().unwrap(),
                    None,
                    None,
                    WasmBounds::unbounded(),
                )
                .expect("module with the mvm:egress import must instantiate");

                let run_egress = instance
                    .get_typed_func::<(), i32>(&mut store, "run_egress")
                    .unwrap();
                let code = run_egress.call(&mut store, ()).unwrap();
                assert!(code < 0, "expected a negative error code, got {code}");
            }

            #[test]
            fn fails_closed_on_oversized_request_length() {
                // A module that claims a request length far larger than
                // the import's bound, without actually writing that much
                // data — proves the size check runs before any read.
                let wat = r#"(module
  (import "mvm" "egress_json" (func $mvm_egress (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "run_egress") (result i32)
    (call $mvm_egress
      (i32.const 0)
      (i32.const 1000000000)
      (i32.const 4096)
      (i32.const 4096)))
  (func (export "_start")))
"#;
                let module = wat_module(wat);
                let dir = tempfile::tempdir().unwrap();
                let socket_path = dir.path().join("unused.sock");

                let engine::InstantiatedForTest {
                    mut store,
                    instance,
                    ..
                } = engine::instantiate_for_test(
                    module.path().to_str().unwrap(),
                    Some(socket_path),
                    None,
                    WasmBounds::unbounded(),
                )
                .expect("module with the mvm:egress import must instantiate");

                let run_egress = instance
                    .get_typed_func::<(), i32>(&mut store, "run_egress")
                    .unwrap();
                let code = run_egress.call(&mut store, ()).unwrap();
                assert!(code < 0, "expected a negative error code, got {code}");
            }

            #[test]
            fn round_trips_browser_abi_over_a_stub_uds_endpoint() {
                let dir = tempfile::tempdir().unwrap();
                let socket_path = dir.path().join("egress.sock");
                let canned_response = WireResponse::Ok {
                    status: 200,
                    headers: vec![],
                    body_b64: B64.encode(b"pong"),
                };
                let server = spawn_stub_network_endpoint(socket_path.clone(), canned_response);
                let wat = r#"(module
  (import "mvm" "egress" (func $mvm_egress (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "example.test")
  (data (i32.const 64) "ping")
  (func (export "run_egress") (result i32)
    (call $mvm_egress
      (i32.const 0)
      (i32.const 12)
      (i32.const 443)
      (i32.const 64)
      (i32.const 4)
      (i32.const 256)
      (i32.const 256)))
  (func (export "_start")))
"#;
                let module = wat_module(wat);
                let backend = WasmBackend::new().with_egress_endpoint(socket_path);
                let engine::InstantiatedForTest {
                    mut store,
                    instance,
                    ..
                } = engine::instantiate_for_test(
                    module.path().to_str().unwrap(),
                    backend.egress_endpoint.clone(),
                    None,
                    WasmBounds::unbounded(),
                )
                .expect("module with the browser-style mvm:egress import must instantiate");
                let run_egress = instance
                    .get_typed_func::<(), i32>(&mut store, "run_egress")
                    .unwrap();
                let len = run_egress.call(&mut store, ()).unwrap();
                assert!(len > 0, "expected a positive response length, got {len}");
                let memory = instance.get_memory(&mut store, "memory").unwrap();
                let mut resp_bytes = vec![0u8; len as usize];
                memory.read(&store, 256, &mut resp_bytes).unwrap();
                assert_eq!(resp_bytes, b"pong");
                let got_request = server.join().unwrap();
                assert_eq!(got_request.method, "POST");
                assert_eq!(got_request.url, "https://example.test:443/");
                assert_eq!(B64.decode(&got_request.body_b64).unwrap(), b"ping");
            }
        }
    }
}
