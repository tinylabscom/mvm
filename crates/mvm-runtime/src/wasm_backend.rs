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

use anyhow::Result;
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
         devices; use a directory-share volume instead"
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
        .find(|v| matches!(v.kind, mvm_core::vm_backend::VmVolumeKind::Disk))
    {
        return Err(WasmBackendError::DiskVolumeNotSupported {
            host: volume.host.clone(),
        });
    }
    // Every directory share becomes a WASI preopen verbatim, so its guest
    // mountpoint must pass the mount-path policy before any of it starts.
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
#[derive(Debug, Clone, Copy)]
struct WasmRun {
    exit: VmExitStatus,
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
/// `crate::substitution_spawn::SubstitutionSpawnParams` (which borrows) so
/// the decided values can be asserted directly in a test.
struct WasmEndpointPlan {
    vm_name: String,
    state_dir: PathBuf,
    tenant: String,
    secrets: Vec<mvm_core::plan::SecretBinding>,
    redaction: mvm_core::policy::RedactionPolicy,
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
    Ok(Some(WasmEndpointPlan {
        vm_name: config.name.clone(),
        state_dir: state_dir.to_path_buf(),
        tenant,
        secrets,
        redaction,
        socket_path: mvm_core::config::vm_substitution_endpoint_socket(&config.name),
    }))
}

/// Build the [`substitution_spawn::SubstitutionSpawnParams`] a wasm run's
/// endpoint spawn needs from a decided [`WasmEndpointPlan`]. Pure (no I/O)
/// so the wasm-specific literal fields are unit-testable without a spawn:
/// always `Uds` (the host-import connects to the endpoint directly — wasm has
/// no VMM to proxy a per-port vsock socket), no terminator (no TAP/nft
/// REDIRECT to feed), no TLS intermediate (http-only POC; HTTPS termination
/// is a later phase), and — unlike libkrun/hvf, which serve raw pass-through
/// when a run carries no secrets — `raw_egress` is unconditionally `false`:
/// the `mvm:egress` host-import always speaks the `WireRequest` wire
/// protocol, never a raw byte relay.
fn wasm_substitution_spawn_params<'a>(
    plan: &'a WasmEndpointPlan,
    network_policy: &'a mvm_core::network_policy::NetworkPolicy,
) -> crate::substitution_spawn::SubstitutionSpawnParams<'a> {
    crate::substitution_spawn::SubstitutionSpawnParams {
        vm_name: &plan.vm_name,
        state_dir: &plan.state_dir,
        tenant: &plan.tenant,
        secrets: &plan.secrets,
        redaction: &plan.redaction,
        transport: crate::substitution_spawn::EndpointTransport::Uds {
            path: plan.socket_path.clone(),
        },
        terminator_listen: None,
        tls_intermediate: None,
        network_policy: Some(network_policy),
        raw_egress: false,
        resolver_remote: None,
        binding_store_dir: None,
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
    let params = wasm_substitution_spawn_params(&plan, &config.network_policy);
    crate::substitution_spawn::spawn_substitution_endpoint(params)?;
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
            // default. `apply_grants` is not yet overridden to wire them, so
            // its default reply still honestly reports nothing enforced —
            // this field only declares what the mechanism *could* bound.
            resource_controls: ResourceControls::for_backend(BackendKind::Wasm),
            ..VmCapabilities::default()
        }
    }

    fn start_with_mode(&self, config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        reject_unsupported_start_config(config)?;
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
        );
        if spawned_endpoint.is_some() {
            // A wasm run is synchronous end-to-end inside `start` — there is
            // no later `stop()` boundary to reap the endpoint at, so its
            // decrypted secrets must not outlive this call either way.
            crate::substitution_spawn::reap_substitution_endpoint(&state_dir, &config.name);
            mvm_vmm::host::netd_spawn::reap_netd(&state_dir);
        }
        let exit = result?;

        let mut runs = self
            .runs
            .lock()
            .map_err(|_| anyhow::anyhow!("wasm backend state mutex poisoned"))?;
        runs.insert(config.name.clone(), WasmRun { exit });
        Ok(VmId(config.name.clone()))
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
            .keys()
            .map(|name| VmInfo {
                id: VmId(name.clone()),
                name: name.clone(),
                status: VmStatus::Stopped,
                guest_ip: None,
                cpus: 0,
                memory_mib: 0,
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

/// The `wasmtime`-touching internals, split so the outer `WasmBackend` type
/// and its `VmBackend` impl compile identically with or without the
/// `wasm-backend` feature. Only this inner module references `wasmtime` —
/// with the feature off, `cargo tree` shows no `wasmtime` anywhere in the
/// dependency graph.
#[cfg(feature = "wasm-backend")]
mod engine {
    use std::path::{Path, PathBuf};

    use super::WasmBackendError;
    use crate::wasm_activation::WasmPreopenPlan;
    use mvm_core::substitution_wire::{WireRequest, WireResponse};
    use mvm_core::vm_backend::VmExitStatus;
    use wasmtime::{Caller, Engine, Extern, Linker, Memory, Module, Store};
    use wasmtime_wasi::p1::{self, WasiP1Ctx};
    use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

    pub fn is_compiled_in() -> bool {
        true
    }

    /// Host state carried in the wasmtime `Store` for a `WasmBackend` run:
    /// the WASI Preview 1 context plus the one bit of state the
    /// `mvm:egress` host-import needs. `egress_endpoint` is host-supplied
    /// — never guest-controlled — and names the substitution-endpoint UDS
    /// the import relays each request to. `None` until an endpoint is
    /// spawned and wired in, in which case the import fails closed rather
    /// than silently allowing egress.
    pub(super) struct WasmHostState {
        wasi: WasiP1Ctx,
        egress_endpoint: Option<PathBuf>,
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
        let ptr = usize::try_from(ptr).map_err(|_| EgressImportError::RequestOutOfBounds)?;
        let len = usize::try_from(len).map_err(|_| EgressImportError::RequestOutOfBounds)?;
        if len > MAX_REQUEST_BYTES {
            return Err(EgressImportError::RequestTooLarge);
        }
        let mut buf = vec![0u8; len];
        memory
            .read(store, ptr, &mut buf)
            .map_err(|_| EgressImportError::RequestOutOfBounds)?;
        Ok(buf)
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

    /// Connect to the substitution endpoint at `endpoint` and relay one
    /// `WireRequest`. Reuses `mvm_agentd::substitution_client::relay` — the
    /// same framed-JSON round-trip the in-guest substitution leg uses —
    /// rather than a second frame codec.
    fn call_egress_endpoint(
        endpoint: &Path,
        req: &WireRequest,
    ) -> std::result::Result<WireResponse, EgressImportError> {
        let mut stream = std::os::unix::net::UnixStream::connect(endpoint).map_err(|e| {
            tracing::warn!(
                endpoint = %endpoint.display(),
                error = %e,
                "mvm:egress: connect to substitution endpoint failed"
            );
            EgressImportError::ConnectFailed
        })?;
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

        let resp = call_egress_endpoint(&endpoint, &req)?;
        let resp_bytes =
            serde_json::to_vec(&resp).map_err(|_| EgressImportError::ResponseSerializeFailed)?;
        if resp_bytes.len() > MAX_RESPONSE_BYTES {
            return Err(EgressImportError::ResponseTooLargeForBuffer);
        }
        write_response_bytes(&memory, caller, resp_ptr, resp_cap, &resp_bytes)
    }

    /// The `"mvm"`/`"egress"` host-import:
    /// `(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_cap: i32) -> i32`.
    ///
    /// Reads a `WireRequest` JSON blob from `req_len` bytes at `req_ptr` in
    /// the calling module's exported `memory`, relays it to the configured
    /// substitution-endpoint UDS, and writes the `WireResponse` JSON back
    /// at `resp_ptr` (up to `resp_cap` bytes), returning its length. Never
    /// panics or traps the host on guest-controlled input: every failure
    /// returns a negative [`EgressImportError`] code and is logged
    /// host-side instead.
    fn mvm_egress_import(
        mut caller: Caller<'_, WasmHostState>,
        req_ptr: i32,
        req_len: i32,
        resp_ptr: i32,
        resp_cap: i32,
    ) -> i32 {
        match mvm_egress_import_inner(&mut caller, req_ptr, req_len, resp_ptr, resp_cap) {
            Ok(len) => len,
            Err(err) => {
                tracing::warn!(error = %err, "mvm:egress host-import failed closed");
                err as i32
            }
        }
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
    fn new_engine_linker_store(
        egress_endpoint: Option<PathBuf>,
        activation: Option<&WasmPreopenPlan>,
    ) -> std::result::Result<(Engine, Linker<WasmHostState>, Store<WasmHostState>), WasmBackendError>
    {
        let engine = Engine::default();
        let mut linker: Linker<WasmHostState> = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |state: &mut WasmHostState| &mut state.wasi).map_err(
            |e| WasmBackendError::ModuleLoadFailed {
                path: String::new(),
                reason: format!("failed to wire WASI imports: {e}"),
            },
        )?;
        linker
            .func_wrap("mvm", "egress", mvm_egress_import)
            .map_err(|e| WasmBackendError::ModuleLoadFailed {
                path: String::new(),
                reason: format!("failed to wire the mvm:egress host-import: {e}"),
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
        let store = Store::new(
            &engine,
            WasmHostState {
                wasi: wasi_ctx,
                egress_endpoint,
            },
        );
        Ok((engine, linker, store))
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
    ) -> std::result::Result<VmExitStatus, WasmBackendError> {
        let (engine, linker, mut store) = new_engine_linker_store(egress_endpoint, activation)?;
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

        match start.call(&mut store, ()) {
            Ok(()) => Ok(VmExitStatus {
                code: Some(0),
                success: true,
            }),
            Err(err) => match err.downcast::<wasmtime_wasi::I32Exit>() {
                Ok(exit) => Ok(VmExitStatus {
                    code: Some(exit.0),
                    success: exit.0 == 0,
                }),
                Err(err) => Err(WasmBackendError::ModuleTrapped {
                    path: path.to_string(),
                    reason: err.to_string(),
                }),
            },
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
    ) -> std::result::Result<(Store<WasmHostState>, wasmtime::Instance), WasmBackendError> {
        let (engine, linker, mut store) = new_engine_linker_store(egress_endpoint, activation)?;
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
        Ok((store, instance))
    }
}

#[cfg(not(feature = "wasm-backend"))]
mod engine {
    use std::path::PathBuf;

    use super::WasmBackendError;
    use crate::wasm_activation::WasmPreopenPlan;
    use mvm_core::vm_backend::VmExitStatus;

    pub fn is_compiled_in() -> bool {
        false
    }

    pub fn run_module_to_completion(
        _path: &str,
        _egress_endpoint: Option<PathBuf>,
        _activation: Option<&WasmPreopenPlan>,
    ) -> std::result::Result<VmExitStatus, WasmBackendError> {
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
            CapabilityAlternative::SubstitutionEndpointOverWasmImport
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
    fn disk_volume_fails_closed_dir_share_passes() {
        let mut config = cfg("x", "/tmp/mod.wasm");
        config.volumes = vec![mvm_core::vm_backend::VmVolume {
            host: "/host/disk.img".into(),
            guest: "/mnt/disk".into(),
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

        config.volumes[0].kind = mvm_core::vm_backend::VmVolumeKind::DirShare;
        assert!(reject_unsupported_start_config(&config).is_ok());
    }

    #[test]
    fn volume_mountpoint_shadowing_the_handshake_fails_closed() {
        for bad in ["mnt/relative", "/run/mvm", "/mvm/runtime"] {
            let mut config = cfg("x", "/tmp/mod.wasm");
            config.volumes = vec![mvm_core::vm_backend::VmVolume {
                host: "/host/share".into(),
                guest: bad.into(),
                size: String::new(),
                read_only: true,
                kind: mvm_core::vm_backend::VmVolumeKind::DirShare,
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

    // ── P3b.1: wasm_endpoint_plan / wasm_substitution_spawn_params ──
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
    // that must NOT mirror libkrun — `raw_egress` is always `false`.
    #[test]
    fn wasm_endpoint_plan_params_mirror_libkrun_with_wasm_deviations() {
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
            mvm_core::config::vm_substitution_endpoint_socket("secret-wasm-vm")
        );

        let params = wasm_substitution_spawn_params(&plan, &config.network_policy);
        assert_eq!(params.vm_name, "secret-wasm-vm");
        assert_eq!(
            params.transport,
            crate::substitution_spawn::EndpointTransport::Uds {
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
            !params.raw_egress,
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
        use std::io::Write;

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
            let exit = engine::run_module_to_completion(
                module.path().to_str().unwrap(),
                None,
                Some(&plan),
            )
            .expect("module with the activation env must run to completion");
            assert_eq!(exit.code, Some(0), "activation env must be visible");

            // Without the activation plan the same module must NOT see the env.
            let exit =
                engine::run_module_to_completion(module.path().to_str().unwrap(), None, None)
                    .expect("module without the activation plan must still run");
            assert_eq!(exit.code, Some(7), "no env without the handshake");
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
            let (mut store, instance) =
                engine::instantiate_for_test(module.path().to_str().unwrap(), None, Some(&plan))
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
            use mvm_core::substitution_wire::{WireRequest, WireResponse};
            use std::os::unix::net::UnixListener;
            use std::thread;

            /// Escape a string for embedding as a WAT string-literal data
            /// segment: backslash and double-quote are the only two bytes
            /// WAT string syntax requires escaped for otherwise-printable
            /// JSON text.
            fn wat_escape(s: &str) -> String {
                s.replace('\\', "\\\\").replace('"', "\\\"")
            }

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
  (import "mvm" "egress" (func $mvm_egress (param i32 i32 i32 i32) (result i32)))
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
            fn spawn_stub_substitution_endpoint(
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
                    spawn_stub_substitution_endpoint(socket_path.clone(), canned_response.clone());

                let request_json = serde_json::to_string(&expected_request).unwrap();
                let resp_ptr: i32 = 4096;
                let resp_cap: i32 = 4096;
                let wat = egress_fixture_wat(&request_json, resp_ptr, resp_cap);
                let module = wat_module(&wat);

                let backend = WasmBackend::new().with_egress_endpoint(socket_path);
                let (mut store, instance) = engine::instantiate_for_test(
                    module.path().to_str().unwrap(),
                    backend.egress_endpoint.clone(),
                    None,
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
                let (mut store, instance) =
                    engine::instantiate_for_test(module.path().to_str().unwrap(), None, None)
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
  (import "mvm" "egress" (func $mvm_egress (param i32 i32 i32 i32) (result i32)))
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

                let (mut store, instance) = engine::instantiate_for_test(
                    module.path().to_str().unwrap(),
                    Some(socket_path),
                    None,
                )
                .expect("module with the mvm:egress import must instantiate");

                let run_egress = instance
                    .get_typed_func::<(), i32>(&mut store, "run_egress")
                    .unwrap();
                let code = run_egress.call(&mut store, ()).unwrap();
                assert!(code < 0, "expected a negative error code, got {code}");
            }
        }
    }
}
