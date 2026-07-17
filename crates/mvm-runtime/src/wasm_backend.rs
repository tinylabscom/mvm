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
//! No networking: a module runs fully isolated from the network by
//! construction (no WASI socket capability is ever granted), and any launch
//! config that asks for real egress, a kernel/verified boot, a snapshot, or
//! an interactive console fails closed with a typed error naming the
//! supported alternative. The governed WASI egress seam is a later phase.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, LayerCoverage, StartMode, VmBackend,
    VmCapabilities, VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
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
        "wasm backend does not mediate real networking yet — the governed WASI egress seam \
         is a later phase; drop --network-allow or select a microVM backend"
    )]
    NetworkingNotSupported,

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
    if config.network_policy.allows_egress() {
        return Err(WasmBackendError::NetworkingNotSupported);
    }
    if config.dev_console {
        return Err(WasmBackendError::ConsoleNotSupported);
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
    /// endpoint UDS. Builder-style so the real endpoint spawn can wire
    /// this in before `start` once it exists; tests inject a stub path
    /// directly.
    pub fn with_egress_endpoint(mut self, path: PathBuf) -> Self {
        self.egress_endpoint = Some(path);
        self
    }
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
            ..VmCapabilities::default()
        }
    }

    fn start_with_mode(&self, config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        reject_unsupported_start_config(config)?;
        let exit =
            engine::run_module_to_completion(&config.rootfs_path, self.egress_endpoint.clone())?;
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
    use mvm_core::substitution_wire::{WireRequest, WireResponse};
    use mvm_core::vm_backend::VmExitStatus;
    use wasmtime::{Caller, Engine, Extern, Linker, Memory, Module, Store};
    use wasmtime_wasi::WasiCtxBuilder;
    use wasmtime_wasi::p1::{self, WasiP1Ctx};

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
    /// as host state. The one wiring path both [`run_module_to_completion`]
    /// and the test-only [`instantiate_for_test`] go through, so the
    /// import can't drift between the production and test instantiation
    /// paths.
    fn new_engine_linker_store(
        egress_endpoint: Option<PathBuf>,
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

        let wasi_ctx = WasiCtxBuilder::new().inherit_stdio().build_p1();
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
    /// completion. No filesystem preopens and no socket capability are ever
    /// granted, so the instance is network- and host-fs-isolated by
    /// construction beyond the explicit `mvm:egress` import — the honest
    /// zero-capability default for everything else; a module with no
    /// `egress_endpoint` configured gets `NoEndpointConfigured` on every
    /// `mvm:egress` call.
    pub fn run_module_to_completion(
        path: &str,
        egress_endpoint: Option<PathBuf>,
    ) -> std::result::Result<VmExitStatus, WasmBackendError> {
        let (engine, linker, mut store) = new_engine_linker_store(egress_endpoint)?;
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
    ) -> std::result::Result<(Store<WasmHostState>, wasmtime::Instance), WasmBackendError> {
        let (engine, linker, mut store) = new_engine_linker_store(egress_endpoint)?;
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
    use mvm_core::vm_backend::VmExitStatus;

    pub fn is_compiled_in() -> bool {
        false
    }

    pub fn run_module_to_completion(
        _path: &str,
        _egress_endpoint: Option<PathBuf>,
    ) -> std::result::Result<VmExitStatus, WasmBackendError> {
        Err(WasmBackendError::NotCompiledIn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn network_allow_request_fails_closed() {
        let mut config = cfg("x", "/tmp/does-not-matter.wasm");
        config.network_policy = mvm_core::network_policy::NetworkPolicy::unrestricted();
        let err = reject_unsupported_start_config(&config).unwrap_err();
        assert_eq!(err, WasmBackendError::NetworkingNotSupported);
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
        }

        #[test]
        fn runs_a_module_that_calls_proc_exit_with_a_nonzero_code() {
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
            let b = WasmBackend::new();
            let config = cfg("missing", "/nonexistent/path/does-not-exist.wasm");
            let err = b.start(&config).unwrap_err();
            assert!(err.to_string().contains("failed to load wasm module"));
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
                    engine::instantiate_for_test(module.path().to_str().unwrap(), None)
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
