//! Host-local VMM dispatch for a fully-prepared boot.
//!
//! The CLI resolves everything a workload needs (rootfs, kernel, verity,
//! overlay, admission) into a `VmStartConfig`, then hands it here. This owns the
//! VMM-selection + start dispatch so the CLI stays off
//! `mvm_runtime::backend::AnyBackend`. The signed-plan admission gate (a
//! mvm-hostd concern) and the launched/failed audit emits stay CLI-side — this
//! seam is only the backend start. It is a host-local free function, not an
//! `MvmClient` trait method: it carries a runtime `VmStartConfig`, which the
//! REST-facing trait deliberately cannot.

use crate::{MvmError, Result};
use mvm_core::protocol::vm_backend::{VmId, VmStatus};
use std::path::Path;

/// A durable-session resume whose backend is selected at the client boundary.
///
/// The CLI owns the stores and admission material, but it must not own the
/// concrete VMM dispatcher. This request keeps those concerns grouped while
/// letting [`resume_and_boot_local`] resolve the named backend here.
pub struct ResumeBootLocalRequest<'a> {
    sessions: &'a mvm_runtime::agent_session::AgentSessionStore,
    checkpoints: &'a mvm_runtime::checkpoint::CheckpointStore,
    resume: &'a mvm_hostd::session_resume::ResumeRequest<'a>,
    backend_name: &'a str,
    state_dir: &'a Path,
    kernel_path: Option<&'a Path>,
    emitter: Option<&'a mvm_hostd::audit::emitter::AuditEmitter>,
}

impl<'a> ResumeBootLocalRequest<'a> {
    /// Start a validated request builder.
    #[must_use]
    pub fn builder() -> ResumeBootLocalRequestBuilder<'a> {
        ResumeBootLocalRequestBuilder::default()
    }
}

/// Builder for [`ResumeBootLocalRequest`].
#[derive(Default)]
pub struct ResumeBootLocalRequestBuilder<'a> {
    sessions: Option<&'a mvm_runtime::agent_session::AgentSessionStore>,
    checkpoints: Option<&'a mvm_runtime::checkpoint::CheckpointStore>,
    resume: Option<&'a mvm_hostd::session_resume::ResumeRequest<'a>>,
    backend_name: Option<&'a str>,
    state_dir: Option<&'a Path>,
    kernel_path: Option<&'a Path>,
    emitter: Option<&'a mvm_hostd::audit::emitter::AuditEmitter>,
}

impl<'a> ResumeBootLocalRequestBuilder<'a> {
    #[must_use]
    pub fn sessions(mut self, sessions: &'a mvm_runtime::agent_session::AgentSessionStore) -> Self {
        self.sessions = Some(sessions);
        self
    }

    #[must_use]
    pub fn checkpoints(
        mut self,
        checkpoints: &'a mvm_runtime::checkpoint::CheckpointStore,
    ) -> Self {
        self.checkpoints = Some(checkpoints);
        self
    }

    #[must_use]
    pub fn resume(mut self, resume: &'a mvm_hostd::session_resume::ResumeRequest<'a>) -> Self {
        self.resume = Some(resume);
        self
    }

    #[must_use]
    pub fn backend_name(mut self, backend_name: &'a str) -> Self {
        self.backend_name = Some(backend_name);
        self
    }

    #[must_use]
    pub fn state_dir(mut self, state_dir: &'a Path) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    #[must_use]
    pub fn kernel_path(mut self, kernel_path: Option<&'a Path>) -> Self {
        self.kernel_path = kernel_path;
        self
    }

    #[must_use]
    pub fn emitter(mut self, emitter: Option<&'a mvm_hostd::audit::emitter::AuditEmitter>) -> Self {
        self.emitter = emitter;
        self
    }

    /// Validate the required request fields.
    pub fn build(self) -> anyhow::Result<ResumeBootLocalRequest<'a>> {
        Ok(ResumeBootLocalRequest {
            sessions: self
                .sessions
                .ok_or_else(|| anyhow::anyhow!("resume boot needs a session store"))?,
            checkpoints: self
                .checkpoints
                .ok_or_else(|| anyhow::anyhow!("resume boot needs a checkpoint store"))?,
            resume: self
                .resume
                .ok_or_else(|| anyhow::anyhow!("resume boot needs a resume request"))?,
            backend_name: self
                .backend_name
                .ok_or_else(|| anyhow::anyhow!("resume boot needs a backend name"))?,
            state_dir: self
                .state_dir
                .ok_or_else(|| anyhow::anyhow!("resume boot needs a state directory"))?,
            kernel_path: self.kernel_path,
            emitter: self.emitter,
        })
    }
}

/// Resolve the named local backend and drive a durable-session resume boot.
///
/// Backend selection lives here with the other host-local VMM dispatch seams,
/// so a CLI caller cannot bypass the client boundary by constructing
/// `AnyBackend` directly.
pub fn resume_and_boot_local(
    req: &ResumeBootLocalRequest<'_>,
    clock: &dyn mvm_hostd::plan_admission::Clock,
    ledger: &mvm_hostd::plan_admission::InMemoryNonceLedger,
) -> anyhow::Result<mvm_hostd::session_resume::BootedSession> {
    require_hypervisor_selectable(req.backend_name)?;
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor(req.backend_name);
    mvm_hostd::session_resume::resume_and_boot(
        req.sessions,
        req.checkpoints,
        &mvm_hostd::session_resume::ResumeBootRequest {
            resume: req.resume,
            backend: &backend,
            state_dir: req.state_dir,
            kernel_path: req.kernel_path,
            emitter: req.emitter,
        },
        clock,
        ledger,
    )
}

/// A VM [`start_prepared`] started, together with the backend object that
/// started it.
///
/// Anything done to the VM after the start — applying its grants, undoing the
/// launch — has to go to this object, not to one rebuilt from the hypervisor
/// name: a rebuilt backend is a different instance, and one that keeps per-run
/// state in memory has nothing to report for a VM it never started.
pub struct StartedVm {
    backend: mvm_runtime::backend::AnyBackend,
    vm_id: VmId,
}

impl StartedVm {
    /// The id the backend assigned the started VM.
    #[must_use]
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }

    /// The backend that started the VM.
    pub(crate) fn backend(&self) -> &mvm_runtime::backend::AnyBackend {
        &self.backend
    }

    /// Pair a backend with a VM it has already started. Crate-private: outside
    /// tests the only way to hold one is to have gone through
    /// [`start_prepared`].
    #[cfg(test)]
    pub(crate) fn from_started(backend: mvm_runtime::backend::AnyBackend, vm_id: VmId) -> Self {
        Self { backend, vm_id }
    }
}

/// Verify `backend` supports workloads and start the fully-prepared config on
/// it. Both failure arms carry the same `backend-start` reason, with the
/// underlying error chain preserved so the caller can surface and audit it.
///
/// Returns the backend that performed the start alongside the VM id, so the
/// post-start steps act on that same object.
pub fn start_prepared(
    backend: mvm_runtime::backend::AnyBackend,
    config: &mvm_core::vm_backend::VmStartConfig,
) -> Result<StartedVm> {
    mvm_runtime::workload_backend::require_workload_backend(&backend).map_err(|e| {
        MvmError::Backend {
            reason: format!("{e:#}"),
        }
    })?;
    let vm_id = backend.start(config).map_err(|e| MvmError::Backend {
        reason: format!("{e:#}"),
    })?;
    Ok(StartedVm { backend, vm_id })
}

/// Clamp a requested vCPU count against the selected backend before admission
/// records the grant and before the backend serializes its machine config.
#[must_use]
pub fn clamp_vcpus_for_backend(backend_name: &str, requested: u32) -> Option<u32> {
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor(backend_name);
    mvm_core::vm_backend::clamp_vcpus(requested, backend.capabilities().max_vcpus)
}

/// The typed tier behind a hypervisor name.
///
/// Admission measures a workload's declared grants against the mechanisms its
/// backend actually has, and that question has to be asked of a `BackendKind`
/// rather than of a string: a name is a label, and a gate that parsed one would
/// be deciding which resource controls apply from whatever the caller typed.
/// The conversion lives here, at the seam that already owns name-to-backend
/// resolution, so a caller holding only a name still never touches
/// `AnyBackend` itself.
pub fn backend_kind_for(hypervisor: &str) -> mvm_core::protocol::vm_backend::BackendKind {
    mvm_runtime::backend::AnyBackend::from_hypervisor(hypervisor).kind()
}

/// Whether the named VM is currently `Running` on `hypervisor`. A status-query
/// error (VM absent) reads as not-running — mirrors the CLI's former inline
/// `from_hypervisor(...).status(...)` check.
pub fn backend_is_running(hypervisor: &str, name: &str) -> bool {
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor(hypervisor);
    matches!(
        backend.status(&VmId(name.to_string())),
        Ok(VmStatus::Running)
    )
}

/// Stop the named VM on `hypervisor` at the VMM level only — no name-registry
/// deregistration. This is the raw pre-recreate / post-failed-init cleanup stop
/// the CLI ran inline, deliberately distinct from the lifecycle
/// [`crate::MvmClient::stop_machine`], which also deregisters.
pub fn backend_stop_by_name(hypervisor: &str, name: &str) -> Result<()> {
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor(hypervisor);
    backend
        .stop(&VmId(name.to_string()))
        .map_err(|e| MvmError::Backend {
            reason: format!("{e:#}"),
        })
}

/// Refuse a `--hypervisor` name the current build cannot select (e.g. `mock`
/// on a build without the `test-support` feature) before any machine
/// construction — mirrors the CLI's former inline
/// `AnyBackend::require_hypervisor_selectable` guard.
pub fn require_hypervisor_selectable(name: &str) -> Result<()> {
    mvm_runtime::backend::AnyBackend::require_hypervisor_selectable(name).map_err(|e| {
        MvmError::Backend {
            reason: format!("{e:#}"),
        }
    })
}

// ============================================================================
// Transient-run backend selection
// ============================================================================
//
// Which backend may serve a transient run, given its egress posture.
// Selection and validation are one cluster: the choice is made from the
// requested hypervisor, the environment override and the image kind, and
// it is only sound if the resulting backend can actually enforce the
// run's network policy. It lives here, rather than in the CLI, so the
// CLI and the host library select (and refuse) the same backend for the
// same egress posture.

use anyhow::Context as _;
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::vm_backend::RequiredCapabilities;
use mvm_runtime::backend::AnyBackend;

/// Select the backend for a transient run: CLI `--hypervisor` wins over
/// the `MVM_HYPERVISOR`/`MVM_BACKEND` environment override, and the
/// result is validated against the run's egress policy before it is
/// returned.
pub fn select_exec_backend(
    image_requested: bool,
    network_policy: &NetworkPolicy,
    requested: Option<&str>,
) -> anyhow::Result<AnyBackend> {
    // CLI `--hypervisor` wins over the MVM_HYPERVISOR/MVM_BACKEND env override.
    let backend_override = requested
        .and_then(normalize_backend_override)
        .or_else(explicit_hypervisor_override);
    let backend_name = select_backend_name_for_egress(
        backend_override.as_deref(),
        image_requested,
        network_policy,
        "OCI --image runs with outbound egress enabled",
    )?;
    AnyBackend::require_hypervisor_selectable(&backend_name)?;
    Ok(AnyBackend::from_hypervisor(&backend_name))
}

/// An explicit workload-backend override from the environment. The transient
/// run path otherwise auto-detects the backend; this lets `MVM_HYPERVISOR`
/// (or `MVM_BACKEND`) pin it — e.g. `libkrun`, whose vsock-tunnel egress path
/// the auto-detected default would otherwise never select on this host. Every
/// `select_exec_backend` call site reads the same value, so the admitted plan's
/// backend and the boot backend agree.
fn explicit_hypervisor_override() -> Option<String> {
    ["MVM_HYPERVISOR", "MVM_BACKEND"]
        .into_iter()
        .filter_map(std::env::var_os)
        .find_map(|raw| normalize_backend_override(&raw.to_string_lossy()))
}

/// Normalize a backend-override string (trim + lowercase); a blank value yields
/// `None` so an empty env var is treated as "unset" rather than an invalid
/// backend name.
fn normalize_backend_override(raw: &str) -> Option<String> {
    let value = raw.trim().to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

pub fn select_backend_name_for_egress(
    backend_override: Option<&str>,
    image_requested: bool,
    network_policy: &NetworkPolicy,
    workload: &str,
) -> anyhow::Result<String> {
    if let Some(backend_name) = backend_override {
        validate_backend_for_egress(backend_name, image_requested, network_policy, workload)?;
        return Ok(backend_name.to_string());
    }

    if !requires_vsock_proxy_backend(image_requested, network_policy) {
        return Ok(AnyBackend::auto_select().name().to_string());
    }

    AnyBackend::select_capable_available(&vsock_proxy_backend_requirements())
        .map(|backend| backend.name().to_string())
        .map_err(|e| anyhow::anyhow!("{workload} require a NIC-less host-vsock-proxy backend: {e}"))
}

pub fn validate_backend_for_egress(
    backend_name: &str,
    image_requested: bool,
    network_policy: &NetworkPolicy,
    workload: &str,
) -> anyhow::Result<()> {
    if !requires_vsock_proxy_backend(image_requested, network_policy) {
        return Ok(());
    }

    let backend = AnyBackend::from_hypervisor(backend_name);
    let missing = backend
        .capabilities()
        .shortfall(&vsock_proxy_backend_requirements());
    if missing.is_empty() {
        let available = backend
            .is_available()
            .with_context(|| format!("probing backend {backend_name} availability"))?;
        if available {
            return Ok(());
        }
        anyhow::bail!(
            "{workload} require a NIC-less host-vsock-proxy backend; backend {backend_name} is unavailable on this host"
        );
    }

    anyhow::bail!(
        "{workload} require a NIC-less host-vsock-proxy backend; backend {backend_name} lacks [{}]",
        missing.join(", ")
    );
}

fn requires_vsock_proxy_backend(image_requested: bool, network_policy: &NetworkPolicy) -> bool {
    image_requested && network_policy.allows_egress()
}

fn vsock_proxy_backend_requirements() -> RequiredCapabilities {
    RequiredCapabilities {
        vsock: true,
        no_routable_guest_nic: true,
        host_vsock_proxy: true,
        ..Default::default()
    }
}

pub fn validate_image_egress_backend(
    backend: &AnyBackend,
    image_requested: bool,
    network_policy: &NetworkPolicy,
) -> anyhow::Result<()> {
    if !image_requested || !network_policy.allows_egress() {
        return Ok(());
    }
    let caps = backend.capabilities();
    if caps.vsock && caps.no_routable_guest_nic && caps.host_vsock_proxy {
        return Ok(());
    }
    anyhow::bail!(
        "OCI --image runs with outbound egress enabled require a NIC-less host-vsock-proxy backend; \
         backend {} does not advertise {{vsock,no_routable_guest_nic,host_vsock_proxy}}",
        backend.name()
    );
}

pub fn validate_image_egress_backend_name(
    backend_name: &str,
    image_requested: bool,
    network_policy: &NetworkPolicy,
) -> anyhow::Result<()> {
    let backend = AnyBackend::from_hypervisor(backend_name);
    validate_image_egress_backend(&backend, image_requested, network_policy)
}

#[cfg(test)]
mod backend_select_tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn validate_backend_for_egress_refuses_unavailable_hvf_before_boot_work() {
        let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let policy = NetworkPolicy::allow_list(vec![mvm_core::network_policy::HostPort::new(
            "example.com",
            443,
        )]);
        env.set("MVM_HVF_SUPERVISOR_PATH", "/no/such/mvm-hvf-supervisor");
        let err = validate_backend_for_egress(
            "hvf",
            true,
            &policy,
            "OCI --image runs with outbound egress enabled",
        )
        .expect_err("unavailable hvf must fail closed before OCI work");
        env.remove("MVM_HVF_SUPERVISOR_PATH");
        // HVF always advertises the NIC-less host-vsock-proxy egress caps (they
        // are unconditional — the fail-closed posture), so the capability
        // shortfall is empty and the refusal comes from the availability probe:
        // a host whose supervisor can't launch is unavailable, not egress-capable.
        let msg = err.to_string();
        assert!(msg.contains("NIC-less host-vsock-proxy backend"));
        assert!(msg.contains("backend hvf is unavailable on this host"));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn select_backend_name_for_egress_picks_hvf_when_proxy_support_is_available() {
        let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let supervisor = dir.path().join("mvm-hvf-supervisor");
        std::fs::write(&supervisor, b"stub").expect("stub supervisor");
        let policy = NetworkPolicy::allow_list(vec![mvm_core::network_policy::HostPort::new(
            "example.com",
            443,
        )]);

        env.set("MVM_HVF_SUPERVISOR_PATH", &supervisor);
        let selected = select_backend_name_for_egress(
            None,
            true,
            &policy,
            "OCI --image runs with outbound egress enabled",
        )
        .expect("hvf should satisfy the proxy backend requirement");

        assert_eq!(selected, "hvf");
    }

    #[test]
    fn normalize_backend_override_trims_lowercases_and_drops_blank() {
        assert_eq!(
            normalize_backend_override("  LibKrun \n"),
            Some("libkrun".to_string())
        );
        assert_eq!(
            normalize_backend_override("firecracker"),
            Some("firecracker".to_string())
        );
        assert_eq!(normalize_backend_override("   "), None);
        assert_eq!(normalize_backend_override(""), None);
    }
}

#[cfg(test)]
mod tests {
    use super::ResumeBootLocalRequest;

    /// An oversized request is granted the largest count the backend will
    /// actually boot — 32 for Firecracker, which is what `/machine-config`
    /// accepts, not the 255 its `u8` `vcpu_count` field can carry. Clamping to
    /// the wire type's ceiling produced a request the API refused, so the
    /// number is written out here rather than read back off the same
    /// `capabilities()` this delegates to, which would assert nothing.
    #[test]
    fn firecracker_vcpus_are_clamped_to_a_count_the_vmm_boots() {
        assert_eq!(
            super::clamp_vcpus_for_backend("firecracker", 9_999),
            Some(32)
        );
        assert_eq!(super::clamp_vcpus_for_backend("firecracker", 2), None);
    }

    /// The same contract on the other backend that declared the wire ceiling.
    /// libkrun accepts every count its config call can carry and aborts at
    /// start on the ones it cannot honour, so 64 is the measured bound.
    #[test]
    fn libkrun_vcpus_are_clamped_to_a_count_the_vmm_boots() {
        assert_eq!(super::clamp_vcpus_for_backend("libkrun", 9_999), Some(64));
        assert_eq!(super::clamp_vcpus_for_backend("libkrun", 2), None);
    }

    #[test]
    fn resume_boot_builder_reports_the_first_missing_required_field() {
        let error = match ResumeBootLocalRequest::builder().build() {
            Ok(_) => panic!("an empty builder must be refused"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("session store"), "{error:#}");
    }
}
