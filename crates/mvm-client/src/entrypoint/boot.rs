//! Booting and tearing down the microVM an entrypoint call runs in.
//!
//! A transient call boots, dispatches once and tears down; a session boots
//! once and keeps the VM for many calls. Both boot here, and both boot only
//! under an admitted plan: the admission callback runs once the rootfs,
//! kernel and VM name are known, and its signed plan is what the backend
//! starts from, so the host spawns the substitution endpoint and the egress
//! gate for this VM before a byte of it runs.
//!
//! These boots take no host-directory shares. A session attaches whatever it
//! needs when it is created, never per call.

use anyhow::{Context, Result};
use mvm_core::vm_backend::{VmId, VmStartConfig};
use mvm_runtime::AnyBackend;

use crate::launch::runtime_source::{
    PairArtifactSource, SdkSidecarAttachment, attach_runtime_overlay_if_cached_version_verified,
    attach_universal_initramfs_if_cached, attach_universal_initramfs_with_verified_release,
};

/// The original higher-layer objects for one host-owned launch. This object is
/// never serialized, sent to the VMM, or reconstructed from the substrate DTO.
pub(crate) struct ClientBootResources {
    pub backend: AnyBackend,
    pub config: VmStartConfig,
    pub admission: crate::admission::AdmissionContext,
    // Custody-only: dropping this original uncommitted preparation rolls back
    // and reseals attachments, so it must outlive every uncertain native use.
    pub _volumes: Option<crate::volume::LaunchPreparation>,
    pub built_runtime: Option<mvm_hostd::plan_admission::PreparedBuiltPackRuntime>,
    pub verified_runtime: Option<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
}

struct ClientCustody {
    resources: Option<ClientBootResources>,
    runtime: Option<mvm_runtime::workload_runner::runner::OwnedRuntimeLaunch>,
}

/// A caller-owned native lifetime, not a serializable session name or helper
/// permit. Keep this value in the host context until terminal stop.
pub struct OwnedClientBoot {
    custody: Option<Box<ClientCustody>>,
}

#[cfg(test)]
thread_local! {
    static TRAP_OWNED_PREPARATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl OwnedClientBoot {
    pub(crate) fn start(
        resources: ClientBootResources,
    ) -> std::result::Result<Self, OwnedBootFailure> {
        let mut owner = Self {
            custody: Some(Box::new(ClientCustody {
                resources: Some(resources),
                runtime: None,
            })),
        };
        let result = {
            let group = owner.custody.as_mut().expect("new client custody");
            let resources = group.resources.as_mut().expect("original client resources");
            mvm_hostd::plan_admission::start_owned_entrypoint(
                &resources.backend,
                &mut resources.admission.admitted,
                &mut resources.config,
                resources.admission.policy_bundle.as_ref(),
                resources.verified_runtime.as_ref(),
                &mut resources.built_runtime,
                &mut group.runtime,
            )
        };
        match result {
            Ok(()) => Ok(owner),
            Err(error) => Err(owner.failure(error)),
        }
    }

    pub(crate) fn resources(&self) -> &ClientBootResources {
        self.custody
            .as_ref()
            .expect("client custody present")
            .resources
            .as_ref()
            .expect("original client resources present")
    }

    pub(crate) fn with_original<T>(
        &mut self,
        operation: impl FnOnce(
            &ClientBootResources,
            &mut mvm_runtime::workload_runner::runner::OwnedRuntimeLaunch,
        ) -> Result<T>,
    ) -> Result<T> {
        let group = self
            .custody
            .as_mut()
            .context("client custody already released")?;
        operation(
            group
                .resources
                .as_ref()
                .context("client resources missing")?,
            group.runtime.as_mut().context("native runtime missing")?,
        )
    }

    pub(crate) fn record_charge(&mut self) -> Result<()> {
        self.with_original(|resources, runtime| {
            let vm_id = runtime.vm_id()?.clone();
            mvm_hostd::plan_admission::record_charge_with_owned_rollback(
                &resources.backend,
                &vm_id,
                &resources.config.name,
                &resources.admission.admitted,
                // The owning caller queues canonical failure/seal after
                // original stop proof; do not emit a duplicate raw failure.
                None,
                || runtime.stop(),
            )
        })
    }

    pub(crate) fn finalize_readonly_entrypoint(&mut self) -> Result<()> {
        self.with_original(|_, runtime| runtime.finalize_readonly_entrypoint())
    }

    /// Dispatch only on the original activated native channel, never by name.
    pub(crate) fn entrypoint(
        &mut self,
        stdin: super::dispatch::CallStdin,
        timeout_secs: u64,
        observer: &mut dyn super::dispatch::CallObserver,
    ) -> Result<super::dispatch::CallOutcome> {
        use super::dispatch::{
            CallOutcome, CallTerminal, CaptureReport, DispatchStdin, RecordedDivergence,
            authorize_stdin, route_event, workload_egress_env,
        };
        self.with_original(|resources, runtime| {
            let name = &resources.config.name;
            // Activation already authenticated this retained connection.
            // A name-resolved readiness session would compete with it.
            runtime
                .validate_live()
                .context("validate the original activated native channel")?;
            let payload = match authorize_stdin(stdin, Some(&resources.admission.admitted))? {
                DispatchStdin::OneShot(bytes) => bytes,
                DispatchStdin::Streaming { .. } => {
                    anyhow::bail!("owned native entrypoint requires one-shot stdin")
                }
                DispatchStdin::Prompt(_) => anyhow::bail!("entrypoint call cannot be a prompt"),
            };
            let request = mvm_agentd::vsock::GuestRequest::RunEntrypoint {
                stdin: payload,
                timeout_secs,
                env: workload_egress_env(name),
                stream_input: false,
            };
            // Audit the verb, not the payload or secret-bearing environment.
            crate::guest::emit_vsock_rpc_audit(
                name,
                &mvm_agentd::vsock::GuestRequest::RunEntrypoint {
                    stdin: Vec::new(),
                    timeout_secs,
                    env: Vec::new(),
                    stream_input: false,
                },
            );
            let mut capture = mvm_hostd::stream::EntrypointSink::for_vm(name);
            let recorded = capture.is_recorded();
            let mut divergence = RecordedDivergence::default();
            observer.dispatching(name, false);
            let terminal = runtime.entrypoint(&request, |event| {
                route_event(event, &mut capture, &mut divergence, observer);
            });
            drop(capture);
            observer.dispatched();
            let outcome = CallOutcome {
                terminal: CallTerminal::from_event(&terminal?),
                capture: Some(CaptureReport {
                    recorded,
                    divergence,
                }),
            };
            observer.call_finished(name, &outcome);
            Ok(outcome)
        })
    }

    pub(crate) fn complete(
        &mut self,
    ) -> Result<mvm_runtime::workload_runner::runner::NativeCompletion> {
        self.with_original(|_, runtime| runtime.complete())
    }

    pub fn stop(&mut self) -> Result<()> {
        let budget = self
            .custody
            .as_ref()
            .and_then(|group| group.resources.as_ref())
            .filter(|resources| {
                resources
                    ._volumes
                    .as_ref()
                    .is_none_or(|volumes| volumes.lease_keys().is_empty())
            })
            .map(|resources| resources.admission.admitted.host_budget_permit());
        if let Some(budget) = budget {
            return budget
                .reconcile_ordinary_stopped(|| self.stop_and_drop_resources())
                .map(|_| ());
        }
        self.stop_and_drop_resources()
    }

    fn stop_and_drop_resources(&mut self) -> Result<()> {
        self.quiesce()?;
        // Only actual original-owner stop/child-free classification permits
        // leases, payloads and admission to be released.
        drop(self.custody.take());
        Ok(())
    }

    pub(crate) fn quiesce(&mut self) -> Result<()> {
        if let Some(group) = self.custody.as_mut()
            && let Some(runtime) = group.runtime.as_mut()
        {
            runtime.stop()?;
        }
        Ok(())
    }

    pub(crate) fn failure(self, error: anyhow::Error) -> OwnedBootFailure {
        OwnedBootFailure {
            error: Some(error),
            owner: std::sync::Mutex::new(Some(self)),
            pending_failure: None,
            audit_panic: None,
        }
    }

    fn release_native_if_child_free(&mut self) -> bool {
        if let Some(group) = self.custody.as_mut()
            && let Some(runtime) = group.runtime.take()
            && let Err(runtime) = runtime.release_if_child_free()
        {
            group.runtime = Some(*runtime);
            return false;
        }
        true
    }

    pub(crate) fn release_if_child_free(mut self) -> std::result::Result<(), Self> {
        if !self.release_native_if_child_free() {
            return Err(self);
        }
        drop(self.custody.take());
        Ok(())
    }
}

impl Drop for OwnedClientBoot {
    fn drop(&mut self) {
        if let Some(mut group) = self.custody.take()
            && let Some(mut runtime) = group.runtime.take()
        {
            if let Some(resources) = group.resources.take() {
                // Runtime's actual child/terminal state decides RAII versus
                // conservative abandonment of the ENTIRE original group.
                let _ = runtime.retain_support(resources);
            }
            drop(runtime);
        }
    }
}

/// Host-only error ownership. It is not the cloneable core facade error.
pub struct OwnedBootFailure {
    error: Option<anyhow::Error>,
    owner: std::sync::Mutex<Option<OwnedClientBoot>>,
    pending_failure: Option<PendingFailureAudit>,
    // Audit uncertainty is distinct from native stop proof. Keep the original
    // panic value without exposing it or automatically repeating audit writes.
    audit_panic: Option<std::sync::Mutex<Box<dyn std::any::Any + Send>>>,
}

#[derive(Clone, Copy)]
enum PendingFailureAudit {
    Queued(&'static str),
    Attempted,
    Returned,
}

impl OwnedBootFailure {
    pub fn error(&self) -> &anyhow::Error {
        self.error.as_ref().expect("original launch error present")
    }

    pub fn retry_stop(&mut self) -> Result<()> {
        let slot = self
            .owner
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(owner) = slot.as_mut() {
            owner.quiesce()?;
        }
        self.flush_pending_failure()?;
        drop(
            self.owner
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
        Ok(())
    }

    pub fn into_released_error(mut self) -> std::result::Result<anyhow::Error, Self> {
        let slot = self
            .owner
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(owner) = slot.as_mut()
            && !owner.release_native_if_child_free()
        {
            return Err(self);
        }
        if self.flush_pending_failure().is_err() {
            return Err(self);
        }
        drop(
            self.owner
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
        Ok(self.error.take().expect("original error consumed once"))
    }

    pub(crate) fn emit_failed(&mut self, stage: &'static str) {
        // This records intent, not a terminal event. In particular activation
        // failure after adoption cannot seal a potentially live native run.
        if self.pending_failure.is_none() {
            self.pending_failure = Some(PendingFailureAudit::Queued(stage));
        }
        let slot = self
            .owner
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let released = slot
            .as_mut()
            .is_none_or(OwnedClientBoot::release_native_if_child_free);
        if released && let Err(error) = self.flush_pending_failure() {
            tracing::warn!(error = %error, "owned terminal failure audit remains unresolved");
        }
    }

    fn flush_pending_failure(&mut self) -> Result<()> {
        let Some(pending) = self.pending_failure else {
            return Ok(());
        };
        if matches!(pending, PendingFailureAudit::Returned) {
            return Ok(());
        }
        let PendingFailureAudit::Queued(stage) = pending else {
            anyhow::bail!("owned terminal failure audit was attempted but remains unconfirmed");
        };
        let error = self.error.as_ref().expect("original launch error present");
        let owner = self
            .owner
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .context("original audit custody missing")?;
        self.pending_failure = Some(PendingFailureAudit::Attempted);
        let emitted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::admission::emit_failed(&owner.resources().admission, stage, error);
        }));
        match emitted {
            Ok(()) => {
                // Canonical audit policy reports its own write/seal failures
                // through the existing unsealed path. Returned is not a new
                // audit durability proof, and this call is never repeated.
                self.pending_failure = Some(PendingFailureAudit::Returned);
                Ok(())
            }
            Err(payload) => {
                self.audit_panic = Some(std::sync::Mutex::new(payload));
                anyhow::bail!(
                    "owned terminal failure audit panicked; original failure and audit custody retained"
                )
            }
        }
    }
}

impl Drop for OwnedBootFailure {
    fn drop(&mut self) {
        let slot = self
            .owner
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(owner) = slot.take()
            && let Err(owner) = owner.release_if_child_free()
        {
            // Preserve pending audit and the primary error with the exact
            // native/client group even on conservative abandonment.
            std::mem::forget((
                owner,
                self.error.take(),
                self.pending_failure.take(),
                self.audit_panic.take(),
            ));
        }
    }
}

impl OwnedBootFailure {}

impl std::fmt::Debug for OwnedBootFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedBootFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for OwnedBootFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.error(), f)
    }
}
impl std::error::Error for OwnedBootFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error().as_ref())
    }
}

/// A booted microVM, named so it can be dispatched into and torn down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionVm {
    /// The name the backend started it under.
    pub vm_name: String,
}

/// What an admitted plan contributes to a VM's start config so the backend
/// spawns the substitution endpoint (the guest never holds a raw secret).
///
/// Strings rather than typed plan values so the boot carries no admission
/// types of its own. **Do not log `plan_json`**: the signed envelope carries
/// secret bindings.
pub struct SessionAuditSubstrate {
    /// The actual host reservation, retained until the boot handoff completes.
    pub host_budget: std::sync::Arc<mvm_hostd::admission_budget::HostBudgetPermit>,
    /// The tenant the plan was admitted under.
    pub tenant_id: String,
    /// The signed plan, serialized.
    pub plan_json: String,
    /// The admitted workload's audit identity. The host endpoint refuses to
    /// start without it, so a boot that applies this substrate must carry it.
    pub audit_context: mvm_core::audit_sink::AuditContext,
    /// Verified launch posture retained outside caller-authored plan JSON.
    pub mailbox_posture: Option<mvm_hostd::plan_admission::MailboxLaunchPosture>,
    /// Trusted admission's optional caller registration, never a producer ACK.
    pub caller_registration: Option<mvm_core::vm_backend::caller_registration::CallerRegistration>,
    /// The tenant policy bundle the plan resolved, serialized, when it has one.
    pub bundle_json: Option<String>,
    /// Config-drive files the plan's guest boot config needs.
    pub config_files: Vec<mvm_core::vm_backend::VmFile>,
    /// Frozen host-directory images admission hardened to read-only.
    pub read_only_materialized_images: Vec<String>,
    /// One-use image expectations from the actual admitted plan. This is not
    /// decoded from `plan_json` and cannot authorize another launch.
    pub built_pack_check: Option<mvm_hostd::plan_admission::BuiltPackBootCheck>,
    /// The admission's audit sync, when the admission left it running beside
    /// the boot. Carried onto [`VmStartConfig::admission_durability`]; `None`
    /// when the admission was already durable.
    ///
    /// [`VmStartConfig::admission_durability`]: mvm_core::vm_backend::VmStartConfig::admission_durability
    pub durability: Option<mvm_core::admission_durability::AdmissionDurability>,
}

impl SessionAuditSubstrate {
    /// Move the admitted substrate onto the start config its boot runs from,
    /// returning the materialized images admission hardened to read-only so a
    /// caller with volumes can fold them into its volume flags.
    pub fn apply_to(self, start_config: &mut mvm_core::vm_backend::VmStartConfig) -> Vec<String> {
        start_config.tenant_id = Some(self.tenant_id);
        start_config.plan_json = Some(self.plan_json);
        start_config.audit_context = Some(self.audit_context);
        start_config.caller_registration = self.caller_registration;
        start_config.bundle_json = self.bundle_json;
        start_config.config_files.extend(self.config_files);
        start_config.admission_durability = self.durability;
        self.read_only_materialized_images
    }
}

/// Admission callback: given what the boot resolved, produce the substrate the
/// admitted plan contributes, or `None` when the caller admits nothing.
///
/// The kernel rides along for the same reason the rootfs does. A plan that
/// names the image but not the kernel pins what the workload *is* and nothing
/// about what confines it, so the callback cannot bind the environment it was
/// admitted onto unless it is told which kernel that is.
pub type SessionAdmit<'a> = dyn Fn(AdmitInputs<'_>) -> Result<Option<SessionAuditSubstrate>> + 'a;

/// What the launch resolution has established by the time admission runs.
///
/// A struct rather than a positional list because every field is something the
/// resolution *discovered* — the rootfs it materialized, the kernel it chose,
/// the name it generated, the sidecar variant that rootfs turned out to need.
#[derive(Debug, Clone, Copy)]
pub struct AdmitInputs<'a> {
    /// The materialized rootfs the workload will boot.
    pub rootfs: &'a std::path::Path,
    /// The kernel confining it, when the tier has one.
    pub kernel: Option<&'a std::path::Path>,
    /// The backend object selected for this boot, not a plan or profile label.
    pub backend_kind: mvm_core::vm_backend::BackendKind,
    /// The name this VM will be started under.
    pub vm_name: &'a str,
    /// The SDK sidecar this boot will attach, or `None`.
    ///
    /// Resolved once, after the rootfs exists — the guest's own recorded libc
    /// decides which variant it is — and handed to both halves from here, so
    /// the plan grant and the attached volume cannot describe different bytes.
    pub sdk_sidecar: Option<&'a SdkSidecarAttachment>,
    /// Declared asset bindings forwarded to admission for content identity
    /// hashing.
    pub assets: &'a [crate::admission::AssetSpec],
    /// Every volume this boot will attach, as the launch config already
    /// resolved them.
    ///
    /// Admission turns these into the plan's host-fs grants, so the signed
    /// plan names the same shares the backend is about to mount. Without it a
    /// mount reaches the guest under a plan that never admitted it, and the
    /// admitted-share check has nothing to compare it against.
    pub volumes: &'a [mvm_core::vm_backend::VmVolume],
    /// The cached archive of the installed bundle `rootfs` and `kernel` were
    /// resolved from, or `None` when they did not come from one.
    ///
    /// Admission pins it into the signed plan and refuses the boot when the
    /// archive, or the extracted files beside it, no longer match what the
    /// publisher signed.
    pub bundle_archive: Option<&'a std::path::Path>,
    /// The selected runtime artifacts and their untrusted release proof.
    /// Admission verifies this same config before the backend consumes it.
    pub runtime_config: Option<&'a VmStartConfig>,
    /// Launch-owned archive verification, carried beside the cloneable config.
    pub verified_runtime: Option<&'a mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    /// The launch-owned handle, when a caller must retain this exact set after admission.
    pub verified_runtime_owner:
        Option<&'a std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
}

/// Identity policy for a session-style VM boot.
#[derive(Debug, Clone, Copy)]
pub enum SessionVmName<'a> {
    /// Preserve a user-visible persistent machine identity exactly.
    Exact(&'a str),
    /// Generate an internal collision-resistant name under this prefix.
    Prefixed(&'a str),
}

impl SessionVmName<'_> {
    pub(crate) fn resolve(self) -> String {
        match self {
            Self::Exact(name) => name.to_string(),
            Self::Prefixed(prefix) => {
                format!("{prefix}-{}", mvm_core::naming::generate_machine_name())
            }
        }
    }
}

/// One session-style boot: which built workload, under what name, how big, and
/// on which backend.
pub struct SessionBoot<'a> {
    slot: &'a str,
    vm_name: SessionVmName<'a>,
    cpus: u32,
    memory_mib: u32,
    network_policy: mvm_core::network_policy::NetworkPolicy,
    backend_name: Option<&'a str>,
    portable_boot_assets: Option<&'a crate::portable_boot_assets::PreparedPortableBootAssets>,
}

impl<'a> SessionBoot<'a> {
    /// A boot of `slot` under `vm_name`, one vCPU and 256 MiB, deny-all egress,
    /// on the host's default backend until told otherwise.
    #[must_use]
    pub fn builder(slot: &'a str, vm_name: SessionVmName<'a>) -> SessionBootBuilder<'a> {
        SessionBootBuilder(Self {
            slot,
            vm_name,
            cpus: 1,
            memory_mib: 256,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            backend_name: None,
            portable_boot_assets: None,
        })
    }
}

/// Builder for [`SessionBoot`].
pub struct SessionBootBuilder<'a>(SessionBoot<'a>);

impl<'a> SessionBootBuilder<'a> {
    /// Producer health may select an already verified release closure. This is
    /// not a consumer acquisition path or an admission grant.
    #[must_use]
    pub fn portable_boot_assets(
        mut self,
        assets: Option<&'a crate::portable_boot_assets::PreparedPortableBootAssets>,
    ) -> Self {
        self.0.portable_boot_assets = assets;
        self
    }

    /// vCPUs for the VM.
    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.0.cpus = cpus;
        self
    }

    /// Guest memory in MiB.
    #[must_use]
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.0.memory_mib = memory_mib;
        self
    }

    /// The egress policy the VM's start config carries.
    #[must_use]
    pub fn network_policy(mut self, policy: mvm_core::network_policy::NetworkPolicy) -> Self {
        self.0.network_policy = policy;
        self
    }

    /// The backend to boot on; the host's default when never called.
    #[must_use]
    pub fn backend_name(mut self, backend_name: &'a str) -> Self {
        self.0.backend_name = Some(backend_name);
        self
    }

    /// The finished boot description.
    #[must_use]
    pub fn build(self) -> SessionBoot<'a> {
        self.0
    }
}

/// Resolve the backend a boot runs on: the named hypervisor, refused when this
/// host cannot select it, or the host's default.
///
/// # Errors
/// A hypervisor name this host cannot select.
pub fn resolve_backend(hypervisor: Option<&str>) -> Result<AnyBackend> {
    match hypervisor {
        Some(name) => {
            AnyBackend::require_hypervisor_selectable(name)?;
            Ok(AnyBackend::from_hypervisor(name))
        }
        None => Ok(AnyBackend::auto_select()),
    }
}

/// Compatibility entrypoint for callers holding only a serialized boot substrate.
///
/// The substrate alone is not admission authority: without the original
/// `AdmittedPlan`, this API refuses before backend dispatch. Use the
/// entrypoint admission path for a boot that can actually run.
///
/// # Errors
/// Always refuses: a serialized substrate cannot prove original admission.
pub fn boot_session_vm(
    _boot: SessionBoot<'_>,
    _admit: &SessionAdmit<'_>,
    _pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<SessionVm> {
    anyhow::bail!(
        "boot_session_vm requires an original EntrypointAdmission; use boot_session_vm_owned \
         for native ownership or the admitted entrypoint/session API for supported backends"
    )
}

/// Host-owned admission and resources, with no DTO/name downgrade on success.
pub fn boot_session_vm_owned(
    boot: SessionBoot<'_>,
    admission: &super::admission::EntrypointAdmission,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<OwnedClientBoot> {
    match boot_session_core(
        boot,
        |inputs| {
            admission
                .admit(inputs)
                .map(Box::new)
                .map(BootAdmission::Owned)
        },
        pair,
    )? {
        SessionBootResult::Owned(owner) => Ok(owner),
        SessionBootResult::Admitted(..) => {
            anyhow::bail!("owned boot did not return native custody")
        }
    }
}

pub(crate) fn boot_session_vm_admitted(
    boot: SessionBoot<'_>,
    admission: &super::admission::EntrypointAdmission,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<(SessionVm, crate::admission::AdmissionContext)> {
    match boot_session_core(
        boot,
        |inputs| {
            admission
                .admit(inputs)
                .map(Box::new)
                .map(BootAdmission::Admitted)
        },
        pair,
    )? {
        SessionBootResult::Admitted(vm, context) => Ok((vm, *context)),
        SessionBootResult::Owned(owner) => Err(anyhow::Error::new(
            owner.failure(anyhow::anyhow!("owning receiver required")),
        )),
    }
}

enum BootAdmission {
    Admitted(Box<super::admission::AdmittedEntrypoint>),
    Owned(Box<super::admission::AdmittedEntrypoint>),
}

enum SessionBootResult {
    Admitted(SessionVm, Box<crate::admission::AdmissionContext>),
    Owned(OwnedClientBoot),
}

fn require_native_owner(backend: mvm_core::vm_backend::BackendKind, has_owner: bool) -> Result<()> {
    anyhow::ensure!(
        backend != mvm_core::vm_backend::BackendKind::Hvf || has_owner,
        "native session requires an owning host context; name-only return is unavailable before launch"
    );
    Ok(())
}

/// The launch-owned verified set for the runtime this session config selected.
fn session_runtime_set(
    config: &VmStartConfig,
    release: Option<crate::launch::runtime_source::ReleaseRuntime>,
) -> Result<Option<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>> {
    crate::launch::runtime_source::paired_release_evidence(config, release)?
        .map(|release| mvm_runtime::runtime_evidence::verify_release_runtime_set(config, release))
        .transpose()
}

fn require_portable_without_installed_bundle(
    portable: bool,
    bundle_archive: Option<&std::path::Path>,
) -> Result<()> {
    anyhow::ensure!(
        !portable || bundle_archive.is_none(),
        "producer health cannot replace an installed bundle's boot closure"
    );
    Ok(())
}

fn boot_session_core(
    boot: SessionBoot<'_>,
    admit: impl FnOnce(AdmitInputs<'_>) -> Result<BootAdmission>,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<SessionBootResult> {
    let SessionBoot {
        slot,
        vm_name,
        cpus,
        memory_mib,
        network_policy,
        backend_name,
        portable_boot_assets,
    } = boot;
    let (spec, vmlinux, initrd, rootfs, rev) =
        mvm_runtime::vm::template::lifecycle::template_artifacts_for_boot(slot)
            .with_context(|| format!("Loading template '{slot}'"))?;
    let bundle_archive = mvm_runtime::vm::template::lifecycle::installed_bundle_archive(slot)?;
    let backend = resolve_backend(backend_name)?;
    let vm_name = vm_name.resolve();
    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);

    let mut start_config = VmStartConfig {
        name: vm_name.clone(),
        rootfs_path: rootfs.clone(),
        kernel_path: Some(vmlinux),
        initrd_path: initrd,
        verity_path,
        roothash,
        revision_hash: rev,
        flake_ref: spec.flake_ref,
        profile: Some(spec.profile),
        cpus,
        memory_mib,
        // Session VMs are short-lived boots; balloon elasticity isn't useful
        // here, so leave commit at boot.
        mem_initial_mib: None,
        ports: vec![],
        volumes: vec![],
        config_files: vec![],
        secret_files: vec![],
        runner_dir: None,
        network_policy,
        ..Default::default()
    };

    // The runtime overlay is the single source of the guest agent and its
    // helpers here, as on the transient path; a missing required overlay is
    // built or acquired, never replaced by a copy baked into the rootfs.
    let release = if let Some(assets) = portable_boot_assets {
        require_portable_without_installed_bundle(true, bundle_archive.as_deref())?;
        Some(assets.apply_for_health(&mut start_config)?)
    } else {
        let release = attach_runtime_overlay_if_cached_version_verified(
            &mut start_config,
            backend.name(),
            None,
            pair,
        )?;
        if let Some(release) = &release {
            attach_universal_initramfs_with_verified_release(
                &mut start_config,
                backend.name(),
                release,
            )?;
        } else {
            attach_universal_initramfs_if_cached(&mut start_config, backend.name())?;
        }
        release
    };
    let verified_runtime = session_runtime_set(&start_config, release)?;

    // Admission starts the plan and verb-grant validity windows. All boot
    // preparation therefore completes before this point, immediately before
    // the backend consumes the admitted start config.
    let admitted = admit(AdmitInputs {
        rootfs: std::path::Path::new(&rootfs),
        kernel: start_config
            .kernel_path
            .as_deref()
            .map(std::path::Path::new),
        backend_kind: backend.kind(),
        vm_name: &vm_name,
        // An entrypoint VM binds no SDK host service.
        sdk_sidecar: None,
        // The function payload is admitted as the workload itself; there are
        // no standalone assets.
        assets: &[],
        volumes: &start_config.volumes,
        bundle_archive: bundle_archive.as_deref(),
        runtime_config: Some(&start_config),
        verified_runtime: verified_runtime.as_ref(),
        verified_runtime_owner: None,
    })?;
    let native_owned = matches!(&admitted, BootAdmission::Owned(_));
    let (substrate, context) = match admitted {
        BootAdmission::Admitted(admitted) | BootAdmission::Owned(admitted) => {
            let admitted = *admitted;
            (admitted.substrate, admitted.context)
        }
    };
    require_native_owner(backend.kind(), native_owned).inspect_err(|error| {
        crate::admission::emit_failed(&context, "backend-start", error);
    })?;
    substrate.apply_to(&mut start_config);
    // The admitted executor prepares or freezes the selected pack's original
    // closure at dispatch, after all of its post-admission checks.
    let prepared = (|| {
        if let Some(runtime) = &verified_runtime {
            runtime.verify_config(&start_config)?;
        }
        if let Some(assets) = portable_boot_assets {
            assets.verify_health_config(&start_config)?;
        }
        Ok::<(), anyhow::Error>(())
    })();
    prepared.inspect_err(|error| {
        crate::admission::emit_failed(&context, "guest-runtime", error);
    })?;

    tracing::info!(vm = %vm_name, slot, "booting session VM");
    if native_owned {
        let mut owner = crate::boot::start_prepared_owned(ClientBootResources {
            backend,
            config: start_config,
            admission: context,
            _volumes: None,
            built_runtime: None,
            verified_runtime,
        })
        .map_err(|mut failure| {
            failure.emit_failed("backend-start");
            anyhow::Error::new(failure)
        })?;
        if let Err(error) = owner.record_charge() {
            let mut failure = owner.failure(error);
            failure.emit_failed("host-budget");
            return Err(anyhow::Error::new(failure));
        }
        return Ok(SessionBootResult::Owned(owner));
    }
    let crate::admission::AdmissionContext {
        admitted,
        emitter,
        policy_bundle,
        host_signer_public_path,
    } = context;
    let audit_plan = admitted.plan().clone();
    let result = mvm_hostd::plan_admission::start_entrypoint(
        mvm_hostd::plan_admission::StartAdmittedParams {
            backend: &backend,
            admitted,
            config: start_config,
            policy_bundle: policy_bundle.as_ref(),
            emitter: Some(&emitter),
            assurance: None,
        },
        verified_runtime.as_ref(),
    );
    let started = result.inspect_err(|error| {
        audit_entrypoint_dispatch_failure(&emitter, &audit_plan, &vm_name, error);
    })?;
    Ok(SessionBootResult::Admitted(
        SessionVm { vm_name },
        Box::new(crate::admission::AdmissionContext {
            admitted: started.admitted,
            emitter,
            policy_bundle,
            host_signer_public_path,
        }),
    ))
}

fn audit_entrypoint_dispatch_failure(
    emitter: &mvm_hostd::audit::emitter::AuditEmitter,
    plan: &mvm_core::plan::ExecutionPlan,
    name: &str,
    error: &anyhow::Error,
) {
    if matches!(
        error.downcast_ref::<mvm_hostd::plan_admission::CliStartFailure>(),
        Some(mvm_hostd::plan_admission::CliStartFailure::UncertainStop(_))
    ) {
        crate::launch::record_unsealed_end(
            Some((emitter, plan)),
            crate::launch::UnsealedEnd::new(name, crate::launch::UnsealedReason::StopFailed)
                .error(format!("{error:#}")),
        );
    } else {
        crate::admission::seal_recorded_failure(emitter, plan);
    }
}

/// Tear down a session VM. Best-effort: a failure (already stopped, backend
/// mismatch) is logged rather than returned, because the reaper calls this
/// where nobody is waiting for an error.
pub fn tear_down_session_vm(vm: SessionVm) {
    if let Err(e) = stop_session_vm(&vm) {
        tracing::warn!(vm = %vm.vm_name, err = %e, "session VM teardown failed");
    }
}

/// Stop a session VM, reporting whether the stop took. A caller that records
/// the end of the VM's session needs to know: a VM that may still be running
/// is not one whose session can be sealed.
///
/// # Errors
/// The backend refused or failed the stop.
pub(crate) fn stop_session_vm(vm: &SessionVm) -> Result<()> {
    // The marker in the VM's state dir names the backend that actually
    // launched it. Falling back to the host default would send the stop to
    // the wrong VMM and leave the guest running.
    let backend = AnyBackend::for_started_vm(&vm.vm_name).unwrap_or_else(AnyBackend::auto_select);
    backend.stop(&VmId(vm.vm_name.clone())).map(|_| ())
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[path = "caller_registration_live_hvf.rs"]
mod caller_registration_live_hvf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_original_admission_refuses_before_owned_images_and_native_preparation() {
        use mvm_contract::protocol::mailbox::{
            ExecutionEpoch, MailboxGrant, MailboxId, service_blind::LaunchProfile,
        };
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = mvm_core::config::mvm_keys_dir();
        mvm_hostd::audit::host_keypair::load_or_init_at(&keys).unwrap();
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"test rootfs").unwrap();
        let selected = LaunchProfile::new([1; 32], [2; 32]).unwrap();
        for projection in 0..4 {
            let audit = tempfile::tempdir().unwrap();
            let ledger = mvm_hostd::plan_admission::InMemoryNonceLedger::new();
            let admission =
                crate::admission::admit_plan_for_boot(crate::admission::AdmitPlanForBootParams {
                    mailbox: Some(MailboxGrant {
                        mailbox: MailboxId::from_bytes([4; 32]),
                        authority_key: [9; 32],
                        epoch: ExecutionEpoch::new(1).unwrap(),
                        report: None,
                        retention: None,
                        service_blind: Some(selected),
                    }),
                    keys_dir: Some(&keys),
                    audit_dir: Some(audit.path()),
                    ..crate::admission::admit_plan_tests::pinning_params(&rootfs, &ledger)
                })
                .unwrap();
            let original = admission.admitted.plan().clone();
            assert_eq!(
                original.mailbox.unwrap().service_blind,
                Some(selected),
                "client admission must preserve selected intent"
            );
            let roundtrip = mvm_core::plan::plan_from_admitted_json(
                &serde_json::to_string(admission.admitted.signed()).unwrap(),
            )
            .unwrap();
            assert_eq!(roundtrip.mailbox, original.mailbox);
            let mut stripped = original.clone();
            stripped.mailbox.as_mut().unwrap().service_blind = None;
            let mut replaced = original.clone();
            replaced.mailbox = None;
            let config = VmStartConfig {
                name: original.image.name.clone(),
                plan_json: match projection {
                    0 => None,
                    1 => Some(serde_json::to_string(&stripped).unwrap()),
                    2 => Some(serde_json::to_string(&replaced).unwrap()),
                    _ => Some("malformed".into()),
                },
                ..Default::default()
            };
            TRAP_OWNED_PREPARATION.set(true);
            let mut failure = OwnedClientBoot::start(ClientBootResources {
                backend: AnyBackend::from_hypervisor("libkrun"),
                config,
                admission,
                _volumes: None,
                built_runtime: None,
                verified_runtime: None,
            })
            .err()
            .expect("selected launch refuses");
            TRAP_OWNED_PREPARATION.set(false);
            let expected = "service-blind V3 mailbox launch is unavailable";
            assert_eq!(failure.error().to_string(), expected);
            {
                let owner = failure.owner.lock().unwrap();
                let owner = owner.as_ref().unwrap();
                assert_eq!(owner.resources().admission.admitted.plan(), &original);
                assert!(owner.custody.as_ref().unwrap().runtime.is_none());
            }
            failure.emit_failed("backend-start");
            failure.emit_failed("backend-start");
            failure.retry_stop().unwrap();
            assert_eq!(failure.into_released_error().unwrap().to_string(), expected);
            let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap();
            assert_eq!(
                chain
                    .lines()
                    .filter(|line| line.contains("\"plan.failed\""))
                    .count(),
                1
            );
            assert!(!chain.contains("\"plan.launched\""));
        }
    }

    #[test]
    fn a_session_config_carrying_a_release_proof_must_carry_verified_evidence() {
        let config = VmStartConfig {
            runtime_release_proof: Some(mvm_core::protocol::runtime_release::RuntimeReleaseProof {
                archive: "/mock/archive".into(),
                checksum: "/mock/checksum".into(),
                signature_bundle: "/mock/signature".into(),
                archive_sha256: "a".repeat(64),
                version: "selected-release".into(),
                arch: mvm_core::arch::GuestArch::host(),
            }),
            runtime_overlay_version: Some("selected-release".into()),
            ..Default::default()
        };
        let error = session_runtime_set(&config, None)
            .expect_err("a selected release proof with no verified evidence is refused");
        assert!(
            format!("{error:#}").contains("requires verified launch evidence"),
            "{error:#}"
        );
    }

    #[test]
    fn a_session_config_with_no_release_proof_carries_no_evidence() {
        assert!(
            session_runtime_set(&VmStartConfig::default(), None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn legacy_hvf_refuses_before_launch_but_owned_hvf_passes_gate() {
        use mvm_core::vm_backend::BackendKind;
        let launched = std::cell::Cell::new(false);
        let result = require_native_owner(BackendKind::Hvf, false).map(|()| launched.set(true));
        assert!(result.is_err());
        assert!(!launched.get());
        require_native_owner(BackendKind::Hvf, true).unwrap();
    }

    #[test]
    fn portable_selection_cannot_override_an_installed_bundle() {
        let archive = std::path::Path::new("/installed/bundle.mvmpkg");
        let refused = require_portable_without_installed_bundle(true, Some(archive))
            .expect_err("portable producer selection must not displace bundle custody");
        assert!(refused.to_string().contains("installed bundle"));
        require_portable_without_installed_bundle(false, Some(archive))
            .expect("the installed bundle alone is a distinct selection");
        require_portable_without_installed_bundle(true, None)
            .expect("portable assets without an installed bundle may proceed");
    }

    #[test]
    fn child_free_failure_audits_once_and_keeps_original_error_through_retry() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();
        let admission = crate::admission::admit_plan_tests::admitted_into(
            keys.path(),
            audit.path(),
            "owned-no-child",
        );
        let owner = OwnedClientBoot {
            custody: Some(Box::new(ClientCustody {
                resources: Some(ClientBootResources {
                    backend: AnyBackend::from_hypervisor("libkrun"),
                    config: VmStartConfig {
                        name: "owned-no-child".into(),
                        ..Default::default()
                    },
                    admission,
                    _volumes: None,
                    built_runtime: None,
                    verified_runtime: None,
                }),
                runtime: None,
            })),
        };
        let mut failure = owner.failure(anyhow::anyhow!("original prechild error"));
        failure.emit_failed("backend-start");
        failure.emit_failed("backend-start");
        failure.retry_stop().unwrap();
        assert_eq!(failure.error().to_string(), "original prechild error");
        let error = failure.into_released_error().unwrap();
        assert_eq!(error.to_string(), "original prechild error");
        let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap();
        assert_eq!(
            chain
                .lines()
                .filter(|line| line.contains("\"plan.failed\""))
                .count(),
            1
        );
        // No original Child ever existed. This does not test native terminal
        // proof, uncertain deferral, or a synthesized ConfirmedExit.
    }

    #[test]
    fn native_dispatch_refusal_keeps_the_original_client_custody() {
        let keys = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();
        let admission = crate::admission::admit_plan_tests::admitted_into(
            keys.path(),
            audit.path(),
            "native-refused",
        );
        let original_id = admission.admitted.plan_id().clone();
        let resources = ClientBootResources {
            backend: AnyBackend::from_hypervisor("libkrun"),
            config: VmStartConfig {
                name: "native-refused".into(),
                ..Default::default()
            },
            admission,
            _volumes: None,
            built_runtime: None,
            verified_runtime: None,
        };
        let mut failure = match OwnedClientBoot::start(resources) {
            Ok(_) => panic!("non-HVF backend must not create an owned native child"),
            Err(failure) => failure,
        };
        assert!(failure.error().to_string().contains("requires HVF"));
        let owner = failure
            .owner
            .get_mut()
            .expect("test owns failure exclusively")
            .as_ref()
            .expect("the original client group stays with the failure");
        assert_eq!(owner.resources().admission.admitted.plan_id(), &original_id);
        assert!(
            owner
                .custody
                .as_ref()
                .expect("original custody")
                .runtime
                .is_none(),
            "pre-start refusal cannot invent an owner"
        );
        failure.emit_failed("backend-start");
        failure.retry_stop().expect("no child needs stopping");
        assert!(failure.into_released_error().is_ok());
    }

    #[test]
    fn entrypoint_uncertain_dispatch_stop_keeps_audit_unsealed() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();
        let admission = crate::admission::admit_plan_tests::admitted_into(
            keys.path(),
            audit.path(),
            "entrypoint-uncertain",
        );
        let error = anyhow::Error::new(mvm_hostd::plan_admission::CliStartFailure::UncertainStop(
            anyhow::anyhow!("mock child stop unconfirmed"),
        ));
        audit_entrypoint_dispatch_failure(
            &admission.emitter,
            admission.admitted.plan(),
            "entrypoint-uncertain",
            &error,
        );
        let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap();
        assert!(!chain.contains("plan.failed"), "{chain}");
        assert!(!chain.contains("session.sealed"), "{chain}");
    }

    fn test_audit_context() -> mvm_core::audit_sink::AuditContext {
        mvm_core::audit_sink::AuditContext::Builder {
            tenant: mvm_core::plan::TenantId("tenant".into()),
            name: "vm".into(),
        }
    }

    #[test]
    fn applying_admission_preserves_durability_and_materialized_images() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        for outcome in [Ok(()), Err(anyhow::anyhow!("audit sync refused"))] {
            let should_succeed = outcome.is_ok();
            let mut substrate = SessionAuditSubstrate {
                host_budget: std::sync::Arc::new(
                    mvm_hostd::admission_budget::HostBudgetPermit::reserve(
                        "vm",
                        mvm_contract::grants::budget::MachineCharge::default(),
                    )
                    .unwrap(),
                ),
                tenant_id: "tenant".into(),
                plan_json: "signed-plan".into(),
                audit_context: test_audit_context(),
                mailbox_posture: None,
                caller_registration: None,
                bundle_json: Some("policy-bundle".into()),
                config_files: Vec::new(),
                read_only_materialized_images: vec!["image.ext4".into()],
                built_pack_check: None,
                durability: Some(
                    mvm_core::admission_durability::AdmissionDurability::settled(outcome),
                ),
            };
            // Taking the image handoff must not bypass the rest of admission.
            let built_pack_check = substrate.built_pack_check.take();
            let mut config = VmStartConfig::default();
            let images = substrate.apply_to(&mut config);
            assert!(built_pack_check.is_none());
            assert_eq!(images, vec!["image.ext4"]);
            assert_eq!(config.tenant_id.as_deref(), Some("tenant"));
            assert_eq!(config.plan_json.as_deref(), Some("signed-plan"));
            assert_eq!(
                config.audit_context,
                Some(test_audit_context()),
                "the endpoint refuses to start without the admitted audit identity"
            );
            assert_eq!(config.bundle_json.as_deref(), Some("policy-bundle"));
            assert_eq!(
                config.admission_durability.as_ref().unwrap().wait().is_ok(),
                should_succeed,
                "a failed audit sync must still refuse activation"
            );
        }
    }

    #[test]
    fn an_exact_session_vm_name_is_not_rewritten() {
        assert_eq!(SessionVmName::Exact("named-agent").resolve(), "named-agent");
    }

    #[test]
    fn a_prefixed_session_vm_name_keeps_its_prefix_and_differs_each_time() {
        let first = SessionVmName::Prefixed("invoke").resolve();
        let second = SessionVmName::Prefixed("invoke").resolve();
        assert!(first.starts_with("invoke-"), "{first}");
        assert_ne!(first, second, "a generated name must not repeat");
    }

    #[test]
    fn the_boot_builder_carries_every_setting() {
        let boot = SessionBoot::builder("slot", SessionVmName::Exact("vm"))
            .cpus(4)
            .memory_mib(1024)
            .backend_name("mock")
            .build();
        assert_eq!((boot.cpus, boot.memory_mib), (4, 1024));
        assert_eq!(boot.backend_name, Some("mock"));
        assert_eq!(
            boot.network_policy,
            mvm_core::network_policy::NetworkPolicy::deny_all()
        );
    }

    #[test]
    fn an_unselectable_hypervisor_is_refused() {
        assert!(resolve_backend(Some("docker")).is_err());
    }

    #[test]
    fn an_unknown_slot_is_refused_before_admission_runs() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let admit = |_: AdmitInputs<'_>| -> Result<BootAdmission> {
            panic!("admission must not run for a slot that does not exist")
        };
        let slot = "0".repeat(64);
        let Err(error) = boot_session_core(
            SessionBoot::builder(&slot, SessionVmName::Prefixed("t")).build(),
            admit,
            None,
        ) else {
            panic!("an unknown slot has nothing to boot");
        };
        assert!(
            format!("{error:#}").contains("Loading template"),
            "{error:#}"
        );
    }

    #[test]
    fn legacy_substrate_callback_refuses_before_it_can_admit_or_start() {
        let invoked = std::cell::Cell::new(false);
        let callback = |_: AdmitInputs<'_>| -> Result<Option<SessionAuditSubstrate>> {
            invoked.set(true);
            Ok(None)
        };
        let error = boot_session_vm(
            SessionBoot::builder("irrelevant-slot", SessionVmName::Exact("unstarted")).build(),
            &callback,
            None,
        )
        .expect_err("serialized substrate cannot prove signed admission");
        assert!(
            error.to_string().contains("EntrypointAdmission"),
            "{error:#}"
        );
        assert!(
            error.to_string().contains("boot_session_vm_owned"),
            "{error:#}"
        );
        assert!(!invoked.get(), "legacy callback may not mint an authority");
    }
}
