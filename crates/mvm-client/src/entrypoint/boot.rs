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
    PairArtifactSource, SdkSidecarAttachment, attach_runtime_overlay_if_cached_version,
    attach_universal_initramfs_if_cached,
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
        let result = (|| {
            let group = owner.custody.as_mut().expect("new client custody");
            let resources = group.resources.as_mut().expect("original client resources");
            mvm_runtime::workload_backend::require_workload_backend(&resources.backend)?;
            if let Some(runtime) = &resources.built_runtime {
                runtime.verify_config(&resources.config)?;
            }
            // Store the prepared runtime BEFORE the first native side effect.
            let images = resources
                .built_runtime
                .as_mut()
                .context("owned native image preparation missing")?
                .take_boot_images()?;
            group.runtime = Some(
                resources
                    .backend
                    .prepare_owned_launch(&resources.config, images)?,
            );
            let runtime = group.runtime.as_mut().expect("prepared runtime");
            if let Some(built) = &resources.built_runtime {
                built.verify_config(runtime.config()?)?;
            }
            runtime.activate()
        })();
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

impl OwnedBootFailure {
    pub(crate) fn observe_failure(
        &mut self,
        observe: impl FnOnce(&crate::admission::AdmissionContext, &anyhow::Error),
    ) {
        let error = self.error.as_ref().expect("launch error present");
        let slot = self
            .owner
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(owner) = slot.as_ref() {
            observe(&owner.resources().admission, error);
        }
    }
}

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
    /// The tenant the plan was admitted under.
    pub tenant_id: String,
    /// The signed plan, serialized.
    pub plan_json: String,
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

/// Boot a session microVM from a built workload slot, under the plan `admit`
/// produces.
///
/// `admit` must admit: a callback that returns `None` is refused before the
/// backend is touched, because a VM these calls dispatch into is one whose
/// egress and secrets the host has to be able to enforce. That is also why
/// there is no snapshot-resume here — a restored VM skips the endpoint spawn
/// an admitted plan exists to drive.
///
/// `pair` is where the runtime overlay comes from when a local image checkout
/// is selected; a caller that offers none gets the cached or published
/// overlay.
///
/// # Errors
/// An unknown slot, an admission refusal, a missing runtime overlay, or a
/// backend that would not start.
pub fn boot_session_vm(
    boot: SessionBoot<'_>,
    admit: &SessionAdmit<'_>,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<SessionVm> {
    match boot_session_core(
        boot,
        |inputs| {
            admit(inputs)?
                .map(Box::new)
                .map(BootAdmission::Legacy)
                .context("refusing to boot an entrypoint VM without an admitted plan")
        },
        pair,
    )? {
        SessionBootResult::Legacy(vm) => Ok(vm),
        SessionBootResult::Owned(owner) => Err(anyhow::Error::new(
            owner.failure(anyhow::anyhow!("owning receiver required")),
        )),
    }
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
        SessionBootResult::Legacy(_) => anyhow::bail!("owned boot did not return native custody"),
    }
}

enum BootAdmission {
    Legacy(Box<SessionAuditSubstrate>),
    Owned(Box<super::admission::AdmittedEntrypoint>),
}

enum SessionBootResult {
    Legacy(SessionVm),
    Owned(OwnedClientBoot),
}

fn require_native_owner(backend: mvm_core::vm_backend::BackendKind, has_owner: bool) -> Result<()> {
    anyhow::ensure!(
        backend != mvm_core::vm_backend::BackendKind::Hvf || has_owner,
        "native session requires an owning host context; name-only return is unavailable before launch"
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
    if let Some(assets) = portable_boot_assets {
        anyhow::ensure!(
            bundle_archive.is_none(),
            "producer health cannot replace an installed bundle's boot closure"
        );
        assets.apply_for_health(&mut start_config)?;
    } else {
        attach_runtime_overlay_if_cached_version(&mut start_config, backend.name(), None, pair)?;
        attach_universal_initramfs_if_cached(&mut start_config, backend.name())?;
    }

    // Admission starts the plan and verb-grant validity windows. All boot
    // preparation therefore completes before this point, immediately before
    // the backend consumes the admitted start config.
    let admitted = admit(AdmitInputs {
        rootfs: std::path::Path::new(&rootfs),
        kernel: start_config
            .kernel_path
            .as_deref()
            .map(std::path::Path::new),
        vm_name: &vm_name,
        // An entrypoint VM binds no SDK host service.
        sdk_sidecar: None,
        // The function payload is admitted as the workload itself; there are
        // no standalone assets.
        assets: &[],
        volumes: &start_config.volumes,
        bundle_archive: bundle_archive.as_deref(),
        runtime_config: Some(&start_config),
    })?;
    let (mut substrate, context) = match admitted {
        BootAdmission::Legacy(substrate) => (*substrate, None),
        BootAdmission::Owned(admitted) => {
            let admitted = *admitted;
            (admitted.substrate, Some(admitted.context))
        }
    };
    require_native_owner(backend.kind(), context.is_some())?;
    let built_pack_check = substrate.built_pack_check.take();
    substrate.apply_to(&mut start_config);
    let _built_runtime = built_pack_check
        .map(|check| {
            if context.is_some() && backend.kind() == mvm_core::vm_backend::BackendKind::Hvf {
                check.freeze_native_boot(&mut start_config, backend.kind())
            } else {
                check.prepare(&mut start_config, backend.kind())
            }
        })
        .transpose()?
        .flatten();
    if let Some(runtime) = &_built_runtime {
        runtime.verify_config(&start_config)?;
    }
    if mvm_runtime::catalog::descriptor(backend.kind()).is_workload {
        mvm_hostd::plan_admission::stash_plan_for_bridge(&start_config)
            .context("persisting admitted session plan before backend start")?;
    }
    if let Some(assets) = portable_boot_assets {
        assets.verify_health_config(&start_config)?;
    }

    tracing::info!(vm = %vm_name, slot, "booting session VM");
    if let Some(admission) = context {
        let mut owner = crate::boot::start_prepared_owned(ClientBootResources {
            backend,
            config: start_config,
            admission,
            _volumes: None,
            built_runtime: _built_runtime,
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
    let vm_id = backend
        .start(&start_config)
        .with_context(|| format!("starting session microVM '{vm_name}'"))?;
    // The budget gate this boot admitted under counts only what is recorded:
    // a session boot that skipped the charge would be invisible to every
    // later admission the way a CLI boot on the old tail was. Fatal, not
    // logged — a VM running without its charge recorded is the undercount
    // the budget exists to prevent, so the boot stops rather than stay up
    // uncounted. Session plans declare no resource grants, so the charge is
    // the configured memory and no CPU millicores.
    let charge = mvm_hostd::admission_budget::charge_for(
        u64::from(memory_mib),
        &mvm_contract::grants::Grants::default(),
    );
    if let Err(err) = mvm_hostd::admission_budget::record_charge(&vm_name, charge) {
        if let Err(stop_err) = backend.stop(&vm_id) {
            tracing::warn!(
                error = %stop_err,
                "stopping a session VM whose admitted charge could not be recorded;                  it may still be running",
            );
        }
        return Err(err).context("recording the session boot's admitted charge");
    }
    Ok(SessionBootResult::Legacy(SessionVm { vm_name }))
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
    fn legacy_hvf_refuses_before_launch_but_owned_hvf_passes_gate() {
        use mvm_core::vm_backend::BackendKind;
        let launched = std::cell::Cell::new(false);
        let result = require_native_owner(BackendKind::Hvf, false).map(|()| launched.set(true));
        assert!(result.is_err());
        assert!(!launched.get());
        require_native_owner(BackendKind::Hvf, true).unwrap();
    }

    #[test]
    fn child_free_failure_audits_once_and_keeps_original_error_through_retry() {
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
    fn applying_admission_preserves_durability_and_materialized_images() {
        for outcome in [Ok(()), Err(anyhow::anyhow!("audit sync refused"))] {
            let should_succeed = outcome.is_ok();
            let mut substrate = SessionAuditSubstrate {
                tenant_id: "tenant".into(),
                plan_json: "signed-plan".into(),
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
        let admit = |_: AdmitInputs<'_>| -> Result<Option<SessionAuditSubstrate>> {
            panic!("admission must not run for a slot that does not exist")
        };
        let slot = "0".repeat(64);
        let error = boot_session_vm(
            SessionBoot::builder(&slot, SessionVmName::Prefixed("t")).build(),
            &admit,
            None,
        )
        .expect_err("an unknown slot has nothing to boot");
        assert!(
            format!("{error:#}").contains("Loading template"),
            "{error:#}"
        );
    }
}
