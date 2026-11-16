//! Launch-time admission gates and the inputs of the one-call admitted boot:
//! the pinned-kernel check, the SDK sidecar checks, and `AdmitAndStartParams`.

use super::{BundleAdmissionContext, Clock, ExtensionAdmissionContext, InMemoryNonceLedger};
use anyhow::{Context, Result};
use mvm_build::guest_libc::GuestLibc;
use mvm_contract::builder::BuilderError;
use mvm_core::plan::{ExecutionPlan, SynthesisInput, Variant};
use mvm_core::policy::PolicyBundle;
use mvm_core::vm_backend::VmStartConfig;

/// Refuse a boot whose kernel is not the one the plan pinned.
///
/// The image digest says what the workload *is*; it says nothing about what
/// confines it. The same signed image on a kernel built for a different job has
/// a different security posture — a kernel with `CONFIG_USER_NS` enabled lets
/// the guest become uid 0 in a user namespace, which the workload kernel is
/// built to prevent. Before the kernel was pinned, that substitution was
/// invisible: identical plan, identical image digest, and confinement decided
/// by whichever kernel the host happened to have cached.
///
/// Fail-closed in both directions. A plan that pins a kernel and a launch
/// config that supplies none is a refusal, not a pass — otherwise dropping the
/// kernel path would be a way to skip the check.
/// Takes the kernel path rather than the whole [`VmStartConfig`] so the two
/// admission seams can share one gate. `mvmctl` synthesizes and admits its plan
/// without ever building a `VmStartConfig`, so a config-shaped signature meant
/// the CLI — the seam that ships — could not call this at all.
pub fn enforce_admitted_environment(
    kernel_path: Option<&std::path::Path>,
    plan: &ExecutionPlan,
) -> Result<()> {
    let Some(environment) = plan.environment.as_ref() else {
        // No environment pinned. Plans predating the field, and backends that
        // boot their own bundled kernel, land here.
        return Ok(());
    };
    let Some(kernel_path) = kernel_path else {
        anyhow::bail!(
            "plan pins kernel {} but the launch config supplies no kernel path",
            environment.kernel_sha256
        );
    };
    let actual =
        mvm_core::crypto::image_verify::sha256_file_cached(kernel_path).with_context(|| {
            format!(
                "hashing kernel at {} for admitted-environment check",
                kernel_path.display()
            )
        })?;
    if actual != environment.kernel_sha256 {
        anyhow::bail!(
            "admitted-environment mismatch: plan pins kernel {} but {} hashes to {actual}",
            environment.kernel_sha256,
            kernel_path.display()
        );
    }
    Ok(())
}

/// Typed reasons the selected backend cannot carry the native SDK sidecar.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SdkSidecarBackendCompatibilityError {
    #[error(
        "refusing to launch SDK host service(s) [{services}] on the wasm backend: the SDK \
         host-services library is delivered as a native shared object on a read-only disk, but \
         wasm has neither block devices nor a native dynamic loader. Remove these bindings or \
         use a microVM backend; WASI host-service imports are not implemented"
    )]
    WasmHostServicesUnsupported { services: String },
}

/// Refuse a host-service delivery mechanism the selected backend cannot carry.
///
/// This gate runs before attachment-shape validation and backend start so an
/// SDK host-service request cannot leak as an error about the synthetic disk
/// volume used to carry its native library.
pub fn enforce_sdk_sidecar_backend_compatibility(
    backend: mvm_core::vm_backend::BackendKind,
    plan: &ExecutionPlan,
) -> std::result::Result<(), SdkSidecarBackendCompatibilityError> {
    use mvm_core::plan::{sdk_host_services_in, sdk_sidecar_required};

    // When sdk_uses_sidecar is false, the workload speaks the broker protocol
    // directly and doesn't need the SDK sidecar regardless of backend.
    if !plan.sdk_uses_sidecar || backend != mvm_core::vm_backend::BackendKind::Wasm {
        return Ok(());
    }

    // Only wasm backends need the SDK sidecar for host services.
    if !sdk_sidecar_required(plan) {
        return Ok(());
    }

    let services = sdk_host_services_in(&plan.services)
        .iter()
        .map(|service| service.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Err(SdkSidecarBackendCompatibilityError::WasmHostServicesUnsupported { services })
}

/// Admission enforcement for the optional SDK sidecar attachment.
///
/// The sidecar carries the host-services cdylib the language SDKs `dlopen`. Its
/// attachment is authorized by the plan's host-service bindings, never by an
/// environment variable or a guess about application content. Both directions
/// fail closed: a bound SDK service requires exactly one read-only disk at the
/// SDK mount point, and a plan with no SDK binding may not carry one.
pub fn enforce_sdk_sidecar_attachment(
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan: &ExecutionPlan,
    image_libc: GuestLibc,
) -> Result<()> {
    use mvm_core::plan::{SDK_SIDECAR_GUEST_PATH, sdk_host_services_in, sdk_sidecar_required};

    // When sdk_uses_sidecar is false, the workload speaks the broker protocol
    // directly and may not carry the SDK sidecar.
    if !plan.sdk_uses_sidecar {
        let attached: Vec<_> = volumes
            .iter()
            .filter(|v| v.guest == SDK_SIDECAR_GUEST_PATH)
            .collect();
        if let Some(stray) = attached.first() {
            anyhow::bail!(
                "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH}: the signed ExecutionPlan \
                 sets sdk_uses_sidecar=false, so this workload must not carry the SDK sidecar",
                stray.host,
            );
        }
        return Ok(());
    }

    let attached: Vec<_> = volumes
        .iter()
        .filter(|v| v.guest == SDK_SIDECAR_GUEST_PATH)
        .collect();
    let required = sdk_sidecar_required(plan);

    if !required {
        if let Some(stray) = attached.first() {
            anyhow::bail!(
                "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH}: the signed ExecutionPlan \
                 binds no SDK host service, so this workload must not carry the SDK sidecar",
                stray.host,
            );
        }
        return Ok(());
    }

    let bound: Vec<&str> = sdk_host_services_in(&plan.services)
        .iter()
        .map(|s| s.as_str())
        .collect();

    let Some(sidecar) = attached.first() else {
        anyhow::bail!(
            "refusing to launch: the signed ExecutionPlan binds SDK host service(s) [{}], which \
             need the SDK sidecar mounted read-only at {SDK_SIDECAR_GUEST_PATH}, and no such \
             attachment is present. The launch path resolves the sidecar from the version-keyed \
             cache under the mvm cache dir; prepare it with \
             `mvmctl bootstrap` and retry.",
            bound.join(", "),
        );
    };
    if attached.len() > 1 {
        anyhow::bail!(
            "refusing to launch: {} attachments target {SDK_SIDECAR_GUEST_PATH}; exactly one \
             read-only SDK sidecar is admissible",
            attached.len(),
        );
    }
    if !sidecar.read_only {
        anyhow::bail!(
            "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH} read-write: the SDK sidecar is \
             read-only by contract",
            sidecar.host,
        );
    }
    if sidecar.materialized_image.is_some() {
        anyhow::bail!(
            "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH}: the SDK sidecar is a read-only \
             disk image, not a host-directory share",
            sidecar.host,
        );
    }
    // The sidecar's own libc comes from the path it was filed under, so both
    // sides of the comparison are observed rather than assumed. Reading it here
    // rather than threading it in keeps this a check on the launch config as
    // presented — the thing admission is actually authorizing.
    let sidecar_libc =
        mvm_build::guest_libc::sidecar_libc_of_image_path(std::path::Path::new(&sidecar.host));
    enforce_sidecar_libc(image_libc, sidecar_libc, &bound)?;
    Ok(())
}

/// Refuse a launch whose SDK sidecar the guest could not load.
///
/// The launch-shaped entry point onto [`enforce_sdk_sidecar_attachment`], for
/// callers that hold a rootfs path and a launch config rather than an
/// `AdmittedPlan`. `mvmctl run` is one: it admits through `admit_for_run`, which
/// does not run the post-admission gates, so without this the only thing
/// standing between a libc mismatch and the guest is nothing at all — the boot
/// succeeds and the workload dies on `dlopen` resolving `_dl_find_object`.
///
/// Takes the rootfs path rather than the libc so the caller cannot supply a
/// libc that disagrees with the image it is about to boot.
pub fn enforce_sdk_sidecar_for_launch(
    rootfs_path: &str,
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan: &ExecutionPlan,
) -> Result<()> {
    enforce_sdk_sidecar_attachment(
        volumes,
        plan,
        mvm_build::guest_libc::recorded_image_libc(std::path::Path::new(rootfs_path)),
    )
}

/// Refuse a sidecar the guest could not load.
///
/// The cdylib inside it is built for one libc, and a process under the other
/// cannot `dlopen` it at all. Left unchecked, the boot succeeds and the failure
/// lands inside the guest as a relocation error naming `_dl_find_object` — a
/// symbol the operator never heard of, from a library they did not ask for.
/// Refusing here is the same outcome, said where it can name the cause.
///
/// [`GuestLibc::Unknown`] refuses too. It covers an image whose loader was
/// unrecognisable and a sidecar written before the field existed, and neither
/// is evidence that loading would work.
fn enforce_sidecar_libc(
    image_libc: GuestLibc,
    sidecar_libc: GuestLibc,
    bound: &[&str],
) -> Result<()> {
    if mvm_build::guest_libc::sidecar_loads_in(image_libc, sidecar_libc) {
        return Ok(());
    }
    let detail = match (image_libc, sidecar_libc) {
        (GuestLibc::Unknown, _) => {
            "the image records no libc this host recognises. An image materialized before mvm \
             began recording it reads this way — re-pull or rebuild it and the sidecar is \
             rewritten with the libc"
        }
        (_, GuestLibc::Unknown) => {
            "the attached sidecar is not filed under a libc this host recognises, so which \
             variant it holds cannot be established. Prepare the cache with \
             `mvmctl bootstrap`, which files each variant under its own libc"
        }
        _ => {
            "a process under one libc cannot dlopen an object built for the other — the guest \
             would fail resolving symbols such as `_dl_find_object`"
        }
    };
    anyhow::bail!(
        "refusing to launch: the signed ExecutionPlan binds SDK host service(s) [{}], which are \
         delivered by a shared object built for {}, but this image is {}. {detail}. Use an image \
         whose libc matches, or drop the host-service binding.",
        bound.join(", "),
        sidecar_libc.as_str(),
        image_libc.as_str(),
    )
}

/// Inputs for [`admit_and_start`]. The `synthesis` describes the plan to admit
/// (the signed authority) and `config` is the launch shape to boot; they come
/// from one source in a well-formed caller, and [`enforce_admitted_shares`]
/// fails closed if they ever disagree on volumes.
pub struct AdmitAndStartParams<'a> {
    pub synthesis: &'a SynthesisInput<'a>,
    pub config: VmStartConfig,
    pub clock: &'a dyn Clock,
    pub ledger: &'a InMemoryNonceLedger,
    pub host_signer_keys_dir: Option<&'a std::path::Path>,
    pub bundle_ctx: Option<&'a BundleAdmissionContext<'a>>,
    pub extension_ctx: Option<&'a ExtensionAdmissionContext<'a>>,
    /// This run's posture. Decides whether a grant the resolved backend has no
    /// mechanism for refuses the boot ([`Variant::Prod`]) or warns and proceeds
    /// ([`Variant::Dev`]).
    pub variant: Variant,
    pub policy_bundle: Option<&'a PolicyBundle>,
    /// Optional chain-signed emitter: `plan.admitted` fires after admission
    /// succeeds, then `plan.launched` on a successful backend start or
    /// `plan.failed` on a start failure — the same event ordering the CLI's
    /// up path wires by hand.
    pub emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
    /// Whether a failure to record `plan.admitted` refuses the boot.
    ///
    /// Only the admission is gated. `plan.launched` and `plan.failed` describe
    /// something that has already happened — refusing after the fact prevents
    /// nothing, and tearing down a running workload because a log write failed
    /// trades a missing record for a killed job. The admission is different:
    /// it is the record that the run was allowed, and it is written before the
    /// backend starts, so refusing on it actually stops the unaudited run.
    pub audit_durability: crate::audit::durability::AuditDurability,
    /// An assurance campaign to open against this boot, when the operator
    /// declared one. `None` — the default — is every ordinary run: extension
    /// discovery must not sit on the launch critical path, so a run that
    /// declares no campaign does no assurance work at all.
    pub assurance: Option<&'a crate::assurance_session::CampaignRequest>,
}

impl<'a> AdmitAndStartParams<'a> {
    /// Start building a [`AdmitAndStartParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> AdmitAndStartParamsBuilder<'a> {
        AdmitAndStartParamsBuilder::new()
    }
}

/// Builder for [`AdmitAndStartParams`]. Required fields are checked by
/// [`AdmitAndStartParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct AdmitAndStartParamsBuilder<'a> {
    synthesis: Option<&'a SynthesisInput<'a>>,
    config: Option<VmStartConfig>,
    clock: Option<&'a dyn Clock>,
    ledger: Option<&'a InMemoryNonceLedger>,
    host_signer_keys_dir: Option<&'a std::path::Path>,
    bundle_ctx: Option<&'a BundleAdmissionContext<'a>>,
    extension_ctx: Option<&'a ExtensionAdmissionContext<'a>>,
    variant: Option<Variant>,
    policy_bundle: Option<&'a PolicyBundle>,
    emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
    audit_durability: Option<crate::audit::durability::AuditDurability>,
    assurance: Option<&'a crate::assurance_session::CampaignRequest>,
}

impl<'a> AdmitAndStartParamsBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            synthesis: None,
            config: None,
            clock: None,
            ledger: None,
            host_signer_keys_dir: None,
            bundle_ctx: None,
            extension_ctx: None,
            variant: None,
            policy_bundle: None,
            emitter: None,
            audit_durability: None,
            assurance: None,
        }
    }

    /// Set `synthesis`.
    #[must_use]
    pub fn synthesis(mut self, synthesis: &'a SynthesisInput<'a>) -> Self {
        self.synthesis = Some(synthesis);
        self
    }

    /// Set `config`.
    #[must_use]
    pub fn config(mut self, config: VmStartConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set `clock`.
    #[must_use]
    pub fn clock(mut self, clock: &'a dyn Clock) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Set `ledger`.
    #[must_use]
    pub fn ledger(mut self, ledger: &'a InMemoryNonceLedger) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Set `host_signer_keys_dir`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn host_signer_keys_dir(
        mut self,
        host_signer_keys_dir: impl Into<Option<&'a std::path::Path>>,
    ) -> Self {
        self.host_signer_keys_dir = host_signer_keys_dir.into();
        self
    }

    /// Set `bundle_ctx`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn bundle_ctx(
        mut self,
        bundle_ctx: impl Into<Option<&'a BundleAdmissionContext<'a>>>,
    ) -> Self {
        self.bundle_ctx = bundle_ctx.into();
        self
    }

    /// Supply current trust and revocation inputs for optional extensions.
    #[must_use]
    pub fn extension_ctx(
        mut self,
        extension_ctx: impl Into<Option<&'a ExtensionAdmissionContext<'a>>>,
    ) -> Self {
        self.extension_ctx = extension_ctx.into();
        self
    }

    /// Set `variant`.
    #[must_use]
    pub fn variant(mut self, variant: Variant) -> Self {
        self.variant = Some(variant);
        self
    }

    /// Set `policy_bundle`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn policy_bundle(mut self, policy_bundle: impl Into<Option<&'a PolicyBundle>>) -> Self {
        self.policy_bundle = policy_bundle.into();
        self
    }

    /// Set `emitter`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn emitter(
        mut self,
        emitter: impl Into<Option<&'a crate::audit::emitter::AuditEmitter>>,
    ) -> Self {
        self.emitter = emitter.into();
        self
    }

    /// Declare an assurance campaign for this boot.
    pub fn assurance(
        mut self,
        assurance: impl Into<Option<&'a crate::assurance_session::CampaignRequest>>,
    ) -> Self {
        self.assurance = assurance.into();
        self
    }

    /// Set `audit_durability`.
    #[must_use]
    pub fn audit_durability(
        mut self,
        audit_durability: crate::audit::durability::AuditDurability,
    ) -> Self {
        self.audit_durability = Some(audit_durability);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<AdmitAndStartParams<'a>, BuilderError> {
        Ok(AdmitAndStartParams {
            synthesis: self
                .synthesis
                .ok_or(BuilderError::missing("AdmitAndStartParams", "synthesis"))?,
            config: self
                .config
                .ok_or(BuilderError::missing("AdmitAndStartParams", "config"))?,
            clock: self
                .clock
                .ok_or(BuilderError::missing("AdmitAndStartParams", "clock"))?,
            ledger: self
                .ledger
                .ok_or(BuilderError::missing("AdmitAndStartParams", "ledger"))?,
            host_signer_keys_dir: self.host_signer_keys_dir,
            bundle_ctx: self.bundle_ctx,
            extension_ctx: self.extension_ctx,
            variant: self
                .variant
                .ok_or(BuilderError::missing("AdmitAndStartParams", "variant"))?,
            policy_bundle: self.policy_bundle,
            emitter: self.emitter,
            audit_durability: self.audit_durability.ok_or(BuilderError::missing(
                "AdmitAndStartParams",
                "audit_durability",
            ))?,
            assurance: self.assurance,
        })
    }
}

impl<'a> Default for AdmitAndStartParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}
