//! The admission entry points: verify a plan, apply the host's gates, spend its
//! nonce and hand back an [`AdmittedPlan`].

use super::assurance_runtime::AssuranceRuntimeBinding;
use super::extension_packs::{validate_extension_bindings, verify_extension_packs};
use super::grant_validation::{admit_grants, enforce_mailbox_retention};
use super::host_gates::admit_host_interface;
use super::registry_pack::verify_registry_pack_assets;
use super::{
    AdmittedExtension, AdmittedPlan, Clock, ExtensionAdmissionContext, InMemoryNonceLedger,
    RunPosture,
};
use super::{bundle_environment, canonical_kernel, composition};
use crate::audit::host_keypair::host_signer_id;
use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_contract::grants::ceiling::GrantCeiling;
use mvm_core::plan::bundle::{BundleResolver, TrustStore};
use mvm_core::plan::{
    ExecutionPlan, PlanValidityError, SignedExecutionPlan, SynthesisInput,
    check_embedded_image_set_for_backend, check_window, sign_plan, synthesize_plan, verify_plan,
    verify_plan_bundle, verify_plan_id,
};

/// The external plan signers this host trusts, from operator config.
///
/// Read from config rather than taken as a parameter for the same reason as
/// the grant ceiling: admission's trust root must not be widen-able by the
/// caller asking for admission. A malformed pin fails the whole read, so the
/// set in force is exactly the set the operator wrote.
fn host_trusted_plan_signers() -> Result<Vec<(String, VerifyingKey)>> {
    mvm_core::user_config::load(None).trusted_plan_signer_keys()
}

/// The bound this host puts on what any workload may be granted.
///
/// Read from the operator's config, never from the plan under admission. The
/// two have different trust roots: whoever authors a plan also authors its
/// grants, so a ceiling the plan could carry would be a bound the bounded party
/// writes. There is no parameter for it here for the same reason — a caller
/// cannot hand admission a wider ceiling than the host configured.
fn host_grant_ceiling() -> GrantCeiling {
    mvm_core::user_config::load(None).grant_ceiling()
}

/// Optional bundle-admission context for plans pinned to a
/// `.mvmpkg`. Carries the resolver (where to find the archive
/// bytes by sha256) and the trust store (which publisher pubkeys
/// to accept). `admit_for_run` ignores it when the plan has no
/// pin; rejects when the plan has a pin but the context is
/// `None` (operator misconfiguration); runs full re-verify when
/// both are present.
pub struct BundleAdmissionContext<'a> {
    pub resolver: &'a dyn BundleResolver,
    pub trust: &'a dyn TrustStore,
    /// Required when the bundle embeds an image set. This is the backend that
    /// is actually about to boot, not a manifest label.
    pub image: Option<BundleImageAdmissionContext<'a>>,
}

#[derive(Clone, Copy)]
pub struct BundleImageAdmissionContext<'a> {
    pub arch: mvm_core::arch::GuestArch,
    pub backend: &'a mvm_core::image_set::BackendImageSupport,
    pub host_protocols: &'a mvm_core::image_set::HostProtocolSupport,
}

/// Run the full admission pipeline for one boot.
///
/// On success, the caller proceeds to `backend.start()` knowing the
/// plan was signed under the host signer, verified with the host's
/// own public key, satisfies its own validity window, hasn't been
/// admitted before (replay protection), and — when the plan pins a
/// `.mvmpkg` bundle — the on-disk archive matches the pin
/// byte-for-byte and verifies under the trust store.
///
/// On failure, the user gets a clear error per failure class:
///   - `tenant must not be empty` / `vm_name must not be empty` —
///     synthesis-time guard
///   - `host signer at {path} has mode {found}; expected 0600` —
///     keystore guard
///   - `plan validity window violated: {detail}` — G4 window check
///   - `plan replay detected for signer {id}; nonce {hex}` — G4 nonce
///   - `bundle re-verify failed: {detail}` — pinned bundle missing,
///     unknown publisher, tampered, or sha256/sig/key_id mismatch
///   - `grant exceeds this host's ceiling: {detail}` — the request asked
///     for more than the host's configured bound in some dimension
///   - `refusing an unenforceable grant: {detail}` — the posture is
///     [`Variant::Prod`] and the backend this run boots on has no mechanism
///     behind a declared grant. The same input under [`Variant::Dev`] warns and
///     proceeds
///   - `plan declares runtime profile {a} but this run boots on {b}` — the
///     plan and the resolved backend disagree about what is about to run
///
/// `posture` is what the plan cannot be trusted to say: whether this is a
/// sealed production launch or a developer's boot, and which backend will
/// actually boot it. See [`RunPosture`].
#[tracing::instrument(skip_all)]
/// Admission decision over an already-synthesized plan.
///
/// This is the inner admission routine that [`admit_for_run`] uses after
/// synthesizing a plan. Keeping it separate lets callers emit a structured
/// refusal audit entry when admission fails, binding the refusal to the
/// plan that was refused.
///
/// `extension_ctx` carries the trust and revocation state a plan with
/// extension bindings is re-verified under: every digest-pinned pack is
/// checked again before signing. `None` refuses any plan that binds an
/// extension.
pub fn admit_plan_for_run(
    plan: &ExecutionPlan,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
    host_signer_keys_dir: Option<&std::path::Path>,
    bundle_ctx: Option<&BundleAdmissionContext<'_>>,
    extension_ctx: Option<&ExtensionAdmissionContext<'_>>,
    posture: RunPosture,
) -> Result<AdmittedPlan> {
    let _activation_barrier =
        mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()?;
    let host_permit = reserve_plan_budget(plan)?;
    admit_plan_for_run_with_host_permit(HostPermitAdmission {
        plan,
        clock,
        ledger,
        host_signer_keys_dir,
        bundle_ctx,
        extension_ctx,
        posture,
        host_permit,
    })
}

/// Admission inputs carrying a host hold acquired before actor plan derivation.
pub struct HostPermitAdmission<'a> {
    pub plan: &'a ExecutionPlan,
    pub clock: &'a dyn Clock,
    pub ledger: &'a InMemoryNonceLedger,
    pub host_signer_keys_dir: Option<&'a std::path::Path>,
    pub bundle_ctx: Option<&'a BundleAdmissionContext<'a>>,
    pub extension_ctx: Option<&'a ExtensionAdmissionContext<'a>>,
    pub posture: RunPosture<'a>,
    pub host_permit: crate::admission_budget::HostBudgetPermit,
}

/// Admit using the existing host hold, never reserving the same launch twice.
pub fn admit_plan_for_run_with_host_permit(
    params: HostPermitAdmission<'_>,
) -> Result<AdmittedPlan> {
    let HostPermitAdmission {
        plan,
        clock,
        ledger,
        host_signer_keys_dir,
        bundle_ctx,
        extension_ctx,
        posture,
        host_permit,
    } = params;
    host_permit.verify_plan_resources(plan)?;
    posture.verify_launch_runtime(plan)?;
    let assurance_runtime = posture.assurance_runtime(plan)?;
    validate_extension_bindings(plan)?;
    let extensions = verify_extension_packs(plan, extension_ctx)?;
    verify_registry_pack_assets(plan)?;
    super::verify_project_generation(plan, posture)?;
    // Grants are checked in the pre-keystore window, and for the same
    // reason as synthesis: a plan we would refuse must never leave here with a
    // signature on it. A signed refused plan is indistinguishable from a
    // signed admitted one to anything downstream that only checks the
    // signature.
    admit_grants(plan, &host_grant_ceiling(), posture)?;
    enforce_mailbox_retention(
        plan.mailbox.as_ref(),
        mvm_core::user_config::load(None).max_mailbox_retention_ms,
    )?;

    // The ceiling above bounds this one workload; the budget bounds the sum of
    // every live one. Both sit in the pre-keystore window for the same reason,
    // and both read host config rather than the plan. The total is measured
    // over live machines only — counting records instead would turn a single
    // crashed VM into a permanent refusal of every later boot.
    admit_host_interface(plan)?;

    // Load or generate the host signer. load_or_init refuses
    // loose perms; that error propagates verbatim.
    let signer = match host_signer_keys_dir {
        Some(dir) => crate::audit::host_keypair::load_or_init_at(dir)?,
        None => crate::audit::host_keypair::load_or_init()?,
    };
    let signer_id = host_signer_id();

    // Sign + verify roundtrip. Verifying our own signature catches
    // wire-format bugs that would otherwise surface at a real
    // verifier (mvmd's supervisor, an upstream consumer's mvm).
    let signed = sign_plan(plan, &signer.signing, &signer_id);
    let trusted: [(&str, &VerifyingKey); 1] = [(&signer_id, &signer.verifying)];
    let verified = verify_plan(&signed, &trusted).context("verifying just-signed plan")?;

    finish_admission(VerifiedAdmission {
        host_permit,
        verified,
        signed,
        signer_id,
        extensions,
        assurance_runtime,
        posture,
        clock,
        ledger,
        host_signer_keys_dir,
        bundle_ctx,
    })
}

/// Admit an externally-signed plan — one signed by a fleet issuer the
/// operator pinned in `trusted_plan_signers`, not by this host's own key.
///
/// The order differs from the self-signed path in exactly the way the trust
/// boundary dictates: the envelope is verified against the pinned signer set
/// *first*, because every byte of it is attacker-controlled until then, and
/// only afterwards do the host's own policy gates (extension bindings, grant
/// ceiling, host budget) read the plan. From [`verify_plan_id`] onward both
/// paths run the same checks through [`finish_admission`] — the host remains
/// the final authority over what it boots, whoever signed the plan.
///
/// The trusted set comes from operator config and nowhere else, so a caller
/// cannot hand admission a wider trust than the host configured. An empty set
/// is the fail-closed default: every externally-signed plan is refused.
///
/// A refusal never emits an audit entry: the plan body is the only anchor a
/// refusal entry could bind to, and until the signature verifies the body is
/// an attacker's claim, not a fact to record.
#[tracing::instrument(skip_all)]
pub fn admit_signed_plan_for_run(
    signed: &SignedExecutionPlan,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
    bundle_ctx: Option<&BundleAdmissionContext<'_>>,
    posture: RunPosture,
) -> Result<AdmittedPlan> {
    let trusted = host_trusted_plan_signers()?;
    if trusted.is_empty() {
        anyhow::bail!(
            "refusing the externally-signed plan: this host pins no trusted plan signers; \
             set `trusted_plan_signers` in the host config.toml to admit fleet-signed plans"
        );
    }
    let trusted_refs: Vec<(&str, &VerifyingKey)> =
        trusted.iter().map(|(id, key)| (id.as_str(), key)).collect();
    let verified =
        verify_plan(signed, &trusted_refs).context("verifying externally-signed plan")?;
    let signer_id = signed.0.signer_id.clone();

    posture.verify_launch_runtime(&verified)?;
    let assurance_runtime = posture.assurance_runtime(&verified)?;
    validate_extension_bindings(&verified)?;
    // No extension verification context on this path: a plan that binds
    // optional extensions is refused rather than admitted unchecked.
    let extensions = verify_extension_packs(&verified, None)?;
    verify_registry_pack_assets(&verified)?;
    admit_grants(&verified, &host_grant_ceiling(), posture)?;
    enforce_mailbox_retention(
        verified.mailbox.as_ref(),
        mvm_core::user_config::load(None).max_mailbox_retention_ms,
    )?;
    let host_permit = reserve_plan_budget(&verified)?;
    admit_host_interface(&verified)?;

    finish_admission(VerifiedAdmission {
        host_permit,
        verified,
        // The caller lends the envelope; the admitted plan owns a copy so
        // downstream consumers can re-verify without trusting this process.
        signed: signed.clone(),
        signer_id,
        extensions,
        assurance_runtime,
        posture,
        clock,
        ledger,
        host_signer_keys_dir: None,
        bundle_ctx,
    })
}

/// Everything the shared post-verification tail of admission needs.
///
/// A params struct rather than seven positional arguments: `verified`,
/// `signed`, and `signer_id` travel together from whichever path verified
/// them, and a positional call could transpose them with nothing to catch it.
struct VerifiedAdmission<'a> {
    host_permit: crate::admission_budget::HostBudgetPermit,
    /// The plan body, already signature-verified against the trust root of
    /// the path that produced it (the host signer, or the operator's pinned
    /// external signer set).
    verified: ExecutionPlan,
    /// The envelope `verified` was decoded from, carried verbatim onto the
    /// launch config for consumers that re-verify.
    signed: SignedExecutionPlan,
    /// The signer the envelope verified under — the audit chain records it.
    signer_id: String,
    /// Re-verified extension artifacts, empty when the plan binds none.
    extensions: Vec<AdmittedExtension>,
    assurance_runtime: Option<AssuranceRuntimeBinding>,
    posture: RunPosture<'a>,
    clock: &'a dyn Clock,
    ledger: &'a InMemoryNonceLedger,
    /// Where the host signer lives, for the topology check's refusal entry;
    /// `None` for the default keys directory.
    host_signer_keys_dir: Option<&'a std::path::Path>,
    bundle_ctx: Option<&'a BundleAdmissionContext<'a>>,
}

/// The checks every admitted plan passes after its signature has verified,
/// shared by the host-signed and externally-signed paths: content-address,
/// ingress shape, validity window, replay protection, bundle re-verify.
///
/// The replay insert is deliberately last but one: every check that can
/// refuse runs before the nonce is spent, so a refused plan can be corrected
/// and resubmitted, while an admitted one cannot be replayed.
fn finish_admission(parts: VerifiedAdmission<'_>) -> Result<AdmittedPlan> {
    let _activation_barrier =
        mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()?;
    let VerifiedAdmission {
        host_permit,
        verified,
        signed,
        signer_id,
        extensions,
        assurance_runtime,
        clock,
        ledger,
        host_signer_keys_dir,
        bundle_ctx,
        posture,
    } = parts;
    let backend = posture.backend;

    // The plan_id is the content-address of the plan body — recompute it and
    // refuse a plan whose stored id doesn't match, so a run is only ever
    // admitted under an id that genuinely addresses its content.
    verify_plan_id(&verified).context("plan_id content-address check")?;
    super::verify_project_generation(&verified, posture)?;

    verified
        .validate_ingress()
        .context("validating signed ingress mappings")?;

    // Validity window — refuses plans whose now() is outside
    // [valid_from, valid_until). For freshly-synthesized plans this
    // can only fire if the host's clock changed during signing or if
    // someone overrode the validity window in synthesis defaults; for an
    // externally-signed plan it is the host's own check that the window the
    // fleet issuer chose still holds here.
    let now = clock.now();
    check_window(&verified, now).map_err(|e| match e {
        PlanValidityError::NotYetValid { .. } | PlanValidityError::Expired { .. } => {
            anyhow::anyhow!("plan validity window violated: {e}")
        }
        other => anyhow::anyhow!("plan validity error: {other}"),
    })?;

    // The topology check needs an authenticated body and a live window, and
    // must refuse before the nonce below is spent.
    let unit = super::topology_binding::admit_topology_binding(&verified, host_signer_keys_dir)?;
    let allowed_cpus = super::placement::admitted_cpus(
        &mvm_core::config::mvm_home_strict()?,
        unit.as_ref(),
        backend,
        host_signer_keys_dir,
    )
    .context("placing the launch on host cores")?;

    // Bundle re-verify at admit time. Only fires
    // when the plan pinned a bundle; missing context with a pinned
    // plan is operator misconfiguration (the driver wasn't wired
    // with a resolver/trust store), so we refuse rather than skip
    // silently.
    let canonical_kernel = canonical_kernel::AdmittedKernel::capture(posture, &verified)?;
    if let Some(pin) = verified.bundle.as_ref() {
        let ctx = bundle_ctx.ok_or_else(|| {
            anyhow::anyhow!(
                "plan pins bundle {bundle} but no BundleAdmissionContext was provided — refuse",
                bundle = pin.bundle_sha256
            )
        })?;
        let verified_bundle = if let Some(config) = posture.runtime_config {
            if let Some(owner) = &config.canonical_kernel {
                mvm_core::plan::bundle::verify_canonical_plan_bundle(
                    pin,
                    ctx.resolver,
                    ctx.trust,
                    owner,
                    config,
                    posture
                        .backend
                        .context("canonical kernel admission requires actual backend")?,
                    &mvm_build::stage0_kernel::current_image_set_protocol_support(),
                )
            } else {
                verify_plan_bundle(pin, ctx.resolver, ctx.trust)
            }
        } else {
            verify_plan_bundle(pin, ctx.resolver, ctx.trust)
        }
        .with_context(|| format!("bundle re-verify for pin {}", pin.bundle_sha256))?;
        bundle_environment::verify_environment(&verified, &verified_bundle.manifest, posture)?;
        composition::verify(&verified, &verified_bundle)?;
        if !verified_bundle.embedded_image_sets.is_empty() {
            let image = ctx.image.ok_or_else(|| {
                anyhow::anyhow!(
                    "plan pins bundle {} with an embedded image set but admission has no selected backend image contract — refuse",
                    pin.bundle_sha256
                )
            })?;
            for embedded in &verified_bundle.embedded_image_sets {
                check_embedded_image_set_for_backend(
                    embedded,
                    image.arch,
                    image.backend,
                    image.host_protocols,
                )
                .with_context(|| {
                    format!(
                        "selected backend refuses embedded image set in bundle {}",
                        pin.bundle_sha256
                    )
                })?;
            }
        }
        // The signature-verified manifest is the only trustworthy statement of
        // the bundle's architecture — the boot-time resolver reads an unsigned
        // registry copy. Refuse here so a foreign-arch pin never reaches a
        // backend, where it surfaces as an unrelated-looking boot failure.
        mvm_core::arch::GuestArch::require_host(&verified_bundle.manifest.arch).map_err(|e| {
            anyhow::anyhow!(
                "plan pins bundle {bundle} which {e} — refuse",
                bundle = pin.bundle_sha256
            )
        })?;
    }

    // Spend the nonce only after every fallible descriptor and bundle check.
    // Refusal must not consume an externally signed plan's replay allowance.
    host_permit.bind_plan(&verified)?;
    ledger.spend(&signer_id, &verified, now)?;

    Ok(AdmittedPlan {
        host_budget: std::sync::Arc::new(host_permit),
        plan_id: verified.plan_id.clone(),
        variant: posture.variant(),
        signer_id,
        plan: verified,
        signed,
        extensions,
        assurance_runtime,
        canonical_kernel,
        backend,
        allowed_cpus,
        dispatched: false,
    })
}

fn reserve_plan_budget(plan: &ExecutionPlan) -> Result<crate::admission_budget::HostBudgetPermit> {
    let charge = crate::admission_budget::charge_for(
        plan.resources.mem_mib,
        plan.grants.as_ref().unwrap_or(&Default::default()),
    );
    crate::admission_budget::HostBudgetPermit::reserve_ordinary(&plan.workload.0, charge)
}

/// Synthesize a plan and admit it for execution.
///
/// This is the high-level admission entry point. It first synthesizes the
/// plan, then delegates to [`admit_plan_for_run`]. Callers that need to emit
/// a structured refusal audit entry should synthesize first and call
/// [`admit_plan_for_run`] directly.
#[tracing::instrument(skip_all)]
pub fn admit_for_run(
    input: &SynthesisInput<'_>,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
    host_signer_keys_dir: Option<&std::path::Path>,
    bundle_ctx: Option<&BundleAdmissionContext<'_>>,
    posture: RunPosture,
) -> Result<AdmittedPlan> {
    // Build the unsigned plan first. Synthesis failures are caught
    // before we touch the keystore — keeps "signed bad plan" from
    // being an outcome.
    let mut plan = synthesize_plan(input).context("synthesizing plan")?;
    if let Some(identity) = posture.release_identity()? {
        plan.runtime_identity = Some(identity);
    }
    admit_plan_for_run(
        &plan,
        clock,
        ledger,
        host_signer_keys_dir,
        bundle_ctx,
        None,
        posture,
    )
}
