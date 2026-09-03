//! Host-side plan-admission pipeline (claim 8).
//!
//! Lives in `mvm-hostd` beside the host signing key it uses, so every driver
//! reaches one admission contract: `mvmctl up`/`run` today, and the
//! `mvm-client` local backend once the boot seam wires local `run`.
//!
//! Threads `synthesize_plan` + the host keypair into the
//! supervisor-equivalent admission flow:
//!
//! ```text
//! cmd_run(args)
//!   ↓ synthesize_plan(args)
//!   ↓ load_or_init_host_signer()
//!   ↓ sign_plan(plan, signer)
//!   ↓ verify_plan(signed, trusted) — catches signing-time bugs
//!   ↓ check_window(plan, now)      — G4 validity window
//!   ↓ nonce_store.check_and_insert  — G4 replay protection
//!   ↓ return AdmittedPlan { plan, plan_id, signer_id, signed }
//!   ↓ caller invokes backend.start() as before
//! ```
//!
//! What this module does NOT do (intentional scope reduction):
//!
//! - **Drive `Supervisor::launch`.** The supervisor's backend
//!   dispatch slot expects a `BackendLauncher` trait impl that
//!   wraps today's `AnyBackend::start()`; landing that wrapper
//!   means refactoring three call sites in 1084 lines of `up.rs`
//!   (the main path, the MVM_DIRECT_BOOT branch, and the `--watch`
//!   path). That refactor lands in a follow-up. **This module is
//!   the substrate that makes the eventual supervisor refactor a
//!   one-line change** — `admit_for_run` produces the
//!   `SignedExecutionPlan` the supervisor needs.
//!
//! - **Emit audit lines.** A later step wires `FileAuditSigner` onto
//!   the `AdmittedPlan`'s `plan_id`; this module is silent on audit.
//!
//! - **Resolve component slots.** A later step maps `PolicyRef →
//!   concrete SupervisorEgressProxy/ToolGate/...`. This module returns the
//!   plan with refs unresolved.
//!
//! ## Test seam
//!
//! `admit_for_run` takes a `Clock` and a `NonceLedger` so tests can
//! drive the validity window + replay protection deterministically.
//! Production callers use `SystemClock` + the host's nonce store.
//!
//! ## Externally-signed plans
//!
//! [`admit_signed_plan_for_run`] admits a plan signed by a fleet issuer the
//! operator pinned in the host config's `trusted_plan_signers`, verifying the
//! envelope against that set — never the host's own key — before any policy
//! gate reads the plan body. From the content-address check onward it runs
//! the same `finish_admission` tail as the self-signed path: the host's
//! ceiling, budget, validity window, and replay protection apply unchanged,
//! so the host stays the final authority over what it boots.

use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use mvm_build::guest_libc::GuestLibc;
use mvm_contract::grants::ceiling::GrantCeiling;
use mvm_contract::grants::{CpuGrant, Grants};
use mvm_contract::protocol::capability_negotiation::negotiate_grants;
use mvm_contract::protocol::resource_controls::{EnforcedGrants, ResourceControls};
use mvm_contract::provenance::{
    ActorRef, AttestationBinding, DecisionActorRole, DecisionCategory, DecisionOutcome,
    DecisionRecord, DecisionRecordBuilder,
};
use mvm_core::pack_cache::{PackVerifyCtx, resolve_pack_digest};
use mvm_core::packs::{PackKind, Sha256Hex};
use mvm_core::plan::bundle::{BundleResolver, TrustStore};
use mvm_core::plan::{
    ExecutionPlan, NonceStore, PlanId, PlanValidityError, SignedExecutionPlan, Variant,
    check_window, sign_plan, verify_plan, verify_plan_bundle, verify_plan_id,
};
use mvm_core::policy::PolicyBundle;
use mvm_core::vm_backend::BackendKind;
use mvm_vmm::quota::QuotaConfig;
use std::sync::Mutex;

use crate::audit::host_keypair::host_signer_id;
use mvm_contract::builder::BuilderError;
use mvm_core::plan::{SynthesisInput, synthesize_plan};
use mvm_core::vm_backend::{VmId, VmStartConfig};
use mvm_runtime::AnyBackend;
use sha2::{Digest, Sha256};

pub use mvm_core::time::{Clock, SystemClock};

/// Production nonce ledger. Holds a `NonceStore` behind a mutex so
/// it's `Send + Sync`. In v0 we instantiate one per `mvmctl up` —
/// later when the supervisor is in-process, the ledger spans every
/// up call for the lifetime of the supervisor.
pub struct InMemoryNonceLedger {
    inner: Mutex<NonceStore>,
}

impl InMemoryNonceLedger {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NonceStore::default()),
        }
    }
}

impl Default for InMemoryNonceLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a successful admission. Carries everything the caller
/// needs to hand to the backend (the plan + its id), to the audit
/// chain (the plan again, for `crate::supervisor::audit::for_plan`), and — for the
/// bridge audit substrate and any cross-process consumer — the canonical
/// `SignedExecutionPlan` envelope, which [`populate_audit_substrate`]
/// serializes verbatim onto `VmStartConfig.plan_json`.
///
/// **The fields are private, and that is the type's whole point.** Consumers
/// downstream of admission — the egress gate, the share enforcer, the workload
/// input gate — decide what a workload may do by reading this plan, so a value
/// of this type has to be a claim that the plan *was* signed, verified,
/// window-checked and replay-checked, not merely a struct shaped like one. Both
/// halves of that are enforced by privacy: `finish_admission` — the shared
/// tail of [`admit_for_run`] and [`admit_signed_plan_for_run`] — is the only
/// non-test code that can build one (a struct literal needs every field named,
/// and there is no `Default` to spread from), and no accessor hands out a `&mut`
/// or an owned field, so a caller that legitimately holds one cannot afterwards
/// push a grant into `plan.services` that admission never saw.
#[derive(Debug)]
pub struct AdmittedPlan {
    plan: ExecutionPlan,
    plan_id: PlanId,
    signer_id: String,
    signed: SignedExecutionPlan,
    extensions: Vec<AdmittedExtension>,
}

/// Re-verified host artifact behind one extension binding in the signed plan.
#[derive(Debug, Clone)]
pub struct AdmittedExtension {
    pub binding: mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
    pub root: std::path::PathBuf,
}

impl AdmittedPlan {
    /// The verified plan body — what every downstream authorization decision
    /// reads.
    #[must_use]
    pub fn plan(&self) -> &ExecutionPlan {
        &self.plan
    }

    /// The plan's content-address, re-derived and checked during admission.
    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    /// The signer whose key the plan verified under — this host's own signer
    /// for a synthesized run, or the pinned external signer for a
    /// fleet-issued one.
    #[must_use]
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// The canonical signed envelope, for a consumer that re-verifies rather
    /// than trusting this process.
    #[must_use]
    pub fn signed(&self) -> &SignedExecutionPlan {
        &self.signed
    }

    /// Exact re-verified extension artifacts available to this launch.
    #[must_use]
    pub fn extensions(&self) -> &[AdmittedExtension] {
        &self.extensions
    }

    /// Mint one without admitting it — **tests only**, and unreachable from a
    /// production build because the whole `impl` is `#[cfg(test)]`.
    ///
    /// A test that exercises a downstream consumer needs a plan of its own
    /// choosing; going through [`admit_for_run`] for each would drag the
    /// keystore and the nonce ledger into tests about something else. That
    /// convenience is exactly the forgery this type exists to prevent, so it is
    /// compiled out of every artifact anyone ships.
    #[cfg(test)]
    pub(crate) fn for_test(
        plan: ExecutionPlan,
        signer_id: String,
        signed: SignedExecutionPlan,
    ) -> Self {
        Self {
            plan_id: plan.plan_id.clone(),
            signer_id,
            plan,
            signed,
            extensions: Vec::new(),
        }
    }
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
}

/// Trust and revocation inputs for exact extension-pack re-verification.
pub struct ExtensionAdmissionContext<'a> {
    verify: &'a PackVerifyCtx<'a>,
    cache_root: Option<&'a std::path::Path>,
}

impl<'a> ExtensionAdmissionContext<'a> {
    /// Use the ordinary MVM pack cache.
    #[must_use]
    pub fn ambient(verify: &'a PackVerifyCtx<'a>) -> Self {
        Self {
            verify,
            cache_root: None,
        }
    }

    /// Use an explicit provider-owned pack cache.
    #[must_use]
    pub fn at(cache_root: &'a std::path::Path, verify: &'a PackVerifyCtx<'a>) -> Self {
        Self {
            verify,
            cache_root: Some(cache_root),
        }
    }

    fn resolve(
        &self,
        digest: &Sha256Hex,
    ) -> Result<Option<mvm_core::pack_cache::VerifiedPackRecord>> {
        match self.cache_root {
            Some(cache_root) => mvm_core::pack_cache::resolve_pack_digest_at(
                cache_root,
                PackKind::Extension,
                digest,
                self.verify,
            ),
            None => resolve_pack_digest(PackKind::Extension, digest, self.verify),
        }
        .map_err(Into::into)
    }
}

/// Run the full admission pipeline for an `mvmctl up` invocation.
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
pub fn admit_plan_for_run(
    plan: &ExecutionPlan,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
    host_signer_keys_dir: Option<&std::path::Path>,
    bundle_ctx: Option<&BundleAdmissionContext<'_>>,
    posture: RunPosture,
) -> Result<AdmittedPlan> {
    admit_plan_for_run_inner(
        plan,
        clock,
        ledger,
        host_signer_keys_dir,
        bundle_ctx,
        None,
        posture,
    )
}

/// Admit a plan carrying optional extension bindings, re-verifying every
/// digest-pinned pack under current trust and revocation state before signing.
pub fn admit_plan_for_run_with_extensions(
    plan: &ExecutionPlan,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
    host_signer_keys_dir: Option<&std::path::Path>,
    bundle_ctx: Option<&BundleAdmissionContext<'_>>,
    extension_ctx: &ExtensionAdmissionContext<'_>,
    posture: RunPosture,
) -> Result<AdmittedPlan> {
    admit_plan_for_run_inner(
        plan,
        clock,
        ledger,
        host_signer_keys_dir,
        bundle_ctx,
        Some(extension_ctx),
        posture,
    )
}

fn admit_plan_for_run_inner(
    plan: &ExecutionPlan,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
    host_signer_keys_dir: Option<&std::path::Path>,
    bundle_ctx: Option<&BundleAdmissionContext<'_>>,
    extension_ctx: Option<&ExtensionAdmissionContext<'_>>,
    posture: RunPosture,
) -> Result<AdmittedPlan> {
    validate_extension_bindings(plan)?;
    let extensions = verify_extension_packs(plan, extension_ctx)?;
    // Grants are checked in the pre-keystore window, and for the same
    // reason as synthesis: a plan we would refuse must never leave here with a
    // signature on it. A signed refused plan is indistinguishable from a
    // signed admitted one to anything downstream that only checks the
    // signature.
    admit_grants(plan, &host_grant_ceiling(), posture)?;

    // The ceiling above bounds this one workload; the budget bounds the sum of
    // every live one. Both sit in the pre-keystore window for the same reason,
    // and both read host config rather than the plan. The total is measured
    // over live machines only — counting records instead would turn a single
    // crashed VM into a permanent refusal of every later boot.
    admit_within_host_budget(plan)?;

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
        verified,
        signed,
        signer_id,
        extensions,
        clock,
        ledger,
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

    validate_extension_bindings(&verified)?;
    // No extension verification context on this path: a plan that binds
    // optional extensions is refused rather than admitted unchecked.
    let extensions = verify_extension_packs(&verified, None)?;
    admit_grants(&verified, &host_grant_ceiling(), posture)?;
    admit_within_host_budget(&verified)?;

    finish_admission(VerifiedAdmission {
        verified,
        // The caller lends the envelope; the admitted plan owns a copy so
        // downstream consumers can re-verify without trusting this process.
        signed: signed.clone(),
        signer_id,
        extensions,
        clock,
        ledger,
        bundle_ctx,
    })
}

/// The external plan signers this host trusts, from operator config.
///
/// Read from config rather than taken as a parameter for the same reason as
/// the grant ceiling: admission's trust root must not be widen-able by the
/// caller asking for admission. A malformed pin fails the whole read, so the
/// set in force is exactly the set the operator wrote.
fn host_trusted_plan_signers() -> Result<Vec<(String, VerifyingKey)>> {
    mvm_core::user_config::load(None).trusted_plan_signer_keys()
}

/// Everything the shared post-verification tail of admission needs.
///
/// A params struct rather than seven positional arguments: `verified`,
/// `signed`, and `signer_id` travel together from whichever path verified
/// them, and a positional call could transpose them with nothing to catch it.
struct VerifiedAdmission<'a> {
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
    clock: &'a dyn Clock,
    ledger: &'a InMemoryNonceLedger,
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
    let VerifiedAdmission {
        verified,
        signed,
        signer_id,
        extensions,
        clock,
        ledger,
        bundle_ctx,
    } = parts;

    // The plan_id is the content-address of the plan body — recompute it and
    // refuse a plan whose stored id doesn't match, so a run is only ever
    // admitted under an id that genuinely addresses its content.
    verify_plan_id(&verified).context("plan_id content-address check")?;

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

    // Replay protection: insert (signer_id, nonce). A second admission with
    // the same signer + nonce — a re-submitted fleet plan, or a synthesized
    // plan that somehow recurred — is refused.
    {
        let mut store = ledger.inner.lock().expect("nonce store mutex poisoned");
        store
            .check_and_insert(&signer_id, &verified)
            .context("replay protection check")?;
    }

    // Bundle re-verify at admit time. Only fires
    // when the plan pinned a bundle; missing context with a pinned
    // plan is operator misconfiguration (the driver wasn't wired
    // with a resolver/trust store), so we refuse rather than skip
    // silently.
    if let Some(pin) = verified.bundle.as_ref() {
        let ctx = bundle_ctx.ok_or_else(|| {
            anyhow::anyhow!(
                "plan pins bundle {bundle} but no BundleAdmissionContext was provided — refuse",
                bundle = pin.bundle_sha256
            )
        })?;
        let verified_bundle = verify_plan_bundle(pin, ctx.resolver, ctx.trust)
            .with_context(|| format!("bundle re-verify for pin {}", pin.bundle_sha256))?;
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

    Ok(AdmittedPlan {
        plan_id: verified.plan_id.clone(),
        signer_id,
        plan: verified,
        signed,
        extensions,
    })
}

fn validate_extension_bindings(plan: &ExecutionPlan) -> Result<()> {
    if !plan.extensions.is_empty() {
        let verbs = plan.agent_verbs.as_deref().unwrap_or_default();
        for required in ["run-extension", "cancel-extension"] {
            if !verbs.iter().any(|verb| verb.as_str() == required) {
                anyhow::bail!(
                    "signed plans with optional extensions must grant the {required} agent verb"
                );
            }
        }
    }
    let mut extension_ids = std::collections::HashSet::new();
    let mut pack_digests = std::collections::HashSet::new();
    let mut capabilities = std::collections::HashSet::new();
    for extension in &plan.extensions {
        extension
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid extension binding: {error}"))?;
        if extension.placement
            != mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload
        {
            anyhow::bail!(
                "extension placement isolated_controller is not executable by this MVM version"
            );
        }
        if !extension_ids.insert(extension.extension_id.clone()) {
            anyhow::bail!("duplicate extension identity in signed plan");
        }
        if !pack_digests.insert(extension.pack_digest) {
            anyhow::bail!("duplicate extension pack digest in signed plan");
        }
        for binding in &extension.capabilities {
            if !plan.services.contains(&binding.capability.service) {
                anyhow::bail!(
                    "extension capability service {} is not bound by the signed plan",
                    binding.capability.service
                );
            }
            if !capabilities.insert(binding.capability.clone()) {
                anyhow::bail!("duplicate extension capability in signed plan");
            }
        }
    }
    Ok(())
}

fn verify_extension_packs(
    plan: &ExecutionPlan,
    context: Option<&ExtensionAdmissionContext<'_>>,
) -> Result<Vec<AdmittedExtension>> {
    if plan.extensions.is_empty() {
        return Ok(Vec::new());
    }
    let context = context.ok_or_else(|| {
        anyhow::anyhow!(
            "plan binds optional extensions but no extension verification context was provided"
        )
    })?;
    plan.extensions
        .iter()
        .map(|binding| {
            let digest = Sha256Hex::new(hex::encode(binding.pack_digest))
                .context("decoding extension pack digest")?;
            let digest_text = digest.as_str();
            let record = context
                .resolve(&digest)
                .with_context(|| format!("re-verifying extension pack {digest_text}"))?
                .ok_or_else(|| anyhow::anyhow!("extension pack {digest_text} is not installed"))?;
            let contract = record.manifest.extension.as_ref().ok_or_else(|| {
                anyhow::anyhow!("verified extension pack {digest_text} has no extension contract")
            })?;
            let contract_digest: [u8; 32] = Sha256::digest(
                serde_json::to_vec(contract).context("encoding extension contract")?,
            )
            .into();
            if !extension_binding_matches_contract(binding, contract, contract_digest) {
                anyhow::bail!("extension binding does not match verified pack {digest_text}");
            }
            let maximum: std::collections::HashSet<_> = contract
                .capabilities
                .iter()
                .map(mvm_contract::protocol::agent_capability::CapabilityDescriptor::binding)
                .collect();
            if binding
                .capabilities
                .iter()
                .any(|capability| !maximum.contains(capability))
            {
                anyhow::bail!("extension binding widens verified pack authority {digest_text}");
            }
            if !budgets_are_narrower(binding.budgets, contract.budgets) {
                anyhow::bail!("extension binding widens verified pack budgets {digest_text}");
            }
            let artifact = record.dir.root.join(&binding.artifact);
            if !artifact.is_file() {
                anyhow::bail!("verified extension artifact is missing from pack {digest_text}");
            }
            let artifact_size = std::fs::metadata(&artifact)
                .with_context(|| format!("inspecting extension artifact for {digest_text}"))?
                .len();
            if extension_artifact_exceeds_budget(artifact_size, binding.budgets.max_artifact_bytes)
            {
                anyhow::bail!(
                    "verified extension artifact exceeds admitted budget for {digest_text}"
                );
            }
            Ok(AdmittedExtension {
                binding: binding.clone(),
                root: record.dir.root,
            })
        })
        .collect()
}

fn extension_binding_matches_contract(
    binding: &mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
    contract: &mvm_contract::protocol::extension_pack::ExtensionPackContract,
    contract_digest: [u8; 32],
) -> bool {
    binding.extension_id == contract.extension_id
        && binding.version == contract.version
        && binding.contract_digest == contract_digest
        && binding.placement == contract.placement
        && binding.artifact == contract.artifact
        && binding.entrypoint == contract.entrypoint
}

fn extension_artifact_exceeds_budget(artifact_size: u64, maximum_size: u64) -> bool {
    artifact_size > maximum_size
}

fn budgets_are_narrower(
    admitted: mvm_contract::protocol::extension_pack::ExtensionBudgets,
    maximum: mvm_contract::protocol::extension_pack::ExtensionBudgets,
) -> bool {
    admitted.cpu_millis <= maximum.cpu_millis
        && admitted.memory_bytes <= maximum.memory_bytes
        && admitted.duration_ms <= maximum.duration_ms
        && admitted.max_steps <= maximum.max_steps
        && admitted.max_concurrency <= maximum.max_concurrency
        && admitted.max_payload_bytes <= maximum.max_payload_bytes
        && admitted.max_output_bytes <= maximum.max_output_bytes
        && admitted.max_artifact_bytes <= maximum.max_artifact_bytes
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
    let plan = synthesize_plan(input).context("synthesizing plan")?;
    admit_plan_for_run(
        &plan,
        clock,
        ledger,
        host_signer_keys_dir,
        bundle_ctx,
        posture,
    )
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

/// Refuse a boot that, on top of every live machine's admitted charge, would
/// exceed the host's configured headroom.
///
/// Skipped entirely when no headroom is configured — not to save the
/// directory walk, but so an unconfigured host cannot be refused by a probe
/// whose result it would ignore anyway.
fn admit_within_host_budget(plan: &ExecutionPlan) -> Result<()> {
    let budget = mvm_core::user_config::load(None).host_budget();
    if !budget.is_configured() {
        return Ok(());
    }
    let undeclared = Grants::default();
    let grants = plan.grants.as_ref().unwrap_or(&undeclared);
    let request = crate::admission_budget::charge_for(plan.resources.mem_mib, grants);
    crate::admission_budget::admits(&budget, crate::admission_budget::committed(), request)
}

/// What admission has to be told, because the plan cannot be trusted to say
/// it: the posture this run carries, and the backend that will actually boot
/// it.
///
/// The backend is a [`BackendKind`] taken from the backend object itself, never
/// parsed out of `ExecutionPlan.runtime_profile`. A profile is a label chosen
/// by whoever wrote the plan and is not always even a tier name — `mvmctl exec`
/// writes `transient-run`, the lineage path writes the workload's name — so a
/// gate that read it would be deciding which resource controls apply from a
/// string a caller picked.
#[derive(Debug, Clone, Copy)]
pub struct RunPosture {
    variant: Variant,
    backend: Option<BackendKind>,
}

impl RunPosture {
    /// A run whose backend is in hand. The only shape that can measure a grant
    /// against the mechanisms that will really be there.
    #[must_use]
    pub fn on_backend(variant: Variant, backend: BackendKind) -> Self {
        Self {
            variant,
            backend: Some(backend),
        }
    }

    /// A caller admitting without a backend object — a dry-run admission, or a
    /// path that resolves its backend only after admission.
    ///
    /// Fail-closed rather than fall back to the plan's label: a declared grant
    /// is then unverifiable, which a sealed run refuses and a dev run is warned
    /// about. Guessing a tier from a string here is exactly the mistake that
    /// would let a mislabelled plan pick its own resource controls.
    #[must_use]
    pub fn without_backend(variant: Variant) -> Self {
        Self {
            variant,
            backend: None,
        }
    }

    /// The sealed-production / developer posture this run carries.
    #[must_use]
    pub fn variant(&self) -> Variant {
        self.variant
    }
}

/// Refuse a run whose grants this host will not admit.
///
/// Two independent questions, in this order:
///
/// 1. *May it ask for this?* — the ceiling, which bounds the request.
/// 2. *Can anything here deliver it?* — the mechanisms of the backend that will
///    boot it, which decide whether an admitted grant would be enforced or
///    merely recorded.
///
/// The second is posture-dependent: a sealed production run must not boot with
/// a bound nothing implements, while a developer's laptop legitimately runs on
/// tiers that cannot bound CPU at all. Warning rather than refusing in dev is
/// what keeps the refusal credible in prod instead of training everyone to
/// route around it.
fn admit_grants(plan: &ExecutionPlan, ceiling: &GrantCeiling, posture: RunPosture) -> Result<()> {
    let undeclared = Grants::default();
    let grants = plan.grants.as_ref().unwrap_or(&undeclared);

    enforce_wall_clock_projection(plan, grants)?;

    // Memory is checked even when nothing was granted: it is fixed at VM
    // creation rather than requested, and an unbounded one reserves the host.
    ceiling
        .admits(grants, plan.resources.mem_mib)
        .map_err(|violation| {
            anyhow::anyhow!(
                "grant exceeds this host's ceiling: {dimension} requested {requested}, \
                 host allows at most {ceiling}",
                dimension = violation.dimension,
                requested = violation.requested,
                ceiling = violation.ceiling,
            )
        })?;

    enforceability_gate(grants, plan, posture)
}

/// Refuse a plan whose two encodings of one wall-clock bound disagree.
///
/// `resources.timeouts.exec_secs` is the projection of `grants.wall_clock`, and
/// synthesis is the only thing that writes it. A signed plan reaching admission
/// with the two out of step was not produced by that path, and there is no
/// right answer to pick between them: enforcing the grant ignores a signed
/// field, enforcing the field ignores what the ceiling was applied to. Refusing
/// is the only choice that cannot silently run a workload under a bound nobody
/// authored.
///
/// The comparison runs against the projection, never against the grant
/// directly, because the projection is lossy: an absent grant and an explicit
/// `Unbounded` both encode as `0`, and only the ceiling distinguishes them.
fn enforce_wall_clock_projection(plan: &ExecutionPlan, grants: &Grants) -> Result<()> {
    let projected = mvm_contract::grants::projection::exec_secs_from_grants(grants);
    let carried = plan.resources.timeouts.exec_secs;
    if projected != carried {
        anyhow::bail!(
            "plan carries exec_secs {carried} but its wall-clock grant projects to \
             {projected}; refusing to choose between two encodings of one bound"
        );
    }
    Ok(())
}

/// Refuse (prod) or warn (dev) when the backend this run boots on has no
/// mechanism behind a declared grant.
fn enforceability_gate(grants: &Grants, plan: &ExecutionPlan, posture: RunPosture) -> Result<()> {
    // A run that granted CPU or wall clock is the only one with anything to
    // enforce here; asking otherwise would warn on every unbounded boot.
    //
    // `grants.egress` is deliberately outside both this gate and the ceiling,
    // and is enforced elsewhere rather than left unenforced. It is not bounded
    // by a numeric ceiling, and "can this tier deliver it" is not a per-backend
    // question for egress: every workload's traffic already leaves through the
    // one per-VM substitution endpoint, so a granted allow-list is projected
    // onto the policy that endpoint installs, and its gate is what admits or
    // drops each flow.
    //
    // What this early return does not do is check that the projection happened.
    // It cannot: the policy the endpoint installs rides on the launch config,
    // not in the plan body this function reads, so keeping the two derived from
    // one authored value is the obligation of the seam that builds both. What
    // holds here unconditionally is the floor — an absent egress grant and an
    // empty allow-list both project to deny-all, so a workload that granted
    // nothing reaches nothing.
    if grants.cpu.is_none() && grants.wall_clock.is_none() {
        return Ok(());
    }

    // No backend object, no answer. The plan's own `runtime_profile` is not a
    // substitute: it is a label the plan's author chose, so believing it would
    // let a mislabelled plan pick which resource controls it is measured
    // against.
    let Some(kind) = posture.backend else {
        return refuse_or_warn(
            posture.variant,
            "this run was admitted without the backend that will boot it, so no mechanism \
             can be named for the grants it declares"
                .to_string(),
        );
    };

    // The gate measures against `kind`. But if the plan *does* name a tier and
    // it is not this one, the plan and the launch disagree about what is about
    // to run, and a grant checked against either answer is checked against the
    // wrong one. Refused in both postures: this is a contradiction, not a
    // missing mechanism, so there is nothing for a dev warning to soften.
    //
    // A profile that names no tier at all (`transient-run`) is not a
    // disagreement — it makes no claim to contradict.
    if let Some(declared) = BackendKind::from_label(&plan.runtime_profile.0)
        && declared != kind
    {
        anyhow::bail!(
            "plan declares runtime profile {declared} but this run boots on {actual}; \
             refusing to measure its grants against either",
            declared = declared.as_str(),
            actual = kind.as_str(),
        );
    }

    if let Err(gaps) = negotiate_grants(grants, kind) {
        let detail = gaps
            .iter()
            .map(|gap| format!("{} — {}", gap.capability, gap.alternative.describe()))
            .collect::<Vec<_>>()
            .join("; ");
        return refuse_or_warn(
            posture.variant,
            format!(
                "the {tier} tier cannot enforce every declared grant: {detail}",
                tier = kind.as_str()
            ),
        );
    }

    // The tier says the mechanism exists; this host has to actually have it.
    // `ResourceControls::for_backend` answers per backend kind and, for CPU,
    // per target OS — neither of which knows whether *this* host has a systemd
    // user session to delegate from. Without this second question a sealed run
    // on a Linux host with no session bus is admitted, boots unbounded, and
    // reports `declared`: refused in prose and permitted in code.
    if let Some(detail) = host_cpu_mechanism_gap(grants, kind, mvm_core::cpu_scope::mechanism_gap())
    {
        return refuse_or_warn(posture.variant, detail);
    }
    Ok(())
}

/// Refusal detail when the backend's tier claims a CPU share it can serve but
/// this host cannot serve it.
///
/// Pure, with the host probe passed in, so both answers are testable on any
/// host — including the combination that cannot be produced locally (a tier
/// that bounds CPU on a machine whose mechanism is missing).
fn host_cpu_mechanism_gap(
    grants: &Grants,
    kind: BackendKind,
    gap: Option<mvm_core::cpu_scope::MechanismGap>,
) -> Option<String> {
    // Only a share rides on this mechanism. A fuel budget is wasmtime's, and an
    // absent CPU grant has nothing to enforce.
    let millicores = match grants.cpu {
        Some(CpuGrant::Share { millicores }) => millicores,
        _ => return None,
    };
    if !ResourceControls::for_backend(kind).cpu.serves_share() {
        // The tier itself cannot serve a share; `negotiate_grants` already
        // spoke to that, and saying it twice would name one problem as two.
        return None;
    }

    // HVF enforces shares with its own in-process scheduler; the cgroup probe
    // is irrelevant there. A share that the scheduler cannot parameterize is
    // the only missing-mechanism case on this tier.
    if kind == BackendKind::Hvf {
        if let Err(e) = QuotaConfig::for_share(millicores) {
            return Some(format!("the hvf tier cannot enforce cpu.share: {e}"));
        }
        return None;
    }

    let gap = gap?;
    Some(format!(
        "the {tier} tier bounds CPU with a cgroup quota, but this host cannot attach one: {reason}",
        tier = kind.as_str(),
        reason = gap.describe()
    ))
}

fn refuse_or_warn(variant: Variant, detail: String) -> Result<()> {
    if variant.is_prod() {
        anyhow::bail!("refusing an unenforceable grant: {detail}");
    }
    tracing::warn!(
        "{detail} — admitting anyway because this is a dev run; the grant is recorded, \
         not enforced"
    );
    Ok(())
}

/// Soft caps on the JSON envelope sizes flowing through
/// `VmStartConfig` → `SupervisorConfig` over the supervisor's
/// stdin pipe. Adversarial envelopes are a DoS vector (memory pressure
/// on the supervisor + pipe-buffer pressure on the producer). 1 MiB /
/// 4 MiB are generous for legitimate plans / bundles and tight enough
/// to refuse pathological inputs.
const PLAN_JSON_MAX_BYTES: usize = 1024 * 1024;
const BUNDLE_JSON_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Refuse an envelope over its byte cap.
///
/// A one-line comparison inlined at each call site is not reachable by a
/// test at its boundary: the only way to exercise it is to serialize a
/// real plan of exactly the cap, which is impractical to construct. So the
/// comparison lives here, where `cap - 1`, `cap` and `cap + 1` are three
/// cheap assertions.
///
/// The direction matters. Loosening `>` to `>=` refuses at exactly the cap
/// — stricter, and merely wrong. Tightening it to `==` refuses *only* at
/// exactly the cap and admits everything larger, which turns the cap into
/// no cap at all and reopens the memory-pressure vector it exists to
/// close.
fn enforce_size_cap(what: &str, len: usize, cap: usize) -> Result<()> {
    if len > cap {
        anyhow::bail!("{what} exceeds {cap} byte cap (got {len}); refusing");
    }
    Ok(())
}

/// Populate the three `VmStartConfig` audit-substrate fields
/// (`tenant_id`, `plan_json`, `bundle_json`) from the admitted
/// plan. Call after the `VmStartConfig` is built and before
/// `backend.start()`; the libkrun/HVF backends read these to wire
/// `SupervisorConfig.{tenant_id, audit_dir, gateway_audit_socket,
/// gateway_events_socket, signing_key_path}` and activate the
/// bridge-factory path.
///
/// JSON-encoded so the `VmStartConfig` wire type stays a serde seam
/// with no typed coupling to `mvm_core::plan` at the backend boundary. The
/// supervisor re-verifies the `SignedExecutionPlan` envelope before
/// trusting any decoded field — see
/// `mvm_hostd::supervisor::supervisor::SupervisorAdmission::admit`.
///
/// **Do not log the resulting `plan_json` / `bundle_json` values.**
/// The signed envelope may contain secret bindings, environment
/// variables, or policy refs that resolve to credentials. Treat as
/// opaque transport bytes.
/// Thread *only* the admitted tenant label onto the `VmStartConfig`.
///
/// The per-VM host-services broker (`host.audit.v1` / `host.time.v1` /
/// `host.cost.v1`) keys its spawn off `config.tenant_id`, so any admitted
/// workload must carry it — `host.audit.v1` is implicitly available to any
/// admitted workload. This is decoupled from
/// [`populate_audit_substrate`]: the broker needs the tenant string, **not**
/// the signed `plan_json`, whose presence flips libkrun/HVF workload boots onto
/// the claim-10 gateway-bridge supervisor path. Call this unconditionally; call
/// `populate_audit_substrate` when a backend has a signed-plan consumer.
pub fn thread_tenant_id(cfg: &mut mvm_core::vm_backend::VmStartConfig, admitted: &AdmittedPlan) {
    cfg.tenant_id = Some(admitted.plan().tenant.0.clone());
}

/// Carry the admitted CPU bound onto the launch config, so the backend can be
/// born inside it rather than adjusted into it afterwards.
///
/// Taken from the **signed, admitted** plan and nowhere else. A caller-supplied
/// `cfg.cpu_grant` would be a bound chosen outside the admission that just
/// checked it against the host's ceiling, so whatever was there is overwritten
/// — including with `None`, which is what an uncapped plan means.
pub fn thread_cpu_grant(cfg: &mut mvm_core::vm_backend::VmStartConfig, admitted: &AdmittedPlan) {
    cfg.cpu_grant = admitted.plan().grants.as_ref().and_then(|g| g.cpu);
}

pub fn populate_audit_substrate(
    cfg: &mut mvm_core::vm_backend::VmStartConfig,
    admitted: &AdmittedPlan,
    policy_bundle: Option<&PolicyBundle>,
) -> Result<()> {
    thread_tenant_id(cfg, admitted);
    thread_cpu_grant(cfg, admitted);

    let plan_json = serde_json::to_string(admitted.signed())
        .context("serializing SignedExecutionPlan for VmStartConfig.plan_json")?;
    enforce_size_cap("plan_json", plan_json.len(), PLAN_JSON_MAX_BYTES)?;
    cfg.plan_json = Some(plan_json);

    // `bundle_json` carries the resolved tenant **PolicyBundle** (network /
    // egress / tool policy) that the supervisor's L4 gate + observers consume.
    // It is NOT the ExecutionPlan's `.mvmpkg` artifact pin
    // (`admitted.plan().bundle`, a `PlanArtifact` — content-addressed
    // kernel/rootfs, verified separately at admit time via `verify_plan_bundle`).
    // Feeding the pin here was a conflation the supervisor's PolicyBundle decode
    // would reject. `None` until a policy-bundle source is wired.
    cfg.bundle_json = match policy_bundle {
        Some(bundle) => {
            let bj = serde_json::to_string(bundle)
                .context("serializing PolicyBundle for VmStartConfig.bundle_json")?;
            enforce_size_cap("bundle_json", bj.len(), BUNDLE_JSON_MAX_BYTES)?;
            Some(bj)
        }
        None => None,
    };
    Ok(())
}

/// Atomically write `body` to `path` at mode 0600 on Unix hosts.
///
/// The Firecracker bridge sidecar reads `plan.json` + `bundle.json` from
/// the per-VM state dir at spawn time. Those files carry the signed
/// `ExecutionPlan` envelope and the (optional) bundle pin, which may
/// resolve through `secrets` / policy refs to credentials. They sit at
/// the same trust tier as the host signer key
/// (mode 0600); `std::fs::write` would default to 0644 minus umask which
/// on most contributor hosts is 0644 or 0664 — world-readable. Use
/// `OpenOptionsExt::mode(0o600)` + tmp-and-rename so a concurrent
/// bridge reader never sees a partial file.
///
/// Parent dir is assumed pre-created by the caller (the producer sites
/// in `up.rs` ensure `mvm_home/vms/<name>/` exists with the same
/// `0700` umbrella as `~/.mvm`).
#[cfg(unix)]
pub(crate) fn write_secret_file(path: &std::path::Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!("write_secret_file: path has no parent: {}", path.display())
    })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create parent dir {}", parent.display()))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("open tmp file {}", tmp.display()))?;
        f.write_all(body)
            .with_context(|| format!("write secret bytes to {}", tmp.display()))?;
        // Best-effort fsync; on tmpfs this is a no-op and on a flaky
        // FS we'd rather succeed-and-warn than fail-and-abort.
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Stash the signed plan envelope + (optional) bundle pin in the
/// per-VM state dir so the Firecracker bridge sidecar can read them
/// at spawn time.
///
/// Called from every `up.rs` producer site immediately after
/// `populate_audit_substrate`, before `backend.start()`. No-op when
/// `cfg.plan_json` is `None` (legacy / no-admission path). Files land
/// at mode 0600 via [`write_secret_file`] — see that helper's doc for
/// why `std::fs::write` is insufficient.
///
/// Lives in the producer (mvm-cli) rather than `microvm::run_from_build`
/// because the producer is the only place that has the signed envelope
/// in scope; `microvm` reads it back from disk inside the
/// `target_os = "linux"` bridge-spawn block.
pub fn stash_plan_for_bridge(cfg: &mvm_core::vm_backend::VmStartConfig) -> Result<()> {
    stash_plan_and_mint_verb_grant(cfg).map(|_| ())
}

/// Persist a VM's admitted plan material and mint its optional signed agent
/// verb grant, returning the exact envelope written to disk. Warm-restore
/// callers use the returned value in the post-restore handshake because there
/// is no new kernel boot at which to consume the sidecar.
pub fn stash_plan_and_mint_verb_grant(
    cfg: &mvm_core::vm_backend::VmStartConfig,
) -> Result<Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>> {
    let Some(plan_json) = cfg.plan_json.as_deref() else {
        return Ok(None);
    };
    let state_dir = mvm_core::config::vm_state_dir(&cfg.name);
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("create per-VM state dir {}", state_dir.display()))?;
    write_secret_file(&state_dir.join("plan.json"), plan_json.as_bytes())?;
    if let Some(bundle_json) = cfg.bundle_json.as_deref() {
        write_secret_file(&state_dir.join("bundle.json"), bundle_json.as_bytes())?;
    }
    mint_verb_grant_sidecar(plan_json, &cfg.name, &state_dir)
}

/// If the plan carries `agent_verbs`, mint a signed `VerbGrantEnvelope` and
/// write it to `<state_dir>/verb-grant.json` (mode 0600). Absent verbs ⇒ no
/// file written (grant-less boot). Best-effort key load — the key is created
/// on first use by `load_or_init_at` against the default keys dir.
///
/// The sidecar is consumed by the backend's `verb_grant_cmdline_token` at
/// launch time and carried to the guest on the kernel cmdline.
fn mint_verb_grant_sidecar(
    plan_json: &str,
    vm_name: &str,
    state_dir: &std::path::Path,
) -> Result<Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>> {
    use mvm_core::plan::SignedExecutionPlan;
    use mvm_core::protocol::vm_backend::VerbGrantEnvelope;

    // Remove any pre-existing sidecar so that a grant-less re-run of a
    // reused VM name does not inherit the previous boot's grant.
    let sidecar_path = state_dir.join("verb-grant.json");
    match std::fs::remove_file(&sidecar_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::Error::from(e)).with_context(|| {
                format!("remove stale verb-grant sidecar {}", sidecar_path.display())
            });
        }
    }

    // Best-effort parse: a missing or malformed plan_json skips the
    // sidecar (grant-less boot), matching the fail-open posture of the
    // other cmdline token producers.
    let Ok(signed) = serde_json::from_str::<SignedExecutionPlan>(plan_json) else {
        return Ok(None);
    };
    let Ok(plan) = serde_json::from_slice::<ExecutionPlan>(&signed.0.payload) else {
        return Ok(None);
    };

    let Some(verbs) = plan.agent_verbs else {
        // No verb grant requested — grant-less boot, sidecar already removed.
        return Ok(None);
    };

    let keys_dir = mvm_core::config::mvm_keys_dir();
    let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir)
        .context("load host signer for verb-grant mint")?;
    let keystore = crate::host_signer::keystore::Keystore::load_from_file(&signer.secret_path)
        .context("load Keystore from host-signer key file")?;

    let grant = crate::host_signer::mint_verb_grant(
        &keystore,
        vm_name,
        &plan.nonce,
        plan.valid_until,
        verbs,
    )
    .context("mint verb grant")?;

    let pubkey_hex: String = keystore
        .pub_key()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let plan_nonce_hex = plan.nonce.as_hex().to_string();

    let envelope = VerbGrantEnvelope {
        pubkey_hex,
        plan_nonce_hex,
        predecessor_session_id: None,
        predecessor_plan_nonce_hex: None,
        grant,
    };
    let envelope_json = serde_json::to_vec(&envelope).context("serialize VerbGrantEnvelope")?;
    write_secret_file(&state_dir.join("verb-grant.json"), &envelope_json)?;
    Ok(Some(envelope))
}

/// Admission enforcement: every volume about to be attached must be
/// named in the verified `ExecutionPlan.shares`, with matching
/// host path, guest path, kind, ro/rw, and encryption.
///
/// On the local `mvmctl up`/`dev` path the CLI builds both the signed
/// plan and the launch config from one source, so this is self-consistent
/// by construction — but it **fails closed** if they ever diverge (a CLI
/// bug, or a future caller that hands a config the plan didn't authorize).
/// It's the trust-boundary hook: no host-fs grant reaches a guest unless
/// the signed plan admitted it (claim 1 / claim 8). The supervisor +
/// mvmd enforcement mirror this check against the same `plan.shares`.
pub fn enforce_admitted_shares(
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan: &ExecutionPlan,
) -> Result<()> {
    for v in volumes {
        let want_kind = if v.materialized_image.is_some() {
            mvm_core::plan::ShareKind::DirShare
        } else {
            mvm_core::plan::ShareKind::Disk
        };
        let admitted = plan.shares.iter().find(|g| {
            g.host_path == v.host
                && g.guest_path == v.guest
                && g.kind == want_kind
                && g.read_only == v.read_only
                && g.encrypted == v.encrypted
        });
        let Some(grant) = admitted else {
            anyhow::bail!(
                "refusing to attach volume '{}' -> '{}' ({}): it is not named in the signed \
                 ExecutionPlan's admitted shares — every host-fs grant must be admitted (claim 1).",
                v.host,
                v.guest,
                if v.read_only { "ro" } else { "rw" },
            );
        };
        // Content identity (claim 19): a grant that recorded what the shared
        // tree hashed to at admission must still hash the same at attach
        // time. The admitted digest is inside the signed plan, so this closes
        // the window between admission and boot where the host directory
        // could change under the granted path — the guest would otherwise
        // receive bytes the plan never vouched for.
        if let Some(expected) = &grant.content_sha256 {
            // Canonicalize so a symlinked host dir (macOS `/tmp`) hashes
            // the same tree admission pinned, whichever alias names it.
            let resolved = std::fs::canonicalize(&v.host)?;
            let actual = mvm_fs::hash::hash_source(&resolved).map_err(|e| {
                anyhow::anyhow!(
                    "refusing to attach volume '{}' -> '{}': cannot re-hash the granted \
                     directory to check its admitted content identity: {e}",
                    v.host,
                    v.guest,
                )
            })?;
            if actual != *expected {
                anyhow::bail!(
                    "refusing to attach volume '{}' -> '{}': the directory changed after \
                     admission — admitted content identity {expected}, now {actual}. Re-admit \
                     the plan against the current tree.",
                    v.host,
                    v.guest,
                );
            }
        }
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
             cache under the mvm cache dir; build it with \
             `mvmctl build sdk-sidecar build` and retry.",
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
             variant it holds cannot be established. Rebuild the cache with \
             `mvmctl build sdk-sidecar build`, which files each variant under its own libc"
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

/// Outcome of a successful admitted boot: the backend's VM id plus the
/// `AdmittedPlan` (for the caller's audit chain / typed result).
#[derive(Debug)]
pub struct StartedMachine {
    pub vm_id: VmId,
    pub admitted: AdmittedPlan,
    /// What actually bounded this workload, read back off the live controls by
    /// the backend that booted it.
    ///
    /// Not the grants that were requested — those are already on the signed
    /// plan. A caller building a receipt gets the tier that fired, so it cannot
    /// report a bound that was only asked for.
    pub enforced_grants: EnforcedGrants,
}

/// Apply the admitted plan's grants to the VM that is now running, and report
/// what the backend achieved.
///
/// After `start` rather than before, because a control needs something to
/// attach to; the backends that bound CPU do it by placing the VMM process
/// itself, which does not exist until then.
///
/// Not best-effort. A workload whose bounds could not be applied is running
/// unbounded, so the launch is undone rather than completed alongside a record
/// that says otherwise — the same posture the supervisor's own launch path
/// takes.
fn apply_admitted_grants(
    backend: &AnyBackend,
    vm_id: &VmId,
    admitted: &AdmittedPlan,
) -> Result<EnforcedGrants> {
    let undeclared = Grants::default();
    let grants = admitted.plan().grants.as_ref().unwrap_or(&undeclared);
    backend
        .as_vm_backend()
        .apply_grants(vm_id, grants)
        .context("applying the admitted plan's grants to the started VM")
}

/// The four post-admission gates between `plan.admitted` and the backend
/// start, run in order. On refusal the failing stage's wire label is
/// returned alongside the error so the caller can emit a terminal
/// `plan.failed` entry naming the gate.
fn run_post_admission_gates(
    mut config: VmStartConfig,
    admitted: &AdmittedPlan,
    backend: BackendKind,
    policy_bundle: Option<&PolicyBundle>,
) -> std::result::Result<VmStartConfig, (&'static str, anyhow::Error)> {
    if let Err(e) = populate_audit_substrate(&mut config, admitted, policy_bundle) {
        return Err(("audit-substrate", e));
    }
    if let Err(e) = enforce_admitted_shares(&config.volumes, admitted.plan()) {
        return Err(("admitted-shares", e));
    }
    if let Err(e) = enforce_admitted_environment(
        config.kernel_path.as_deref().map(std::path::Path::new),
        admitted.plan(),
    ) {
        return Err(("admitted-environment", e));
    }
    if let Err(e) = enforce_sdk_sidecar_backend_compatibility(backend, admitted.plan()) {
        return Err(("sdk-sidecar", e.into()));
    }
    if let Err(e) = enforce_sdk_sidecar_attachment(
        &config.volumes,
        admitted.plan(),
        mvm_build::guest_libc::recorded_image_libc(std::path::Path::new(&config.rootfs_path)),
    ) {
        return Err(("sdk-sidecar", e));
    }
    if let Err(e) = attach_admitted_extensions(&mut config, admitted) {
        return Err(("extension-attachment", e));
    }
    Ok(config)
}

fn attach_admitted_extensions(config: &mut VmStartConfig, admitted: &AdmittedPlan) -> Result<()> {
    if !admitted.extensions().is_empty() {
        config.extension_plan_id = Some(admitted.plan_id().0.clone());
    }
    for extension in admitted.extensions() {
        if extension.binding.placement
            != mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload
        {
            anyhow::bail!(
                "extension placement isolated_controller reached guest attachment after admission"
            );
        }
        let digest = hex::encode(extension.binding.pack_digest);
        let guest = format!("/run/mvm/extensions/{digest}");
        if config.volumes.iter().any(|volume| volume.guest == guest) {
            anyhow::bail!("extension mountpoint collision at {guest}");
        }
        config.volumes.push(mvm_core::vm_backend::VmVolume {
            materialized_image: None,
            volume_label: None,
            host: extension
                .root
                .join(&extension.binding.artifact)
                .display()
                .to_string(),
            guest,
            size: String::new(),
            read_only: true,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        });
        config.extensions.push(extension.binding.clone());
    }
    Ok(())
}

fn launch_decision_record(plan: &ExecutionPlan, backend_name: &str) -> DecisionRecord {
    DecisionRecordBuilder::new()
        .version(1)
        .category(DecisionCategory::Launch)
        .actor(ActorRef {
            principal: crate::audit::host_keypair::host_signer_id(),
            key_id: crate::audit::host_keypair::host_signer_id(),
            key_role: Some(DecisionActorRole::Orchestrator),
        })
        .scenario(mvm_contract::provenance::DecisionScenario {
            plan_id: Some(plan.plan_id.0.clone()),
            ..Default::default()
        })
        .reasoning(format!("workload launched on backend {backend_name}"))
        .outcome(DecisionOutcome::Approved)
        .timestamp(Utc::now().to_rfc3339())
        .attestation(AttestationBinding {
            plan_id: Some(plan.plan_id.0.clone()),
            ..AttestationBinding::default()
        })
        .build()
        .expect("launch decision record is well-formed")
}

fn attach_assurance_proxy(
    config: &mut VmStartConfig,
    proxy: mvm_contract::protocol::broker_control::ServiceProxyBinding,
) -> Result<()> {
    if config
        .service_proxies
        .iter()
        .any(|binding| binding.service == proxy.service)
    {
        anyhow::bail!("assurance controller proxy service is already configured");
    }
    config.service_proxies.push(proxy);
    Ok(())
}

/// What rolling a launch back needs to know. A struct rather than seven
/// positional arguments, so a caller cannot silently swap the stage label for
/// the reason.
struct UndoLaunch<'a> {
    backend: &'a AnyBackend,
    vm_id: &'a VmId,
    admitted: &'a AdmittedPlan,
    emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
    /// Wire label of the stage that refused, for the terminal audit entry.
    stage: &'static str,
    /// Human-readable clause naming what went wrong, for the stop-failure log.
    reason: &'static str,
    err: anyhow::Error,
}

/// Stop a VM that started but must not keep running, emit the terminal
/// `plan.failed` entry, and hand the original error back.
///
/// One helper for both post-start refusals: leaving a VM up whose bounds were
/// never established would mean the only record of the run claims it was
/// bounded when it was not.
fn undo_launch(undo: UndoLaunch<'_>) -> anyhow::Error {
    if let Err(stop_err) = undo.backend.stop(undo.vm_id) {
        tracing::warn!(
            error = %stop_err,
            "stopping a VM whose {reason} failed; it may still be running",
            reason = undo.reason,
        );
    }
    if let Some(emitter) = undo.emitter
        && let Err(e) = emitter.emit_failed(
            undo.admitted.plan(),
            undo.stage,
            &format!("{err:#}", err = undo.err),
        )
    {
        tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
    }
    undo.err
}

/// Everything the post-admission tail needs, in one struct.
///
/// A params struct rather than six positional arguments: three of the fields
/// are optional borrows of unrelated types and a positional call could drop or
/// transpose one with nothing to catch it.
pub struct StartAdmittedParams<'a> {
    pub backend: &'a AnyBackend,
    /// The plan this boot runs under. Taken by value because it is handed back
    /// on the [`StartedMachine`], and holding one is the only proof admission
    /// ran — it cannot be built any other way.
    pub admitted: AdmittedPlan,
    pub config: VmStartConfig,
    pub policy_bundle: Option<&'a PolicyBundle>,
    /// Optional chain-signed emitter: `plan.launched` fires on a successful
    /// backend start, `plan.failed` on a start failure or a post-start refusal.
    /// The caller owns `plan.admitted`, which is already recorded by the time
    /// this runs.
    pub emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
    /// An assurance campaign to open against this boot, when the operator
    /// declared one. `None` — the default — is every ordinary run.
    pub assurance: Option<&'a crate::assurance_session::CampaignRequest>,
}

/// The post-admission tail every admitted boot shares: the gates, the backend
/// start, the grants, the budget charge and the launch records.
///
/// Split out of [`admit_and_start`] so a caller holding an already-admitted
/// plan — a resumed durable session, for one — can boot it without admitting a
/// second time. Two admissions would mean two nonces and two signed plans, with
/// the second silently becoming the real authority. Because this is the only
/// path from an `AdmittedPlan` to a running VM, a caller cannot boot on a path
/// that skipped a gate.
///
/// Order matters and is fail-closed: the signed plan is threaded onto the
/// launch config and every volume checked against the admitted shares
/// (claim 1); only then does the backend start the VM. A refusal in any gate
/// returns with **no VM created**, and a refusal *after* the start rolls the
/// launch back rather than leaving a VM up whose only record says it was
/// bounded.
///
/// The caller resolves the image to a `config.rootfs_path` beforehand; this
/// function is backend-agnostic (it drives whatever `AnyBackend` it is handed,
/// including the in-memory mock in tests).
#[tracing::instrument(skip_all)]
pub fn start_admitted(params: StartAdmittedParams<'_>) -> Result<StartedMachine> {
    let backend = params.backend;
    let admitted = params.admitted;

    // A refusal in any post-admission gate must still terminate the chain:
    // `plan.admitted` already fired, so a gate refusal emits `plan.failed`
    // carrying the refusing stage rather than leaving a dangling admission.
    let mut config = match run_post_admission_gates(
        params.config,
        &admitted,
        backend.kind(),
        params.policy_bundle,
    ) {
        Ok(config) => config,
        Err((stage, err)) => {
            if let Some(emitter) = params.emitter
                && let Err(e) = emitter.emit_failed(admitted.plan(), stage, &format!("{err:#}"))
            {
                tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
            }
            return Err(err.context(format!("admission gate refused ({stage})")));
        }
    };
    if params.assurance.is_some() {
        let proxy = crate::assurance_session::prepare_controller_proxy(&config.name)
            .context("preparing admitted assurance controller proxy")?;
        attach_assurance_proxy(&mut config, proxy)?;
    }

    let backend_name = backend.name().to_string();
    let vm_name = config.name.clone();
    match backend
        .start(&config)
        .context("backend start after signed-plan admission")
    {
        Ok(vm_id) => {
            let enforced_grants = match apply_admitted_grants(backend, &vm_id, &admitted) {
                Ok(enforced) => enforced,
                Err(err) => {
                    // Undo the launch: a VM whose grants could not be applied is
                    // running without the bounds it was admitted under, and
                    // leaving it up would mean the only record of the run says
                    // it was bounded.
                    return Err(undo_launch(UndoLaunch {
                        backend,
                        vm_id: &vm_id,
                        admitted: &admitted,
                        emitter: params.emitter,
                        stage: "grants",
                        reason: "grants could not be applied",
                        err,
                    }));
                }
            };

            // Record what this boot committed, so every later admission counts
            // it. A machine running without a record is invisible to the
            // budget, and an undercounted host is precisely the state the
            // budget exists to prevent — so this is fatal, and rolls the
            // launch back the same way an unapplied grant does.
            let undeclared = Grants::default();
            let charge = crate::admission_budget::charge_for(
                admitted.plan().resources.mem_mib,
                admitted.plan().grants.as_ref().unwrap_or(&undeclared),
            );
            if let Err(err) = crate::admission_budget::record_charge(&vm_name, charge) {
                return Err(undo_launch(UndoLaunch {
                    backend,
                    vm_id: &vm_id,
                    admitted: &admitted,
                    emitter: params.emitter,
                    stage: "host-budget",
                    reason: "its admitted charge could not be recorded",
                    err,
                }));
            }
            if let Some(emitter) = params.emitter {
                if let Err(e) = emitter.emit_launched(admitted.plan(), &backend_name) {
                    tracing::warn!(error = %e, "audit emit_launched failed (non-fatal)");
                }
                let record = launch_decision_record(admitted.plan(), &backend_name);
                if let Err(e) = emitter.emit_decision_record(admitted.plan(), record) {
                    tracing::warn!(error = %e, "audit emit_decision_record for launch failed (non-fatal)");
                }
                if let Err(e) = emitter.emit_grants_enforced(admitted.plan(), &enforced_grants) {
                    tracing::warn!(error = %e, "audit emit_grants_enforced failed (non-fatal)");
                }
            }
            // After the VM is running, so a failed boot leaves no session, and
            // after `plan.launched`, so the campaign's own records follow the
            // launch they belong to. A refusal here fails the boot: a campaign
            // the operator declared and that silently did not open would be
            // reported as a trial that observed nothing.
            if let Some(campaign) = params.assurance
                && let Err(err) =
                    crate::assurance_session::open_for_boot(campaign, &vm_id.0, &admitted)
            {
                // Rolls the launch back rather than returning with the VM up.
                // The session opens after the backend start, so a bare `?`
                // here left a running workload behind while reporting the boot
                // as failed — and an orphan whose only record says it did not
                // start is worse than either outcome alone.
                return Err(undo_launch(UndoLaunch {
                    backend,
                    vm_id: &vm_id,
                    admitted: &admitted,
                    emitter: params.emitter,
                    stage: "assurance-session",
                    reason: "the declared assurance campaign could not be opened",
                    err,
                }));
            }
            Ok(StartedMachine {
                vm_id,
                admitted,
                enforced_grants,
            })
        }
        Err(err) => {
            if let Some(emitter) = params.emitter
                && let Err(e) =
                    emitter.emit_failed(admitted.plan(), "backend-start", &format!("{err:#}"))
            {
                tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
            }
            Err(err)
        }
    }
}

/// The single admitted-boot entrypoint every driver shares — the CLI's
/// `mvmctl up`/`run` and the `mvm-client` local backend both reach it, so a
/// workload can never boot on a path that skipped admission.
///
/// Order matters and is fail-closed: synthesize + sign + verify + validity +
/// replay (+ bundle re-verify) run first, and any failure among them returns
/// with **no VM created** — admission is a gate, not a formality. Only once the
/// admission is recorded does this delegate to [`start_admitted`], which owns
/// the rest of the order.
#[tracing::instrument(skip_all)]
pub fn admit_and_start(
    backend: &AnyBackend,
    params: AdmitAndStartParams<'_>,
) -> Result<StartedMachine> {
    // The tier comes from the backend that is about to boot this plan — the
    // object itself, via its typed discriminant. Nothing here reads a backend
    // name: the grant gate decides which resource controls a run is measured
    // against, and deciding that from a string is how a plan ends up measured
    // against a tier it is not running on.
    let posture = RunPosture::on_backend(params.variant, backend.kind());

    // Synthesize the plan up-front so a refusal can be recorded with the
    // plan context if admission fails. Synthesis failures have no plan to
    // anchor to; they propagate without a chain entry.
    let plan = synthesize_plan(params.synthesis).context("synthesizing plan")?;

    let admitted_result = match params.extension_ctx {
        Some(extension_ctx) => admit_plan_for_run_with_extensions(
            &plan,
            params.clock,
            params.ledger,
            params.host_signer_keys_dir,
            params.bundle_ctx,
            extension_ctx,
            posture,
        ),
        None => admit_plan_for_run(
            &plan,
            params.clock,
            params.ledger,
            params.host_signer_keys_dir,
            params.bundle_ctx,
            posture,
        ),
    };
    let admitted = match admitted_result {
        Ok(admitted) => admitted,
        Err(err) => {
            if let Some(emitter) = params.emitter
                && let Err(e) =
                    emitter.emit_refused(&plan, "admit_plan_for_run", &format!("{err:#}"))
            {
                tracing::warn!(error = %e, "audit emit_refused failed (non-fatal)");
            }
            return Err(err);
        }
    };

    crate::audit::durability::record_admission(
        params.emitter,
        admitted.plan(),
        admitted.signer_id(),
        params.audit_durability,
    )?;

    start_admitted(StartAdmittedParams {
        backend,
        admitted,
        config: params.config,
        policy_bundle: params.policy_bundle,
        emitter: params.emitter,
        assurance: params.assurance,
    })
}

#[cfg(test)]
mod admitted_environment_tests {
    use super::*;

    fn plan_pinning(kernel_sha256: Option<&str>) -> ExecutionPlan {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.environment = kernel_sha256.map(|k| mvm_core::plan::EnvironmentRef {
            kernel_sha256: k.to_string(),
        });
        plan
    }

    fn write_kernel(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join("vmlinux");
        std::fs::write(&p, bytes).expect("write kernel fixture");
        p
    }

    /// The pinned kernel is the one on disk: the boot proceeds.
    #[test]
    fn matching_kernel_digest_is_admitted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let kernel = write_kernel(tmp.path(), b"workload-kernel");
        let sha = mvm_core::crypto::image_verify::sha256_file(&kernel).expect("hash");
        enforce_admitted_environment(Some(kernel.as_path()), &plan_pinning(Some(&sha)))
            .expect("matching kernel must be admitted");
    }

    /// A different kernel than the plan pinned is refused: same plan, same
    /// image, a kernel swapped underneath — the substitution that used to be
    /// invisible because nothing in the plan described the environment.
    #[test]
    fn substituted_kernel_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let kernel = write_kernel(tmp.path(), b"workload-kernel");
        let sha = mvm_core::crypto::image_verify::sha256_file(&kernel).expect("hash");
        std::fs::write(&kernel, b"a-general-purpose-kernel").expect("swap kernel");

        let err = enforce_admitted_environment(Some(kernel.as_path()), &plan_pinning(Some(&sha)))
            .expect_err("a substituted kernel must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("admitted-environment mismatch"),
            "error must name the mismatch, got: {msg}"
        );
    }

    /// Dropping the kernel path must not be a way around the pin.
    #[test]
    fn pinned_plan_with_no_kernel_path_is_refused() {
        let err = enforce_admitted_environment(None, &plan_pinning(Some(&"a".repeat(64))))
            .expect_err("a pinned plan with no kernel path must be refused");
        assert!(format!("{err:#}").contains("supplies no kernel path"));
    }

    /// Plans that pin nothing still boot — every plan written before the field
    /// existed, and backends that carry their own bundled kernel.
    #[test]
    fn unpinned_plan_is_unaffected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let kernel = write_kernel(tmp.path(), b"whatever");
        enforce_admitted_environment(Some(kernel.as_path()), &plan_pinning(None))
            .expect("an unpinned plan must be unaffected");
        enforce_admitted_environment(None, &plan_pinning(None))
            .expect("an unpinned plan with no kernel must be unaffected");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy};
    use rand::Rng;

    const FIXTURE_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// This module's own source, for the unforgeability check below.
    const SOURCE: &str = include_str!("plan_admission.rs");

    /// The production half of it — everything before this test module, so the
    /// checks below cannot be satisfied by a string literal written here.
    fn production_source() -> &'static str {
        SOURCE
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("this module keeps its tests at the end")
            .0
    }

    /// The body of the `AdmittedPlan` declaration, plus the derives above it.
    fn admitted_plan_declaration() -> (&'static str, &'static str) {
        let (before, after) = production_source()
            .split_once("pub struct AdmittedPlan {")
            .expect("the type is declared in this file");
        let derives = before
            .rfind("#[derive(")
            .map(|at| &before[at..])
            .unwrap_or_default();
        let body = after
            .split_once("\n}")
            .expect("the declaration is brace-terminated")
            .0;
        (derives, body)
    }

    /// Every `impl ... for AdmittedPlan` line, i.e. trait impls on the type.
    fn trait_impls_on_admitted_plan() -> Vec<&'static str> {
        production_source()
            .lines()
            .map(str::trim_start)
            .filter(|line| line.starts_with("impl") && line.contains("for AdmittedPlan"))
            .collect()
    }

    #[test]
    fn an_admitted_plan_cannot_be_fabricated_outside_this_module() {
        // Downstream consumers — the share enforcer, the workload input gate —
        // treat a value of this type as proof that admission ran, so a caller
        // able to mint one has the authority admission was supposed to hold.
        // What stops them is a set of *absences* in this declaration, and an
        // absence is exactly what no runtime assertion can observe: the honest
        // form is a compile-fail test, and this workspace has no harness for
        // one. So the source is the assertion, and each branch below names the
        // public path it keeps closed.
        let (derives, body) = admitted_plan_declaration();

        // 1. No `pub` field: a struct literal needs every field named, and a
        //    private one makes the literal unwritable outside this module.
        //    Privacy also means no `&mut` reaches a field, so a caller holding
        //    a legitimately-admitted plan cannot afterwards push a service
        //    grant into it that admission never saw.
        for field in ["plan", "plan_id", "signer_id", "signed", "extensions"] {
            assert!(
                body.contains(&format!("\n    {field}: ")),
                "`AdmittedPlan.{field}` must stay private — a pub field is a forge"
            );
        }

        // 2. No derive that reconstitutes one: `Clone` would let a caller
        //    duplicate a legitimate plan (harmless alone, but it is the first
        //    half of clone-then-mutate), `Default` and `Deserialize` would
        //    each build one from nothing at all.
        for derive in ["Clone", "Default", "Deserialize", "Serialize"] {
            assert!(
                !derives.contains(derive),
                "`AdmittedPlan` must not derive {derive} — it is a second way to obtain one"
            );
        }

        // 3. No trait impl offering a conversion in: `From`/`TryFrom`, a
        //    hand-written `Default`, a `Deserialize` impl.
        assert!(
            trait_impls_on_admitted_plan().is_empty(),
            "no trait may be implemented for AdmittedPlan without re-checking \
             whether it hands out a construction path: {:?}",
            trait_impls_on_admitted_plan()
        );

        // 4. The one convenience constructor is compiled out of production.
        assert!(
            SOURCE.contains("#[cfg(test)]\n    pub(crate) fn for_test("),
            "the test constructor must stay `#[cfg(test)]` and crate-private"
        );

        // 5. And `finish_admission` is the only place that writes the literal.
        let literals = production_source().matches("Ok(AdmittedPlan {").count();
        assert_eq!(
            literals, 1,
            "exactly one production construction site, inside finish_admission"
        );
    }

    fn fixture_input(vm_name: &str) -> SynthesisInput<'_> {
        SynthesisInput {
            grants: None,
            stream_edges: Vec::new(),
            kernel_sha256: None,
            network_mode: Default::default(),
            ingress: Vec::new(),
            vm_name,
            tenant: None,
            backend_name: "firecracker",
            image_name: "img",
            image_sha256: FIXTURE_SHA,
            image_cosign_bundle: None,
            intent: None,
            seccomp_tier: PlanSeccompTier::Standard,
            network_policy_ref: None,
            fs_policy_ref: None,
            egress_policy_ref: None,
            tool_policy_ref: None,
            secret_release: SecretReleasePolicy::None,
            secrets: Vec::new(),
            audit_event_prefix: None,
            cpus: 1,
            mem_mib: 256,
            disk_mib: 0,
            boot_timeout_secs: 30,
            destroy_on_exit: true,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            caller_commitment: None,
            audit_labels: Default::default(),
            agent_verbs: None,
            services: Vec::new(),
            extensions: Vec::new(),
            stream_retention: Default::default(),
            attestation_mode: mvm_contract::plan::AttestationMode::Noop,
        }
    }

    fn extension_binding(
        placement: mvm_contract::protocol::extension_pack::ExtensionPlacement,
    ) -> mvm_contract::protocol::extension_pack::ExtensionPlanBinding {
        mvm_contract::protocol::extension_pack::ExtensionPlanBinding {
            extension_id: mvm_contract::protocol::extension_pack::ExtensionId::parse(
                "org.example.generic-extension",
            )
            .expect("valid fixture extension id"),
            version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse("1.0.0")
                .expect("valid fixture extension version"),
            pack_digest: [7; 32],
            contract_digest: [8; 32],
            placement,
            artifact: "extension.ext4".to_string(),
            entrypoint: "bin/extension".to_string(),
            capabilities: vec![mvm_contract::assurance::probe_capability_descriptor().binding()],
            budgets: mvm_contract::protocol::extension_pack::ExtensionBudgets {
                cpu_millis: 500,
                memory_bytes: 128 * 1024 * 1024,
                duration_ms: 30_000,
                max_steps: 12,
                max_concurrency: 1,
                max_payload_bytes: 16 * 1024,
                max_output_bytes: 16 * 1024,
                max_artifact_bytes: 1024 * 1024,
            },
        }
    }

    fn extension_contract(
        binding: &mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
    ) -> mvm_contract::protocol::extension_pack::ExtensionPackContract {
        mvm_contract::protocol::extension_pack::ExtensionPackContract {
            schema: mvm_contract::protocol::extension_pack::EXTENSION_PACK_SCHEMA.to_string(),
            extension_id: binding.extension_id.clone(),
            version: binding.version.clone(),
            protocol: mvm_contract::protocol::extension_pack::ExtensionProtocolRange {
                min_mvm_version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse(
                    "0.18.0",
                )
                .expect("valid minimum extension version"),
                max_mvm_version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse(
                    "0.18.9",
                )
                .expect("valid maximum extension version"),
                min_protocol: 1,
                max_protocol: 1,
            },
            placement: binding.placement,
            artifact: binding.artifact.clone(),
            entrypoint: binding.entrypoint.clone(),
            capabilities: vec![mvm_contract::assurance::probe_capability_descriptor()],
            budgets: binding.budgets,
            revocation_identity: "org.example.generic-extension.release".to_string(),
            permission_delta: "May execute one declared assurance probe.".to_string(),
        }
    }

    fn admitted_with_extension(
        binding: mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
        root: &std::path::Path,
    ) -> AdmittedPlan {
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .extensions(vec![binding.clone()])
            .build();
        let signer_id = "host:extension-test".to_string();
        let signed = mvm_core::plan::signing::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[31; 32]),
            &signer_id,
        );
        let mut admitted = AdmittedPlan::for_test(plan, signer_id, signed);
        admitted.extensions.push(AdmittedExtension {
            binding,
            root: root.to_path_buf(),
        });
        admitted
    }

    #[test]
    fn extension_budget_comparison_requires_every_dimension() {
        let maximum = extension_binding(
            mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
        )
        .budgets;
        assert!(budgets_are_narrower(maximum, maximum));

        let mut candidates = Vec::new();
        let mut candidate = maximum;
        candidate.cpu_millis += 1;
        candidates.push(candidate);
        let mut candidate = maximum;
        candidate.memory_bytes += 1;
        candidates.push(candidate);
        let mut candidate = maximum;
        candidate.duration_ms += 1;
        candidates.push(candidate);
        let mut candidate = maximum;
        candidate.max_steps += 1;
        candidates.push(candidate);
        let mut candidate = maximum;
        candidate.max_concurrency += 1;
        candidates.push(candidate);
        let mut candidate = maximum;
        candidate.max_payload_bytes += 1;
        candidates.push(candidate);
        let mut candidate = maximum;
        candidate.max_output_bytes += 1;
        candidates.push(candidate);
        let mut candidate = maximum;
        candidate.max_artifact_bytes += 1;
        candidates.push(candidate);

        for candidate in candidates {
            assert!(
                !budgets_are_narrower(candidate, maximum),
                "one widened budget dimension must refuse the whole binding"
            );
        }
    }

    #[test]
    fn extension_binding_identity_requires_every_verified_field() {
        let mut binding = extension_binding(
            mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
        );
        let contract = extension_contract(&binding);
        let contract_digest: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&contract).expect("encode extension contract fixture"),
        )
        .into();
        binding.contract_digest = contract_digest;
        assert!(extension_binding_matches_contract(
            &binding,
            &contract,
            contract_digest
        ));

        let mut mismatches = Vec::new();
        let mut mismatch = binding.clone();
        mismatch.extension_id =
            mvm_contract::protocol::extension_pack::ExtensionId::parse("org.example.other")
                .expect("valid alternate extension id");
        mismatches.push(mismatch);
        let mut mismatch = binding.clone();
        mismatch.version = mvm_contract::protocol::extension_pack::ExtensionVersion::parse("1.0.1")
            .expect("valid alternate extension version");
        mismatches.push(mismatch);
        let mut mismatch = binding.clone();
        mismatch.contract_digest[0] ^= 1;
        mismatches.push(mismatch);
        let mut mismatch = binding.clone();
        mismatch.placement =
            mvm_contract::protocol::extension_pack::ExtensionPlacement::IsolatedController;
        mismatches.push(mismatch);
        let mut mismatch = binding.clone();
        mismatch.artifact.push_str(".other");
        mismatches.push(mismatch);
        let mut mismatch = binding.clone();
        mismatch.entrypoint.push_str("-other");
        mismatches.push(mismatch);

        for mismatch in mismatches {
            assert!(
                !extension_binding_matches_contract(&mismatch, &contract, contract_digest),
                "one mismatched identity field must refuse the whole binding"
            );
        }
    }

    #[test]
    fn extension_artifact_budget_is_inclusive_at_the_exact_limit() {
        assert!(!extension_artifact_exceeds_budget(7, 8));
        assert!(!extension_artifact_exceeds_budget(8, 8));
        assert!(extension_artifact_exceeds_budget(9, 8));
    }

    #[test]
    fn extension_attachment_sets_plan_identity_and_refuses_controller_placement() {
        let root = tempfile::tempdir().expect("extension root");
        let guest_binding = extension_binding(
            mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
        );
        let admitted = admitted_with_extension(guest_binding.clone(), root.path());
        let mut config = mvm_core::vm_backend::VmStartConfig::default();
        attach_admitted_extensions(&mut config, &admitted)
            .expect("an admitted guest extension attaches");
        assert_eq!(
            config.extension_plan_id.as_deref(),
            Some(admitted.plan_id().0.as_str())
        );
        assert_eq!(config.extensions, vec![guest_binding]);
        assert_eq!(config.volumes.len(), 1);
        let error = attach_admitted_extensions(&mut config, &admitted)
            .expect_err("the same guest mountpoint must not attach twice");
        assert!(error.to_string().contains("mountpoint collision"));

        let controller_binding = extension_binding(
            mvm_contract::protocol::extension_pack::ExtensionPlacement::IsolatedController,
        );
        let admitted = admitted_with_extension(controller_binding, root.path());
        let error = attach_admitted_extensions(
            &mut mvm_core::vm_backend::VmStartConfig::default(),
            &admitted,
        )
        .expect_err("a controller extension must never reach guest attachment");
        assert!(error.to_string().contains("isolated_controller"));
    }

    #[test]
    fn assurance_proxy_attachment_refuses_a_duplicate_service() {
        let proxy = mvm_contract::protocol::broker_control::ServiceProxyBinding {
            service: mvm_contract::protocol::broker::ServiceId::parse(
                mvm_contract::assurance::HOST_ASSURANCE_SERVICE,
            )
            .expect("valid assurance service"),
            endpoint: "/tmp/mvm-assurance-test.sock".to_string(),
            capabilities: vec![mvm_contract::assurance::probe_capability_descriptor()],
        };
        let mut config = mvm_core::vm_backend::VmStartConfig::default();
        config.service_proxies.push(proxy.clone());
        let error = attach_assurance_proxy(&mut config, proxy)
            .expect_err("the same controller service must not be attached twice");
        assert!(error.to_string().contains("already configured"));
    }

    #[test]
    fn extension_binding_requires_the_signed_dispatch_verb() {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .services(vec![
                mvm_contract::protocol::broker::ServiceId::parse(
                    mvm_contract::assurance::HOST_ASSURANCE_SERVICE,
                )
                .expect("valid fixture service"),
            ])
            .extensions(vec![extension_binding(
                mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
            )])
            .build();

        let error = validate_extension_bindings(&plan)
            .expect_err("an extension plan without the dispatch verb must be refused");
        assert!(error.to_string().contains("run-extension"));

        plan.agent_verbs = Some(vec![
            mvm_contract::plan::VerbId::new("run-extension").expect("valid fixture verb"),
        ]);
        let error = validate_extension_bindings(&plan)
            .expect_err("an extension plan without the cancellation verb must be refused");
        assert!(error.to_string().contains("cancel-extension"));

        plan.agent_verbs = Some(vec![
            mvm_contract::plan::VerbId::new("run-extension").expect("valid fixture verb"),
            mvm_contract::plan::VerbId::new("cancel-extension").expect("valid fixture verb"),
        ]);
        validate_extension_bindings(&plan).expect("the exact signed verb admits dispatch");
    }

    #[test]
    fn unsupported_extension_placement_fails_closed() {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .services(vec![
                mvm_contract::protocol::broker::ServiceId::parse(
                    mvm_contract::assurance::HOST_ASSURANCE_SERVICE,
                )
                .expect("valid fixture service"),
            ])
            .extensions(vec![extension_binding(
                mvm_contract::protocol::extension_pack::ExtensionPlacement::IsolatedController,
            )])
            .build();
        plan.agent_verbs = Some(vec![
            mvm_contract::plan::VerbId::new("run-extension").expect("valid fixture verb"),
            mvm_contract::plan::VerbId::new("cancel-extension").expect("valid fixture verb"),
        ]);

        let error = validate_extension_bindings(&plan)
            .expect_err("an unimplemented placement must never fall through to guest dispatch");
        assert!(error.to_string().contains("not executable"));
    }

    /// A musl guest cannot load the glibc cdylib, and the failure would
    /// otherwise land inside the guest at `dlopen` time as a relocation error
    /// naming a symbol the operator never heard of. Refuse on the host, where
    /// the cause can be named.
    /// Stage a rootfs whose `mvm-meta.json` records `libc`, and hand back the
    /// rootfs path the launch would boot.
    fn rootfs_recording_libc(dir: &std::path::Path, libc: GuestLibc) -> String {
        let sidecar = mvm_build::builder_vm::GuestSidecar::for_oci_run("fixture", false, false)
            .with_libc(libc);
        sidecar.write_to_dir(dir).expect("write mvm-meta.json");
        dir.join("rootfs.ext4").to_string_lossy().into_owned()
    }

    /// The launch-shaped entry point reads the image's libc off the rootfs
    /// rather than taking it on trust, so a caller cannot pass a libc that
    /// disagrees with the image it is about to boot.
    #[test]
    fn the_launch_gate_reads_the_libc_off_the_rootfs_it_is_given() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = plan_binding(&["host.kv.v1"]);

        let musl_rootfs = rootfs_recording_libc(dir.path(), GuestLibc::Musl);
        enforce_sdk_sidecar_for_launch(
            &musl_rootfs,
            &[sdk_sidecar_volume_for(GuestLibc::Musl)],
            &plan,
        )
        .expect("a musl image may load the musl sidecar");

        let err = enforce_sdk_sidecar_for_launch(
            &musl_rootfs,
            &[sdk_sidecar_volume_for(GuestLibc::Glibc)],
            &plan,
        )
        .expect_err("a musl image must not receive the glibc sidecar");
        let msg = err.to_string();
        assert!(msg.contains("musl") && msg.contains("glibc"), "{msg}");
    }

    /// A rootfs with no sidecar beside it records nothing, and an image whose
    /// libc cannot be established is refused rather than assumed loadable.
    #[test]
    fn the_launch_gate_refuses_an_image_recording_no_libc() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = plan_binding(&["host.kv.v1"]);
        let rootfs = dir
            .path()
            .join("rootfs.ext4")
            .to_string_lossy()
            .into_owned();

        let err = enforce_sdk_sidecar_for_launch(
            &rootfs,
            &[sdk_sidecar_volume_for(GuestLibc::Musl)],
            &plan,
        )
        .expect_err("an image of unknown libc must not receive a sidecar");

        assert!(
            err.to_string().contains("records no libc"),
            "the refusal must say the image is the unknown side: {err}"
        );
    }

    /// A sidecar whose path carries no libc segment cannot be identified, and
    /// an unidentifiable variant is refused rather than assumed to match. Any
    /// path this layout did not write reads that way — the check is on what the
    /// launch config presents, not on where it came from.
    #[test]
    fn a_sidecar_filed_under_no_libc_is_refused() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let plan = plan_binding(&["host.kv.v1"]);
        let unkeyed = VmVolume {
            host: "/cache/sdk-sidecar/1.2.3/aarch64/sdk.ext4".into(),
            guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
            read_only: true,
            kind: VmVolumeKind::Disk,
            ..Default::default()
        };

        let err = enforce_sdk_sidecar_attachment(&[unkeyed], &plan, GuestLibc::Musl)
            .expect_err("a sidecar of unknown variant must not be attached");

        assert!(
            err.to_string().contains("sdk-sidecar build"),
            "the refusal must say how to repopulate the cache: {err}"
        );
    }

    #[test]
    fn a_sidecar_the_guest_cannot_load_is_refused_before_boot() {
        let plan = plan_binding(&["host.kv.v1"]);
        let err = enforce_sdk_sidecar_attachment(
            &[sdk_sidecar_volume_for(GuestLibc::Glibc)],
            &plan,
            GuestLibc::Musl,
        )
        .expect_err("a musl image must not receive the glibc sidecar");
        let msg = err.to_string();
        assert!(msg.contains("musl"), "must name the image's libc: {msg}");
        assert!(msg.contains("glibc"), "must name the sidecar's libc: {msg}");
        assert!(
            msg.contains("host.kv.v1"),
            "must name the binding that asked for it: {msg}"
        );
    }

    /// Unknown is the arm a permissive default would wave through. It covers an
    /// image materialized before mvm recorded the libc, so the message has to
    /// say how to make it known rather than just refusing.
    #[test]
    fn an_unknown_libc_is_refused_and_says_how_to_resolve_it() {
        let plan = plan_binding(&["host.kv.v1"]);
        let err = enforce_sdk_sidecar_attachment(
            &[sdk_sidecar_volume()],
            &plan,
            mvm_build::guest_libc::GuestLibc::Unknown,
        )
        .expect_err("an unrecorded libc must not be attached on a guess");
        let msg = err.to_string();
        assert!(
            msg.contains("re-pull or rebuild"),
            "must name the remedy: {msg}"
        );
    }

    /// The libc gate must sit behind the binding check: a workload that binds
    /// no SDK service carries no sidecar, so its libc is irrelevant and must
    /// not refuse the boot.
    #[test]
    fn an_unbound_workload_is_unaffected_by_its_libc() {
        let plan = plan_binding(&[]);
        assert!(
            enforce_sdk_sidecar_attachment(&[], &plan, mvm_build::guest_libc::GuestLibc::Unknown)
                .is_ok()
        );
    }

    /// The libc the shipped cdylib is built for. These tests assert attachment
    /// *shape* — count, read-only, kind — so they hold the libc loadable and
    /// let the dedicated libc tests vary it.
    /// One libc for both sides of the admission fixtures: what the image
    /// records and what the sidecar was filed under have to agree for the
    /// attachment to be admissible, and these tests are about the other rules.
    const LOADABLE_LIBC: GuestLibc = GuestLibc::Musl;

    /// A sidecar volume shaped the way the resolver actually hands one over:
    /// filed under its libc, because that segment is where the gate reads the
    /// variant from. A path without it is not a lesser fixture, it is a
    /// different case — covered by
    /// `a_sidecar_filed_under_no_libc_is_refused`.
    fn sdk_sidecar_volume() -> mvm_core::vm_backend::VmVolume {
        sdk_sidecar_volume_for(LOADABLE_LIBC)
    }

    /// The same volume filed under an arbitrary libc, so a test can state both
    /// sides of the comparison instead of leaning on which one the shared
    /// fixture happens to use.
    fn sdk_sidecar_volume_for(libc: GuestLibc) -> mvm_core::vm_backend::VmVolume {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        VmVolume {
            host: format!(
                "/cache/sdk-sidecar/1.2.3/aarch64/{}/sdk.ext4",
                libc.as_str()
            ),
            guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
            read_only: true,
            kind: VmVolumeKind::Disk,
            ..Default::default()
        }
    }

    fn plan_binding(services: &[&str]) -> ExecutionPlan {
        let mut input = fixture_input("vm-sdk");
        input.services = services
            .iter()
            .map(|s| {
                mvm_contract::protocol::broker::ServiceId::parse(*s).expect("fixture service id")
            })
            .collect();
        synthesize_plan(&input).expect("fixture plan synthesizes")
    }

    struct FixedClock(DateTime<Utc>);

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// Claim 1: a volume that the signed plan didn't admit — or that
    /// mismatches the admitted ro/rw — is refused before launch.
    /// Materializing a granted directory must not change what it has to be
    /// granted *as*.
    ///
    /// `enforce_admitted_shares` is the trust-boundary hook for claim 1: a
    /// volume reaches a guest only if the signed plan admitted that exact
    /// host path, guest path and kind. `--mount` now attaches an ext4 image
    /// rather than the directory, and the volume records which image in
    /// `materialized_image` — but `host` stays the directory that was
    /// granted, so the grant still matches.
    ///
    /// This is not cosmetic. Had the materialized mount become a `Disk` whose
    /// `host` was the image under `~/.mvm`, this check would compare that path
    /// against the granted directory and refuse the boot. The field exists so
    /// the transport can change without the grant changing.
    #[test]
    fn a_materialized_grant_still_satisfies_the_directory_share_it_was_granted_as() {
        let grant = mvm_core::plan::HostShareGrant {
            tag: "uvol0".into(),
            host_path: "/h/src".into(),
            guest_path: "/data".into(),
            kind: mvm_core::plan::ShareKind::DirShare,
            read_only: true,
            encrypted: false,
            content_sha256: None,
        };
        let mut input = fixture_input("vm-materialized-share");
        input.shares = vec![grant];
        let plan = synthesize_plan(&input).unwrap();

        let materialized = mvm_core::vm_backend::VmVolume {
            host: "/h/src".into(),
            guest: "/data".into(),
            read_only: true,
            materialized_image: Some("/state/mount-0.ext4".into()),
            volume_label: None,
            ..Default::default()
        };
        enforce_admitted_shares(std::slice::from_ref(&materialized), &plan)
            .expect("a materialized grant is still the grant that was admitted");

        // And the image path is not what is checked: a volume claiming a host
        // path nobody granted is refused whatever it materialized into.
        let ungranted = mvm_core::vm_backend::VmVolume {
            host: "/state/mount-0.ext4".into(),
            ..materialized.clone()
        };
        assert!(
            enforce_admitted_shares(std::slice::from_ref(&ungranted), &plan).is_err(),
            "only the granted host path may reach a guest"
        );

        let mut disk_input = fixture_input("vm-materialized-share-as-disk");
        disk_input.shares = vec![mvm_core::plan::HostShareGrant {
            tag: "uvol0".into(),
            host_path: "/h/src".into(),
            guest_path: "/data".into(),
            kind: mvm_core::plan::ShareKind::Disk,
            read_only: true,
            encrypted: false,
            content_sha256: None,
        }];
        let disk_plan = synthesize_plan(&disk_input).expect("synthesize disk plan");
        assert!(
            enforce_admitted_shares(std::slice::from_ref(&materialized), &disk_plan).is_err(),
            "a materialized directory must not satisfy a disk grant"
        );
    }

    #[test]
    fn admitted_share_digest_refuses_directory_changed_after_admission() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("rows.csv"), b"a,b\n1,2\n").expect("write");

        let digest = mvm_fs::hash::hash_source(&data).expect("hash admitted tree");
        let grant = mvm_core::plan::HostShareGrant {
            tag: "uvol0".into(),
            host_path: data.to_string_lossy().into_owned(),
            guest_path: "/data".into(),
            kind: mvm_core::plan::ShareKind::DirShare,
            read_only: true,
            encrypted: false,
            content_sha256: Some(digest.clone()),
        };
        let mut input = fixture_input("vm-share-digest-drift");
        input.shares = vec![grant];
        let plan = synthesize_plan(&input).expect("synthesize");

        let volume = |host: &str| mvm_core::vm_backend::VmVolume {
            host: host.into(),
            guest: "/data".into(),
            read_only: true,
            materialized_image: Some("/state/mount-0.ext4".into()),
            ..Default::default()
        };

        // Unchanged tree: the admitted identity still matches.
        enforce_admitted_shares(
            std::slice::from_ref(&volume(&plan.shares[0].host_path)),
            &plan,
        )
        .expect("unchanged tree attaches");

        // A byte flips between admission and attach: refused, and the error
        // names both identities.
        std::fs::write(data.join("rows.csv"), b"a,b\n1,TAMPERED\n").expect("tamper");
        let err = enforce_admitted_shares(
            std::slice::from_ref(&volume(&plan.shares[0].host_path)),
            &plan,
        )
        .expect_err("a changed tree must not attach under the admitted identity");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&digest),
            "error names the admitted digest: {msg}"
        );
        assert!(
            msg.contains("changed after admission"),
            "error says why: {msg}"
        );
    }

    #[test]
    fn enforce_admitted_shares_refuses_unadmitted_or_mismatched() {
        use mvm_core::vm_backend::VmVolume;
        let grant = mvm_core::plan::HostShareGrant {
            tag: "uvol0".into(),
            host_path: "/h/src".into(),
            guest_path: "/data".into(),
            kind: mvm_core::plan::ShareKind::DirShare,
            read_only: true,
            encrypted: false,
            content_sha256: None,
        };
        let mut input = fixture_input("vm-shares");
        input.shares = vec![grant];
        let plan = synthesize_plan(&input).unwrap();

        let admitted_vol = VmVolume {
            host: "/h/src".into(),
            guest: "/data".into(),
            read_only: true,
            materialized_image: Some("/state/mount-0.ext4".into()),
            ..Default::default()
        };
        // The exact admitted volume passes.
        assert!(enforce_admitted_shares(std::slice::from_ref(&admitted_vol), &plan).is_ok());

        // A volume the plan never named is refused.
        let unadmitted = VmVolume {
            host: "/etc".into(),
            guest: "/data".into(),
            read_only: true,
            materialized_image: Some("/state/mount-1.ext4".into()),
            ..Default::default()
        };
        assert!(enforce_admitted_shares(&[unadmitted], &plan).is_err());

        // Same path/kind, but read-WRITE when the plan admitted read-only:
        // an unauthorized escalation, refused.
        let escalated = VmVolume {
            read_only: false,
            ..admitted_vol
        };
        assert!(enforce_admitted_shares(&[escalated], &plan).is_err());
    }

    /// A workload that binds no SDK host service gets no sidecar, and nothing
    /// may attach one behind the plan's back.
    #[test]
    fn no_sdk_binding_means_no_sidecar_attachment() {
        let plan = plan_binding(&[]);
        assert!(enforce_sdk_sidecar_attachment(&[], &plan, LOADABLE_LIBC).is_ok());

        let err = enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan, LOADABLE_LIBC)
            .expect_err("an unauthorized sidecar must be refused");
        let msg = err.to_string();
        assert!(msg.contains("binds no SDK host service"), "{msg}");
    }

    /// An unrelated host-service binding is not an SDK binding: it must not pull
    /// the glibc sidecar into an ordinary workload.
    #[test]
    fn unrelated_service_binding_does_not_require_the_sidecar() {
        let plan = plan_binding(&["broker.v1", "host.other.v1"]);
        assert!(enforce_sdk_sidecar_attachment(&[], &plan, LOADABLE_LIBC).is_ok());
        assert!(
            enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan, LOADABLE_LIBC).is_err()
        );
    }

    /// A bound SDK host service with the sidecar attached read-only is admitted.
    #[test]
    fn sdk_binding_with_a_read_only_sidecar_is_admitted() {
        for service in mvm_core::plan::SDK_HOST_SERVICES {
            let plan = plan_binding(&[service]);
            assert!(
                enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan, LOADABLE_LIBC)
                    .is_ok(),
                "{service} bound + sidecar attached read-only must be admitted"
            );
        }
    }

    /// Wasm has neither block devices nor a native dynamic loader, so the
    /// ext4-hosted SDK cdylib cannot reach that tier. Refuse in terms of the
    /// requested service before the backend leaks a synthetic disk-volume
    /// implementation detail.
    #[test]
    fn wasm_sdk_binding_is_refused_at_the_delivery_seam() {
        let plan = plan_binding(&["host.time.v1"]);
        let err = enforce_sdk_sidecar_backend_compatibility(
            mvm_core::vm_backend::BackendKind::Wasm,
            &plan,
        )
        .expect_err("wasm cannot receive or load the SDK sidecar");
        let msg = err.to_string();
        assert!(msg.contains("wasm"), "{msg}");
        assert!(msg.contains("host.time.v1"), "{msg}");
        assert!(msg.contains("SDK host service"), "{msg}");
        assert!(!msg.contains("DiskVolumeNotSupported"), "{msg}");
    }

    #[test]
    fn microvm_backend_keeps_the_sdk_sidecar_delivery_path() {
        let plan = plan_binding(&["host.time.v1"]);
        assert!(
            enforce_sdk_sidecar_backend_compatibility(
                mvm_core::vm_backend::BackendKind::Firecracker,
                &plan,
            )
            .is_ok()
        );
    }

    #[test]
    fn direct_protocol_binding_requires_no_sidecar_and_refuses_a_stray_one() {
        let mut plan = plan_binding(&["host.kv.v1"]);
        plan.sdk_uses_sidecar = false;

        assert!(
            enforce_sdk_sidecar_backend_compatibility(
                mvm_core::vm_backend::BackendKind::Wasm,
                &plan,
            )
            .is_ok()
        );
        assert!(enforce_sdk_sidecar_attachment(&[], &plan, LOADABLE_LIBC).is_ok());

        let err = enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan, LOADABLE_LIBC)
            .expect_err("a direct-protocol plan must refuse a stray sidecar");
        assert!(err.to_string().contains("sdk_uses_sidecar=false"), "{err}");
    }

    /// A bound SDK host service with no sidecar attachment fails closed, and the
    /// message names the binding that demanded it without leaking file bytes.
    #[test]
    fn sdk_binding_without_the_sidecar_fails_closed() {
        let plan = plan_binding(&["host.secrets.v1"]);
        let err = enforce_sdk_sidecar_attachment(&[], &plan, LOADABLE_LIBC)
            .expect_err("a required-but-absent sidecar must refuse the launch");
        let msg = err.to_string();
        assert!(msg.contains("host.secrets.v1"), "{msg}");
        assert!(
            msg.contains(mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
            "{msg}"
        );
    }

    /// The sidecar is read-only by contract: a writable or directory-share
    /// attachment at the sidecar mount point is a different, unadmitted shape.
    #[test]
    fn a_writable_or_dir_share_sidecar_fails_closed() {
        let plan = plan_binding(&["host.audit.v1"]);

        let writable = mvm_core::vm_backend::VmVolume {
            read_only: false,
            ..sdk_sidecar_volume()
        };
        let err = enforce_sdk_sidecar_attachment(&[writable], &plan, LOADABLE_LIBC)
            .expect_err("rw refused");
        assert!(err.to_string().contains("read-only"), "{err}");

        let share = mvm_core::vm_backend::VmVolume {
            materialized_image: Some("/state/mount.ext4".to_string()),
            ..sdk_sidecar_volume()
        };
        let err = enforce_sdk_sidecar_attachment(&[share], &plan, LOADABLE_LIBC)
            .expect_err("share refused");
        assert!(err.to_string().contains("disk image"), "{err}");
    }

    /// Two attachments racing for the same mount point is ambiguous — refuse
    /// rather than let mount order decide which cdylib the workload loads.
    #[test]
    fn duplicate_sidecar_attachments_fail_closed() {
        let plan = plan_binding(&["host.time.v1"]);
        let dup = [sdk_sidecar_volume(), sdk_sidecar_volume()];
        let err = enforce_sdk_sidecar_attachment(&dup, &plan, LOADABLE_LIBC)
            .expect_err("duplicates refused");
        assert!(err.to_string().contains("exactly one"), "{err}");
    }

    /// Unrelated volumes are untouched by the sidecar gate in either direction.
    #[test]
    fn unrelated_volumes_are_ignored_by_the_sidecar_gate() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let other = VmVolume {
            host: "/h/data.img".into(),
            guest: "/data".into(),
            read_only: false,
            kind: VmVolumeKind::Disk,
            ..Default::default()
        };
        assert!(
            enforce_sdk_sidecar_attachment(
                std::slice::from_ref(&other),
                &plan_binding(&[]),
                LOADABLE_LIBC
            )
            .is_ok()
        );
        let bound = plan_binding(&["host.cost.v1"]);
        assert!(
            enforce_sdk_sidecar_attachment(
                &[other.clone(), sdk_sidecar_volume()],
                &bound,
                LOADABLE_LIBC
            )
            .is_ok()
        );
        assert!(
            enforce_sdk_sidecar_attachment(std::slice::from_ref(&other), &bound, LOADABLE_LIBC)
                .is_err(),
            "an unrelated volume must not satisfy the sidecar requirement"
        );
    }

    /// The signed plan round-trips its service bindings, so the gate decides on
    /// the same bytes the signature covers.
    #[test]
    fn service_bindings_survive_plan_serialization() {
        let plan = plan_binding(&["host.audit.v1", "broker.v1"]);
        let json = serde_json::to_string(&plan).expect("plan serializes");
        let back: ExecutionPlan = serde_json::from_str(&json).expect("plan round-trips");
        assert_eq!(back.services, plan.services);
        assert!(mvm_core::plan::sdk_sidecar_required(&back));
        assert!(
            enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &back, LOADABLE_LIBC).is_ok()
        );
    }

    // ---- grants: the ceiling, and what the tier can actually enforce ----

    /// Isolate `MVM_HOME` and write an operator config carrying `ceiling`.
    ///
    /// Admission reads the ceiling from host config rather than from a
    /// parameter, so a test that wants a bounded host has to *be* one. Every
    /// test that reaches `admit_for_run` or `admit_and_start` must hold the
    /// returned guard, including tests using the default ceiling; otherwise it
    /// can observe another parallel test's process-wide `MVM_HOME`. The guard
    /// and home dir must both outlive the admission call.
    fn host_with_ceiling(
        ceiling: mvm_contract::grants::ceiling::GrantCeiling,
    ) -> (mvm_core::util::test_env::TestEnv, tempfile::TempDir) {
        let home = tempfile::tempdir().expect("scratch mvm home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let cfg = mvm_core::user_config::MvmConfig {
            max_cpu_millicores: ceiling.max_cpu_millicores,
            max_memory_mib: ceiling.max_memory_mib,
            max_wall_clock_secs: ceiling.max_wall_clock_secs,
            ..mvm_core::user_config::MvmConfig::default()
        };
        mvm_core::user_config::save(&cfg, None).expect("writing the host config");
        // Precondition, not a redundant assertion: if this fails the isolation
        // did not hold, and every ceiling assertion below would then be
        // measuring some other directory's config.
        assert_eq!(
            mvm_core::user_config::load(None).grant_ceiling(),
            ceiling,
            "the isolated host must read back the ceiling it was configured with"
        );
        (env, home)
    }

    /// Run `f` with a subscriber installed, returning its value and everything
    /// that was logged.
    ///
    /// A test that only asserts "admitted" cannot tell a warned admission from
    /// a silent one, and the difference is the whole dev half of the rule.
    fn capturing_warnings<T>(f: impl FnOnce() -> T) -> (T, String) {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Sink(Arc<Mutex<Vec<u8>>>);

        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("log sink poisoned")
                    .extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Self;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let sink = Sink(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let value = tracing::subscriber::with_default(subscriber, f);
        let logged = String::from_utf8(sink.0.lock().expect("log sink poisoned").clone())
            .expect("log output is utf-8");
        (value, logged)
    }

    fn cpu_share(millicores: u32) -> mvm_contract::grants::Grants {
        mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores }),
            ..mvm_contract::grants::Grants::default()
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_cpu_mechanism_gap_honors_hvf_quota_range() {
        // On macOS the HVF tier serves CPU shares through its own scheduler.
        // A share outside the scheduler's range is a missing mechanism; a
        // share inside the range is enforceable.
        assert!(
            host_cpu_mechanism_gap(&cpu_share(1500), BackendKind::Hvf, None).is_some(),
            "1500 millicores is out of range and must be reported as unenforceable"
        );
        assert!(
            host_cpu_mechanism_gap(&cpu_share(500), BackendKind::Hvf, None).is_none(),
            "500 millicores is inside the scheduler range and is enforceable"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn prod_admits_a_valid_hvf_cpu_share() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let keys = tempfile::tempdir().unwrap();

        let mut input = fixture_input("vm-hvf-valid-share");
        input.backend_name = "hvf";
        input.grants = Some(cpu_share(500));

        admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::on_backend(Variant::Prod, BackendKind::Hvf),
        )
        .expect("a 500 millicore share is enforceable on HVF");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_cpu_mechanism_gap_requires_a_share_capable_tier_and_a_reported_gap() {
        use mvm_core::cpu_scope::MechanismGap;

        let missing_bus = Some(MechanismGap::NoUserSessionBus);
        assert_eq!(
            host_cpu_mechanism_gap(
                &mvm_contract::grants::Grants::default(),
                BackendKind::Firecracker,
                missing_bus,
            ),
            None,
            "a plan with no CPU share has no CPU mechanism gap"
        );
        assert_eq!(
            host_cpu_mechanism_gap(&cpu_share(1000), BackendKind::Wasm, missing_bus),
            None,
            "a tier whose CPU control is not a cgroup share does not use the host mechanism"
        );
        assert_eq!(
            host_cpu_mechanism_gap(&cpu_share(1000), BackendKind::Firecracker, None),
            None,
            "an available host mechanism leaves no gap"
        );

        let detail =
            host_cpu_mechanism_gap(&cpu_share(1000), BackendKind::Firecracker, missing_bus)
                .expect("a missing mechanism must be reported for a share-capable tier");
        assert!(detail.contains("no user session bus"), "{detail}");
    }

    #[test]
    fn admission_refuses_a_grant_over_the_ceiling() {
        let (_env, _home) = host_with_ceiling(mvm_contract::grants::ceiling::GrantCeiling {
            max_cpu_millicores: Some(2000),
            ..Default::default()
        });
        let keys = tempfile::tempdir().unwrap();

        let mut input = fixture_input("vm-over-ceiling");
        input.grants = Some(cpu_share(64_000));

        let err = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect_err("a grant above the host's ceiling must not be admitted");
        let msg = err.to_string();
        assert!(msg.contains("ceiling"), "{msg}");
        assert!(msg.contains("64000") && msg.contains("2000"), "{msg}");

        // Under the same ceiling, a request within it still admits — otherwise
        // this test would pass on a gate that refuses everything.
        let mut within = fixture_input("vm-under-ceiling");
        within.grants = Some(cpu_share(1500));
        admit_for_run(
            &within,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("a grant inside the ceiling admits");
    }

    #[test]
    fn admission_refuses_before_signing() {
        // Not "an error came back" — no *signature* may exist for a run we
        // refuse. The host signer is generated lazily on first use, so an
        // untouched keys dir is proof the keystore was never reached and
        // therefore that nothing was signed.
        let (_env, _home) = host_with_ceiling(mvm_contract::grants::ceiling::GrantCeiling {
            max_cpu_millicores: Some(2000),
            ..Default::default()
        });
        let keys = tempfile::tempdir().unwrap();
        let key_file = keys
            .path()
            .join(crate::audit::host_keypair::SECRET_FILENAME);

        let mut input = fixture_input("vm-refused-unsigned");
        input.grants = Some(cpu_share(64_000));
        let refused = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        );
        assert!(refused.is_err(), "the ceiling must refuse this run");
        assert!(
            !key_file.exists(),
            "the refusal path reached the keystore; a plan we would not admit \
             must never acquire a signature"
        );

        // The control: an admitted run does reach the keystore, so the
        // assertion above is about the refusal and not about a keys dir that
        // is never written under any outcome.
        admit_for_run(
            &fixture_input("vm-admitted-signed"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("an unbounded run admits");
        assert!(
            key_file.exists(),
            "an admitted run signs under the host key"
        );
    }

    #[test]
    fn prod_refuses_a_cpu_grant_on_a_backend_that_cannot_bound_cpu() {
        // The hvf tier has no cgroup equivalent on any host, so a CPU share is
        // a bound nothing behind it implements. The tier comes from the
        // posture — the backend in hand — not from the plan's label.
        let (_env, _home) = host_with_ceiling(Default::default());
        let keys = tempfile::tempdir().unwrap();

        let mut input = fixture_input("vm-prod-unenforceable");
        input.backend_name = "hvf";
        input.grants = Some(cpu_share(1500));

        let err = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::on_backend(Variant::Prod, BackendKind::Hvf),
        )
        .expect_err("a sealed run must not boot with a bound nothing enforces");
        let msg = err.to_string();
        assert!(msg.contains("unenforceable"), "{msg}");
        assert!(msg.contains("cpu.share"), "{msg}");
    }

    #[test]
    fn dev_warns_and_proceeds_on_the_same_input() {
        // Same tier, same grant, dev posture: admitted, because a laptop that
        // cannot bound CPU is where most development happens and refusing
        // there would only teach everyone to stop declaring grants.
        let (_env, _home) = host_with_ceiling(Default::default());
        let keys = tempfile::tempdir().unwrap();

        let mut input = fixture_input("vm-dev-unenforceable");
        input.backend_name = "hvf";
        input.grants = Some(cpu_share(1500));

        let (result, logs) = capturing_warnings(|| {
            admit_for_run(
                &input,
                &SystemClock,
                &InMemoryNonceLedger::new(),
                Some(keys.path()),
                None,
                RunPosture::on_backend(Variant::Dev, BackendKind::Hvf),
            )
        });
        let admitted = result.expect("a dev run proceeds with an unenforceable grant");
        assert_eq!(
            admitted.plan().grants.as_ref().map(|g| g.cpu),
            Some(Some(mvm_contract::grants::CpuGrant::Share {
                millicores: 1500
            })),
            "the declared grant rides in the signed plan even when unenforced"
        );

        // "Warns" is half of what this test's name promises, so it is asserted
        // rather than assumed: a silent admission would leave the operator with
        // a grant they believe is bounding something.
        assert!(
            logs.contains("WARN"),
            "the dev path must warn, not admit silently: {logs:?}"
        );
        assert!(
            logs.contains("cpu.share") && logs.contains("not enforced"),
            "the warning must name what went unenforced: {logs:?}"
        );

        // Posture is the only difference between this outcome and the refusal
        // above. Asserted against the gate directly as well, so a change that
        // makes the rule unconditional in either direction fails here and not
        // only in the prod witness.
        let plan = admitted.plan();
        let grants = cpu_share(1500);
        assert!(
            enforceability_gate(
                &grants,
                plan,
                RunPosture::on_backend(Variant::Prod, BackendKind::Hvf)
            )
            .is_err()
        );
        assert!(
            enforceability_gate(
                &grants,
                plan,
                RunPosture::on_backend(Variant::Dev, BackendKind::Hvf)
            )
            .is_ok()
        );
    }

    #[test]
    fn a_mismatched_profile_label_cannot_select_the_wrong_tier() {
        // A fuel grant is enforceable on the wasm tier and on no other. A plan
        // labelled `wasm` that is actually booting on hvf must not be admitted
        // on the strength of that label — the label is the plan author's
        // string, the tier is what will run.
        let (_env, _home) = host_with_ceiling(Default::default());
        let keys = tempfile::tempdir().unwrap();
        let fuel = mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Fuel {
                instructions: 1_000_000,
            }),
            ..mvm_contract::grants::Grants::default()
        };

        let mut mislabelled = fixture_input("vm-mislabelled");
        mislabelled.backend_name = "wasm";
        mislabelled.grants = Some(fuel.clone());
        let err = admit_for_run(
            &mislabelled,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::on_backend(Variant::Prod, BackendKind::Hvf),
        )
        .expect_err("the label must not buy admission for a tier that is not booting");
        let msg = err.to_string();
        assert!(msg.contains("runtime profile"), "{msg}");
        assert!(msg.contains("wasm") && msg.contains("hvf"), "{msg}");

        // Honest label, honest tier, and the same grant: still refused, because
        // hvf meters no instructions. The refusal follows the tier either way.
        let mut honest = fixture_input("vm-honest-label");
        honest.backend_name = "hvf";
        honest.grants = Some(fuel.clone());
        let err = admit_for_run(
            &honest,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::on_backend(Variant::Prod, BackendKind::Hvf),
        )
        .expect_err("no microVM tier counts instructions");
        assert!(err.to_string().contains("cpu.fuel"), "{err}");

        // And on the tier that does meter them, the same grant admits — so the
        // two refusals above are about the mechanism, not about fuel grants
        // being refused everywhere.
        let mut on_wasm = fixture_input("vm-on-wasm");
        on_wasm.backend_name = "wasm";
        on_wasm.grants = Some(fuel);
        admit_for_run(
            &on_wasm,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::on_backend(Variant::Prod, BackendKind::Wasm),
        )
        .expect("the wasm tier meters instructions, so a fuel grant is enforceable there");
    }

    #[test]
    fn a_run_admitted_without_a_backend_cannot_claim_its_grants_are_enforced() {
        // A caller with no backend object has nothing to measure against. That
        // must fail closed rather than fall back to the plan's own label, which
        // is how a mislabelled plan would pick its own controls.
        let (_env, _home) = host_with_ceiling(Default::default());
        let keys = tempfile::tempdir().unwrap();

        // `firecracker` is a tier that *can* bound a share on Linux, so a gate
        // reading the label would admit this on a host where that is true.
        let mut input = fixture_input("vm-no-backend");
        input.backend_name = "firecracker";
        input.grants = Some(cpu_share(1500));

        let err = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::without_backend(Variant::Prod),
        )
        .expect_err("an unmeasurable grant must not be admitted under a sealed posture");
        assert!(err.to_string().contains("without the backend"), "{err}");
    }

    #[test]
    fn a_profile_that_names_no_tier_is_not_treated_as_a_disagreement() {
        // `mvmctl exec` labels its plans `transient-run`; the lineage path uses
        // the workload's name. Neither is a backend, so neither can contradict
        // the backend in hand — refusing them as a mismatch would break real
        // paths over a string that never claimed to be a tier.
        let (_env, _home) = host_with_ceiling(Default::default());
        let keys = tempfile::tempdir().unwrap();

        let mut input = fixture_input("vm-transient");
        input.backend_name = "transient-run";
        input.grants = Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Fuel {
                instructions: 1_000_000,
            }),
            ..mvm_contract::grants::Grants::default()
        });

        admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::on_backend(Variant::Prod, BackendKind::Wasm),
        )
        .expect("the tier that boots meters instructions, whatever the profile is called");
    }

    #[test]
    fn a_run_that_grants_nothing_is_unaffected_by_the_tier_gate() {
        // The gate must stay silent for the overwhelmingly common case, or
        // every unbounded boot on a laptop becomes a warning.
        let (_env, _home) = host_with_ceiling(Default::default());
        let keys = tempfile::tempdir().unwrap();

        let mut input = fixture_input("vm-no-grants");
        input.backend_name = "hvf";
        admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::without_backend(Variant::Prod),
        )
        .expect("a run declaring no grant admits on any tier");
    }

    #[test]
    fn the_ceiling_bounds_memory_even_though_no_one_granted_it() {
        // Memory is fixed at VM creation rather than requested, so a plan that
        // declares no grants at all can still reserve the whole host.
        let (_env, _home) = host_with_ceiling(mvm_contract::grants::ceiling::GrantCeiling {
            max_memory_mib: Some(128),
            ..Default::default()
        });
        let keys = tempfile::tempdir().unwrap();

        let err = admit_for_run(
            &fixture_input("vm-fat"), // fixture asks for 256 MiB
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect_err("memory above the ceiling must be refused");
        assert!(err.to_string().contains("memory_mib"), "{err}");
    }

    #[test]
    fn happy_path_returns_admitted_plan_with_plan_id() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let clock = SystemClock;
        let ledger = InMemoryNonceLedger::new();
        let admitted = admit_for_run(
            &fixture_input("vm1"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("happy path");
        assert!(!admitted.plan_id().0.is_empty());
        assert!(admitted.signer_id().starts_with("host:"));
        // The signed envelope must be re-verifiable with the public
        // half of the host signer.
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
            [(admitted.signer_id(), &signer.verifying)];
        let recovered = mvm_core::plan::verify_plan(admitted.signed(), &trusted).unwrap();
        assert_eq!(&recovered.plan_id, admitted.plan_id());
    }

    #[test]
    fn admitted_plan_id_is_a_content_address() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let admitted = admit_for_run(
            &fixture_input("vm1"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("happy path");
        assert!(
            admitted.plan_id().0.starts_with("sha256:"),
            "content-addressed, not a UUID: {}",
            admitted.plan_id().0
        );
        // The admission path enforces the content-address; the admitted plan
        // re-derives to exactly its stored id.
        assert_eq!(mvm_core::plan::verify_plan_id(admitted.plan()), Ok(()));
    }

    #[test]
    fn rejects_replay_within_validity_window() {
        let dir = tempfile::tempdir().unwrap();
        // We can't naturally replay because synthesize_plan generates a
        // fresh nonce each call — instead, build the plan once, sign,
        // then ask the ledger to admit twice. The second call must
        // refuse with nonce-replay.
        let plan = synthesize_plan(&fixture_input("vm1")).unwrap();
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let signer_id = host_signer_id();
        let signed = sign_plan(&plan, &signer.signing, &signer_id);
        let verified =
            mvm_core::plan::verify_plan(&signed, &[(&signer_id, &signer.verifying)]).unwrap();

        let ledger = InMemoryNonceLedger::new();
        {
            let mut store = ledger.inner.lock().unwrap();
            assert!(store.check_and_insert(&signer_id, &verified).is_ok());
            assert!(
                store.check_and_insert(&signer_id, &verified).is_err(),
                "second insert of same (signer, nonce) must fail"
            );
        }
    }

    #[test]
    fn rejects_plan_outside_validity_window() {
        // Construct a fixed clock 30 minutes in the future — past
        // the plan's 10-minute window from synthesis.
        let now_plus_30 = Utc.with_ymd_and_hms(2099, 1, 1, 12, 30, 0).unwrap();
        // Override time by constructing a plan with a known window
        // and a FixedClock outside it.
        let dir = tempfile::tempdir().unwrap();
        // To exercise the window check deterministically, we
        // pre-build a stale signed plan and feed it directly through
        // the check (synthesize_plan can't make a stale plan because
        // it uses Utc::now()).
        let mut plan = synthesize_plan(&fixture_input("vm1")).unwrap();
        plan.valid_from = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
        plan.valid_until = Utc.with_ymd_and_hms(2000, 1, 1, 0, 10, 0).unwrap();
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let signed = sign_plan(&plan, &signer.signing, &host_signer_id());
        let verified = verify_plan(&signed, &[(&host_signer_id(), &signer.verifying)]).unwrap();
        let _clock = FixedClock(now_plus_30);
        // Inline the window check (admit_for_run does it after
        // synthesis; we're proving the underlying assert).
        assert!(check_window(&verified, now_plus_30).is_err());
    }

    #[test]
    fn admitted_plan_signed_field_round_trips_through_verify() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let admitted = admit_for_run(
            &fixture_input("vm1"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .unwrap();
        // The signed field is what the audit signer will hash;
        // proving it round-trips here closes the contract.
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
            [(admitted.signer_id(), &signer.verifying)];
        assert!(verify_plan(admitted.signed(), &trusted).is_ok());
    }

    #[test]
    fn propagates_synthesis_failures() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let err = admit_for_run(
            &fixture_input(""), // empty vm_name fails synthesis
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect_err("must refuse");
        assert!(
            err.to_string().contains("vm_name")
                || err.chain().any(|e| e.to_string().contains("vm_name"))
        );
    }

    #[test]
    fn two_distinct_admit_calls_produce_distinct_plan_ids_and_nonces() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let clock = SystemClock;
        let ledger = InMemoryNonceLedger::new();
        let a1 = admit_for_run(
            &fixture_input("vm1"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .unwrap();
        let a2 = admit_for_run(
            &fixture_input("vm1"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .unwrap();
        assert_ne!(a1.plan_id, a2.plan_id);
        assert_ne!(a1.plan.nonce, a2.plan.nonce);
    }

    // ── Claim 9: admit-time bundle re-verify ─────────────────────
    //
    // Tests exercise the boundary between `synthesize_plan`'s
    // `bundle_pin` (the input) and `admit_for_run`'s
    // `BundleAdmissionContext` (the verifier seam). The mvm_plan
    // bundle module already tests every BundleVerifyError /
    // PlanBundleError variant in isolation; these tests prove the
    // wiring fires when admit_for_run sees a pinned plan.

    use mvm_core::plan::bundle::{
        BundleResolveError, BundleResolver, KeyId as BundleKeyId, PlanArtifact, TrustStore,
        bundle_sha256, key_id_from_pubkey, write_bundle,
    };
    use std::collections::HashMap;

    struct FixedResolver(Vec<u8>);
    impl BundleResolver for FixedResolver {
        fn resolve(&self, _bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError> {
            Ok(self.0.clone())
        }
    }

    struct MapTrust(HashMap<BundleKeyId, ed25519_dalek::VerifyingKey>);
    impl TrustStore for MapTrust {
        fn lookup(&self, key_id: &BundleKeyId) -> Option<ed25519_dalek::VerifyingKey> {
            self.0.get(key_id).copied()
        }
    }

    /// Build a minimal signed bundle around `(kernel, rootfs)` bytes.
    /// Returns the archive plus the matching `PlanArtifact` pin.
    fn make_test_bundle(
        sk: &ed25519_dalek::SigningKey,
        kernel: &[u8],
        rootfs: &[u8],
    ) -> (Vec<u8>, PlanArtifact) {
        make_test_bundle_for_arch(
            sk,
            kernel,
            rootfs,
            &mvm_core::arch::GuestArch::host().to_string(),
        )
    }

    /// [`make_test_bundle`] with an explicit declared architecture, so the
    /// cross-arch refusal can be exercised from either host.
    fn make_test_bundle_for_arch(
        sk: &ed25519_dalek::SigningKey,
        kernel: &[u8],
        rootfs: &[u8],
        arch: &str,
    ) -> (Vec<u8>, PlanArtifact) {
        use mvm_core::plan::bundle::{
            ARTIFACTS_DIR, ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest,
            sha256_hex,
        };
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        let make_art = |name: &str, role: ArtifactRole, bytes: &[u8]| BundleArtifact {
            name: name.to_string(),
            role,
            path: format!("{ARTIFACTS_DIR}/{name}"),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        };
        let manifest = BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            publisher: "test".to_string(),
            key_id: key_id.clone(),
            arch: arch.to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-05-13T00:00:00Z".to_string(),
            labels: std::collections::BTreeMap::new(),
            artifacts: vec![
                make_art("vmlinux", ArtifactRole::Kernel, kernel),
                make_art("rootfs.ext4", ArtifactRole::Rootfs, rootfs),
            ],
            verity: None,
            resources: None,
        };
        let archive = write_bundle(
            &manifest,
            sk,
            vec![
                (format!("{ARTIFACTS_DIR}/vmlinux"), kernel.to_vec()),
                (format!("{ARTIFACTS_DIR}/rootfs.ext4"), rootfs.to_vec()),
            ],
        )
        .expect("write_bundle");

        // Recover the signature bytes from the archive for the pin.
        let mut sig_bytes: Vec<u8> = Vec::new();
        let mut a = tar::Archive::new(std::io::Cursor::new(&archive));
        for entry in a.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == "manifest.sig" {
                std::io::Read::read_to_end(&mut entry, &mut sig_bytes).unwrap();
                break;
            }
        }
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let pin = PlanArtifact::new(bundle_sha256(&archive), &sig_arr, key_id);
        (archive, pin)
    }

    fn input_with_pin<'a>(vm_name: &'a str, pin: &PlanArtifact) -> SynthesisInput<'a> {
        let mut input = fixture_input(vm_name);
        input.bundle_pin = Some(pin.clone());
        input
    }

    #[test]
    fn admit_with_clean_pinned_bundle_passes() {
        // Generate the publisher key out of band, build a bundle,
        // enrol the pubkey in the trust store, hand admit_for_run a
        // matching pin + context.
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (archive, pin) = make_test_bundle(&sk, b"kernel-bytes", b"rootfs-bytes");
        let mut map = HashMap::new();
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        map.insert(key_id, sk.verifying_key());
        let trust = MapTrust(map);
        let resolver = FixedResolver(archive);
        let ctx = BundleAdmissionContext {
            resolver: &resolver,
            trust: &trust,
        };
        let admitted = admit_for_run(
            &input_with_pin("vm-pinned", &pin),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            Some(&ctx),
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("clean pin admits");
        assert!(admitted.plan().bundle.is_some());
    }

    #[test]
    fn admit_with_pin_but_no_context_refuses() {
        // Publisher misconfiguration: plan carries a pin but the
        // mvmctl up path didn't wire a BundleAdmissionContext. The
        // admit path refuses rather than silently skipping the
        // re-verify step (fail closed, not fail open).
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (_archive, pin) = make_test_bundle(&sk, b"k", b"r");
        let err = admit_for_run(
            &input_with_pin("vm-no-ctx", &pin),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect_err("must refuse without context");
        let msg = format!("{err:#}");
        assert!(msg.contains("BundleAdmissionContext"), "got: {msg}");
    }

    /// A pinned bundle built for the other architecture is refused at the trust
    /// boundary, before any backend sees it. Without this the plan admits and
    /// fails deep in boot with an unrelated-looking kernel error.
    #[test]
    fn admit_with_cross_arch_pinned_bundle_refuses() {
        let other = match mvm_core::arch::GuestArch::host() {
            mvm_core::arch::GuestArch::X86_64 => "aarch64",
            mvm_core::arch::GuestArch::Aarch64 => "x86_64",
        };
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (archive, pin) =
            make_test_bundle_for_arch(&sk, b"kernel-bytes", b"rootfs-bytes", other);
        let mut map = HashMap::new();
        map.insert(key_id_from_pubkey(&sk.verifying_key()), sk.verifying_key());
        let trust = MapTrust(map);
        let resolver = FixedResolver(archive);
        let ctx = BundleAdmissionContext {
            resolver: &resolver,
            trust: &trust,
        };
        let err = admit_for_run(
            &input_with_pin("vm-cross-arch", &pin),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            Some(&ctx),
            RunPosture::without_backend(Variant::Dev),
        )
        .expect_err("a foreign-arch bundle must not be admitted");
        let msg = format!("{err:#}");
        assert!(msg.contains("but this host is"), "{msg}");
        assert!(msg.contains(other), "{msg}");
    }

    #[test]
    fn admit_with_unknown_publisher_in_trust_store_refuses() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (archive, pin) = make_test_bundle(&sk, b"k", b"r");
        // Empty trust store — publisher's key_id is unknown locally.
        let trust = MapTrust(HashMap::new());
        let resolver = FixedResolver(archive);
        let ctx = BundleAdmissionContext {
            resolver: &resolver,
            trust: &trust,
        };
        let err = admit_for_run(
            &input_with_pin("vm-untrusted", &pin),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            Some(&ctx),
            RunPosture::without_backend(Variant::Dev),
        )
        .expect_err("must refuse unknown publisher");
        let msg = format!("{err:#}");
        // The error chain bubbles up the BundleVerifyError::UnknownKey
        // variant from the read_and_verify pass.
        assert!(
            err.chain().any(|e| e.to_string().contains("key_id")),
            "expected key_id mention; got: {msg}"
        );
    }

    #[test]
    fn admit_with_pin_mismatching_archive_refuses() {
        // Resolver returns a different archive than the pin describes.
        // The bundle_sha256 cross-check catches it before the
        // signature verify even runs.
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (_archive_a, pin_a) = make_test_bundle(&sk, b"kA", b"rA");
        let (archive_b, _pin_b) = make_test_bundle(&sk, b"kB", b"rB");
        let mut map = HashMap::new();
        map.insert(key_id_from_pubkey(&sk.verifying_key()), sk.verifying_key());
        let trust = MapTrust(map);
        let resolver = FixedResolver(archive_b);
        let ctx = BundleAdmissionContext {
            resolver: &resolver,
            trust: &trust,
        };
        let err = admit_for_run(
            &input_with_pin("vm-pin-drift", &pin_a),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            Some(&ctx),
            RunPosture::without_backend(Variant::Dev),
        )
        .expect_err("must refuse pin drift");
        assert!(
            err.chain().any(|e| e.to_string().contains("sha256")),
            "expected sha256 mismatch chain; got {err:#}"
        );
    }

    #[test]
    fn thread_tenant_id_sets_only_tenant_label_not_the_bridge_plan() {
        use mvm_core::vm_backend::VmStartConfig;
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let admitted = admit_for_run(
            &fixture_input("vm-tenant-only"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("happy admit");

        let mut cfg = VmStartConfig::default();
        thread_tenant_id(&mut cfg, &admitted);

        // The broker spawn keys off this label.
        assert_eq!(
            cfg.tenant_id.as_deref(),
            Some(admitted.plan().tenant.0.as_str())
        );
        // It must NOT thread the signed plan / policy bundle — that flips
        // libkrun/HVF onto the gateway-bridge supervisor (+ its ~/.mvm/keys
        // substrate validation), which is a separate opt-in concern.
        assert!(
            cfg.plan_json.is_none(),
            "thread_tenant_id must not set plan_json"
        );
        assert!(
            cfg.bundle_json.is_none(),
            "thread_tenant_id must not set bundle_json"
        );
    }

    #[test]
    fn populate_audit_substrate_threads_tenant_and_signed_envelope() {
        use mvm_core::vm_backend::VmStartConfig;
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let clock = SystemClock;
        let ledger = InMemoryNonceLedger::new();
        let admitted = admit_for_run(
            &fixture_input("vm-substrate"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("happy admit");

        let mut cfg = VmStartConfig::default();
        populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
        assert_eq!(
            cfg.tenant_id.as_deref(),
            Some(admitted.plan().tenant.0.as_str())
        );
        let plan_json = cfg.plan_json.expect("plan_json populated");
        let roundtrip: mvm_core::plan::SignedExecutionPlan =
            serde_json::from_str(&plan_json).expect("roundtrip");
        // Re-verify the envelope to get the inner ExecutionPlan and
        // confirm the plan_id matches what the producer admitted.
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
            [(admitted.signer_id(), &signer.verifying)];
        let recovered =
            mvm_core::plan::verify_plan(&roundtrip, &trusted).expect("envelope re-verifies");
        assert_eq!(&recovered.plan_id, admitted.plan_id());
        // fixture has no bundle pin, so bundle_json stays None
        assert!(cfg.bundle_json.is_none());
    }

    #[test]
    fn bundle_json_carries_a_policy_bundle_not_the_artifact_pin() {
        // De-conflation: bundle_json is the tenant PolicyBundle the
        // supervisor's L4 gate + observers consume — sourced from the
        // policy_bundle arg, NOT from `admitted.plan().bundle` (the .mvmpkg
        // PlanArtifact pin, a different bundle verified separately).
        use mvm_core::vm_backend::VmStartConfig;
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let clock = SystemClock;
        let ledger = InMemoryNonceLedger::new();
        let admitted = admit_for_run(
            &fixture_input("vm-policy-bundle"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("happy admit");

        let bundle = mvm_core::policy::PolicyBundle {
            schema_version: mvm_core::policy::SCHEMA_VERSION,
            bundle_id: mvm_core::policy::PolicyId("test".into()),
            bundle_version: 1,
            network: Default::default(),
            egress: Default::default(),
            pii: Default::default(),
            tool: Default::default(),
            artifact: Default::default(),
            keys: Default::default(),
            audit: Default::default(),
            wasi: Default::default(),
            tenant_overlays: std::collections::BTreeMap::new(),
        };

        let mut cfg = VmStartConfig::default();
        populate_audit_substrate(&mut cfg, &admitted, Some(&bundle)).expect("populate");
        let bj = cfg.bundle_json.expect("bundle_json populated");
        let roundtrip: mvm_core::policy::PolicyBundle =
            serde_json::from_str(&bj).expect("bundle_json deserializes as a PolicyBundle");
        assert_eq!(roundtrip, bundle);

        // No policy bundle → None (the de-conflated default; a pinned artifact
        // no longer leaks into this field).
        let mut cfg2 = VmStartConfig::default();
        populate_audit_substrate(&mut cfg2, &admitted, None).expect("populate none");
        assert!(cfg2.bundle_json.is_none());
    }

    // ───────────────────────────────────────────────────────────────
    // write_secret_file + stash_plan_for_bridge
    // ───────────────────────────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn write_secret_file_creates_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.json");
        write_secret_file(&path, b"{\"hello\":\"world\"}").expect("write");
        let meta = std::fs::metadata(&path).expect("stat");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be mode 0600 (got {mode:o})");
        let body = std::fs::read(&path).expect("read");
        assert_eq!(body, b"{\"hello\":\"world\"}");
    }

    #[test]
    #[cfg(unix)]
    fn write_secret_file_atomic_via_rename() {
        // Two consecutive writes; the second must fully replace the
        // first and leave no `*.json.tmp` artifact behind. This proves
        // the tmp-and-rename happy path doesn't leak partial files.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.json");
        write_secret_file(&path, b"first body").expect("first write");
        write_secret_file(&path, b"second body wins").expect("second write");
        assert_eq!(std::fs::read(&path).unwrap(), b"second body wins");
        // The tmp file path is `plan.json.tmp`; it must not exist after
        // a clean write.
        assert!(
            !dir.path().join("plan.json.tmp").exists(),
            "tmp file should be renamed away"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_secret_file_creates_parent_dir() {
        // The bridge writes under `~/.mvm/vms/<vm>/`; that dir may not
        // exist on a first boot. The helper must create it (matching
        // the `stash_plan_for_bridge` callsite's invariant).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vms").join("foo").join("plan.json");
        write_secret_file(&path, b"body").expect("write with missing parent");
        assert!(path.exists());
    }

    #[test]
    fn stash_plan_for_bridge_skips_when_plan_json_none() {
        use mvm_core::vm_backend::VmStartConfig;
        // Legacy / no-admission path: cfg.plan_json is None.
        // `stash_plan_for_bridge` must succeed without touching disk
        // because there's nothing to stash.
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let cfg = VmStartConfig {
            name: "skip-me".into(),
            ..Default::default()
        };
        stash_plan_for_bridge(&cfg).expect("None plan_json is a no-op");
        assert!(
            !dir.path().join("vms/skip-me/plan.json").exists(),
            "no files when plan_json is None"
        );
    }

    #[test]
    #[cfg(unix)]
    fn stash_plan_for_bridge_writes_both_files_when_present() {
        use mvm_core::vm_backend::VmStartConfig;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let cfg = VmStartConfig {
            name: "with-plan".into(),
            plan_json: Some("{\"plan\":\"body\"}".into()),
            bundle_json: Some("{\"bundle\":\"pin\"}".into()),
            ..Default::default()
        };
        stash_plan_for_bridge(&cfg).expect("stash succeeds");

        let plan_path = dir.path().join("vms/with-plan/plan.json");
        let bundle_path = dir.path().join("vms/with-plan/bundle.json");
        assert!(plan_path.exists(), "plan.json must be written");
        assert!(bundle_path.exists(), "bundle.json must be written");
        assert_eq!(
            std::fs::metadata(&plan_path).unwrap().permissions().mode() & 0o777,
            0o600,
            "plan.json must be mode 0600"
        );
        assert_eq!(
            std::fs::metadata(&bundle_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "bundle.json must be mode 0600"
        );
    }

    #[test]
    fn caller_audit_labels_flow_through_admission() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let mut input = fixture_input("vm-label");
        input.audit_labels.insert(
            "origin.descriptor".to_string(),
            "blake3:testvalue".to_string(),
        );
        let admitted = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("happy path");
        assert_eq!(
            admitted.plan().audit_labels["origin.descriptor"],
            "blake3:testvalue"
        );
        // Profile-derived keys must still be present and authoritative.
        assert!(!admitted.plan().audit_labels["intent"].is_empty());
        assert!(!admitted.plan().audit_labels["admission_profile"].is_empty());
        assert_eq!(admitted.plan().audit_labels["seccomp_tier"], "standard");
    }

    // ───────────────────────────────────────────────────────────────
    // verb-grant sidecar: stash_plan_for_bridge mint path
    // ───────────────────────────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn stash_plan_for_bridge_writes_verb_grant_when_agent_verbs_present() {
        use ed25519_dalek::VerifyingKey;
        use mvm_core::plan::VerbId;
        use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
        use mvm_core::vm_backend::VmStartConfig;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let keys_dir = mvm_core::config::mvm_keys_dir();

        // Build an admitted plan that carries agent_verbs.
        let mut input = fixture_input("vm-verb-grant");
        input.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
        let admitted = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys_dir.as_path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("admit with agent_verbs");

        let mut cfg = VmStartConfig {
            name: "vm-verb-grant".into(),
            ..Default::default()
        };
        populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
        let issued = stash_plan_and_mint_verb_grant(&cfg)
            .expect("stash succeeds")
            .expect("agent verbs mint a grant");

        let grant_path = dir.path().join("vms/vm-verb-grant/verb-grant.json");
        assert!(grant_path.exists(), "verb-grant.json must be written");
        let mode = std::fs::metadata(&grant_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "verb-grant.json must be mode 0600");

        // Parse the envelope and verify the grant under the signer key.
        let raw = std::fs::read(&grant_path).unwrap();
        let envelope: VerbGrantEnvelope = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            serde_json::to_vec(&issued).unwrap(),
            serde_json::to_vec(&envelope).unwrap(),
            "the returned envelope is exactly the sidecar payload"
        );
        assert!(!envelope.pubkey_hex.is_empty(), "pubkey_hex must be set");
        assert_eq!(
            envelope.plan_nonce_hex,
            admitted.plan().nonce.as_hex(),
            "nonce hex must match plan"
        );
        assert_eq!(
            envelope.grant.not_after,
            admitted.plan().valid_until,
            "a verb grant must not outlive its admitted plan"
        );
        let pub_arr: [u8; 32] = hex::decode(&envelope.pubkey_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = VerifyingKey::from_bytes(&pub_arr).unwrap();
        envelope
            .grant
            .verify(
                &vk,
                "vm-verb-grant",
                &admitted.plan().nonce,
                SystemClock.now(),
            )
            .expect("grant must verify under the signer key");
    }

    #[test]
    fn stash_plan_for_bridge_no_verb_grant_when_agent_verbs_absent() {
        use mvm_core::vm_backend::VmStartConfig;

        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let keys_dir = mvm_core::config::mvm_keys_dir();

        // Plain plan with no agent_verbs — the fixture default.
        let admitted = admit_for_run(
            &fixture_input("vm-no-verbs"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys_dir.as_path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("admit without agent_verbs");

        let mut cfg = VmStartConfig {
            name: "vm-no-verbs".into(),
            ..Default::default()
        };
        populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
        stash_plan_for_bridge(&cfg).expect("stash succeeds");

        assert!(
            !dir.path().join("vms/vm-no-verbs/verb-grant.json").exists(),
            "verb-grant.json must NOT be written when agent_verbs is None"
        );
    }

    #[test]
    #[cfg(unix)]
    fn stash_plan_for_bridge_removes_stale_verb_grant_on_grant_less_restash() {
        use mvm_core::plan::VerbId;
        use mvm_core::vm_backend::VmStartConfig;

        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let keys_dir = mvm_core::config::mvm_keys_dir();

        let vm_name = "vm-stale-grant";

        // First boot: plan with agent_verbs — sidecar must be written.
        let mut input_with = fixture_input(vm_name);
        input_with.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
        let admitted_with = admit_for_run(
            &input_with,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys_dir.as_path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("admit with agent_verbs");
        let mut cfg_with = VmStartConfig {
            name: vm_name.into(),
            ..Default::default()
        };
        populate_audit_substrate(&mut cfg_with, &admitted_with, None).expect("populate");
        stash_plan_for_bridge(&cfg_with).expect("first stash succeeds");

        let grant_path = dir.path().join(format!("vms/{vm_name}/verb-grant.json"));
        assert!(
            grant_path.exists(),
            "verb-grant.json must be present after first stash"
        );

        // Second boot: same VM name, no agent_verbs — stale sidecar must be removed.
        let admitted_without = admit_for_run(
            &fixture_input(vm_name),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys_dir.as_path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("admit without agent_verbs");
        let mut cfg_without = VmStartConfig {
            name: vm_name.into(),
            ..Default::default()
        };
        populate_audit_substrate(&mut cfg_without, &admitted_without, None).expect("populate");
        stash_plan_for_bridge(&cfg_without).expect("second stash succeeds");

        assert!(
            !grant_path.exists(),
            "stale verb-grant.json must be removed on a grant-less re-stash of the same VM name"
        );
    }

    // ───────────────────────────────────────────────────────────────
    // admit_and_start: the shared admitted-boot entrypoint
    // ───────────────────────────────────────────────────────────────

    #[test]
    fn admit_and_start_admits_then_boots_on_mock() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-boot".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };
        let started = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-boot"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: None,
                variant: Variant::Dev,
                policy_bundle: None,
                emitter: None,
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
                assurance: None,
            },
        )
        .expect("admit + boot");

        // Admission ran (claim 8): a signed plan id under the host signer.
        assert!(!started.admitted.plan_id().0.is_empty());
        assert!(started.admitted.signer_id().starts_with("host:"));
        // The backend actually started the VM and reports it running.
        assert_eq!(started.vm_id.0, "vm-boot");
        assert!(matches!(
            backend.status(&started.vm_id).unwrap(),
            mvm_core::vm_backend::VmStatus::Running
        ));
    }

    #[test]
    fn a_campaign_that_cannot_open_rolls_the_launch_back() {
        // The session opens *after* the backend start, so a failure there used
        // to return with the workload still running.
        //
        // The campaign declares no destination, which `open` refuses whether or
        // not a plane happens to be installed. Asserting on the absence of the
        // process-global plane instead would make this test depend on run
        // order — a `OnceLock` admits one value and the neighbouring test
        // installs it, so it would pass under nextest and flake under
        // `cargo test`.
        use std::sync::Arc;

        use mvm_contract::assurance::{
            ApprovalSet, AssuranceId, ObservationScope, RequestedAuthority, Sha256Digest, ToolId,
        };

        use crate::assurance_session::{
            CampaignDeclaration, CampaignRequest, default_policy_ceiling,
        };

        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let emitter = Arc::new(
            crate::audit::emitter::AuditEmitter::with_dir(
                ed25519_dalek::SigningKey::from_bytes(&[41u8; 32]),
                audit.path(),
            )
            .expect("emitter"),
        );
        let id = |raw: &str| AssuranceId::parse(raw).expect("identifier");
        let declaration = CampaignDeclaration {
            request_id: id("mvm-request-rollback"),
            idempotency_key: id("trial-retry-rollback"),
            campaign_id: id("mvm-campaign-9"),
            trial_id: id("trial-9"),
            source_run_id: id("scout-9"),
            source_digest: Sha256Digest::parse(format!("sha256:{}", "5".repeat(64)))
                .expect("digest"),
            artifact_digest: Sha256Digest::parse(format!("sha256:{}", "6".repeat(64)))
                .expect("artifact digest"),
            edges: Vec::new(),
            approvals: ApprovalSet::none().with(ToolId::CampaignProbeV1),
            requested: RequestedAuthority {
                allowed_tools: vec![ToolId::CampaignProbeV1],
                observation_scopes: vec![ObservationScope::HostAuditRefs],
                max_steps: 4,
                max_output_bytes: 4096,
                deadline_unix_ms: 0,
            },
            grant_ttl_ms: 600_000,
        };
        let campaign = CampaignRequest {
            declaration,
            emitter: Arc::clone(&emitter),
            policy_ceiling: default_policy_ceiling(),
            policy: mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
            backend: "mock".to_string(),
            now_unix_ms: 1_800_000_000_000,
        };

        let service =
            mvm_core::protocol::broker::ServiceId::parse("host.assurance.v1").expect("service id");
        let mut synthesis = fixture_input("vm-rollback");
        synthesis.services = vec![service];
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-rollback".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };

        let err = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &synthesis,
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: None,
                variant: Variant::Dev,
                policy_bundle: None,
                emitter: Some(&emitter),
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
                assurance: Some(&campaign),
            },
        )
        .expect_err("a campaign declaring no destination cannot open");
        // Deliberately not asserted on the message: which refusal fires
        // depends on whether a neighbouring test installed the process-global
        // plane first (`NoPlane`) or not (`NoEdges`). Both roll the launch
        // back, and the rollback is the property under test.
        let _ = &err;

        // The whole point: no workload is left running behind the failure.
        assert!(
            !matches!(
                backend.status(&mvm_core::vm_backend::VmId("vm-rollback".into())),
                Ok(mvm_core::vm_backend::VmStatus::Running)
            ),
            "a campaign that could not open must not leave the VM up"
        );
    }

    #[test]
    fn a_declared_campaign_opens_its_session_on_the_boot_path() {
        // The production seam: `admit_and_start` is what a run goes through,
        // and a declared campaign has to become a live session there rather
        // than in a test that hand-built one. The broker-handler tests may
        // already have installed the process-global plane, so this test uses
        // that legitimate instance when running in parallel.
        use std::sync::Arc;

        use mvm_contract::assurance::{
            ApprovalSet, AssuranceId, ObservationScope, RequestedAuthority, Sha256Digest, ToolId,
        };

        use crate::assurance_session::{
            CampaignDeclaration, CampaignRequest, DeclaredEdge, default_policy_ceiling,
            host_assurance_plane, install_host_assurance_plane,
        };
        use crate::broker::handlers::host_assurance_v1::HostAssuranceV1Handler;

        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();

        let plane = Arc::new(HostAssuranceV1Handler::new());
        let _ = install_host_assurance_plane(Arc::clone(&plane));

        let emitter = Arc::new(
            crate::audit::emitter::AuditEmitter::with_dir(
                ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]),
                audit.path(),
            )
            .expect("emitter")
            .with_receipts(),
        );
        let id = |raw: &str| AssuranceId::parse(raw).expect("identifier");
        let declaration = CampaignDeclaration {
            request_id: id("mvm-request-1"),
            idempotency_key: id("trial-retry-1"),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_run_id: id("scout-1"),
            source_digest: Sha256Digest::parse(format!("sha256:{}", "3".repeat(64)))
                .expect("digest"),
            artifact_digest: Sha256Digest::parse(format!("sha256:{}", "b".repeat(64)))
                .expect("artifact digest"),
            edges: vec![DeclaredEdge {
                label: id("undeclared.synthetic.destination"),
                host: "attacker.example.com".to_string(),
                port: 443,
            }],
            approvals: ApprovalSet::none().with(ToolId::CampaignProbeV1),
            requested: RequestedAuthority {
                allowed_tools: vec![ToolId::CampaignProbeV1],
                observation_scopes: vec![ObservationScope::HostAuditRefs],
                max_steps: 4,
                max_output_bytes: 4096,
                deadline_unix_ms: 0,
            },
            grant_ttl_ms: 600_000,
        };
        let now_unix_ms = 1_800_000_000_000;
        let campaign = CampaignRequest {
            declaration,
            emitter: Arc::clone(&emitter),
            policy_ceiling: default_policy_ceiling(),
            policy: mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
            backend: "mock".to_string(),
            now_unix_ms,
        };

        let service =
            mvm_core::protocol::broker::ServiceId::parse("host.assurance.v1").expect("service id");
        let mut synthesis = fixture_input("vm-assurance");
        synthesis.services = vec![service];
        struct Trust(ed25519_dalek::VerifyingKey);
        impl mvm_core::packs::PackTrustStore for Trust {
            fn verifying_key(
                &self,
                _key_id: &mvm_core::plan::bundle::KeyId,
            ) -> Option<ed25519_dalek::VerifyingKey> {
                Some(self.0)
            }
        }
        struct Revocations;
        impl mvm_core::packs::PackRevocationChecker for Revocations {
            fn status(
                &self,
                _key_id: &mvm_core::plan::bundle::KeyId,
                _pack_hash: &mvm_core::packs::Sha256Hex,
            ) -> mvm_core::packs::RevocationStatus {
                mvm_core::packs::RevocationStatus::Good
            }
        }
        let staged = tempfile::tempdir().expect("extension staging");
        std::fs::write(
            staged.path().join("extension.ext4"),
            b"fixture extension filesystem",
        )
        .expect("write extension artifact");
        let pack_key = ed25519_dalek::SigningKey::from_bytes(&[45; 32]);
        let pack_policy_hash = mvm_core::packs::Sha256Hex::from_bytes(b"extension-policy");
        let pack_metadata = mvm_core::packs::PackMetadata {
            kind: mvm_core::packs::PackKind::Extension,
            target_arch: mvm_core::arch::GuestArch::host(),
            backend_compatibility: vec![mvm_core::packs::PackBackend::Firecracker],
            required_host_capabilities: vec![mvm_core::packs::HostCapability("vsock".to_string())],
            policy_compatibility: mvm_core::packs::PolicyCompatibility {
                policy_hash: pack_policy_hash.clone(),
                local_rebuild_required: false,
                allowed_channels: vec!["stable".to_string()],
            },
            inputs: mvm_core::packs::PackInputs {
                flake_locks: Vec::new(),
                derivations: Vec::new(),
                nar_hashes: Vec::new(),
                oci_images: Vec::new(),
                setup_commands: Vec::new(),
                source_revisions: Vec::new(),
                toolchain_versions: Default::default(),
            },
            provenance: mvm_core::packs::PackProvenanceMeta {
                builder_identity: "assurance-release".to_string(),
                build_environment_identity: "test".to_string(),
                build_timestamp: Utc::now(),
                reproducibility: mvm_core::packs::ReproducibilityStatus::NotChecked,
                sbom: mvm_core::packs::SbomReference {
                    uri: "urn:sbom:extension".to_string(),
                    sha256: mvm_core::packs::Sha256Hex::from_bytes(b"sbom"),
                },
            },
            trust: mvm_core::packs::PackTrustMeta {
                expires_at: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
                revocation_channel: "https://example.invalid/revocations".to_string(),
                channel_identity: "stable".to_string(),
                mirror_identity: None,
                transparency_log: None,
            },
            signature: mvm_core::packs::SignatureValidity {
                signed_at: Utc::now(),
                expires_at: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            },
        };
        let extension_budgets = mvm_contract::protocol::extension_pack::ExtensionBudgets {
            cpu_millis: 500,
            memory_bytes: 128 * 1024 * 1024,
            duration_ms: 600_000,
            max_steps: 12,
            max_concurrency: 1,
            max_payload_bytes: 16 * 1024,
            max_output_bytes: 16 * 1024,
            max_artifact_bytes: 1024 * 1024,
        };
        let contract = mvm_contract::protocol::extension_pack::ExtensionPackContract {
            schema: mvm_contract::protocol::extension_pack::EXTENSION_PACK_SCHEMA.to_string(),
            extension_id: mvm_contract::protocol::extension_pack::ExtensionId::parse(
                "org.example.assurance-extension",
            )
            .expect("extension id"),
            version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse("1.0.0")
                .expect("extension version"),
            protocol: mvm_contract::protocol::extension_pack::ExtensionProtocolRange {
                min_mvm_version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse(
                    "0.18.0",
                )
                .expect("minimum version"),
                max_mvm_version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse(
                    "0.18.9",
                )
                .expect("maximum version"),
                min_protocol: 1,
                max_protocol: 1,
            },
            placement: mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
            artifact: "extension.ext4".to_string(),
            entrypoint: "bin/assurance-extension".to_string(),
            capabilities: vec![mvm_contract::assurance::probe_capability_descriptor()],
            budgets: extension_budgets,
            revocation_identity: "org.example.assurance-extension.release".to_string(),
            permission_delta: "May execute one declared assurance probe.".to_string(),
        };
        let manifest = mvm_core::packs::PackBuilder::new(staged.path(), pack_metadata, &pack_key)
            .file("extension.ext4")
            .extension(contract)
            .build()
            .expect("build signed extension pack");
        let pack_policy = mvm_core::packs::LocalPackPolicy {
            host_arch: mvm_core::arch::GuestArch::host(),
            backend: mvm_core::packs::PackBackend::Firecracker,
            host_capabilities: [mvm_core::packs::HostCapability("vsock".to_string())]
                .into_iter()
                .collect(),
            policy_hash: pack_policy_hash,
            allowed_channels: ["stable".to_string()].into_iter().collect(),
            now: Utc::now(),
        };
        let trust = Trust(pack_key.verifying_key());
        let revocations = Revocations;
        let verify =
            mvm_core::pack_cache::PackVerifyCtx::ed25519(&pack_policy, &trust, &revocations);
        let promoted = mvm_core::pack_cache::promote(staged.path(), &manifest, &verify)
            .expect("promote extension pack");
        let capability = mvm_contract::assurance::probe_capability_descriptor().id;
        let authority = std::collections::HashSet::from([capability]);
        let placements = std::collections::BTreeSet::from([
            mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
        ]);
        let extension = mvm_core::extension_admission::admit_extension(
            &manifest,
            &promoted.verified,
            mvm_core::extension_admission::ExtensionAuthority {
                requested: &authority,
                policy_ceiling: &authority,
                session_grant: &authority,
                explicit_approval: &authority,
            },
            mvm_core::extension_admission::ExtensionAdmissionPolicy {
                placements: &placements,
                budgets: extension_budgets,
            },
        )
        .expect("admit extension authority");
        synthesis.extensions = vec![extension];
        synthesis.agent_verbs = Some(vec![
            mvm_contract::plan::VerbId::new("run-extension").expect("extension verb"),
            mvm_contract::plan::VerbId::new("cancel-extension").expect("extension verb"),
        ]);
        synthesis
            .audit_labels
            .insert("assurance.source_run_id".to_string(), "scout-1".to_string());
        synthesis.audit_labels.insert(
            "assurance.source_digest".to_string(),
            format!("sha256:{}", "3".repeat(64)),
        );
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-assurance".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };

        let started = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &synthesis,
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: Some(&ExtensionAdmissionContext::ambient(&verify)),
                variant: Variant::Dev,
                policy_bundle: None,
                emitter: Some(&emitter),
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
                assurance: Some(&campaign),
            },
        )
        .expect("admit + boot with a declared campaign");

        let plane = host_assurance_plane().expect("the plane this test installed");
        let binding = plane
            .binding_for(&started.vm_id.0)
            .expect("the boot path opened a session for this VM");
        // The binding renders the content address in the counterparty's
        // identifier grammar; it still names exactly this plan.
        assert_eq!(
            binding.plan_id.as_str(),
            started.admitted.plan_id().0.replace(':', "-")
        );
        assert_eq!(binding.runtime.backend.as_str(), "mock");
        // Its citations came from real emission on the boot path.
        assert!(!binding.audit_refs.is_empty());
        assert!(!binding.receipt_refs.is_empty());

        let mut refused_synthesis = synthesis.clone();
        refused_synthesis.vm_name = "vm-assurance-refused";
        refused_synthesis
            .audit_labels
            .remove("assurance.source_digest");
        let refusal = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &refused_synthesis,
                config: mvm_core::vm_backend::VmStartConfig {
                    name: "vm-assurance-refused".into(),
                    rootfs_path: "/store/rootfs.ext4".into(),
                    ..Default::default()
                },
                clock: &SystemClock,
                ledger: &InMemoryNonceLedger::new(),
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: Some(&ExtensionAdmissionContext::ambient(&verify)),
                variant: Variant::Dev,
                policy_bundle: None,
                emitter: Some(&emitter),
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
                assurance: Some(&campaign),
            },
        )
        .expect_err("an assurance launch without its admitted service must fail");
        assert!(
            refusal
                .to_string()
                .contains("does not bind the campaign source identity")
        );
        assert!(
            matches!(
                backend.status(&mvm_core::vm_backend::VmId(
                    "vm-assurance-refused".to_string()
                )),
                Ok(mvm_core::vm_backend::VmStatus::Stopped)
            ),
            "a post-start assurance refusal must roll the VM back"
        );
    }

    /// The bound the backend spawns under comes off the signed plan, and only
    /// off the signed plan. A caller-supplied one would be a bound chosen
    /// outside the admission that just measured it against the host's ceiling.
    #[test]
    fn the_admitted_grant_reaches_the_launch_config_and_a_caller_supplied_one_does_not() {
        use mvm_core::vm_backend::VmStartConfig;
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let mut input = fixture_input("vm-grant-threaded");
        let grants = mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
            ..Default::default()
        };
        input.grants = Some(grants);
        let admitted = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("admit");

        let mut cfg = VmStartConfig {
            // A bound nobody admitted, planted by the caller.
            cpu_grant: Some(mvm_contract::grants::CpuGrant::Share { millicores: 64_000 }),
            ..VmStartConfig::default()
        };
        thread_cpu_grant(&mut cfg, &admitted);
        assert_eq!(
            cfg.cpu_grant,
            Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
            "the launch must carry the admitted bound, not the caller's"
        );
    }

    /// An uncapped plan must clear a planted bound rather than leave it: a
    /// launch config is not a place to smuggle a control past admission.
    #[test]
    fn an_ungranted_plan_clears_a_caller_supplied_bound() {
        use mvm_core::vm_backend::VmStartConfig;
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let admitted = admit_for_run(
            &fixture_input("vm-no-grant"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
        .expect("admit");

        let mut cfg = VmStartConfig {
            cpu_grant: Some(mvm_contract::grants::CpuGrant::Share { millicores: 64_000 }),
            ..VmStartConfig::default()
        };
        thread_cpu_grant(&mut cfg, &admitted);
        assert_eq!(cfg.cpu_grant, None);
    }

    /// Every admitted boot leaves a record of what actually bounded it. Before
    /// this, `apply_grants` was reachable only from a launch path with no
    /// production implementation, so a real boot recorded nothing at all — and
    /// a bound nobody reports is indistinguishable from a bound nobody applied.
    #[test]
    fn an_admitted_boot_records_the_tier_that_bounded_it() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-tiers".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };
        let started = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-tiers"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: None,
                variant: Variant::Dev,
                policy_bundle: None,
                emitter: None,
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
                assurance: None,
            },
        )
        .expect("admit + boot");

        // The mock bounds nothing, and says so rather than claiming a tier it
        // has no mechanism for.
        assert_eq!(started.enforced_grants, EnforcedGrants::all_declared());
        assert!(!started.enforced_grants.cpu.is_enforced());
    }

    /// The achieved tier reaches the chain-signed log, not just the return
    /// value — an operator answering "was this run bounded?" from the audit
    /// trail alone must not have to take the caller's word for it.
    #[test]
    fn an_admitted_boot_writes_the_achieved_tier_to_the_audit_chain() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-tier-audit".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };
        let audit_dir = dir.path().join("audit");
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let emitter = crate::audit::emitter::AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&seed),
            &audit_dir,
        )
        .expect("emitter");

        admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-tier-audit"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: None,
                variant: Variant::Dev,
                policy_bundle: None,
                emitter: Some(&emitter),
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
                assurance: None,
            },
        )
        .expect("admit + boot");

        let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).expect("chain written");
        assert!(
            chain.contains("plan.grants_enforced"),
            "the achieved tier must be on the chain: {chain}"
        );
        assert!(
            chain.contains("grants_cpu_tier"),
            "the CPU dimension must be named: {chain}"
        );
    }

    /// The end-to-end half of the tier question: `admit_and_start` holds the
    /// backend object, so the grant gate must be measuring against *its* kind
    /// and not against whatever the plan's profile says.
    ///
    /// The fixture's plan is labelled `firecracker` while the backend booting
    /// it is the mock. With a grant declared, that disagreement has to surface
    /// — and, because the refusal precedes signing, no VM may exist afterwards.
    #[test]
    fn admit_and_start_measures_grants_against_the_backend_that_boots() {
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let mut synthesis = fixture_input("vm-tier-mismatch");
        synthesis.grants = Some(cpu_share(1500));
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-tier-mismatch".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };

        let err = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &synthesis,
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: None,
                variant: Variant::Prod,
                policy_bundle: None,
                emitter: None,
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
                assurance: None,
            },
        )
        .expect_err("the plan's profile and the booting backend disagree");
        let msg = err.to_string();
        assert!(msg.contains("firecracker") && msg.contains("mock"), "{msg}");
        assert_eq!(
            backend
                .status(&mvm_core::vm_backend::VmId("vm-tier-mismatch".into()))
                .expect("the mock reports a status for any name"),
            mvm_core::vm_backend::VmStatus::Stopped,
            "no VM may exist behind a refused admission"
        );
    }

    /// The point of `AuditDurability::Required`: a run that cannot record its
    /// admission does not reach the backend at all.
    ///
    /// Asserting the error is not enough — what matters is that no VM booted,
    /// because the failure mode being closed is a workload that ran while
    /// leaving no evidence it was ever admitted.
    #[test]
    fn a_required_admission_record_that_cannot_be_written_stops_the_boot() {
        use crate::audit::durability::AuditDurability;

        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-unauditable".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };

        // A chain whose tenant file cannot be written: a directory sits where
        // the JSONL belongs.
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir(audit_dir.join("local.jsonl")).unwrap();
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let emitter = crate::audit::emitter::AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&seed),
            &audit_dir,
        )
        .expect("the emitter opens; writing the tenant file is what fails");

        let err = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-unauditable"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: None,
                variant: Variant::Dev,
                policy_bundle: None,
                emitter: Some(&emitter),
                audit_durability: AuditDurability::Required,
                assurance: None,
            },
        )
        .expect_err("an unauditable sealed run must not boot");
        assert!(
            format!("{err:#}").contains("cannot be proven"),
            "the refusal must explain itself: {err:#}"
        );

        assert!(
            backend.list().expect("mock list").is_empty(),
            "no VM may exist for a run whose admission could not be recorded"
        );
    }

    /// The same broken chain under the dev tier boots and warns.
    #[test]
    fn a_best_effort_admission_record_does_not_stop_the_boot() {
        use crate::audit::durability::AuditDurability;

        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-dev-unauditable".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };

        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir(audit_dir.join("local.jsonl")).unwrap();
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let emitter = crate::audit::emitter::AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&seed),
            &audit_dir,
        )
        .expect("emitter");

        let started = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-dev-unauditable"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: None,
                variant: Variant::Dev,
                policy_bundle: None,
                emitter: Some(&emitter),
                audit_durability: AuditDurability::BestEffort,
                assurance: None,
            },
        )
        .expect("a dev run is not blocked by a broken audit chain");
        assert_eq!(started.vm_id.0, "vm-dev-unauditable");
    }

    #[test]
    fn admit_and_start_refuses_unadmitted_volume_before_boot() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let (_env, _home) = host_with_ceiling(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        // The synthesized plan admits no shares, but the launch config carries a
        // volume — claim 1 must refuse before the backend ever starts.
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-badvol".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            volumes: vec![VmVolume {
                host: "/etc".into(),
                guest: "/data".into(),
                read_only: true,
                kind: VmVolumeKind::Disk,
                materialized_image: Some("/state/mount.ext4".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-badvol"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                extension_ctx: None,
                variant: Variant::Dev,
                policy_bundle: None,
                emitter: None,
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
                assurance: None,
            },
        )
        .expect_err("unadmitted volume must refuse");
        assert!(
            err.chain()
                .any(|e| e.to_string().contains("not named in the signed")),
            "expected admitted-shares refusal; got: {err:#}"
        );
        // Crucially: no VM was started (the gate fired before backend.start).
        assert!(matches!(
            backend.status(&VmId("vm-badvol".into())),
            Ok(mvm_core::vm_backend::VmStatus::Stopped)
        ));
    }

    /// Three points around the cap. The `>` → `==` mutant admits
    /// everything above the cap, which is the whole vector the cap closes;
    /// `>` → `>=` refuses a payload exactly at it. Only a boundary test
    /// separates the two, and only an extracted comparison makes a
    /// boundary test cheap.
    #[test]
    fn the_size_cap_admits_up_to_the_cap_and_refuses_above_it() {
        assert!(enforce_size_cap("plan_json", 0, 16).is_ok());
        assert!(enforce_size_cap("plan_json", 15, 16).is_ok());
        assert!(
            enforce_size_cap("plan_json", 16, 16).is_ok(),
            "a payload exactly at the cap is within it"
        );
        assert!(
            enforce_size_cap("plan_json", 17, 16).is_err(),
            "a payload over the cap must be refused"
        );
        assert!(
            enforce_size_cap("plan_json", usize::MAX, 16).is_err(),
            "a cap that only refuses one exact size is not a cap"
        );
    }

    /// The stale-sidecar removal exists so a reused VM name cannot inherit
    /// the previous boot's grant. Swallowing a real removal failure leaves
    /// that grant in place while reporting success — the one outcome the
    /// removal is there to prevent.
    #[test]
    fn a_failed_stale_grant_removal_is_not_reported_as_success() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state_dir = tmp.path().join("vm-state");
        std::fs::create_dir_all(&state_dir).unwrap();

        // A non-empty directory where the sidecar file belongs: remove_file
        // refuses it, and the refusal is not NotFound.
        let sidecar = state_dir.join("verb-grant.json");
        std::fs::create_dir_all(&sidecar).unwrap();
        std::fs::write(sidecar.join("occupant"), b"stale").unwrap();

        assert!(
            mint_verb_grant_sidecar("{}", "vm-reused", &state_dir).is_err(),
            "a stale grant that could not be removed must not read as removed"
        );

        // Absent is still the quiet, successful case.
        let clean = tmp.path().join("clean-state");
        std::fs::create_dir_all(&clean).unwrap();
        assert!(mint_verb_grant_sidecar("{}", "vm-fresh", &clean).is_ok());
    }
}

#[cfg(test)]
mod admit_and_start_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = AdmitAndStartParams::builder().build() else {
            panic!("an empty AdmitAndStartParams builder must not build");
        };
        assert_eq!(
            err,
            BuilderError::missing("AdmitAndStartParams", "synthesis")
        );
    }
}

#[cfg(test)]
mod launch_decision_record_tests {
    use super::*;

    /// The launch decision record names the plan it launched — in the
    /// scenario it describes and in the attestation it binds to.
    ///
    /// Deleting either `plan_id` leaves a record that says a workload was
    /// launched but not which signed plan authorized it, and the scenario's
    /// `plan_id` is part of the record's content address, so dropping it also
    /// re-addresses the decision. Both deletions survived mutation because
    /// nothing read the fields back.
    #[test]
    fn a_launch_decision_record_binds_the_plan_it_launched() {
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .plan_id("plan-under-launch")
            .build();

        let record = launch_decision_record(&plan, "firecracker");

        assert_eq!(record.category, DecisionCategory::Launch);
        assert_eq!(
            record.scenario.plan_id.as_deref(),
            Some("plan-under-launch"),
            "the scenario must name the launched plan"
        );
        assert_eq!(
            record.attestation.plan_id.as_deref(),
            Some("plan-under-launch"),
            "the attestation binding must name the launched plan"
        );
    }
}

#[cfg(test)]
mod signed_plan_admission_tests {
    use super::*;
    use chrono::{Duration, Utc};
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::user_config::{MvmConfig, TrustedPlanSigner};
    use mvm_core::util::test_env::TestEnv;

    /// The fleet issuer key the tests pin — or deliberately don't.
    fn fleet_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn pin_for(signer_id: &str, key: &SigningKey) -> TrustedPlanSigner {
        TrustedPlanSigner {
            signer_id: signer_id.to_string(),
            ed25519_pubkey_hex: hex::encode(key.verifying_key().as_bytes()),
        }
    }

    /// Isolate `MVM_HOME` and write `cfg` as the host config. Admission reads
    /// the trusted signer set (and the grant ceiling) from host config rather
    /// than from a parameter, so a test that wants a trusting host has to
    /// *be* one. The guard and home must both outlive the admission call.
    fn host_with(cfg: MvmConfig) -> (TestEnv, tempfile::TempDir) {
        let home = tempfile::tempdir().expect("scratch mvm home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let pins = cfg.trusted_plan_signers.len();
        mvm_core::user_config::save(&cfg, None).expect("writing the host config");
        // Precondition, not a redundant assertion: if this fails the isolation
        // did not hold and every check below would measure some other host.
        assert_eq!(
            mvm_core::user_config::load(None).trusted_plan_signers.len(),
            pins,
            "the isolated host must read back the pins it was configured with"
        );
        (env, home)
    }

    fn host_pinning(signers: Vec<TrustedPlanSigner>) -> (TestEnv, tempfile::TempDir) {
        host_with(MvmConfig {
            trusted_plan_signers: signers,
            ..MvmConfig::default()
        })
    }

    fn signed_by_fleet(plan: &ExecutionPlan) -> SignedExecutionPlan {
        sign_plan(plan, &fleet_key(), "fleet-prod")
    }

    fn admit(signed: &SignedExecutionPlan, ledger: &InMemoryNonceLedger) -> Result<AdmittedPlan> {
        admit_signed_plan_for_run(
            signed,
            &SystemClock,
            ledger,
            None,
            RunPosture::without_backend(Variant::Dev),
        )
    }

    #[test]
    fn a_pinned_fleet_signers_plan_is_admitted() {
        let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
        let plan = PlanFixture::new().tenant("fleet-tenant").build();
        let signed = signed_by_fleet(&plan);

        let admitted = admit(&signed, &InMemoryNonceLedger::new())
            .expect("a plan signed by a pinned fleet signer admits");

        assert_eq!(admitted.signer_id(), "fleet-prod");
        assert_eq!(admitted.plan().tenant.0, "fleet-tenant");
        // The admitted plan is content-addressed and the envelope the caller
        // handed in is carried verbatim — not re-signed under the host key.
        assert_eq!(admitted.plan_id(), &admitted.plan().plan_id);
        assert_eq!(admitted.signed().0.signer_id, "fleet-prod");
        assert_eq!(admitted.signed().0.signature, signed.0.signature);
    }

    #[test]
    fn an_unpinned_host_refuses_every_signed_plan() {
        // The default: no pins, no externally-signed admissions. This is the
        // fail-closed posture a host is in before the operator delegates.
        let (_env, _home) = host_pinning(Vec::new());
        let signed = signed_by_fleet(&PlanFixture::new().build());

        let err = admit(&signed, &InMemoryNonceLedger::new())
            .expect_err("a host that pins nobody must refuse");
        assert!(
            format!("{err:#}").contains("pins no trusted plan signers"),
            "got: {err:#}"
        );
    }

    #[test]
    fn an_unknown_signer_is_refused() {
        // The host pins a *different* fleet issuer; the envelope names one it
        // never heard of.
        let other = SigningKey::from_bytes(&[7u8; 32]);
        let (_env, _home) = host_pinning(vec![pin_for("fleet-staging", &other)]);
        let signed = signed_by_fleet(&PlanFixture::new().build());

        let err = admit(&signed, &InMemoryNonceLedger::new())
            .expect_err("an unpinned signer must be refused");
        assert!(
            format!("{err:#}").contains("no trusted key matched signer_id fleet-prod"),
            "got: {err:#}"
        );
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
        let mut signed = signed_by_fleet(&PlanFixture::new().build());
        signed.0.payload[0] ^= 0x01;

        let err = admit(&signed, &InMemoryNonceLedger::new())
            .expect_err("a tampered payload must fail signature verification");
        assert!(
            format!("{err:#}").contains("signature verification failed"),
            "got: {err:#}"
        );
    }

    #[test]
    fn an_expired_plan_is_refused() {
        let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
        let now = Utc::now();
        let plan = PlanFixture::new()
            .validity(now - Duration::hours(2), now - Duration::hours(1))
            .build();
        let signed = signed_by_fleet(&plan);

        let err = admit(&signed, &InMemoryNonceLedger::new())
            .expect_err("a validly-signed but expired plan must be refused");
        assert!(
            format!("{err:#}").contains("plan validity window violated"),
            "got: {err:#}"
        );
    }

    #[test]
    fn a_not_yet_valid_plan_is_refused() {
        let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
        let now = Utc::now();
        let plan = PlanFixture::new()
            .validity(now + Duration::hours(1), now + Duration::hours(2))
            .build();
        let signed = signed_by_fleet(&plan);

        let err = admit(&signed, &InMemoryNonceLedger::new())
            .expect_err("a plan whose window has not opened must be refused");
        assert!(
            format!("{err:#}").contains("plan validity window violated"),
            "got: {err:#}"
        );
    }

    #[test]
    fn a_replayed_nonce_is_refused() {
        let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
        let signed = signed_by_fleet(&PlanFixture::new().build());
        let ledger = InMemoryNonceLedger::new();

        admit(&signed, &ledger).expect("the first admission succeeds");
        let err = admit(&signed, &ledger).expect_err("the same plan admitted twice is a replay");
        assert!(format!("{err:#}").contains("replay"), "got: {err:#}");
    }

    #[test]
    fn a_plan_id_that_does_not_address_its_content_is_refused() {
        use ed25519_dalek::Signer as _;

        let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
        // sign_plan re-derives the content address, so a mismatched id cannot
        // come through it — build the envelope by hand: a valid signature over
        // a plan whose stored id does not address its body.
        let plan = PlanFixture::new()
            .plan_id("not-the-content-address")
            .build();
        let payload = serde_json::to_vec(&plan).expect("plan serializes");
        let signature = fleet_key().sign(&payload);
        let signed = SignedExecutionPlan(mvm_core::protocol::signing::SignedPayload {
            payload,
            signature: signature.to_bytes().to_vec(),
            signer_id: "fleet-prod".to_string(),
        });

        let err = admit(&signed, &InMemoryNonceLedger::new())
            .expect_err("a signed plan whose id does not address its content must be refused");
        assert!(
            format!("{err:#}").contains("plan_id content-address check"),
            "got: {err:#}"
        );
    }

    #[test]
    fn a_grant_over_the_host_ceiling_is_refused() {
        // The fleet's signature does not widen host policy: the ceiling the
        // operator configured still bounds what an externally-signed plan may
        // ask for.
        let (_env, _home) = host_with(MvmConfig {
            max_cpu_millicores: Some(2000),
            trusted_plan_signers: vec![pin_for("fleet-prod", &fleet_key())],
            ..MvmConfig::default()
        });
        let plan = PlanFixture::new()
            .grants(Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 64_000 }),
                ..mvm_contract::grants::Grants::default()
            }))
            .build();
        let signed = signed_by_fleet(&plan);

        let err = admit(&signed, &InMemoryNonceLedger::new())
            .expect_err("a grant above the host's ceiling must not be admitted");
        let msg = format!("{err:#}");
        assert!(msg.contains("ceiling"), "{msg}");
        assert!(msg.contains("64000") && msg.contains("2000"), "{msg}");
    }

    #[test]
    fn a_malformed_pin_refuses_admission() {
        // A pin the operator mistyped fails the whole load — admission never
        // runs against a silently-truncated trust set.
        let (_env, _home) = host_pinning(vec![TrustedPlanSigner {
            signer_id: "fleet-prod".to_string(),
            ed25519_pubkey_hex: "not-hex".to_string(),
        }]);
        let signed = signed_by_fleet(&PlanFixture::new().build());

        let err = admit(&signed, &InMemoryNonceLedger::new())
            .expect_err("a malformed pin must refuse admission");
        assert!(format!("{err:#}").contains("fleet-prod"), "got: {err:#}");
    }
}
