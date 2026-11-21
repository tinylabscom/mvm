//! Host-side plan-admission pipeline (claim 8).
//!
//! Lives in `mvm-hostd` beside the host signing key it uses, so every driver
//! reaches one admission contract: `mvmctl run` and `mvmctl machine run`
//! today, and the `mvm-client` local backend once the boot seam wires local
//! `run`.
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
use mvm_core::plan::{ExecutionPlan, PlanId, SignedExecutionPlan, Variant};
use mvm_core::vm_backend::{BackendKind, VmStartConfig};

mod admission_support;
mod admit;
mod assurance_runtime;
mod bundle_environment;
mod canonical_kernel;
mod cli_cold;
mod composition;
mod containment_recheck;
mod display_grants;
mod extension_packs;
mod final_gates;
mod fs_quick;
mod grant_validation;
mod host_gates;
mod launch_substrate;
mod mailbox_posture;
mod nonce_ledger;
mod placement;
mod registry_pack;
mod restore;
mod rollback;
mod shares;
mod start;
mod topology_binding;
mod verb_grant_sidecar;

use assurance_runtime::AssuranceRuntimeBinding;

pub use admission_support::{
    AdmitAndStartParams, AdmitAndStartParamsBuilder, SdkSidecarBackendCompatibilityError,
    enforce_admitted_environment, enforce_sdk_sidecar_attachment,
    enforce_sdk_sidecar_backend_compatibility, enforce_sdk_sidecar_for_launch,
};
pub use admit::{
    BundleAdmissionContext, BundleImageAdmissionContext, HostPermitAdmission, admit_for_run,
    admit_plan_for_run, admit_plan_for_run_with_host_permit, admit_signed_plan_for_run,
};
pub use bundle_environment::BundleEnvironmentRefused;
pub use cli_cold::{
    DispatchedCliCold, PrepareCliColdParams, PreparedCliCold, PreparedCliWarmClaim,
    abandon_prepared_cli_cold, claim_prepared_cli_cold, prepare_cli_cold, start_prepared_cli_cold,
};
pub use extension_packs::{AdmittedExtension, ExtensionAdmissionContext};
pub use fs_quick::{PreparedFilesystemFork, prepare_filesystem_fork};
pub use launch_substrate::{
    persists_plan_before_start, populate_audit_substrate, stash_plan_and_mint_verb_grant,
    stash_plan_for_bridge, thread_cpu_grant, thread_tenant_id,
};
pub use mailbox_posture::{MailboxLaunchPosture, MailboxPostureHandoff};
pub use mvm_core::time::{Clock, SystemClock};
pub use nonce_ledger::InMemoryNonceLedger;
pub use registry_pack::{BuiltPackBootCheck, PreparedBuiltPackRuntime, prepare_built_pack_start};
pub use restore::dispatch_vm_full_fork;
pub use rollback::{
    UndoLaunchFailure, apply_admitted_grants_or_undo_launch,
    apply_persistent_grants_or_undo_launch, record_charge_or_undo_launch,
    record_charge_with_owned_rollback, record_persistent_charge_or_undo_launch,
};
pub use shares::enforce_admitted_shares;
pub use start::{
    CliStartFailure, DispatchedPersistent, LaunchAdmission, PreparePersistentParams,
    PreparedEntrypoint, PreparedPersistent, StartAdmittedParams, StartedMachine, WarmClaimDispatch,
    admit_and_start, boot_vm, claim_cli_transient, prepare_entrypoint, prepare_portable_entrypoint,
    start_admitted, start_admitted_owned_actor, start_admitted_owned_actor_with_bootstrap,
    start_cli_transient, start_entrypoint, start_fs_quick_fork, start_owned_entrypoint,
    start_persistent,
};
pub(crate) use start::{
    LaunchSource, admit_synthesized_with_verified_release, prepare_launch,
    start_admitted_with_verified_release,
};
pub use topology_binding::{CORE_PLACEMENT_STAGE, TOPOLOGY_BINDING_STAGE};

/// Result of a successful admission. Carries everything the caller
/// needs to hand to the backend (the plan + its id), to the audit
/// chain (the plan again, for `crate::supervisor::audit::signer::for_plan`), and — for the
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
    host_budget: std::sync::Arc<crate::admission_budget::HostBudgetPermit>,
    plan: ExecutionPlan,
    plan_id: PlanId,
    variant: Variant,
    signer_id: String,
    signed: SignedExecutionPlan,
    extensions: Vec<AdmittedExtension>,
    assurance_runtime: Option<AssuranceRuntimeBinding>,
    canonical_kernel: Option<std::sync::Arc<canonical_kernel::AdmittedKernel>>,
    backend: Option<BackendKind>,
    /// The host cores this launch is confined to, decided at admission from
    /// the topology unit it boots and the cores held on the host.
    placement: Option<placement::AdmittedPlacement>,
    /// Set once the backend has been started under this admission. An
    /// admission authorizes one launch; the plan is handed back on
    /// `StartedMachine`, and holding it again must not start a second backend.
    dispatched: bool,
}

impl AdmittedPlan {
    /// Spend the host hold before invoking any backend start.
    pub fn mark_host_budget_dispatching(&self, vm_name: &str) -> Result<()> {
        self.host_budget.mark_dispatching_for(&self.plan, vm_name)
    }

    /// Host reservation identity bound by a coordinating lifecycle owner.
    pub fn host_budget_id(&self) -> &str {
        self.host_budget.id()
    }

    /// Retain the same one-dispatch reservation across a legacy boot substrate.
    pub fn host_budget_permit(&self) -> std::sync::Arc<crate::admission_budget::HostBudgetPermit> {
        std::sync::Arc::clone(&self.host_budget)
    }

    /// The verified plan body — what every downstream authorization decision
    /// reads.
    #[must_use]
    pub fn plan(&self) -> &ExecutionPlan {
        &self.plan
    }

    /// The audit identity the host endpoint records this admitted workload's
    /// flows under: the admitted plan itself, never a builder identity.
    #[must_use]
    pub fn workload_audit_context(&self) -> mvm_core::audit_sink::AuditContext {
        mvm_core::audit_sink::AuditContext::Workload {
            plan: Box::new(self.plan.clone()),
        }
    }

    /// The plan's content-address, re-derived and checked during admission.
    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    /// Retain this host admission's mailbox posture for the exact VM it admitted.
    #[must_use]
    pub fn mailbox_posture(&self) -> Option<MailboxLaunchPosture> {
        self.plan.mailbox.map(|grant| MailboxLaunchPosture {
            variant: self.variant,
            plan_id: self.plan_id.clone(),
            plan_nonce: self.plan.nonce.clone(),
            vm_name: self.plan.image.name.clone(),
            grant,
        })
    }

    /// The host cores this launch is confined to, or `None` when admission
    /// placed it nowhere.
    #[must_use]
    pub fn allowed_cpus(&self) -> Option<&mvm_contract::protocol::cpu_set::CpuSet> {
        self.placement.as_ref().map(|placement| &placement.cpus)
    }

    /// Whether the cores this launch is confined to are its unit's own,
    /// rather than the cores left over by other units' exclusive placements.
    #[must_use]
    pub fn holds_cores_exclusively(&self) -> bool {
        self.placement
            .as_ref()
            .is_some_and(|placement| placement.exclusive)
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
        let host_budget = crate::admission_budget::HostBudgetPermit::reserve_ordinary(
            &plan.workload.0,
            crate::admission_budget::charge_for(
                plan.resources.mem_mib,
                plan.grants.as_ref().unwrap_or(&Default::default()),
            ),
        )
        .expect("test host capacity");
        host_budget.bind_plan(&plan).expect("test plan binding");
        Self {
            host_budget: std::sync::Arc::new(host_budget),
            plan_id: plan.plan_id.clone(),
            variant: Variant::Dev,
            signer_id,
            plan,
            signed,
            extensions: Vec::new(),
            assurance_runtime: None,
            canonical_kernel: None,
            backend: None,
            placement: None,
            dispatched: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_allowed_cpus_for_test(
        mut self,
        cpus: mvm_contract::protocol::cpu_set::CpuSet,
    ) -> Self {
        self.placement = Some(placement::AdmittedPlacement {
            cpus,
            exclusive: false,
        });
        self
    }

    #[cfg(test)]
    pub(crate) fn with_assurance_runtime_for_test(mut self, config: &VmStartConfig) -> Self {
        self.assurance_runtime = Some(
            AssuranceRuntimeBinding::verify(config, &self.plan, None)
                .expect("verified test runtime"),
        );
        self
    }
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
pub struct RunPosture<'a> {
    variant: Variant,
    backend: Option<BackendKind>,
    runtime_config: Option<&'a VmStartConfig>,
    verified_runtime: Option<&'a mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    verified_retained: Option<&'a mvm_runtime::checkpoint::VerifiedRetainedRuntime>,
}

impl<'a> RunPosture<'a> {
    /// A run whose backend is in hand. The only shape that can measure a grant
    /// against the mechanisms that will really be there.
    #[must_use]
    pub fn on_backend(variant: Variant, backend: BackendKind) -> Self {
        Self {
            variant,
            backend: Some(backend),
            runtime_config: None,
            verified_runtime: None,
            verified_retained: None,
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
            runtime_config: None,
            verified_runtime: None,
            verified_retained: None,
        }
    }

    /// The actual launch selection, not claims copied from plan JSON.
    #[must_use]
    pub fn with_runtime(mut self, runtime_config: Option<&'a VmStartConfig>) -> Self {
        self.runtime_config = runtime_config;
        self
    }

    /// Carry authenticated release bytes beside the cloneable launch config.
    #[must_use]
    pub fn with_verified_runtime(
        mut self,
        runtime: Option<&'a mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Self {
        self.verified_runtime = runtime;
        self
    }

    /// Carry authenticated checkpoint runtime evidence beside a fork's config.
    #[must_use]
    pub fn with_verified_retained(
        mut self,
        retained: Option<&'a mvm_runtime::checkpoint::VerifiedRetainedRuntime>,
    ) -> Self {
        self.verified_retained = retained;
        self
    }

    fn release_identity(&self) -> Result<Option<mvm_core::plan::RuntimeIdentity>> {
        anyhow::ensure!(
            self.verified_runtime.is_none() || self.verified_retained.is_none(),
            "launch cannot mix fresh and retained runtime verification"
        );
        if let Some(retained) = self.verified_retained {
            if let Some(identity) = retained.identity() {
                mvm_runtime::runtime_evidence::verify_runtime_for_claim(
                    retained,
                    self.runtime_config,
                )?;
                return Ok(Some(identity.clone()));
            }
            // Source and legacy forks have no signed release identity. Keep
            // their existing admission verifier; the warm-claim comparator
            // deliberately refuses legacy bindings and is not a fork gate.
            return Ok(None);
        }
        self.verified_runtime
            .map(|runtime| {
                runtime.verify_config(
                    self.runtime_config
                        .context("verified runtime has no selected launch config")?,
                )?;
                Ok(runtime.identity().clone())
            })
            .transpose()
    }

    fn verify_launch_runtime(&self, plan: &ExecutionPlan) -> Result<()> {
        if let Some(identity) = self.release_identity()? {
            plan.require_runtime_identity(&identity)?;
        } else {
            anyhow::ensure!(
                plan.runtime_identity.is_none(),
                "signed runtime identity has no verified launch evidence"
            );
            anyhow::ensure!(
                !self
                    .runtime_config
                    .is_some_and(|config| config.runtime_release_proof.is_some()),
                "release runtime requires verified launch evidence"
            );
            self.verify_runtime()?;
        }
        Ok(())
    }

    /// The sealed-production / developer posture this run carries.
    #[must_use]
    pub fn variant(&self) -> Variant {
        self.variant
    }
}

fn verify_project_generation(plan: &ExecutionPlan, posture: RunPosture<'_>) -> Result<()> {
    if plan.asset_identities.iter().any(|asset| {
        asset
            .name
            .starts_with(crate::policy_generation::GENERATION_ASSET_PREFIX)
    }) {
        anyhow::ensure!(
            cfg!(target_os = "linux") && posture.backend == Some(BackendKind::Firecracker),
            "a committed project generation requires a known Linux Firecracker backend"
        );
    }
    crate::policy_generation::verify_plan_generation_assets(plan)
}

#[cfg(test)]
mod admission_support_tests;
#[cfg(test)]
mod admit_tests;
#[cfg(test)]
mod admitted_plan_tests;
#[cfg(test)]
mod bundle_admission_tests;
#[cfg(test)]
mod containment_recheck_tests;
#[cfg(test)]
mod extension_tests;
#[cfg(test)]
mod grant_gate_tests;
#[cfg(test)]
mod launch_substrate_tests;
#[cfg(test)]
mod registry_pack_tests;
#[cfg(test)]
mod shares_tests;
#[cfg(test)]
mod signed_plan_admission_tests;
#[cfg(test)]
mod start_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod topology_binding_tests;
