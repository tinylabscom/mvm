//! Inputs for the one-call admitted boot.

use super::{BundleAdmissionContext, Clock, ExtensionAdmissionContext, InMemoryNonceLedger};
use anyhow::Result;
use mvm_contract::builder::BuilderError;
use mvm_core::plan::{SynthesisInput, Variant};
use mvm_core::policy::PolicyBundle;
use mvm_core::vm_backend::VmStartConfig;

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
