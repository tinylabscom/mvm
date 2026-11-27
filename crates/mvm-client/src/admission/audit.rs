//! Audit-chain emitter construction + policy-resolution audit hooks for
//! boot admission — the chain-signed emitter, and the
//! `plan.policy_resolved` / `plan.failed` event helpers admission wires
//! around it.

use anyhow::Result;

use mvm_hostd::audit::emitter::{AuditEmitter, default_audit_dir};

/// Which policy admission recorded for a plan: none (`local-default`
/// refs), or the launch's own network policy, whose digest the plan binds
/// as a policy asset identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PolicyResolutionKind {
    LocalDefault,
    NetworkPolicy,
}

impl PolicyResolutionKind {
    pub(super) const fn audit_label(self) -> &'static str {
        match self {
            Self::LocalDefault => "local-default",
            Self::NetworkPolicy => "network-policy",
        }
    }
}

pub(super) fn build_default_audit_emitter(
    signing_key: ed25519_dalek::SigningKey,
    audit_dir: Option<&std::path::Path>,
) -> Result<AuditEmitter> {
    let dir = match audit_dir {
        Some(dir) => dir.to_path_buf(),
        None => default_audit_dir()?,
    };
    let emitter = match mvm_hostd::audit::active_signer::active_signer_for(&dir) {
        Some(signer) => AuditEmitter::with_primary_signer(signing_key, &dir, signer),
        None => AuditEmitter::with_dir(signing_key, &dir),
    }?;
    emitter.with_decisions()
}

pub(super) fn emit_policy_resolved(
    plan: &mvm_core::plan::ExecutionPlan,
    emitter: &AuditEmitter,
    resolution: PolicyResolutionKind,
) {
    if let Err(e) = emitter.emit_policy_resolved(plan, resolution.audit_label()) {
        tracing::warn!(error = %e, "audit emit_policy_resolved failed (non-fatal)");
    }
}

/// Record a launch refused for asking more than its bundle's signed posture
/// allows, bound to the plan it would have run under.
pub(super) fn emit_bundle_posture_refused(
    plan: &mvm_core::plan::ExecutionPlan,
    emitter: &AuditEmitter,
    err: &anyhow::Error,
) {
    if let Err(audit_err) =
        emitter.emit_failed(plan, "bundle-posture-exceeded", &format!("{err:#}"))
    {
        tracing::warn!(
            error = %audit_err,
            "audit emit_failed for bundle-posture-exceeded failed (non-fatal)"
        );
    }
}

/// The audit class a launch refused by its bundle's signed environment is
/// recorded under.
pub(super) const BUNDLE_ENVIRONMENT_REFUSED_CLASS: &str = "bundle-environment-refused";

pub(super) fn emit_bundle_environment_refused(
    plan: &mvm_core::plan::ExecutionPlan,
    emitter: &AuditEmitter,
    err: &anyhow::Error,
) {
    if let Err(audit_err) =
        emitter.emit_failed(plan, BUNDLE_ENVIRONMENT_REFUSED_CLASS, &format!("{err:#}"))
    {
        tracing::warn!(
            error = %audit_err,
            "audit emit_failed for {BUNDLE_ENVIRONMENT_REFUSED_CLASS} failed (non-fatal)"
        );
    }
}
