//! The admission check that holds a plan to the topology admitted for its
//! tenant.
//!
//! It runs once, on the shared tail of admission, after the signature, the
//! content address and the validity window, and before the nonce is spent, so
//! a refused plan keeps its replay allowance and can be presented again. Every
//! refusal is written to the tenant's chain as `plan.admission_refused` with
//! the stage below.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::plan::topology::{Unit, check_topology_binding};
use mvm_core::plan::ExecutionPlan;

use crate::audit::emitter::AuditEmitter;

/// The `stage` label a refusal carries.
pub const TOPOLOGY_BINDING_STAGE: &str = "topology_binding";

/// Check `plan` against the topology admitted for its tenant under the
/// resolved mvm home, and return the unit it boots, if it is bound.
pub(super) fn admit_topology_binding(
    plan: &ExecutionPlan,
    host_signer_keys_dir: Option<&Path>,
) -> Result<Option<Unit>> {
    let home = mvm_core::config::mvm_home_strict()?;
    admit_topology_binding_at(&home, plan, host_signer_keys_dir)
}

/// [`admit_topology_binding`] under an explicit `home`.
///
/// # Errors
///
/// A [`mvm_contract::plan::topology::TopologyBindingRefusal`] as the root
/// cause for a mismatch, or the error that kept the admitted topology from
/// being read. Both are audited; if the audit write fails too, the refusal
/// stands and the error says so.
pub(crate) fn admit_topology_binding_at(
    home: &Path,
    plan: &ExecutionPlan,
    host_signer_keys_dir: Option<&Path>,
) -> Result<Option<Unit>> {
    match decide(home, plan, host_signer_keys_dir) {
        Ok(unit) => Ok(unit),
        Err(refusal) => Err(audit_refusal(home, plan, host_signer_keys_dir, refusal)),
    }
}

fn decide(
    home: &Path,
    plan: &ExecutionPlan,
    host_signer_keys_dir: Option<&Path>,
) -> Result<Option<Unit>> {
    let admitted =
        crate::topology_admission::last_admitted_topology(home, &plan.tenant, host_signer_keys_dir)
            .context("reading the topology admitted for the plan's tenant")?;
    Ok(check_topology_binding(plan, admitted.as_ref())?.cloned())
}

/// Context on a refusal this check has already written to the chain. A caller
/// that audits admission failures itself skips an error carrying it, so each
/// refusal is recorded once. A refusal whose entry could not be written does
/// not carry it, and is left for that caller to record.
#[derive(Debug)]
pub(crate) struct TopologyRefusalAudited;

impl std::fmt::Display for TopologyRefusalAudited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REFUSED)
    }
}

const REFUSED: &str = "plan refused: it does not match the admitted topology";

fn audit_refusal(
    home: &Path,
    plan: &ExecutionPlan,
    host_signer_keys_dir: Option<&Path>,
    refusal: anyhow::Error,
) -> anyhow::Error {
    let reason = format!("{REFUSED}: {refusal:#}");
    match emit(home, plan, host_signer_keys_dir, &reason) {
        Ok(()) => refusal.context(TopologyRefusalAudited),
        Err(e) => refusal.context(REFUSED).context(format!(
            "the refusal could not be written to the audit chain: {e:#}"
        )),
    }
}

fn emit(
    home: &Path,
    plan: &ExecutionPlan,
    host_signer_keys_dir: Option<&Path>,
    reason: &str,
) -> Result<()> {
    let signer = match host_signer_keys_dir {
        Some(dir) => crate::audit::host_keypair::load_or_init_at(dir)?,
        None => crate::audit::host_keypair::load_or_init()?,
    };
    AuditEmitter::with_dir(signer.signing, &home.join("audit"))?.emit_refused(
        plan,
        TOPOLOGY_BINDING_STAGE,
        reason,
    )
}
