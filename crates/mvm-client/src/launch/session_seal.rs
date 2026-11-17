//! Closing a run's chain-signed audit session: the transient exit seal, the
//! stopped persistent machine's seal, and the unsealed-end records a failure
//! to close writes instead.
//!
//! Every record here is best-effort in the direction of the run itself: the
//! workload already ran or the machine is already stopped, so a failure is
//! reported on the audit log rather than failing the caller.

use mvm_core::client::Result;
use mvm_core::config::vm_state_dir;
use mvm_core::plan::ExecutionPlan;
use mvm_hostd::audit::emitter::{AuditEmitter, ExitRecord};

use super::{TransientExitAudit, UnsealedEnd, UnsealedReason, record_unsealed_end};

/// Best-effort chain-signed emitter under the host signer. Audit emission is
/// tamper-evidence, not part of the admission decision: a construction
/// failure warns and the boot proceeds unaudited-on-chain (CLI parity).
pub(crate) fn build_audit_emitter() -> Option<AuditEmitter> {
    let signer = match mvm_hostd::audit::host_keypair::load_or_init() {
        Ok(signer) => signer,
        Err(e) => {
            tracing::warn!(error = %e, "host signer unavailable; skipping chain audit emission");
            return None;
        }
    };
    match AuditEmitter::new(signer.signing) {
        Ok(emitter) => Some(emitter.with_receipts()),
        Err(e) => {
            tracing::warn!(error = %e, "audit emitter unavailable; skipping chain audit emission");
            None
        }
    }
}

/// Record and seal a CLI-owned transient run before its state directory is
/// removed. The signed envelope comes from the admitted launch configuration;
/// an invalid signature cannot create an exit claim or a session seal.
pub fn record_transient_exit(exit: TransientExitAudit<'_>) -> Result<()> {
    let (emitter, plan) = match verified_transient_plan(exit.signed_plan_json) {
        Ok(verified) => verified,
        Err(e) => {
            record_unsealed_end(
                None,
                UnsealedEnd::new(exit.vm_name, UnsealedReason::NoVerifiedPlan).error(&e),
            );
            return Err(e);
        }
    };
    seal_transient_end(
        &emitter,
        &plan,
        TransientEnd {
            vm_name: exit.vm_name,
            backend: exit.backend,
            exit_code: exit.exit_code,
            completed: exit.completed,
            posture: exit.posture,
        },
    )
}

/// Record that a CLI-owned transient run ended without a seal because its VM
/// could not be shown to be stopped. A session whose guest may still be
/// running is not sealed, but its end is still put on the record: chain-signed
/// under the admitted plan when that plan verifies, in the local audit log
/// when it does not.
pub fn record_transient_stop_failure(exit: TransientExitAudit<'_>, error: &str) {
    let end = UnsealedEnd::new(exit.vm_name, UnsealedReason::StopFailed).error(error);
    match verified_transient_plan(exit.signed_plan_json) {
        Ok((emitter, plan)) => record_unsealed_end(Some((&emitter, &plan)), end),
        Err(_) => record_unsealed_end(None, end),
    }
}

/// The admitted plan carried in a transient run's signed envelope, verified
/// under the host signer, and the emitter to record its end with.
fn verified_transient_plan(signed_plan_json: &str) -> Result<(AuditEmitter, ExecutionPlan)> {
    let signed: mvm_core::plan::SignedExecutionPlan =
        serde_json::from_str(signed_plan_json).map_err(crate::local::backend_err)?;
    let signer =
        mvm_hostd::audit::host_keypair::load_or_init().map_err(crate::local::backend_err)?;
    let signer_id = mvm_hostd::audit::host_keypair::host_signer_id();
    let plan = mvm_core::plan::verify_plan(&signed, &[(signer_id.as_str(), &signer.verifying)])
        .map_err(crate::local::backend_err)?;
    let emitter = AuditEmitter::new(signer.signing)
        .map(AuditEmitter::with_receipts)
        .map_err(crate::local::backend_err)?;
    Ok((emitter, plan))
}

/// How a transient run whose VM has already been stopped ended.
pub(crate) struct TransientEnd<'a> {
    pub(crate) vm_name: &'a str,
    pub(crate) backend: &'a str,
    /// The observed exit code; `None` when none was observed, never zero.
    pub(crate) exit_code: Option<i32>,
    /// Whether the workload ran to an exit, as opposed to a failed dispatch.
    pub(crate) completed: bool,
    /// How the run booted; recorded ahead of the exit record when it completed.
    pub(crate) posture: Option<crate::admission::BootPosture>,
}

/// Close a transient run's session under its admitted `plan`: `plan.exited`
/// with the observed exit and captured usage, then the seal (`exited`, or
/// `failed` for a run that did not complete), then the closing root.
///
/// Each step runs only if the one before it was written, so a failure leaves
/// the session `UNSEALED` rather than sealed over a missing exit record. The
/// caller stops the VM first: sealing a session whose VM may still be running
/// would close a narrative the guest can still extend.
pub(crate) fn seal_transient_end(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    end: TransientEnd<'_>,
) -> Result<()> {
    let state_dir = vm_state_dir(end.vm_name);
    let mut usage = mvm_core::usage_capture::read_captured(&state_dir);
    usage.host_state_bytes = mvm_core::usage_capture::host_state_bytes(&state_dir);
    let reason = if end.completed {
        mvm_hostd::audit::session::SealReason::Exited
    } else {
        mvm_hostd::audit::session::SealReason::Failed
    };
    // The exit record, the seal and the closing root reach the disk in one
    // flush, as admission's records do. Nothing acts on any of them before
    // this returns, so syncing each on its own bought no ordering; it bought
    // one serial fsync per record on a path the caller waits on. A flush that
    // fails is a seal that failed, and is recorded as one.
    let closed = emitter.batched(|| {
        if let Some(posture) = end.posture.filter(|_| end.completed) {
            crate::admission::record_boot(emitter, plan, end.backend, end.vm_name, posture);
        }
        emitter.emit_exit_record(
            plan,
            ExitRecord {
                exit_code: end.exit_code,
                backend: end.backend,
                usage,
            },
        )?;
        emitter.seal_session(plan, reason)?;
        // The session is sealed from here: a root that fails to publish
        // weakens a later consistency check but leaves the seal in place.
        Ok(emitter.publish_root(&plan.tenant.0).map(drop))
    });
    let published = match closed {
        Ok(published) => published,
        Err(e) => {
            let e = crate::local::backend_err(format!("{e:#}"));
            record_unsealed_end(
                Some((emitter, plan)),
                UnsealedEnd::new(end.vm_name, UnsealedReason::SealFailed).error(&e),
            );
            return Err(e);
        }
    };
    if let Err(e) = published {
        tracing::warn!(
            error = %format!("{e:#}"),
            machine = end.vm_name,
            "could not publish an audit root at exit; the session is sealed but a later \
             consistency check has one fewer point to verify against"
        );
        return Err(crate::local::backend_err(format!("{e:#}")));
    }
    mvm_hostd::audit::witness::flush_configured(emitter.audit_dir(), &plan.tenant.0);
    Ok(())
}

/// The records that close a waited-for run, written best-effort: the workload
/// already ran, so a failure here is reported rather than failing the exit
/// report.
pub(crate) struct ClosingRecords<'a> {
    pub(crate) plan: &'a ExecutionPlan,
    pub(crate) machine: &'a str,
    pub(crate) memory_limit_exceeded: Option<&'a mvm_core::spawn_scope::MemoryLimitExceeded>,
    pub(crate) exit: ExitRecord<'a>,
}

impl ClosingRecords<'_> {
    /// Write them, and say whether the closing root was published.
    ///
    /// The exit record, the seal and the closing root reach the disk in one
    /// flush, as admission's records and the transient path do. Nothing acts
    /// on any of them before this returns, so syncing each on its own bought
    /// no ordering; it bought one serial fsync per record on a path the
    /// caller waits on.
    pub(crate) fn record(&self, emitter: &AuditEmitter) -> bool {
        let (plan, name) = (self.plan, self.machine);
        let closed = emitter.batched(|| {
            if let Some(exceeded) = self.memory_limit_exceeded {
                emitter.emit_memory_limit_exceeded(plan, exceeded)?;
            }
            emitter.emit_exit_record(plan, self.exit)?;
            emitter.seal_session(plan, mvm_hostd::audit::session::SealReason::Exited)?;
            Ok(emitter.publish_root(&plan.tenant.0).map(drop))
        });
        match closed {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    machine = name,
                    "could not publish an audit root at exit; the log stays intact but a later \
                     consistency check has one fewer point to verify against"
                );
                // The seal is on disk; only the root failed.
                true
            }
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), machine = name, "audit closing records failed (non-fatal)");
                record_unsealed_end(
                    Some((emitter, plan)),
                    UnsealedEnd::new(name, UnsealedReason::SealFailed).error(format!("{e:#}")),
                );
                false
            }
        }
    }
}

/// Seal the session of a persistent machine that was just stopped, then publish
/// the closing root over it. Best-effort for the same reason as at exit: the
/// machine is already stopped, and a missing seal is reported by
/// `trust audit verify` as `UNSEALED` rather than hidden.
pub(crate) fn seal_stopped_session(plan: &mvm_core::plan::ExecutionPlan, machine: &str) {
    let Some(emitter) = build_audit_emitter() else {
        record_unsealed_end(
            None,
            UnsealedEnd::new(machine, UnsealedReason::SealFailed)
                .error(format!("no host audit emitter for plan {}", plan.plan_id.0)),
        );
        return;
    };
    if let Err(e) =
        mvm_hostd::supervisor::lifecycle::session_expiry::seal_stopped_session(&emitter, plan)
    {
        record_unsealed_end(
            Some((&emitter, plan)),
            UnsealedEnd::new(machine, UnsealedReason::SealFailed).error(format!("{e:#}")),
        );
    }
}

/// Record that a session's VM could not be stopped, so it was not sealed:
/// chain-signed under `plan` when there is one, locally otherwise.
pub(crate) fn record_session_stop_failure(
    plan: Option<&mvm_core::plan::ExecutionPlan>,
    machine: &str,
    error: &str,
) {
    let end = UnsealedEnd::new(machine, UnsealedReason::StopFailed).error(error);
    match (plan, build_audit_emitter()) {
        (Some(plan), Some(emitter)) => record_unsealed_end(Some((&emitter, plan)), end),
        _ => record_unsealed_end(None, end),
    }
}
