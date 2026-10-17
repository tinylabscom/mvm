//! One post-launch rollback and failure-audit policy for all admission callers.

use super::{AdmittedPlan, AnyBackend, Result, VmId};

/// What rolling a launch back needs to know. A struct rather than seven
/// positional arguments, so a caller cannot silently swap the stage label for
/// the reason.
pub(super) struct UndoLaunch<'a> {
    pub(super) backend: &'a AnyBackend,
    pub(super) vm_id: &'a VmId,
    pub(super) admitted: &'a AdmittedPlan,
    pub(super) emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
    /// Wire label of the stage that refused, for the terminal audit entry.
    pub(super) stage: &'static str,
    /// Human-readable clause naming what went wrong, for the stop-failure log.
    pub(super) reason: &'static str,
    pub(super) err: anyhow::Error,
}

/// Stop a VM that started but must not keep running, emit the terminal
/// `plan.failed` entry, and hand the original error back.
///
/// One helper for both post-start refusals: leaving a VM up whose bounds were
/// never established would mean the only record of the run claims it was
/// bounded when it was not.
pub(super) fn undo_launch(undo: UndoLaunch<'_>) -> anyhow::Error {
    let backend = undo.backend;
    let vm_id = undo.vm_id;
    undo_launch_with(
        undo,
        || backend.stop(vm_id).map(|_| ()),
        FailureAuditPolicy::LegacyImmediate,
    )
}

#[derive(Debug, thiserror::Error)]
#[error("{primary:#}; rollback remains unconfirmed: {stop:#}")]
struct UndoLaunchFailure {
    #[source]
    primary: anyhow::Error,
    stop: anyhow::Error,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum FailureAuditPolicy {
    LegacyImmediate,
    OwnedAfterConfirmedRollback,
}

pub(super) fn undo_launch_with(
    undo: UndoLaunch<'_>,
    rollback: impl FnOnce() -> Result<()>,
    audit_policy: FailureAuditPolicy,
) -> anyhow::Error {
    let stopped = rollback();
    if let Err(stop_err) = &stopped {
        tracing::warn!(
            error = %stop_err,
            "stopping a VM whose {reason} failed; it may still be running",
            reason = undo.reason,
        );
    }
    if (audit_policy == FailureAuditPolicy::LegacyImmediate || stopped.is_ok())
        && let Some(emitter) = undo.emitter
        && let Err(e) = emitter.emit_failed(
            undo.admitted.plan(),
            undo.stage,
            &format!("{err:#}", err = undo.err),
        )
    {
        tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
    }
    match stopped {
        Ok(()) => undo.err,
        Err(stop) => anyhow::Error::new(UndoLaunchFailure {
            primary: undo.err,
            stop,
        }),
    }
}
