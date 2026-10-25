//! Closing a launch's audit narrative against the plan it was admitted
//! under: `plan.launched`, the boot posture and start mode a successful run
//! records, `plan.failed` for one that did not.

use anyhow::Result;

use super::AdmissionContext;

/// Emit `plan.launched` against the supplied admission context. Tolerates
/// emission failure with a `tracing::warn` so a flaky audit fs can't block a
/// VM that already booted.
///
/// Also persists the admitted plan into the VM state dir so
/// out-of-process lifecycle verbs (e.g. `mvmctl checkpoint create`) can
/// rehydrate it and bind their audit events to the same plan_id.
/// Plan persistence failure is non-fatal — the launch already
/// succeeded; the cost is that lifecycle audit will be unbound on
/// this VM until the next launch.
pub fn emit_launched(ctx: &AdmissionContext, backend: &str, persist_plan: bool) {
    if let Err(e) = ctx.emitter.emit_launched(ctx.admitted.plan(), backend) {
        tracing::warn!(error = %e, "audit emit_launched failed (non-fatal)");
    }
    if persist_plan
        && let Err(e) = mvm_hostd::audit::plan_persist::write_plan(
            &ctx.admitted.plan().workload.0,
            ctx.admitted.plan(),
        )
    {
        tracing::warn!(
            error = %e,
            "persisting admitted plan to ~/.mvm/vms/<vm>/plan.json failed (non-fatal)"
        );
    }
}

/// Record the resolved boot posture (which rootfs strategy the run-path tier
/// gate actually selected) on the chain-signed admission log. Fires alongside
/// `plan.launched`, reflecting the decision `run_inner` made — never a
/// re-derivation — so a virtiofs-root dev boot and an Option-B block boot are
/// distinguishable in the tamper-evident chain.
pub(crate) fn emit_boot_posture(
    ctx: &AdmissionContext,
    strategy: mvm_build::run_image::RootStrategy,
) {
    let label = match strategy {
        mvm_build::run_image::RootStrategy::BlockExt4 => "block-ext4",
    };
    if let Err(e) = ctx.emitter.emit_boot_posture(ctx.admitted.plan(), label) {
        tracing::warn!(error = %e, "audit emit_boot_posture failed (non-fatal)");
    }
}

/// How a transient launch came to be running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMode {
    /// It claimed a prepared standby.
    Warm,
    /// It booted from nothing, for the reason the label names.
    Cold { reason: &'static str },
}

/// What a transient launch reports back about how it booted, for the
/// chain-signed log: the rootfs strategy, and whether it was warm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootPosture {
    pub root_strategy: mvm_build::run_image::RootStrategy,
    /// `None` for a launch that never reached the claim-or-boot decision.
    pub start: Option<StartMode>,
}

impl BootPosture {
    /// A posture with no start mode yet, as the run path seeds it.
    #[must_use]
    pub fn block() -> Self {
        Self {
            root_strategy: mvm_build::run_image::RootStrategy::BlockExt4,
            start: None,
        }
    }
}

fn emit_start_mode(ctx: &AdmissionContext, start: StartMode) {
    let (mode, reason) = match start {
        StartMode::Warm => ("warm", None),
        StartMode::Cold { reason } => ("cold", Some(reason)),
    };
    if let Err(e) = ctx
        .emitter
        .emit_start_mode(ctx.admitted.plan(), mode, reason)
    {
        tracing::warn!(error = %e, "audit emit_start_mode failed (non-fatal)");
    }
}

/// Close a transient run's audit narrative against the plan it booted under:
/// `plan.launched`, the boot posture and the start mode when the run
/// succeeded, `plan.failed` when it did not.
///
/// `admitted` is `None` only when the run failed before admission was reached —
/// resolving the image, say. There is no plan to bind that failure to, so
/// nothing is recorded. It is never `None` for a run that booted: admission is
/// unconditional, and the admit closure fills this before the backend starts.
///
/// Both transient paths close the same way, so they share this rather than each
/// carrying its own copy of the two branches.
pub fn record_transient_outcome<T>(
    admitted: Option<&AdmissionContext>,
    backend: &str,
    posture: BootPosture,
    outcome: &Result<T>,
) {
    let Some(ctx) = admitted else { return };
    match outcome {
        Ok(_) => {
            emit_launched(ctx, backend, false);
            emit_boot_posture(ctx, posture.root_strategy);
            if let Some(start) = posture.start {
                emit_start_mode(ctx, start);
            }
        }
        Err(e) => emit_failed(
            ctx,
            crate::launch::startup_budget::failure_class(e, "launch"),
            e,
        ),
    }
}

/// Emit `plan.failed` against the supplied admission context. `class` is a short grep-friendly tag
/// (e.g. `backend-start`, `snapshot-restore`); `err` becomes the
/// rendered error chain.
pub fn emit_failed(ctx: &AdmissionContext, class: &str, err: &anyhow::Error) {
    let msg = format!("{err:#}");
    if let Err(e) = ctx.emitter.emit_failed(ctx.admitted.plan(), class, &msg) {
        tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
    }
    // A failed boot is the end of its session.
    if let Err(e) = ctx.emitter.seal_session(
        ctx.admitted.plan(),
        mvm_hostd::audit::session::SealReason::Failed,
    ) {
        crate::launch::record_unsealed_end(
            Some((&ctx.emitter, ctx.admitted.plan())),
            crate::launch::UnsealedEnd::new(
                &ctx.admitted.plan().workload.0,
                crate::launch::UnsealedReason::SealFailed,
            )
            .error(format!("{e:#}")),
        );
    }
}
