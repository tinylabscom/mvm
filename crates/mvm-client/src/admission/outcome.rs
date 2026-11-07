//! Closing a launch's audit narrative against the plan it was admitted
//! under: `plan.launched`, the boot posture and start mode a successful run
//! records, `plan.failed` for one that did not.

use mvm_core::plan::ExecutionPlan;
use mvm_hostd::audit::emitter::AuditEmitter;

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

fn boot_posture_label(strategy: mvm_build::run_image::RootStrategy) -> &'static str {
    match strategy {
        mvm_build::run_image::RootStrategy::BlockExt4 => "block-ext4",
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

/// Record that a transient run booted: `plan.launched`, the boot posture and,
/// when the claim-or-boot decision was reached, the start mode. Written ahead of
/// the run's exit record and seal, so the seal covers the whole narrative.
pub(crate) fn record_boot(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    backend: &str,
    posture: BootPosture,
) {
    if let Err(e) = emitter.emit_launched(plan, backend) {
        tracing::warn!(error = %e, "audit emit_launched failed (non-fatal)");
    }
    if let Err(e) = emitter.emit_boot_posture(plan, boot_posture_label(posture.root_strategy)) {
        tracing::warn!(error = %e, "audit emit_boot_posture failed (non-fatal)");
    }
    let Some(start) = posture.start else { return };
    let (mode, reason) = match start {
        StartMode::Warm => ("warm", None),
        StartMode::Cold { reason } => ("cold", Some(reason)),
    };
    if let Err(e) = emitter.emit_start_mode(plan, mode, reason) {
        tracing::warn!(error = %e, "audit emit_start_mode failed (non-fatal)");
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
