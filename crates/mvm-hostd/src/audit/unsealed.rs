//! Recording a session end that carries no seal.
//!
//! A session that ends is sealed, or it is deliberately left `UNSEALED`
//! because its VM could not be shown to be stopped, its seal could not be
//! written, or there is no admitted plan to bind a seal to. In every one of
//! those cases the end still goes on the record, so the audit trail never goes
//! quiet about a session that stopped.

use crate::audit::emitter::AuditEmitter;
use mvm_core::plan::ExecutionPlan;

/// Why a session that ended carries no seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsealedReason {
    /// The VM could not be shown to be stopped, so the guest may still act.
    StopFailed,
    /// The exit record or the seal itself could not be written.
    SealFailed,
    /// There is no admitted plan to bind a seal to, or it did not verify.
    NoVerifiedPlan,
}

impl UnsealedReason {
    /// The tag written to the audit trail.
    pub fn tag(self) -> &'static str {
        match self {
            Self::StopFailed => "stop-failed",
            Self::SealFailed => "seal-failed",
            Self::NoVerifiedPlan => "no-verified-plan",
        }
    }
}

/// A session end that will not be sealed, and why.
pub struct UnsealedEnd<'a> {
    vm_name: &'a str,
    reason: UnsealedReason,
    error: Option<String>,
}

impl<'a> UnsealedEnd<'a> {
    pub fn new(vm_name: &'a str, reason: UnsealedReason) -> Self {
        Self {
            vm_name,
            reason,
            error: None,
        }
    }

    /// Attach the error that caused it.
    pub fn error(mut self, error: impl std::fmt::Display) -> Self {
        self.error = Some(error.to_string());
        self
    }
}

/// Put on the record why a session that ended was not sealed, so its end never
/// goes unrecorded. With an admitted plan the record is a chain-signed
/// `plan.teardown_failed` bound to the session; with no plan, or a chain that
/// refuses the write, it is a `session_unsealed` entry in the local audit log.
/// `trust audit verify` still reports the session `UNSEALED`: the record says
/// why, it does not stand in for the seal.
pub fn record_unsealed_end(chain: Option<(&AuditEmitter, &ExecutionPlan)>, end: UnsealedEnd<'_>) {
    let message = end.error.as_deref().unwrap_or("");
    tracing::warn!(
        machine = end.vm_name,
        reason = end.reason.tag(),
        error = message,
        "session ended without a seal; `trust audit verify` will report it unsealed"
    );
    let mut plan_id = None;
    if let Some((emitter, plan)) = chain {
        match emitter.emit_teardown_failed(plan, end.reason.tag(), message) {
            Ok(()) => return,
            Err(e) => tracing::warn!(
                error = %format!("{e:#}"),
                machine = end.vm_name,
                "could not write plan.teardown_failed; recording the unsealed end locally"
            ),
        }
        plan_id = Some(plan.plan_id.0.as_str());
    }
    let mut detail = format!("reason={}", end.reason.tag());
    if let Some(id) = plan_id {
        detail.push_str(&format!(",plan={id}"));
    }
    if let Some(error) = &end.error {
        detail.push_str(&format!(",error={error}"));
    }
    mvm_core::audit_emit!(SessionUnsealed, vm: end.vm_name, "{detail}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn local_audit_text() -> String {
        std::fs::read_to_string(mvm_core::audit::default_audit_log()).unwrap_or_default()
    }

    fn emitter_in(dir: &std::path::Path) -> AuditEmitter {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        AuditEmitter::with_dir(key, dir).expect("emitter")
    }

    #[test]
    fn an_unsealed_end_with_a_plan_is_chain_signed_under_it() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().expect("home");
        env.isolate_mvm_home(home.path());
        let chain_dir = home.path().join("chain");
        let emitter = emitter_in(&chain_dir);
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();

        record_unsealed_end(
            Some((&emitter, &plan)),
            UnsealedEnd::new("vm-stuck", UnsealedReason::StopFailed).error("vmm still running"),
        );

        let chain = std::fs::read_to_string(crate::audit::emitter::audit_path_for_tenant(
            &chain_dir,
            &plan.tenant.0,
        ))
        .expect("chain");
        assert!(chain.contains("plan.teardown_failed"), "{chain}");
        assert!(chain.contains("stop-failed"), "{chain}");
        assert!(
            !local_audit_text().contains("session_unsealed"),
            "the chain took it"
        );
    }

    #[test]
    fn an_unsealed_end_the_chain_refuses_is_recorded_locally() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().expect("home");
        env.isolate_mvm_home(home.path());
        let chain_dir = home.path().join("unwritable-chain");
        let emitter = emitter_in(&chain_dir);
        // Put a file where the chain directory was, so the write fails.
        std::fs::remove_dir_all(&chain_dir).expect("remove chain dir");
        std::fs::write(&chain_dir, b"not a directory").expect("block the chain dir");
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();

        record_unsealed_end(
            Some((&emitter, &plan)),
            UnsealedEnd::new("vm-chain-refused", UnsealedReason::SealFailed).error("disk full"),
        );

        let local = local_audit_text();
        assert!(local.contains("session_unsealed"), "{local}");
        assert!(local.contains("seal-failed"), "{local}");
        assert!(local.contains(&plan.plan_id.0), "{local}");
        assert!(local.contains("disk full"), "{local}");
    }

    #[test]
    fn an_unsealed_end_with_no_plan_is_recorded_locally() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().expect("home");
        env.isolate_mvm_home(home.path());

        record_unsealed_end(
            None,
            UnsealedEnd::new("vm-planless", UnsealedReason::NoVerifiedPlan),
        );

        let local = local_audit_text();
        assert!(local.contains("session_unsealed"), "{local}");
        assert!(local.contains("vm-planless"), "{local}");
        assert!(local.contains("no-verified-plan"), "{local}");
    }
}
