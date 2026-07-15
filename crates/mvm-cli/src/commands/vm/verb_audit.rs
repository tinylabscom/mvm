//! Best-effort chain-signed `verb_denied` audit for agent-RPC refusals.
//!
//! When the guest agent refuses a verb the admitted plan's `agent_verbs` grant
//! does not permit, it answers `VerbNotAuthorized`, which the host dispatch
//! surfaces as a typed [`RpcError::VerbNotAuthorized`]. The host records that
//! refusal as a chain-signed `verb_denied` entry (claim-12 parity) so denials are
//! observable and tamper-evident. Emission is best-effort — the refusal already
//! surfaces to the caller as an error; the audit is an observability record, not
//! load-bearing.

use mvm_agentd::vsock::RpcError;

/// Extract the denied verb from an error chain that carries an
/// [`RpcError::VerbNotAuthorized`]. Pure (no I/O) so it is unit-tested; returns
/// `None` for any other error, letting callers hand every dispatch failure to
/// [`audit_verb_refusal`] without discriminating.
fn denied_verb(err: &anyhow::Error) -> Option<&str> {
    err.chain()
        .find_map(|e| match e.downcast_ref::<RpcError>() {
            Some(RpcError::VerbNotAuthorized { verb }) => Some(verb.as_str()),
            _ => None,
        })
}

/// Record a chain-signed `verb_denied` entry for `verb` on `vm_name`. Best-effort:
/// loads the VM's persisted plan + host signer; a missing plan/signer or a flaky
/// audit fs warns and skips — it never fails the caller.
pub(in crate::commands) fn emit_verb_denied(vm_name: &str, verb: &str) {
    let plan = match super::plan_persist::read_plan(vm_name) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, vm = vm_name, verb = verb,
                "no persisted plan; verb_denied not chain-bound");
            return;
        }
    };
    let signer = match super::host_signer::load_or_init() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "host signer unavailable; verb_denied entry skipped");
            return;
        }
    };
    let emitter = match super::audit_chain::AuditEmitter::new(signer.signing) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "audit emitter unavailable; verb_denied entry skipped");
            return;
        }
    };
    if let Err(e) = emitter.emit_verb_denied(&plan, verb) {
        tracing::warn!(error = %e, vm = vm_name, verb = verb,
            "audit emit_verb_denied failed (non-fatal)");
    }
}

/// If `err`'s chain carries an [`RpcError::VerbNotAuthorized`], record the
/// refusal; a no-op for any other error. Callers pass every dispatch failure here
/// on the error path so grant refusals are audited uniformly across the verb
/// surface (exec / run-code / attach / set-timeout).
pub(in crate::commands) fn audit_verb_refusal(vm_name: &str, err: &anyhow::Error) {
    if let Some(verb) = denied_verb(err) {
        emit_verb_denied(vm_name, verb);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_verb_extracts_from_a_context_wrapped_rpc_error() {
        // Mirrors the real dispatch chain: RpcError::VerbNotAuthorized wrapped by
        // `.context(...)` on the way up to the CLI command handler.
        let err = anyhow::Error::from(RpcError::VerbNotAuthorized {
            verb: "exec".into(),
        })
        .context("dispatching into session s-1");
        assert_eq!(denied_verb(&err), Some("exec"));
    }

    #[test]
    fn denied_verb_is_none_for_a_different_rpc_error() {
        let err = anyhow::Error::from(RpcError::Agent("boom".into())).context("x");
        assert_eq!(denied_verb(&err), None);
    }

    #[test]
    fn denied_verb_is_none_for_a_plain_error() {
        let err = anyhow::anyhow!("connection reset by peer");
        assert_eq!(denied_verb(&err), None);
    }

    #[test]
    fn audit_verb_refusal_is_best_effort_when_no_plan() {
        // Carries a VerbNotAuthorized but the VM has no persisted plan ⇒ the helper
        // warns and returns without panicking.
        let err = anyhow::Error::from(RpcError::VerbNotAuthorized {
            verb: "exec".into(),
        });
        audit_verb_refusal("nonexistent-vm-for-verb-audit-test", &err);
    }
}
