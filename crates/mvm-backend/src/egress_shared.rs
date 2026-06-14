//! Cfg-free egress-substitution plan decode for the macOS workload backends.
//!
//! libkrun (and vz, next commit) decode the admitted plan's secret bindings
//! with no OS gate. The Firecracker path still has its own Linux-gated copy in
//! `microvm.rs`; collapsing that into this function is a tracked cleanup (it
//! edits Linux-only code and wants a Linux-target check) — until then this is
//! the macOS-side copy, not yet the single shared one.

use anyhow::Result;
use std::path::Path;

/// Decode the admitted plan's egress secret bindings from `<state_dir>/plan.json`.
///
/// `Some((secrets, redaction, tenant))` when the admitted plan carries egress
/// secrets, else `None` (legacy / non-admitted / no-secret boot — nothing to
/// wire). A missing `plan.json` or an undecodable placeholder plan is the no-op
/// path, not an error.
pub(crate) fn decode_plan_secrets_from_state(
    state_dir: &Path,
) -> Result<
    Option<(
        Vec<mvm_core::plan::SecretBinding>,
        mvm_core::policy::RedactionPolicy,
        String,
    )>,
> {
    let plan_path = state_dir.join("plan.json");
    let plan_json = match std::fs::read_to_string(&plan_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "read plan.json at {} for egress substitution: {e}",
                plan_path.display()
            ));
        }
    };
    // Both producers land here: the pre-start persist writes the bare
    // `ExecutionPlan` (the shape the firecracker bridge parses too) and the
    // gateway-bridge stash writes the signed envelope. Accept either.
    let plan = match mvm_core::plan::plan_from_admitted_json(&plan_json) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "plan.json not a decodable admitted plan; skipping egress substitution");
            return Ok(None);
        }
    };
    if plan.secrets.is_empty() {
        return Ok(None);
    }
    Ok(Some((plan.secrets, plan.redaction, plan.tenant.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_when_no_plan_json() {
        let dir = std::env::temp_dir().join(format!("mvm-egress-shared-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // No plan.json in the fresh dir → no-op path, not an error.
        let out = decode_plan_secrets_from_state(&dir).unwrap();
        assert!(out.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn returns_none_when_plan_json_undecodable() {
        let dir =
            std::env::temp_dir().join(format!("mvm-egress-shared-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plan.json"), b"not a plan").unwrap();
        let out = decode_plan_secrets_from_state(&dir).unwrap();
        assert!(out.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
