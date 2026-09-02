//! `--host-service` validation: raw CLI strings into plan-bound service ids.
//!
//! Validation only. The SDK sidecar these bindings imply is resolved much
//! later, in `exec::resolve_launch`, because which of the two artifacts a
//! workload needs depends on the guest's libc and the guest does not exist
//! until the image has been materialized.
//!
//! Kept beside the transient-run surface that reads the flag, and separate from
//! it, so the parser is unit-testable on its own and the run module stays within
//! the workspace file-size budget.

use anyhow::Result;

/// Validate `--host-service` values into plan-bound service ids.
///
/// Every value must be a well-formed `<name>.v<n>` service id. Refusing a
/// malformed id here — rather than at broker dispatch — keeps the signed plan
/// from carrying a binding no handler could ever satisfy.
pub(crate) fn parse_host_service_bindings(
    raw: &[String],
) -> Result<Vec<mvm_contract::protocol::broker::ServiceId>> {
    let mut out = Vec::with_capacity(raw.len());
    for value in raw {
        let id = mvm_contract::protocol::broker::ServiceId::parse(value.trim())
            .map_err(|e| anyhow::anyhow!("invalid --host-service '{value}': {e}"))?;
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flag_binds_no_services() {
        assert!(parse_host_service_bindings(&[]).unwrap().is_empty());
    }

    #[test]
    fn well_formed_ids_are_bound_in_order() {
        let bound =
            parse_host_service_bindings(&["host.audit.v1".into(), "host.time.v1".into()]).unwrap();
        assert_eq!(
            bound.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ["host.audit.v1", "host.time.v1"]
        );
    }

    #[test]
    fn duplicates_collapse_so_the_plan_carries_each_binding_once() {
        let bound =
            parse_host_service_bindings(&["host.audit.v1".into(), "host.audit.v1".into()]).unwrap();
        assert_eq!(bound.len(), 1);
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let bound = parse_host_service_bindings(&["  host.cost.v1 ".into()]).unwrap();
        assert_eq!(bound[0].as_str(), "host.cost.v1");
    }

    #[test]
    fn a_malformed_id_is_refused_before_it_reaches_the_plan() {
        for bad in [
            "",
            "host.audit",
            "host..v1",
            "HOST.AUDIT.V1",
            "host.audit.vX",
        ] {
            assert!(
                parse_host_service_bindings(&[bad.to_string()]).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn only_sdk_served_bindings_ask_for_the_sidecar() {
        let sdk = parse_host_service_bindings(&["host.secrets.v1".into()]).unwrap();
        assert!(mvm_core::plan::sdk_sidecar_required_for(&sdk));
        let other = parse_host_service_bindings(&["broker.v1".into()]).unwrap();
        assert!(!mvm_core::plan::sdk_sidecar_required_for(&other));
    }
}
