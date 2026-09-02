//! Cfg-free egress-substitution plan decode shared by every workload backend.
//!
//! libkrun, hvf, and the Linux-gated Firecracker path (`microvm.rs`) all decode
//! the admitted plan's secret bindings through this one function — no OS gate,
//! no per-backend copy.

use anyhow::Result;
use std::path::Path;

use mvm_core::vm_backend::VmStartConfig;

/// Read the admitted plan a VM's state dir carries, if any.
///
/// `Ok(None)` for a state dir with no `plan.json` (legacy / non-admitted boot).
/// A read error other than "not found" is an error rather than a silent no-op,
/// because a plan that exists but cannot be read must not read as "no secrets".
fn read_plan_json_from_state(state_dir: &Path) -> Result<Option<String>> {
    let plan_path = state_dir.join("plan.json");
    match std::fs::read_to_string(&plan_path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!(
            "read plan.json at {} for egress substitution: {e}",
            plan_path.display()
        )),
    }
}

/// Decode the admitted plan's egress secret bindings from `<state_dir>/plan.json`.
///
/// `Some((secrets, redaction, tenant))` when the admitted plan carries egress
/// secrets, else `None` (legacy / non-admitted / no-secret boot — nothing to
/// wire). A missing `plan.json` or an undecodable placeholder plan is the no-op
/// path, not an error.
pub fn decode_plan_secrets_from_state(
    state_dir: &Path,
) -> Result<
    Option<(
        Vec<mvm_core::plan::SecretBinding>,
        mvm_core::policy::RedactionPolicy,
        String,
    )>,
> {
    let Some(plan_json) = read_plan_json_from_state(state_dir)? else {
        return Ok(None);
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

/// The output-retention mode an admitted plan was signed with.
///
/// Read off the launch config's own copy of the plan rather than the state
/// dir, so a warm claim answers it before the child has a state dir at all —
/// the same source [`effective_vsock_egress`] partitions the warm pool on.
///
/// Every uncertain case answers `Persist`: an unadmitted boot, a plan that
/// will not decode, a plan predating the field. Recording is the safe side of
/// this decision — the failure mode of the wrong answer here is a transcript
/// that exists when nobody asked for one, against a workload silently going
/// unrecorded.
pub fn plan_stream_retention(plan_json: Option<&str>) -> mvm_core::plan::StreamRetention {
    plan_json
        .and_then(|json| mvm_core::plan::plan_from_admitted_json(json).ok())
        .map(|plan| plan.stream_retention)
        .unwrap_or_default()
}

/// True when `plan_json` — an admitted plan in either the bare or the signed
/// shape — binds at least one egress secret.
///
/// The single predicate behind both [`state_has_bound_secrets`], which asks it
/// of the bytes a VM's state dir already holds, and [`effective_vsock_egress`],
/// which asks it of the same bytes while they are still only in the launch
/// config. An undecodable plan answers `false`, matching the substitution path's
/// own treatment of a placeholder plan.
pub fn plan_json_has_bound_secrets(plan_json: &str) -> bool {
    mvm_core::plan::plan_from_admitted_json(plan_json).is_ok_and(|plan| !plan.secrets.is_empty())
}

/// True when an admitted plan declares at least one host-owned ingress mapping.
/// Undecodable or absent plans remain the closed path.
pub fn plan_json_has_ingress(plan_json: &str) -> bool {
    mvm_core::plan::plan_from_admitted_json(plan_json).is_ok_and(|plan| !plan.ingress.is_empty())
}

/// True when the workload's persisted plan carries at least one bound secret
/// (i.e. the credential-substitution endpoint will own `EGRESS_PORT`). The
/// transparent-TCP vsock egress path (Phase A) is scoped to the `false` case so
/// the two never contend for the port.
pub fn state_has_bound_secrets(state_dir: &Path) -> Result<bool> {
    Ok(read_plan_json_from_state(state_dir)?
        .as_deref()
        .is_some_and(plan_json_has_bound_secrets))
}

/// Whether this launch's guest boots with its authenticated vsock client
/// started — the *effective* client enablement, not just the raw policy.
///
/// The guest starts that client when the launch allows egress, or when its
/// admitted plan declares host-owned ingress, and it carries no bound secrets.
/// A secret-bearing workload's egress goes through the host-side substitution
/// endpoint, which owns the shared egress port, so the raw client stays off
/// and must not contend for it. These inputs are read from the launch config,
/// so the answer is available at warm-claim decision time.
///
/// This is the value the warm pool partitions on. It is the same predicate the
/// guest's cmdline token is derived from, with the plan read from the config
/// instead of from disk; when the two sources can disagree (a launch path that
/// has not persisted its plan beside the VM yet) this is the *conservative*
/// side — it can only withhold the client from a warm child that a cold boot
/// would have started it for, never the reverse.
pub fn effective_vsock_egress(config: &VmStartConfig) -> bool {
    let plan_has_ingress = config
        .plan_json
        .as_deref()
        .is_some_and(plan_json_has_ingress);
    (config.network_policy.allows_egress() || plan_has_ingress)
        && !config
            .plan_json
            .as_deref()
            .is_some_and(plan_json_has_bound_secrets)
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

    /// Every shape that is not an explicit, decodable opt-out has to come back
    /// recording — an undecodable plan reading as `Ephemeral` would turn a
    /// parse bug into a silently unrecorded workload.
    #[test]
    fn retention_reads_persist_unless_a_decodable_plan_opts_out() {
        use mvm_core::plan::StreamRetention;
        use mvm_core::plan::test_support::PlanFixture;

        assert_eq!(plan_stream_retention(None), StreamRetention::Persist);
        assert_eq!(
            plan_stream_retention(Some("not a plan")),
            StreamRetention::Persist
        );
        assert_eq!(
            plan_stream_retention(Some(&plan_json_without_secrets())),
            StreamRetention::Persist
        );

        let opted_out = PlanFixture::new()
            .stream_retention(StreamRetention::Ephemeral)
            .build();
        let json = serde_json::to_string(&opted_out).unwrap();
        assert_eq!(
            plan_stream_retention(Some(&json)),
            StreamRetention::Ephemeral
        );
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

/// An admitted plan in the bare shape, carrying one bound egress secret — the
/// shape `plan.json` holds beside a secret-bearing workload. Shared with the
/// warm-pool tests, which need the same plan on both the launch config and the
/// state dir to compare a warm parent's boot against a cold one's.
#[cfg(any(test, feature = "test-support"))]
pub fn plan_json_with_one_bound_secret() -> String {
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::plan::{SecretBinding, SecretSource};

    let plan = PlanFixture::new()
        .secrets(vec![SecretBinding {
            name: "API_KEY".into(),
            source: SecretSource::Keystore {
                address: "test-key".into(),
            },
        }])
        .build();
    serde_json::to_string(&plan).expect("serialize admitted plan fixture")
}

/// The same admitted plan with no secret bound at all.
#[cfg(test)]
pub(crate) fn plan_json_without_secrets() -> String {
    let plan = mvm_core::plan::test_support::PlanFixture::new().build();
    serde_json::to_string(&plan).expect("serialize admitted plan fixture")
}

#[cfg(test)]
mod phase_a_tests {
    use super::*;

    use mvm_core::network_policy::{HostPort, NetworkPolicy};

    #[test]
    fn state_has_bound_secrets_is_false_for_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        // No plan file written → no secrets.
        assert!(!state_has_bound_secrets(dir.path()).unwrap());
    }

    /// The one predicate must answer identically whether it is asked of the
    /// launch config's bytes or of the same bytes on disk — that equality is
    /// what lets the warm pool decide at claim time what a cold boot would only
    /// discover at start time.
    #[test]
    fn the_secret_predicate_agrees_between_the_launch_config_and_the_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        for (json, want) in [
            (plan_json_with_one_bound_secret(), true),
            (plan_json_without_secrets(), false),
            ("not a plan".to_string(), false),
        ] {
            std::fs::write(dir.path().join("plan.json"), &json).unwrap();
            assert_eq!(plan_json_has_bound_secrets(&json), want);
            assert_eq!(state_has_bound_secrets(dir.path()).unwrap(), want);
        }
    }

    fn allow_list_launch(plan_json: Option<String>) -> VmStartConfig {
        VmStartConfig {
            network_policy: NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
            plan_json,
            ..Default::default()
        }
    }

    #[test]
    fn effective_egress_is_on_for_an_egress_launch_carrying_no_bound_secret() {
        assert!(effective_vsock_egress(&allow_list_launch(None)));
        assert!(effective_vsock_egress(&allow_list_launch(Some(
            plan_json_without_secrets()
        ))));
    }

    /// The case that must never come out permissive: a secret-bearing workload's
    /// outbound traffic belongs to the host-side substitution endpoint, so the
    /// guest's own egress client stays off even though the policy allows egress.
    #[test]
    fn effective_egress_is_off_when_the_admitted_plan_binds_a_secret() {
        let cfg = allow_list_launch(Some(plan_json_with_one_bound_secret()));
        assert!(
            cfg.network_policy.allows_egress(),
            "fixture must exercise the suppression, not a deny-all policy"
        );
        assert!(!effective_vsock_egress(&cfg));
    }

    #[test]
    fn effective_egress_is_off_under_deny_all_whatever_the_plan_says() {
        for plan in [None, Some(plan_json_without_secrets())] {
            let cfg = VmStartConfig {
                plan_json: plan,
                ..Default::default()
            };
            assert!(!cfg.network_policy.allows_egress(), "default is deny-all");
            assert!(!effective_vsock_egress(&cfg));
        }
    }

    #[test]
    fn ingress_starts_client_under_deny_all_without_secrets() {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.ingress.push(
            mvm_core::plan::IngressMapping::builder()
                .mapping_id(1)
                .protocol(mvm_core::plan::IngressProtocol::Tcp)
                .host_addr("127.0.0.1")
                .host_port(8080)
                .guest_addr("127.0.0.1")
                .guest_port(8080)
                .transform(mvm_core::plan::IngressTransform::Opaque)
                .build()
                .expect("valid ingress fixture"),
        );
        let cfg = VmStartConfig {
            plan_json: Some(serde_json::to_string(&plan).expect("serialize ingress fixture")),
            ..Default::default()
        };
        assert!(!cfg.network_policy.allows_egress());
        assert!(effective_vsock_egress(&cfg));
    }

    #[test]
    fn ingress_does_not_bypass_secret_suppression() {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .secrets(vec![mvm_core::plan::SecretBinding {
                name: "API_KEY".into(),
                source: mvm_core::plan::SecretSource::Keystore {
                    address: "test-key".into(),
                },
            }])
            .build();
        plan.ingress.push(
            mvm_core::plan::IngressMapping::builder()
                .mapping_id(1)
                .protocol(mvm_core::plan::IngressProtocol::Tcp)
                .host_addr("127.0.0.1")
                .host_port(8080)
                .guest_addr("127.0.0.1")
                .guest_port(8080)
                .transform(mvm_core::plan::IngressTransform::Opaque)
                .build()
                .expect("valid ingress fixture"),
        );
        let cfg = VmStartConfig {
            plan_json: Some(serde_json::to_string(&plan).expect("serialize ingress fixture")),
            ..Default::default()
        };
        assert!(!effective_vsock_egress(&cfg));
    }
}
