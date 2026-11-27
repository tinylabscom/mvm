//! Fold committed project policy into SDK launch requests before admission.

use super::LaunchRequest;

pub(super) fn apply_committed_sdk_policy(
    request: &mut LaunchRequest,
    candidate: &mvm_hostd::policy_generation::ProjectPolicyCandidate,
) -> anyhow::Result<()> {
    use mvm_contract::grants::{CpuGrant, Grants, WallClockGrant};

    anyhow::ensure!(
        request.signed_plan.is_none(),
        "a fleet-signed plan cannot replace an activated project's committed admission"
    );
    anyhow::ensure!(
        request.secret_refs.is_empty(),
        "committed SDK project launches cannot preserve machine secret references"
    );
    let policy = candidate.policy();
    anyhow::ensure!(
        policy.shares.is_empty()
            && policy.env.is_empty()
            && policy.secrets.bind.is_empty()
            && policy.network.routes.is_empty(),
        "this committed policy has shares, environment, secret bindings or routes \
         the SDK machine spec cannot preserve; use the CLI project launch"
    );
    anyhow::ensure!(
        request.ports.is_empty(),
        "committed SDK project launches cannot preserve inbound port mappings"
    );
    let mut grants = request.grants.take().unwrap_or_default();
    let flags = crate::policy_profiles::LaunchFlags {
        allow_host: grants
            .egress
            .as_ref()
            .map(|egress| egress.allow.iter().map(ToString::to_string).collect())
            .unwrap_or_default(),
        cpu_limit: match grants.cpu {
            Some(CpuGrant::Share { millicores }) => Some(millicores),
            _ => None,
        },
        timeout: match grants.wall_clock {
            Some(WallClockGrant::Secs { secs }) => Some(u64::from(secs.get())),
            _ => None,
        },
        declared_secrets: request
            .secret_refs
            .iter()
            .map(|reference| reference.name.clone())
            .collect(),
        cpus: request.cpus,
        memory_mib: u64::from(request.memory_mib),
        ..crate::policy_profiles::LaunchFlags::default()
    };
    let folded = crate::policy_profiles::fold(policy, &flags)?;
    if let Some(millicores) = folded.cpu_limit {
        anyhow::ensure!(
            !matches!(grants.cpu, Some(CpuGrant::Fuel { .. })),
            "committed CPU-share bound cannot be represented by an SDK fuel grant"
        );
        grants.cpu = Some(CpuGrant::Share { millicores });
    }
    if let Some(timeout) = folded.timeout {
        let secs = u32::try_from(timeout)
            .ok()
            .and_then(std::num::NonZeroU32::new)
            .ok_or_else(|| anyhow::anyhow!("committed wall-clock bound cannot fit an SDK grant"))?;
        grants.wall_clock = Some(WallClockGrant::Secs { secs });
    }
    request.grants = (grants != Grants::default()).then_some(grants);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launch::{LaunchRequestBuilder, LifecycleMode};

    fn persistent_request(image: &str, name: &str) -> LaunchRequestBuilder {
        LaunchRequest::builder(
            LifecycleMode::Persistent,
            image.parse().expect("test image parses"),
        )
        .name(name)
    }

    #[test]
    fn sdk_generation_fold_persists_required_bounds_and_refuses_widening() {
        let mut policy = crate::policy_profiles::PolicyBody::default();
        policy.resources.cpu_millicores = Some(750);
        policy.resources.wall_clock_secs = Some(40);
        policy.resources.max_cpus = Some(2);
        let candidate: mvm_hostd::policy_generation::ProjectPolicyCandidate =
            serde_json::from_value(serde_json::json!({
                "schema_version": 1,
                "generation": 1,
                "project_dir": "/project",
                "manifest_path": "/project/mvm.toml",
                "manifest_text": "flake = \".\"\n",
                "defaults": [],
                "platform": mvm_core::policy::authored::Platform::default(),
                "sources": [],
                "effective": policy,
                "effective_sha256": "0".repeat(64),
                "closure_sha256": "0".repeat(64),
            }))
            .unwrap();
        let mut request = persistent_request("docker.io/library/alpine:3.20", "bounded")
            .build()
            .unwrap();
        apply_committed_sdk_policy(&mut request, &candidate).unwrap();
        let grants = request.grants.unwrap();
        assert_eq!(
            grants.cpu,
            Some(mvm_contract::grants::CpuGrant::Share { millicores: 750 })
        );
        assert_eq!(
            grants.wall_clock,
            Some(mvm_contract::grants::WallClockGrant::Secs {
                secs: std::num::NonZeroU32::new(40).unwrap()
            })
        );
        let mut too_wide = persistent_request("docker.io/library/alpine:3.20", "too-wide")
            .cpus(3)
            .build()
            .unwrap();
        assert!(apply_committed_sdk_policy(&mut too_wide, &candidate).is_err());
        let mut mapped = persistent_request("docker.io/library/alpine:3.20", "mapped")
            .port("8080:80")
            .build()
            .unwrap();
        assert!(
            apply_committed_sdk_policy(&mut mapped, &candidate).is_err(),
            "an ingress mapping must not bypass the committed SDK policy fold"
        );
    }
}
