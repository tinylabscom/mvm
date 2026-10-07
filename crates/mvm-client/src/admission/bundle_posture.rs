//! A signed bundle's security posture as a ceiling on the launch that boots it.
//!
//! A `.mvmpkg` may declare what its workload is allowed to do. The launch
//! asks for its own network policy, host shares, and agent verbs; admission
//! measures that request against the declaration and refuses a launch that
//! asks for more. The posture never grants anything: a bundle that allows
//! egress still boots deny-all unless the launch asks for egress.

use mvm_core::network_policy::NetworkPolicy;
use mvm_core::plan::{BundleSecurityPosture, HostShareGrant, SDK_SIDECAR_GUEST_PATH};
use mvm_core::security::AgentProfile;

/// What the launch asks for, in the terms a posture can bound.
#[derive(Debug, Clone, Copy)]
pub struct PostureRequest<'a> {
    /// The resolved egress policy the run boots with.
    pub network_policy: &'a NetworkPolicy,
    /// Every host share the plan names.
    pub shares: &'a [HostShareGrant],
    /// Whether the run's agent grant is restricted to production-safe verbs.
    /// An interactive, ad-hoc-argv, or dev-profile run is not.
    pub restrict_agent_verbs: bool,
}

/// One way a launch asks for more than its bundle's posture allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureExceedance {
    /// The network policy can take the workload off-box; the posture
    /// allows no egress.
    Egress { policy: String },
    /// The launch attaches host shares; the posture allows no volumes.
    Volumes { guest_paths: Vec<String> },
    /// The launch needs development-only agent verbs (an interactive,
    /// ad-hoc-command, or dev-profile run); the posture is sealed-prod.
    DevAccess,
}

impl std::fmt::Display for PostureExceedance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Egress { policy } => write!(
                f,
                "network policy {policy} reaches off the host, but the bundle allows no egress"
            ),
            Self::Volumes { guest_paths } => write!(
                f,
                "host shares at {} are attached, but the bundle allows no volumes",
                guest_paths.join(", ")
            ),
            Self::DevAccess => f.write_str(
                "the run needs development-only agent verbs (an interactive, ad-hoc command, \
                 or dev-profile launch), but the bundle is sealed-prod",
            ),
        }
    }
}

/// Every way `request` exceeds `posture`, in a fixed order. Empty when the
/// launch stays within it.
pub fn posture_exceedances(
    posture: &BundleSecurityPosture,
    request: &PostureRequest<'_>,
) -> Vec<PostureExceedance> {
    let mut exceeded = Vec::new();
    if !posture.allows_egress && request.network_policy.admits_outbound() {
        exceeded.push(PostureExceedance::Egress {
            policy: request.network_policy.posture_label(),
        });
    }
    if !posture.allows_volumes {
        let guest_paths: Vec<String> = request
            .shares
            .iter()
            .filter(|share| !is_system_share(share))
            .map(|share| share.guest_path.clone())
            .collect();
        if !guest_paths.is_empty() {
            exceeded.push(PostureExceedance::Volumes { guest_paths });
        }
    }
    if posture.profile == AgentProfile::SealedProd && !request.restrict_agent_verbs {
        exceeded.push(PostureExceedance::DevAccess);
    }
    exceeded
}

/// The SDK sidecar is attached by mvm for a workload that calls host
/// services, read-only, at a fixed guest path. It is not a volume the
/// launch asked for, so a no-volumes posture does not refuse it.
fn is_system_share(share: &HostShareGrant) -> bool {
    share.read_only && share.guest_path == SDK_SIDECAR_GUEST_PATH
}

/// The refusal message for a non-empty set of exceedances.
pub fn refusal_message(exceeded: &[PostureExceedance]) -> String {
    let reasons: Vec<String> = exceeded.iter().map(ToString::to_string).collect();
    format!(
        "the launch asks for more than the bundle's signed security posture allows: {}",
        reasons.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::network_policy::HostPort;
    use mvm_core::plan::ShareKind;

    fn closed(profile: AgentProfile) -> BundleSecurityPosture {
        BundleSecurityPosture {
            profile,
            verity_protected: profile == AgentProfile::SealedProd,
            requires_auth: true,
            allows_volumes: false,
            allows_egress: false,
        }
    }

    fn share(guest_path: &str, read_only: bool) -> HostShareGrant {
        HostShareGrant {
            tag: "uvol0".to_string(),
            host_path: "/host/data".to_string(),
            guest_path: guest_path.to_string(),
            kind: ShareKind::DirShare,
            read_only,
            encrypted: false,
            content_sha256: None,
        }
    }

    fn request<'a>(
        network_policy: &'a NetworkPolicy,
        shares: &'a [HostShareGrant],
        restrict_agent_verbs: bool,
    ) -> PostureRequest<'a> {
        PostureRequest {
            network_policy,
            shares,
            restrict_agent_verbs,
        }
    }

    #[test]
    fn a_launch_inside_a_closed_posture_is_admitted() {
        let deny = NetworkPolicy::deny_all();
        let exceeded = posture_exceedances(
            &closed(AgentProfile::SealedProd),
            &request(&deny, &[], true),
        );
        assert!(exceeded.is_empty(), "{exceeded:?}");
    }

    #[test]
    fn egress_past_a_no_egress_posture_is_refused() {
        let allow = NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]);
        let exceeded = posture_exceedances(&closed(AgentProfile::Dev), &request(&allow, &[], true));
        assert!(matches!(
            exceeded.as_slice(),
            [PostureExceedance::Egress { .. }]
        ));
    }

    #[test]
    fn egress_inside_an_egress_posture_is_admitted() {
        let allow = NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]);
        let posture = BundleSecurityPosture {
            allows_egress: true,
            ..closed(AgentProfile::Dev)
        };
        assert!(posture_exceedances(&posture, &request(&allow, &[], true)).is_empty());
    }

    #[test]
    fn a_user_volume_past_a_no_volumes_posture_is_refused() {
        let deny = NetworkPolicy::deny_all();
        let shares = [share("/data", false)];
        let exceeded =
            posture_exceedances(&closed(AgentProfile::Dev), &request(&deny, &shares, true));
        assert_eq!(
            exceeded,
            vec![PostureExceedance::Volumes {
                guest_paths: vec!["/data".to_string()]
            }]
        );
    }

    #[test]
    fn the_sdk_sidecar_is_not_a_volume() {
        let deny = NetworkPolicy::deny_all();
        let shares = [share(SDK_SIDECAR_GUEST_PATH, true)];
        assert!(
            posture_exceedances(&closed(AgentProfile::Dev), &request(&deny, &shares, true))
                .is_empty()
        );
    }

    #[test]
    fn a_writable_share_at_the_sidecar_path_is_still_a_volume() {
        let deny = NetworkPolicy::deny_all();
        let shares = [share(SDK_SIDECAR_GUEST_PATH, false)];
        assert_eq!(
            posture_exceedances(&closed(AgentProfile::Dev), &request(&deny, &shares, true)).len(),
            1
        );
    }

    #[test]
    fn dev_verbs_under_a_sealed_posture_are_refused() {
        let deny = NetworkPolicy::deny_all();
        assert_eq!(
            posture_exceedances(
                &closed(AgentProfile::SealedProd),
                &request(&deny, &[], false)
            ),
            vec![PostureExceedance::DevAccess]
        );
        assert!(
            posture_exceedances(&closed(AgentProfile::Dev), &request(&deny, &[], false)).is_empty(),
            "a dev posture admits an interactive run"
        );
    }

    #[test]
    fn every_exceedance_is_reported_together() {
        let allow = NetworkPolicy::unrestricted();
        let shares = [share("/data", false)];
        let exceeded = posture_exceedances(
            &closed(AgentProfile::SealedProd),
            &request(&allow, &shares, false),
        );
        assert_eq!(exceeded.len(), 3);
        let message = refusal_message(&exceeded);
        assert!(message.contains("no egress"), "{message}");
        assert!(message.contains("/data"), "{message}");
        assert!(message.contains("sealed-prod"), "{message}");
    }
}
