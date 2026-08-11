//! The single `Grants` -> `NetworkPolicy` projection.
//!
//! Egress policy is *derived* from grants and never supplied alongside them.
//! Two independently-settable representations of the same decision can
//! disagree, and whichever one the enforcement path happens to read becomes
//! the real policy — so there is exactly one function here, and
//! `xtask check-single-grants-projection` fails the build if a second appears.
//!
//! Every path through this function is closed. There is no input that yields
//! an unrestricted policy.

use crate::grants::Grants;
use crate::policy::network_policy::{HostPort, NetworkPolicy};

/// Derive the egress policy a set of grants authorizes.
///
/// An absent `egress` grant and an empty allow-list both mean deny-all: the
/// distinction between "unspecified" and "explicitly nothing" never opens
/// anything, so collapsing them is safe.
#[must_use]
pub fn network_policy_from_grants(grants: &Grants) -> NetworkPolicy {
    match grants.egress.as_ref() {
        None => NetworkPolicy::deny_all(),
        Some(egress) => {
            let rules: alloc::vec::Vec<HostPort> = egress.allow.clone();
            if rules.is_empty() {
                NetworkPolicy::deny_all()
            } else {
                NetworkPolicy::allow_list(rules)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{EgressGrant, Grants};
    use alloc::vec;

    #[test]
    fn absent_egress_projects_to_deny_all() {
        let p = network_policy_from_grants(&Grants::default());
        assert_eq!(
            p.resolve_rules().as_deref(),
            Some(&[][..]),
            "an unspecified egress grant must be deny-all, never permissive"
        );
    }

    #[test]
    fn an_empty_allow_list_projects_to_deny_all() {
        let g = Grants {
            egress: Some(EgressGrant { allow: vec![] }),
            ..Default::default()
        };
        let p = network_policy_from_grants(&g);
        assert_eq!(p.resolve_rules().as_deref(), Some(&[][..]));
    }

    #[test]
    fn an_allow_list_projects_to_those_rules() {
        let g = Grants {
            egress: Some(EgressGrant {
                allow: vec![
                    HostPort::new("api.example.com", 443),
                    HostPort::new("db.internal", 5432),
                ],
            }),
            ..Default::default()
        };
        let rules = network_policy_from_grants(&g)
            .resolve_rules()
            .expect("an allow-list resolves to rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], HostPort::new("api.example.com", 443));
        assert_eq!(rules[1], HostPort::new("db.internal", 5432));
    }

    #[test]
    fn no_projection_ever_yields_unrestricted() {
        // Unrestricted is reachable only by an explicit operator opt-in
        // elsewhere. No grant, however shaped, may produce it here.
        for g in [
            Grants::default(),
            Grants {
                egress: Some(EgressGrant { allow: vec![] }),
                ..Default::default()
            },
            Grants {
                egress: Some(EgressGrant {
                    allow: vec![HostPort::new("example.com", 80)],
                }),
                ..Default::default()
            },
        ] {
            assert!(
                !network_policy_from_grants(&g).is_unrestricted(),
                "projection must never open the network"
            );
        }
    }
}
