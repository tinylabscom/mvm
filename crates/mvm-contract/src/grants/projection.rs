//! The projections out of `Grants` into the plan's older encodings.
//!
//! Egress policy and the wall-clock timeout are *derived* from grants and
//! never supplied alongside them. Two independently-settable representations
//! of the same decision can disagree, and whichever one the enforcement path
//! happens to read becomes the real one — so each has exactly one derivation
//! here. `xtask check-single-grants-projection` fails the build if a second
//! `Grants` -> `NetworkPolicy` appears, and
//! `xtask check-single-exec-secs-writer` fails it if anything but
//! `exec_secs_from_grants` writes `TimeoutSpec::exec_secs`.
//!
//! Every path through the egress projection is closed. There is no input that
//! yields an unrestricted policy.

use crate::grants::{Grants, WallClockGrant};
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

/// Derive the plan's legacy `TimeoutSpec::exec_secs` from a wall-clock grant.
///
/// The grant is the declaration; this is its projection into the encoding the
/// signed plan has always carried. Nothing else may write that field, so a
/// reader of the plan and a reader of the grant can never be told two
/// different bounds.
///
/// The mapping is lossy in exactly one direction and deliberately so:
/// `WallClockGrant::Unbounded` and an *absent* grant both land on `0`, the
/// legacy encoding's "no limit". They are not interchangeable to
/// [`GrantCeiling`](crate::grants::ceiling::GrantCeiling), which refuses an
/// explicit `Unbounded` under a bounded ceiling but admits an absent grant —
/// so a ceiling check must read the grant, never a reconstructed `exec_secs`.
#[must_use]
pub fn exec_secs_from_grants(grants: &Grants) -> u32 {
    match grants.wall_clock {
        None | Some(WallClockGrant::Unbounded) => 0,
        Some(WallClockGrant::Secs { secs }) => secs.get(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{EgressGrant, Grants};
    use alloc::vec;
    use core::num::NonZeroU32;

    fn bounded(secs: u32) -> Grants {
        Grants {
            wall_clock: Some(WallClockGrant::Secs {
                secs: NonZeroU32::new(secs).expect("nonzero"),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_wall_clock_grant_projects_to_exec_secs() {
        assert_eq!(exec_secs_from_grants(&bounded(600)), 600);
    }

    #[test]
    fn an_unbounded_grant_and_an_absent_grant_both_project_to_zero() {
        // The lossy direction. Both mean "no limit" in the legacy encoding,
        // which is why the ceiling has to read the grant instead of this.
        assert_eq!(exec_secs_from_grants(&Grants::default()), 0);
        assert_eq!(
            exec_secs_from_grants(&Grants {
                wall_clock: Some(WallClockGrant::Unbounded),
                ..Default::default()
            }),
            0
        );
    }

    #[test]
    fn an_unbounded_grant_and_an_absent_grant_differ_at_the_ceiling() {
        // Same projection, opposite verdicts: proof that the projection is not
        // a stand-in for the grant when a ceiling is being applied.
        let ceiling = crate::grants::ceiling::GrantCeiling {
            max_wall_clock_secs: Some(3600),
            ..Default::default()
        };
        let absent = Grants::default();
        let unbounded = Grants {
            wall_clock: Some(WallClockGrant::Unbounded),
            ..Default::default()
        };
        assert_eq!(
            exec_secs_from_grants(&absent),
            exec_secs_from_grants(&unbounded),
            "the two must project identically, or this test proves nothing"
        );
        assert!(
            ceiling.admits_grants(&absent).is_ok(),
            "an absent grant asks for nothing and is admitted"
        );
        assert!(
            ceiling.admits_grants(&unbounded).is_err(),
            "an explicit Unbounded asks for more than the ceiling and is refused"
        );
    }

    #[test]
    fn no_grant_projects_to_a_bound_it_did_not_ask_for() {
        for secs in [1_u32, 30, 600, u32::MAX] {
            assert_eq!(exec_secs_from_grants(&bounded(secs)), secs);
        }
    }

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
