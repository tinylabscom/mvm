//! Whether a plan's networking mode is compatible with what it asks for.
//!
//! Selecting `l3-vsock` gives up capabilities the socket-aware path has.
//! That is a legitimate trade, but only when it is made deliberately — a
//! plan that binds secrets for host-side substitution and *also* selects
//! L3 has not made a trade, it has lost a control it still believes it has.
//!
//! ## Why substitution cannot follow the guest onto L3
//!
//! Substitution works in the socket-aware path because the host-side
//! endpoint **originates** the outbound connection. It holds the cleartext,
//! so it can replace a placeholder with the real credential on the way out
//! and never hand the guest anything sensitive.
//!
//! Over the L3 tunnel the guest originates the connection. What crosses the
//! vsock boundary for a TLS flow is ciphertext the host cannot read, and
//! the only ways to change that are to terminate the guest's TLS with a
//! host CA in its trust store — deliberately out of scope — or to leave the
//! secret out of the guest entirely.
//!
//! The second is what mvm already does, and it is unaffected by the
//! networking mode: destination-bound credentials are minted host-side and
//! raw secret bytes never enter the guest. What L3 gives up is the
//! *backstop* — the egress-time scan that catches a secret which reached
//! the guest by some other route. Losing a backstop silently is how a
//! defence-in-depth layer becomes a defence-in-name, so this module makes
//! the combination an admission failure instead.

use mvm_protocol::plan::NetworkMode;

/// What a plan asks for that bears on mode compatibility.
///
/// A struct rather than a long argument list because every field is a
/// separate reason, and a caller that grows a new one should have to name
/// it here rather than thread another boolean through.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubstitutionRequirements {
    /// The plan binds one or more secrets for host-side release.
    pub binds_secrets: bool,
    /// Reversible replacement is enabled for at least one destination.
    pub reversible_replacement_enabled: bool,
    /// Per-destination redaction is enabled for at least one destination.
    pub redaction_enabled: bool,
}

impl SubstitutionRequirements {
    /// Whether the plan depends on the host seeing outbound cleartext.
    pub fn needs_owned_cleartext(&self) -> bool {
        self.binds_secrets || self.reversible_replacement_enabled || self.redaction_enabled
    }

    /// The reasons, for an error message that tells an operator what to
    /// change rather than merely that something is wrong.
    pub fn reasons(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.binds_secrets {
            out.push("the plan binds secrets for host-side release");
        }
        if self.reversible_replacement_enabled {
            out.push("reversible replacement is enabled");
        }
        if self.redaction_enabled {
            out.push("per-destination redaction is enabled");
        }
        out
    }
}

/// Why a mode and a plan cannot go together.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModeCompatError {
    /// The plan needs the host to see outbound cleartext, and `l3-vsock`
    /// cannot provide it.
    #[error(
        "l3-vsock is incompatible with this plan: {}. \
         In l3-vsock mode the guest originates its own connections, so the host sees \
         ciphertext and cannot substitute or redact inside them. Drop \
         raw_ip_stack from this workload's network declaration so it runs \
         on the socket-aware transport, or remove the requirement from the \
         plan.",
        .reasons.join("; ")
    )]
    NeedsOwnedCleartext { reasons: Vec<&'static str> },
    /// An `l3-vsock` plan carried no L3 spec, or a spec appeared on a plan
    /// that did not select the mode.
    #[error("network mode {mode:?} and the l3 network spec disagree: {detail}")]
    SpecMismatch {
        mode: NetworkMode,
        detail: &'static str,
    },
}

/// Refuse a plan whose networking mode cannot serve what it asks for.
///
/// Fail-closed and explicit: there is no "warn and continue", because the
/// thing being lost is silent by nature — a workload whose substitution
/// stopped applying looks exactly like one that never needed it.
pub fn check_mode_compatibility(
    mode: NetworkMode,
    requirements: &SubstitutionRequirements,
    has_l3_spec: bool,
) -> Result<(), ModeCompatError> {
    if mode.is_l3_vsock() && requirements.needs_owned_cleartext() {
        return Err(ModeCompatError::NeedsOwnedCleartext {
            reasons: requirements.reasons(),
        });
    }
    match (mode.is_l3_vsock(), has_l3_spec) {
        (true, false) => Err(ModeCompatError::SpecMismatch {
            mode,
            detail: "l3-vsock was selected but the plan carries no l3 network spec",
        }),
        (false, true) => Err(ModeCompatError::SpecMismatch {
            mode,
            detail: "an l3 network spec is present but the plan does not select l3-vsock",
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needs_substitution() -> SubstitutionRequirements {
        SubstitutionRequirements {
            binds_secrets: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_plan_needing_nothing_special_may_select_l3() {
        assert!(
            check_mode_compatibility(
                NetworkMode::L3Vsock,
                &SubstitutionRequirements::default(),
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn a_plan_that_binds_secrets_cannot_select_l3() {
        let err = check_mode_compatibility(NetworkMode::L3Vsock, &needs_substitution(), true)
            .unwrap_err();
        assert!(matches!(err, ModeCompatError::NeedsOwnedCleartext { .. }));
        // The message must tell the operator what to do, not just refuse.
        let msg = err.to_string();
        assert!(msg.contains("raw_ip_stack"), "{msg}");
        assert!(msg.contains("binds secrets"), "{msg}");
    }

    #[test]
    fn reversible_replacement_and_redaction_each_block_l3_on_their_own() {
        for requirements in [
            SubstitutionRequirements {
                reversible_replacement_enabled: true,
                ..Default::default()
            },
            SubstitutionRequirements {
                redaction_enabled: true,
                ..Default::default()
            },
        ] {
            assert!(
                check_mode_compatibility(NetworkMode::L3Vsock, &requirements, true).is_err(),
                "{requirements:?} must not be admitted on l3-vsock"
            );
        }
    }

    #[test]
    fn every_reason_is_named_so_an_operator_can_fix_all_of_them_at_once() {
        let requirements = SubstitutionRequirements {
            binds_secrets: true,
            reversible_replacement_enabled: true,
            redaction_enabled: true,
        };
        let err = check_mode_compatibility(NetworkMode::L3Vsock, &requirements, true).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("binds secrets"), "{msg}");
        assert!(msg.contains("reversible replacement"), "{msg}");
        assert!(msg.contains("redaction"), "{msg}");
    }

    #[test]
    fn the_socket_aware_mode_keeps_every_substitution_capability() {
        let requirements = SubstitutionRequirements {
            binds_secrets: true,
            reversible_replacement_enabled: true,
            redaction_enabled: true,
        };
        assert!(
            check_mode_compatibility(NetworkMode::HostVsockProxy, &requirements, false).is_ok(),
            "the brokered mode is exactly where these workloads belong"
        );
    }

    #[test]
    fn selecting_l3_without_a_spec_is_refused() {
        assert!(matches!(
            check_mode_compatibility(
                NetworkMode::L3Vsock,
                &SubstitutionRequirements::default(),
                false
            ),
            Err(ModeCompatError::SpecMismatch { .. })
        ));
    }

    #[test]
    fn an_l3_spec_on_a_non_l3_plan_is_refused() {
        // The two fields must never disagree about what was admitted.
        assert!(matches!(
            check_mode_compatibility(
                NetworkMode::HostVsockProxy,
                &SubstitutionRequirements::default(),
                true
            ),
            Err(ModeCompatError::SpecMismatch { .. })
        ));
    }

    #[test]
    fn the_closed_mode_is_always_compatible() {
        let requirements = SubstitutionRequirements {
            binds_secrets: true,
            ..Default::default()
        };
        assert!(check_mode_compatibility(NetworkMode::None, &requirements, false).is_ok());
    }

    #[test]
    fn needs_owned_cleartext_is_the_disjunction_of_its_reasons() {
        assert!(!SubstitutionRequirements::default().needs_owned_cleartext());
        assert!(needs_substitution().needs_owned_cleartext());
        assert_eq!(SubstitutionRequirements::default().reasons().len(), 0);
        assert_eq!(needs_substitution().reasons().len(), 1);
    }
}
