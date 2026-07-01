//! Host-side egress secret substitution decision.
//!
//! Secrets never enter the microVM — not in the image, not at runtime, not in a
//! snapshot. The guest holds only an opaque placeholder; the real secret lives
//! only in the host broker's address space. On egress the broker substitutes
//! the placeholder for the real credential **host-side**, after terminating the
//! guest hop, so the secret is added to the outbound request the guest never
//! sees. This module is the closed-by-default gate that decides whether to
//! substitute for a given destination: only when the request's destination is
//! exactly the host the secret is bound to ([`SecretBinding::target_host`]). Any
//! other destination withholds it, so a bound credential can never reach an
//! unbound host. The raw value is resolved and written by the broker — this
//! module only decides substitute/withhold and which header carries it. There
//! is no path that delivers a secret into the guest.

use crate::policy::secret_binding::SecretBinding;

/// Why a bound secret was not substituted for a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithholdReason {
    /// The destination is not the host the secret is bound to.
    DestinationNotBound,
}

impl WithholdReason {
    pub const fn label(self) -> &'static str {
        match self {
            WithholdReason::DestinationNotBound => "destination_not_bound",
        }
    }
}

/// Whether a bound secret may be substituted into an outbound request — a
/// host-side decision; nothing here is ever delivered to the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubstitutionVerdict {
    /// Substitute the secret into `header` for this (bound) destination.
    Substitute { header: String },
    /// Withhold the secret — the destination is not the bound host.
    Withhold { reason: WithholdReason },
}

impl SubstitutionVerdict {
    pub const fn substitutes(&self) -> bool {
        matches!(self, SubstitutionVerdict::Substitute { .. })
    }
}

/// Decide whether `binding`'s secret may be substituted host-side for an egress
/// to `dest_host`. Closed by default: substitution happens only when the
/// destination exactly matches the binding's bound `target_host`, so a
/// destination-bound credential can never reach an unbound host — and it is
/// never sent to the guest under any outcome.
pub fn decide_substitution(binding: &SecretBinding, dest_host: &str) -> SubstitutionVerdict {
    if binding.target_host == dest_host {
        SubstitutionVerdict::Substitute {
            header: binding.header.clone(),
        }
    } else {
        SubstitutionVerdict::Withhold {
            reason: WithholdReason::DestinationNotBound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_only_for_the_bound_host() {
        let binding = SecretBinding::new("OPENAI_API_KEY", "api.openai.com");
        assert!(matches!(
            decide_substitution(&binding, "api.openai.com"),
            SubstitutionVerdict::Substitute { .. }
        ));
        assert!(matches!(
            decide_substitution(&binding, "evil.example.com"),
            SubstitutionVerdict::Withhold { .. }
        ));
    }

    #[test]
    fn substitute_carries_the_bindings_header() {
        let binding =
            SecretBinding::new("AWS_KEY", "s3.amazonaws.com").with_header("X-Amz-Security-Token");
        assert_eq!(
            decide_substitution(&binding, "s3.amazonaws.com"),
            SubstitutionVerdict::Substitute {
                header: "X-Amz-Security-Token".to_string()
            }
        );
    }

    #[test]
    fn withhold_names_the_reason_and_does_not_substitute() {
        let binding = SecretBinding::new("OPENAI_API_KEY", "api.openai.com");
        let verdict = decide_substitution(&binding, "attacker.example");
        assert!(!verdict.substitutes());
        assert_eq!(
            verdict,
            SubstitutionVerdict::Withhold {
                reason: WithholdReason::DestinationNotBound
            }
        );
    }
}
