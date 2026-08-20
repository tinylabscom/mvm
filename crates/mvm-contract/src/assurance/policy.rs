//! Canonical policy-reference identity for assurance admission.
//!
//! The assurance controller and MVM must compute the same identity without
//! exchanging policy contents. The v1 encoding is the four references in
//! their fixed admission order, separated by a single NUL byte, hashed with
//! SHA-256, and rendered as a `sha256:` digest.

use sha2::{Digest, Sha256};

use super::Sha256Digest;

/// Stable identifier for the policy-reference digest encoding.
pub const POLICY_DIGEST_ALGORITHM_V1: &str = "sha256:nul-separated-policy-refs-v1";

/// Compute the effective policy identity from its four admitted references.
///
/// The order is part of the wire contract: network, egress, filesystem, then
/// tool policy. Empty references are not rejected here because the policy
/// loader owns reference validation; preserving them in the digest makes a
/// malformed or incomplete admission distinguishable rather than silently
/// equivalent to another policy.
#[must_use]
pub fn policy_digest_from_refs(
    network_policy: &str,
    egress_policy: &str,
    fs_policy: &str,
    tool_policy: &str,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(network_policy.as_bytes());
    hasher.update([0]);
    hasher.update(egress_policy.as_bytes());
    hasher.update([0]);
    hasher.update(fs_policy.as_bytes());
    hasher.update([0]);
    hasher.update(tool_policy.as_bytes());
    Sha256Digest::from_bytes(&hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::{POLICY_DIGEST_ALGORITHM_V1, policy_digest_from_refs};

    #[test]
    fn vector_is_stable_for_counterparty_implementations() {
        assert_eq!(
            POLICY_DIGEST_ALGORITHM_V1,
            "sha256:nul-separated-policy-refs-v1"
        );
        assert_eq!(
            policy_digest_from_refs("network-ref", "egress-ref", "fs-ref", "tool-ref").as_str(),
            "sha256:ceb231aeca18c7c5a226eee39df6ba05a7b8c9179885ea0f1bc67aaf121161b8"
        );
    }

    #[test]
    fn checked_in_fixture_matches_the_public_vector() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            algorithm: String,
            references: References,
            digest: String,
        }

        #[derive(serde::Deserialize)]
        struct References {
            network: String,
            egress: String,
            filesystem: String,
            tool: String,
        }

        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../fixtures/assurance-policy-digest-v1.json"
        ))
        .expect("policy digest fixture is valid JSON");
        assert_eq!(fixture.algorithm, POLICY_DIGEST_ALGORITHM_V1);
        assert_eq!(
            policy_digest_from_refs(
                &fixture.references.network,
                &fixture.references.egress,
                &fixture.references.filesystem,
                &fixture.references.tool,
            )
            .as_str(),
            fixture.digest
        );
    }

    #[test]
    fn reference_order_is_identity_bound() {
        assert_ne!(
            policy_digest_from_refs("network", "egress", "fs", "tool"),
            policy_digest_from_refs("egress", "network", "fs", "tool")
        );
    }
}
