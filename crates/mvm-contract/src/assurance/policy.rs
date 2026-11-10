//! Canonical policy-reference identity for assurance admission.
//!
//! The assurance controller and MVM must compute the same identity without
//! exchanging policy contents. The v2 encoding is the three system-policy
//! references in their fixed admission order, separated by a single NUL byte, hashed with
//! SHA-256, and rendered as a `sha256:` digest.

use sha2::{Digest, Sha256};

use super::Sha256Digest;

/// Stable identifier for the three-reference policy digest encoding.
pub const POLICY_DIGEST_ALGORITHM_V2: &str = "sha256:nul-separated-policy-refs-v2";

/// Operator-published policy references used by assurance admission.
pub const NETWORK_POLICY_REF: &str = "operator-network-v1";
pub const EGRESS_POLICY_REF: &str = "operator-egress-v1";
pub const FILESYSTEM_POLICY_REF: &str = "operator-fs-v1";

/// Published three-reference identity for the operator assurance policy.
pub const PUBLISHED_POLICY_DIGEST: &str =
    "sha256:8858f8b7282224ef81bd32550f227aeda2d8fcbc1236c8d9cb2c68921c38a06c";

/// Compute the effective policy identity from its three admitted references.
///
/// The order is part of the wire contract: network, egress, filesystem.
/// Empty references are not rejected here because the policy
/// loader owns reference validation; preserving them in the digest makes a
/// malformed or incomplete admission distinguishable rather than silently
/// equivalent to another policy.
#[must_use]
pub fn policy_digest_from_refs(
    network_policy: &str,
    egress_policy: &str,
    fs_policy: &str,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(network_policy.as_bytes());
    hasher.update([0]);
    hasher.update(egress_policy.as_bytes());
    hasher.update([0]);
    hasher.update(fs_policy.as_bytes());
    Sha256Digest::from_bytes(&hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::{
        EGRESS_POLICY_REF, FILESYSTEM_POLICY_REF, NETWORK_POLICY_REF, POLICY_DIGEST_ALGORITHM_V2,
        PUBLISHED_POLICY_DIGEST, policy_digest_from_refs,
    };

    #[test]
    fn vector_is_stable_for_counterparty_implementations() {
        assert_eq!(
            POLICY_DIGEST_ALGORITHM_V2,
            "sha256:nul-separated-policy-refs-v2"
        );
        assert_eq!(
            policy_digest_from_refs(NETWORK_POLICY_REF, EGRESS_POLICY_REF, FILESYSTEM_POLICY_REF)
                .as_str(),
            PUBLISHED_POLICY_DIGEST
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
        }

        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../fixtures/assurance-policy-digest-v2.json"
        ))
        .expect("policy digest fixture is valid JSON");
        assert_eq!(fixture.algorithm, POLICY_DIGEST_ALGORITHM_V2);
        assert_eq!(
            policy_digest_from_refs(
                &fixture.references.network,
                &fixture.references.egress,
                &fixture.references.filesystem,
            )
            .as_str(),
            fixture.digest
        );
    }

    #[test]
    fn reference_order_is_identity_bound() {
        assert_ne!(
            policy_digest_from_refs("network", "egress", "fs"),
            policy_digest_from_refs("egress", "network", "fs")
        );
        assert_ne!(
            policy_digest_from_refs("network", "egress", "fs"),
            policy_digest_from_refs("network", "fs", "egress")
        );
    }

    #[test]
    fn legacy_four_reference_identity_is_not_accepted_as_system_policy() {
        let legacy: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/assurance-policy-digest-v1.json"
        ))
        .expect("historical policy digest fixture is valid JSON");
        assert_eq!(legacy["algorithm"], "sha256:nul-separated-policy-refs-v1");
        assert_ne!(
            legacy["digest"].as_str(),
            Some(
                policy_digest_from_refs(
                    NETWORK_POLICY_REF,
                    EGRESS_POLICY_REF,
                    FILESYSTEM_POLICY_REF
                )
                .as_str()
            )
        );
    }
}
