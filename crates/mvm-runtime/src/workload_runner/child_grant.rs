//! Signed child capability issuance at the warm-restore boundary.
//!
//! The runner owns the final child identity, while the host admission layer
//! owns the signing key. This seam lets the runner request a grant only after
//! it has minted that identity, then validates every plan-derived field before
//! the envelope crosses into the restored guest.

use anyhow::Result;
use mvm_core::plan::ExecutionPlan;
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
use mvm_core::vm_backend::VmStartConfig;

/// Host authority that persists the admitted child plan and signs its optional
/// agent-verb grant.
pub trait ChildGrantIssuer: Send + Sync {
    /// Persist the child's admitted launch material and return a signed grant
    /// when the plan carries an agent-verb allow-list.
    fn issue(&self, config: &VmStartConfig) -> Result<Option<VerbGrantEnvelope>>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ChildGrantError {
    #[error("the admitted plan requests agent verbs but no child grant issuer is configured")]
    IssuerRequired,
    #[error("child grant issuer failed: {0}")]
    Issue(#[source] anyhow::Error),
    #[error("the admitted plan requests agent verbs but the issuer returned no grant")]
    GrantRequired,
    #[error("the admitted plan requests no agent verbs but the issuer returned a grant")]
    UnexpectedGrant,
    #[error("child grant session id does not match the final child identity")]
    SessionMismatch,
    #[error("child grant envelope nonce does not match the admitted plan")]
    EnvelopeNonceMismatch,
    #[error("child grant nonce does not match the admitted plan")]
    GrantNonceMismatch,
    #[error("child grant expiry does not match the admitted plan")]
    ExpiryMismatch,
    #[error("child grant verbs do not match the admitted plan")]
    VerbsMismatch,
    #[error("fresh child grant unexpectedly carries predecessor lineage")]
    UnexpectedPredecessor,
    #[error("child grant public key is not a 32-byte lowercase hex key")]
    PublicKeyMalformed,
    #[error("child grant signature is not 64 bytes")]
    SignatureMalformed,
}

/// Issue and structurally bind the optional child grant to the admitted plan
/// and the runner-minted final identity.
pub(crate) fn issue_child_grant(
    plan: &ExecutionPlan,
    config: &VmStartConfig,
    issuer: Option<&dyn ChildGrantIssuer>,
) -> std::result::Result<Option<VerbGrantEnvelope>, ChildGrantError> {
    let Some(issuer) = issuer else {
        return if plan.agent_verbs.is_some() {
            Err(ChildGrantError::IssuerRequired)
        } else {
            Ok(None)
        };
    };
    let issued = issuer.issue(config).map_err(ChildGrantError::Issue)?;

    let Some(expected_verbs) = plan.agent_verbs.as_ref() else {
        return if issued.is_some() {
            Err(ChildGrantError::UnexpectedGrant)
        } else {
            Ok(None)
        };
    };
    let envelope = issued.ok_or(ChildGrantError::GrantRequired)?;

    if envelope.grant.session_id != config.name {
        return Err(ChildGrantError::SessionMismatch);
    }
    if envelope.plan_nonce_hex != plan.nonce.as_hex() {
        return Err(ChildGrantError::EnvelopeNonceMismatch);
    }
    if envelope.grant.plan_nonce != plan.nonce {
        return Err(ChildGrantError::GrantNonceMismatch);
    }
    if envelope.grant.not_after != plan.valid_until {
        return Err(ChildGrantError::ExpiryMismatch);
    }
    if &envelope.grant.verbs != expected_verbs {
        return Err(ChildGrantError::VerbsMismatch);
    }
    if envelope.predecessor_session_id.is_some() || envelope.predecessor_plan_nonce_hex.is_some() {
        return Err(ChildGrantError::UnexpectedPredecessor);
    }
    if envelope.pubkey_hex.len() != 64
        || !envelope
            .pubkey_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChildGrantError::PublicKeyMalformed);
    }
    if envelope.grant.sig.len() != 64 {
        return Err(ChildGrantError::SignatureMalformed);
    }

    Ok(Some(envelope))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use anyhow::Result;
    use mvm_core::plan::{ExecutionPlan, VerbGrant, VerbId};
    use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
    use mvm_core::vm_backend::VmStartConfig;

    use super::{ChildGrantError, ChildGrantIssuer, issue_child_grant};

    struct FixedIssuer {
        envelope: Option<VerbGrantEnvelope>,
        seen_names: Mutex<Vec<String>>,
    }

    impl FixedIssuer {
        fn returning(envelope: Option<VerbGrantEnvelope>) -> Self {
            Self {
                envelope,
                seen_names: Mutex::new(Vec::new()),
            }
        }
    }

    impl ChildGrantIssuer for FixedIssuer {
        fn issue(&self, config: &VmStartConfig) -> Result<Option<VerbGrantEnvelope>> {
            self.seen_names.lock().unwrap().push(config.name.clone());
            Ok(self.envelope.clone())
        }
    }

    fn plan_with_verbs() -> ExecutionPlan {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .nonce([7u8; 16])
            .build();
        plan.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
        plan
    }

    fn matching_envelope(plan: &ExecutionPlan, child: &str) -> VerbGrantEnvelope {
        VerbGrantEnvelope {
            pubkey_hex: "ab".repeat(32),
            plan_nonce_hex: plan.nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: VerbGrant {
                session_id: child.to_string(),
                plan_nonce: plan.nonce.clone(),
                not_after: plan.valid_until,
                verbs: plan.agent_verbs.clone().unwrap(),
                sig: vec![3u8; 64],
            },
        }
    }

    #[test]
    fn matching_grant_is_issued_for_the_final_child_identity() {
        let plan = plan_with_verbs();
        let config = VmStartConfig {
            name: "child-final".into(),
            ..Default::default()
        };
        let issuer = FixedIssuer::returning(Some(matching_envelope(&plan, &config.name)));

        let envelope = issue_child_grant(&plan, &config, Some(&issuer))
            .expect("matching grant is accepted")
            .expect("plan requests a grant");

        assert_eq!(envelope.grant.session_id, "child-final");
        assert_eq!(
            issuer.seen_names.lock().unwrap().as_slice(),
            ["child-final"]
        );
    }

    #[test]
    fn grant_bearing_plan_requires_an_issuer_and_an_envelope() {
        let plan = plan_with_verbs();
        let config = VmStartConfig {
            name: "child-final".into(),
            ..Default::default()
        };

        assert!(matches!(
            issue_child_grant(&plan, &config, None),
            Err(ChildGrantError::IssuerRequired)
        ));
        let issuer = FixedIssuer::returning(None);
        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::GrantRequired)
        ));
    }

    #[test]
    fn grant_is_rejected_when_its_child_or_plan_binding_differs() {
        let plan = plan_with_verbs();
        let config = VmStartConfig {
            name: "child-final".into(),
            ..Default::default()
        };

        let mut wrong_child = matching_envelope(&plan, "child-other");
        let issuer = FixedIssuer::returning(Some(wrong_child.clone()));
        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::SessionMismatch)
        ));

        wrong_child.grant.session_id = config.name.clone();
        wrong_child.plan_nonce_hex = "00".repeat(16);
        let issuer = FixedIssuer::returning(Some(wrong_child));
        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::EnvelopeNonceMismatch)
        ));

        let mut wrong_verbs = matching_envelope(&plan, &config.name);
        wrong_verbs.grant.verbs = vec![VerbId::new("ping").unwrap()];
        let issuer = FixedIssuer::returning(Some(wrong_verbs));
        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::VerbsMismatch)
        ));
    }

    #[test]
    fn grant_is_rejected_when_any_signed_security_field_is_malformed() {
        let plan = plan_with_verbs();
        let config = VmStartConfig {
            name: "child-final".into(),
            ..Default::default()
        };

        let mut wrong_nonce = matching_envelope(&plan, &config.name);
        wrong_nonce.grant.plan_nonce = mvm_core::plan::Nonce::from_bytes([8u8; 16]);
        let issuer = FixedIssuer::returning(Some(wrong_nonce));
        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::GrantNonceMismatch)
        ));

        let mut wrong_expiry = matching_envelope(&plan, &config.name);
        wrong_expiry.grant.not_after += chrono::Duration::seconds(1);
        let issuer = FixedIssuer::returning(Some(wrong_expiry));
        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::ExpiryMismatch)
        ));

        let mut predecessor = matching_envelope(&plan, &config.name);
        predecessor.predecessor_session_id = Some("parent".into());
        let issuer = FixedIssuer::returning(Some(predecessor));
        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::UnexpectedPredecessor)
        ));

        let mut bad_key = matching_envelope(&plan, &config.name);
        bad_key.pubkey_hex = "AB".repeat(32);
        let issuer = FixedIssuer::returning(Some(bad_key));
        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::PublicKeyMalformed)
        ));

        let mut bad_signature = matching_envelope(&plan, &config.name);
        bad_signature.grant.sig.pop();
        let issuer = FixedIssuer::returning(Some(bad_signature));
        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::SignatureMalformed)
        ));
    }

    #[test]
    fn grantless_plan_rejects_an_unexpected_issued_grant() {
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        let config = VmStartConfig {
            name: "child-final".into(),
            ..Default::default()
        };
        let mut envelope = matching_envelope(&plan_with_verbs(), &config.name);
        envelope.grant.plan_nonce = plan.nonce.clone();
        envelope.plan_nonce_hex = plan.nonce.as_hex().to_string();
        envelope.grant.not_after = plan.valid_until;
        let issuer = FixedIssuer::returning(Some(envelope));

        assert!(matches!(
            issue_child_grant(&plan, &config, Some(&issuer)),
            Err(ChildGrantError::UnexpectedGrant)
        ));
    }
}
