use crate::host_signer::keystore::Keystore;
use anyhow::Result;
use chrono::{DateTime, Utc};
use mvm_contract::grants::{ApplicationTerminalBinding, DriveGrant};
use mvm_core::plan::{Nonce, ToolMediationGrant, VerbGrant, VerbId};

/// The plan-derived authority a verb grant carries beside its verb list.
/// Every part is absent by default.
#[derive(Debug, Clone, Default)]
pub struct VerbGrantAuthority {
    pub drive: Option<DriveGrant>,
    pub tool_mediation: Option<ToolMediationGrant>,
    pub application_terminal: Option<ApplicationTerminalBinding>,
}

/// Mint a session-bound verb grant signed by the host-signer authority.
pub fn mint_verb_grant(
    signer: &Keystore,
    session_id: &str,
    plan_nonce: &Nonce,
    not_after: DateTime<Utc>,
    verbs: Vec<VerbId>,
    authority: VerbGrantAuthority,
) -> Result<VerbGrant> {
    let mut grant = VerbGrant {
        session_id: session_id.to_string(),
        plan_nonce: plan_nonce.clone(),
        not_after,
        verbs,
        drive: authority.drive,
        tool_mediation: authority.tool_mediation,
        application_terminal: authority.application_terminal,
        sig: vec![],
    };
    let result = signer.sign(&grant.signing_bytes());
    grant.sig = result.signature;
    Ok(grant)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use ed25519_dalek::VerifyingKey;
    use mvm_core::plan::{Nonce, VerbId};

    #[test]
    fn minted_grant_verifies_under_signer_key() {
        let signer = Keystore::generate();
        let now = Utc::now();
        let nonce = Nonce::from_bytes([3u8; 16]);
        let grant = mint_verb_grant(
            &signer,
            "sess-Z",
            &nonce,
            now + Duration::minutes(5),
            vec![VerbId::new("run-entrypoint").unwrap()],
            VerbGrantAuthority::default(),
        )
        .unwrap();

        // Reconstruct VerifyingKey from the signer's public key bytes.
        let pub_arr: [u8; 32] = signer.pub_key().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pub_arr).unwrap();

        grant.verify(&verifying_key, "sess-Z", &nonce, now).unwrap();
    }
}
