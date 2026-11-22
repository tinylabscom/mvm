//! Verification for one protected cold-HVF owner grant.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use mvm_contract::protocol::hvf_entrypoint_owner::{
    FreshAdmissionRequest, OwnerGrant, SignedOwnerGrant, VERSION,
};

const DOMAIN: &[u8] = b"mvm.hvf-owner.grant.v1\0";
const PROVIDER_DOMAIN: &[u8] = b"mvm.hvf-owner.provider.v1\0";

/// Independently retained expectations from the protected deployment and policy.
#[derive(Debug)]
pub struct OwnerGrantExpectation<'a> {
    pub issuer: &'a str,
    pub issuer_key: &'a VerifyingKey,
    pub provider_epoch: u64,
    pub operation_id: [u8; 32],
    pub owner_incarnation: [u8; 32],
    pub controlling_principal: [u8; 32],
    pub installation: [u8; 16],
    pub tenant_id: &'a str,
    pub workload_id: &'a str,
    pub canonical_plan_digest: [u8; 32],
    pub frozen_inputs_digest: [u8; 32],
    pub policy_revision: [u8; 32],
    pub expires_at_secs: u64,
}

/// Signature-valid exact one-shot grant, not yet durably consumed.
#[derive(Debug)]
pub struct VerifiedOwnerGrant {
    provider_id: [u8; 32],
    grant_id: [u8; 32],
    operation_id: [u8; 32],
    request_digest: [u8; 32],
    verified_at_secs: u64,
    expires_at_secs: u64,
}

impl VerifiedOwnerGrant {
    /// Deployment-bound issuer identity used to select the durable namespace.
    #[must_use]
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    /// Public grant identity used only to select protected durable state.
    #[must_use]
    pub fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }

    /// Exact lifecycle operation protected from conflicting reissuance.
    #[must_use]
    pub fn operation_id(&self) -> [u8; 32] {
        self.operation_id
    }

    /// Exact request commitment retained by the durable consumer.
    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Security time at verification; later consumption cannot move backward.
    #[must_use]
    pub fn verified_at_secs(&self) -> u64 {
        self.verified_at_secs
    }

    /// Absolute provider expiry; consumption cannot extend it.
    #[must_use]
    pub fn expires_at_secs(&self) -> u64 {
        self.expires_at_secs
    }
}

/// Owner-grant verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OwnerGrantError {
    #[error("invalid HVF owner grant binding")]
    Binding,
    #[error("HVF owner grant signature is invalid")]
    Signature,
    #[error("HVF owner grant is outside its validity window")]
    Expired,
    #[error("HVF owner grant encoding failed")]
    Encoding,
}

/// Sign one typed owner grant under the provider-only domain.
///
/// This is not a generic signing operation and does not consume or authorize
/// the resulting grant.
///
/// # Errors
/// Returns an encoding error when the typed grant cannot be serialized.
pub fn sign_owner_grant(
    grant: OwnerGrant,
    key: &SigningKey,
) -> Result<SignedOwnerGrant, OwnerGrantError> {
    let bytes = signing_bytes(&grant)?;
    Ok(SignedOwnerGrant {
        grant,
        signature: key.sign(&bytes).to_bytes().to_vec(),
    })
}

/// Verify a provider grant and every independently retained request expectation.
///
/// The returned value remains non-clonable and non-serializable. Durable
/// consumption is a separate required step before native effects.
///
/// # Errors
/// Refuses changed records, wrong identities, signatures, time and encoding.
pub fn verify_owner_grant(
    signed: &SignedOwnerGrant,
    request: &FreshAdmissionRequest,
    expected: OwnerGrantExpectation<'_>,
    now_secs: u64,
) -> Result<VerifiedOwnerGrant, OwnerGrantError> {
    request.validate().map_err(|_| OwnerGrantError::Binding)?;
    let grant = &signed.grant;
    let binding = &request.binding;
    if grant.version != VERSION
        || grant.issuer.is_empty()
        || grant.issuer.len() > 256
        || grant.issuer.chars().any(char::is_control)
        || grant.issuer != expected.issuer
        || grant.provider_epoch == 0
        || grant.provider_epoch != expected.provider_epoch
        || grant.grant_id == [0; 32]
        || grant.request_digest != request.digest().map_err(|_| OwnerGrantError::Encoding)?
        || grant.issued_at_secs >= grant.expires_at_secs
        || binding.expires_at_secs > grant.expires_at_secs
        || binding.operation_id != expected.operation_id
        || binding.owner_incarnation != expected.owner_incarnation
        || binding.controlling_principal != expected.controlling_principal
        || binding.installation != expected.installation
        || binding.tenant_id != expected.tenant_id
        || binding.workload_id != expected.workload_id
        || binding.canonical_plan_digest != expected.canonical_plan_digest
        || binding.frozen_inputs_digest != expected.frozen_inputs_digest
        || binding.policy_revision != expected.policy_revision
        || binding.expires_at_secs != expected.expires_at_secs
    {
        return Err(OwnerGrantError::Binding);
    }
    if now_secs < grant.issued_at_secs
        || now_secs >= grant.expires_at_secs
        || now_secs >= binding.expires_at_secs
    {
        return Err(OwnerGrantError::Expired);
    }
    let signature =
        Signature::from_slice(&signed.signature).map_err(|_| OwnerGrantError::Signature)?;
    expected
        .issuer_key
        .verify(&signing_bytes(grant)?, &signature)
        .map_err(|_| OwnerGrantError::Signature)?;
    Ok(VerifiedOwnerGrant {
        provider_id: provider_identity(
            expected.issuer,
            expected.issuer_key,
            expected.provider_epoch,
        ),
        grant_id: grant.grant_id,
        operation_id: binding.operation_id,
        request_digest: grant.request_digest,
        verified_at_secs: now_secs,
        expires_at_secs: grant.expires_at_secs.min(binding.expires_at_secs),
    })
}

/// Stable identity of one commissioned provider issuer generation.
#[must_use]
pub fn provider_identity(issuer: &str, key: &VerifyingKey, provider_epoch: u64) -> [u8; 32] {
    use sha2::Digest as _;

    let mut hasher = sha2::Sha256::new();
    hasher.update(PROVIDER_DOMAIN);
    hasher.update((issuer.len() as u64).to_be_bytes());
    hasher.update(issuer.as_bytes());
    hasher.update(key.to_bytes());
    hasher.update(provider_epoch.to_be_bytes());
    hasher.finalize().into()
}

fn signing_bytes(grant: &OwnerGrant) -> Result<Vec<u8>, OwnerGrantError> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(grant).map_err(|_| OwnerGrantError::Encoding)?);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;
    use mvm_contract::protocol::hvf_entrypoint_owner::FreshOwnerBinding;

    fn fixture() -> (
        SigningKey,
        FreshAdmissionRequest,
        SignedOwnerGrant,
        [u8; 32],
    ) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let plan = br#"{"schema_version":1}"#.to_vec();
        let request = FreshAdmissionRequest {
            binding: FreshOwnerBinding {
                version: VERSION,
                operation_id: [1; 32],
                owner_incarnation: [2; 32],
                controlling_principal: [3; 32],
                installation: [4; 16],
                tenant_id: "tenant".into(),
                workload_id: "workload".into(),
                canonical_plan_digest: Sha256::digest(&plan).into(),
                frozen_inputs_digest: [5; 32],
                policy_revision: [6; 32],
                expires_at_secs: 90,
            },
            canonical_plan: plan,
        };
        let request_digest = request.digest().unwrap();
        let grant = sign_owner_grant(
            OwnerGrant {
                version: VERSION,
                issuer: "provider".into(),
                provider_epoch: 1,
                grant_id: [8; 32],
                request_digest,
                issued_at_secs: 10,
                expires_at_secs: 100,
            },
            &key,
        )
        .unwrap();
        (key, request, grant, request_digest)
    }

    fn expectation(key: &VerifyingKey) -> OwnerGrantExpectation<'_> {
        OwnerGrantExpectation {
            issuer: "provider",
            issuer_key: key,
            provider_epoch: 1,
            operation_id: [1; 32],
            owner_incarnation: [2; 32],
            controlling_principal: [3; 32],
            installation: [4; 16],
            tenant_id: "tenant",
            workload_id: "workload",
            canonical_plan_digest: Sha256::digest(br#"{"schema_version":1}"#).into(),
            frozen_inputs_digest: [5; 32],
            policy_revision: [6; 32],
            expires_at_secs: 90,
        }
    }

    #[test]
    fn exact_signed_grant_returns_a_non_wire_verification_result() {
        let (key, request, signed, digest) = fixture();
        assert_eq!(
            serde_json::to_string(&signed.grant).unwrap(),
            concat!(
                "{\"version\":1,\"issuer\":\"provider\",\"provider_epoch\":1,",
                "\"grant_id\":[8,8,8,8,8,8,8,8,",
                "8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8],",
                "\"request_digest\":[",
                "68,28,33,143,182,72,76,16,34,181,174,201,203,191,13,245,",
                "99,85,230,197,84,77,109,237,243,87,213,152,176,15,147,39],",
                "\"issued_at_secs\":10,\"expires_at_secs\":100}"
            )
        );
        assert_eq!(
            signed.signature,
            vec![
                118, 9, 173, 172, 105, 105, 4, 100, 106, 155, 169, 185, 5, 141, 109, 193, 77, 200,
                80, 126, 71, 15, 43, 73, 136, 76, 239, 207, 151, 48, 220, 61, 32, 243, 30, 126, 93,
                159, 237, 169, 203, 102, 159, 148, 96, 253, 193, 84, 107, 133, 48, 42, 89, 189, 96,
                32, 149, 129, 85, 45, 192, 214, 0, 9,
            ]
        );
        let key = key.verifying_key();
        let verified = verify_owner_grant(&signed, &request, expectation(&key), 50).unwrap();
        assert_eq!(verified.grant_id(), [8; 32]);
        assert_eq!(verified.request_digest(), digest);
        assert_eq!(verified.expires_at_secs(), 90);
    }

    #[test]
    fn every_independent_binding_and_time_change_refuses() {
        let (key, request, signed, _) = fixture();
        let verifying = key.verifying_key();
        for now in [9, 90, 100] {
            assert!(verify_owner_grant(&signed, &request, expectation(&verifying), now).is_err());
        }
        let mutations: [fn(&mut FreshAdmissionRequest); 8] = [
            |request| request.binding.operation_id[0] ^= 1,
            |request| request.binding.owner_incarnation[0] ^= 1,
            |request| request.binding.controlling_principal[0] ^= 1,
            |request| request.binding.installation[0] ^= 1,
            |request| request.binding.tenant_id.push('x'),
            |request| request.binding.workload_id.push('x'),
            |request| request.binding.frozen_inputs_digest[0] ^= 1,
            |request| request.binding.policy_revision[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = request.clone();
            mutate(&mut changed);
            let mut grant = signed.grant.clone();
            grant.request_digest = changed.digest().unwrap();
            let resigned = sign_owner_grant(grant, &key).unwrap();
            assert!(matches!(
                verify_owner_grant(&resigned, &changed, expectation(&verifying), 50),
                Err(OwnerGrantError::Binding)
            ));
        }
        let mut changed = request.clone();
        changed.canonical_plan.push(b' ');
        changed.binding.canonical_plan_digest = Sha256::digest(&changed.canonical_plan).into();
        let mut grant = signed.grant.clone();
        grant.request_digest = changed.digest().unwrap();
        let resigned = sign_owner_grant(grant, &key).unwrap();
        assert!(matches!(
            verify_owner_grant(&resigned, &changed, expectation(&verifying), 50),
            Err(OwnerGrantError::Binding)
        ));
        let mut changed = request;
        changed.binding.expires_at_secs -= 1;
        let mut grant = signed.grant;
        grant.request_digest = changed.digest().unwrap();
        let resigned = sign_owner_grant(grant, &key).unwrap();
        assert!(matches!(
            verify_owner_grant(&resigned, &changed, expectation(&verifying), 50),
            Err(OwnerGrantError::Binding)
        ));
    }

    #[test]
    fn wrong_key_tamper_and_signature_lengths_refuse() {
        let (key, request, mut signed, _) = fixture();
        let wrong = SigningKey::from_bytes(&[9; 32]);
        let wrong = wrong.verifying_key();
        let verifying = key.verifying_key();
        assert!(matches!(
            verify_owner_grant(&signed, &request, expectation(&wrong), 50),
            Err(OwnerGrantError::Signature)
        ));
        signed.grant.grant_id[0] ^= 1;
        assert!(matches!(
            verify_owner_grant(&signed, &request, expectation(&verifying), 50),
            Err(OwnerGrantError::Signature)
        ));
        for length in [0, 63, 65] {
            signed.signature = vec![0; length];
            assert!(matches!(
                verify_owner_grant(&signed, &request, expectation(&verifying), 50),
                Err(OwnerGrantError::Signature)
            ));
        }
    }
}
