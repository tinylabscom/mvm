//! Host-only attestation verification for assurance trials.
//!
//! The extension and provider never submit a verification boolean. A trusted
//! runtime verifier receives a canonical challenge assembled from the admitted
//! session, verifies its native quote against an enrolled trust root, and
//! returns only bounded verification metadata. This module then checks the
//! provider, freshness, and challenge join before the audit ledger can record
//! the attestation as evidence.

use anyhow::{Context, Result};
use mvm_contract::assurance::{AssuranceId, EvidenceRef, MvmBinding, Sha256Digest};
use mvm_contract::plan::types::AttestationMode;
use mvm_core::crypto::attestation::HwProviderKind;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::assurance_session::CampaignDeclaration;
use crate::audit::assurance::{AttestationRecord, SessionIdentity};
use crate::broker::handlers::host_assurance_v1::HostAssuranceV1Handler;

const CHALLENGE_SCHEMA: &str = "mvm.assurance.runtime-attestation-challenge/v1";
const TRUST_ROOT_REF_PREFIX: &str = "mvm:attestation-root:";

/// Exact public material a hardware quote must bind as its report data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAttestationChallenge {
    pub schema: &'static str,
    pub session_id: AssuranceId,
    pub plan_id: AssuranceId,
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub source_digest: Sha256Digest,
    pub workload_digest: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub policy_digest: Sha256Digest,
    pub session_grant_digest: Sha256Digest,
    pub session_grant_nonce: AssuranceId,
    pub backend: AssuranceId,
    pub grant_expires_at_unix_ms: u64,
    pub receipt_refs: Vec<EvidenceRef>,
}

impl RuntimeAttestationChallenge {
    /// Build the challenge only from the admission-issued binding and the
    /// already joined host campaign declaration.
    #[must_use]
    pub fn new(binding: &MvmBinding, declaration: &CampaignDeclaration) -> Self {
        Self {
            schema: CHALLENGE_SCHEMA,
            session_id: binding.session_id.clone(),
            plan_id: binding.plan_id.clone(),
            campaign_id: declaration.campaign_id.clone(),
            trial_id: declaration.trial_id.clone(),
            source_digest: declaration.source_digest.clone(),
            workload_digest: binding.workload_digest.clone(),
            artifact_digest: binding.artifact_digest.clone(),
            policy_digest: binding.effective_policy_digest.clone(),
            session_grant_digest: binding.grant.grant_digest.clone(),
            session_grant_nonce: binding.grant.nonce.clone(),
            backend: binding.runtime.backend.clone(),
            grant_expires_at_unix_ms: binding.grant.expires_unix_ms,
            receipt_refs: binding.receipt_refs.clone(),
        }
    }

    /// Digest placed in the provider-native quote's report-data field.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let canonical = serde_jcs::to_vec(self).context("canonicalizing attestation challenge")?;
        Ok(Sha256Digest::from_bytes(&Sha256::digest(canonical).into()))
    }
}

/// Bounded result returned by a trusted runtime quote verifier.
///
/// The verifier must have authenticated the native quote, its report-data
/// challenge, and the named trust root before constructing this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAttestationVerification {
    pub provider: HwProviderKind,
    pub challenge_digest: Sha256Digest,
    pub quote_digest: Sha256Digest,
    pub trust_root_ref: EvidenceRef,
    pub verified_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Trusted host/runtime verification seam.
///
/// Implementations are selected by host configuration and have no request
/// fields from the extension or model. Absence or any error is not promoted to
/// evidence by callers.
pub trait RuntimeAttestationVerifier: Send + Sync {
    fn verify(
        &self,
        challenge: &RuntimeAttestationChallenge,
    ) -> Result<RuntimeAttestationVerification>;
}

/// Joined and signed attestation evidence accepted by the host finalizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub(crate) session_id: AssuranceId,
    pub(crate) campaign_id: AssuranceId,
    pub(crate) trial_id: AssuranceId,
    pub(crate) source_digest: Sha256Digest,
    pub(crate) audit_ref: EvidenceRef,
    pub(crate) receipt_ref: EvidenceRef,
}

/// Inputs to one host-controlled runtime attestation verification.
pub struct VerifyRuntimeAttestation<'a> {
    pub plane: &'a HostAssuranceV1Handler,
    pub vm: &'a str,
    pub binding: &'a MvmBinding,
    pub declaration: &'a CampaignDeclaration,
    pub required_mode: &'a AttestationMode,
    pub verifier: &'a dyn RuntimeAttestationVerifier,
    pub now_unix_ms: u64,
}

/// Verify, rejoin, and record one native runtime quote.
pub fn verify_runtime_attestation(
    request: VerifyRuntimeAttestation<'_>,
) -> Result<AttestationEvidence> {
    let challenge = RuntimeAttestationChallenge::new(request.binding, request.declaration);
    let expected_digest = challenge.digest()?;
    let verification = request
        .verifier
        .verify(&challenge)
        .context("verifying admitted runtime attestation")?;
    validate_verification(
        &verification,
        &expected_digest,
        request.required_mode,
        request.binding.grant.expires_unix_ms,
        request.now_unix_ms,
    )?;

    let identity = SessionIdentity {
        session_id: request.binding.session_id.clone(),
        campaign_id: request.declaration.campaign_id.clone(),
        trial_id: request.declaration.trial_id.clone(),
        source_digest: request.declaration.source_digest.clone(),
    };
    let refs = request.plane.record_verified_attestation(
        request.vm,
        request.binding,
        &identity,
        &AttestationRecord {
            provider: verification.provider.as_str(),
            challenge_digest: &verification.challenge_digest,
            quote_digest: &verification.quote_digest,
            trust_root_ref: &verification.trust_root_ref,
        },
    )?;
    let receipt_ref = refs
        .receipt
        .ok_or_else(|| anyhow::anyhow!("attestation verification produced no receipt"))?;
    Ok(AttestationEvidence {
        session_id: identity.session_id,
        campaign_id: identity.campaign_id,
        trial_id: identity.trial_id,
        source_digest: identity.source_digest,
        audit_ref: refs.audit,
        receipt_ref,
    })
}

fn validate_verification(
    verification: &RuntimeAttestationVerification,
    expected_digest: &Sha256Digest,
    required_mode: &AttestationMode,
    grant_expires_unix_ms: u64,
    now_unix_ms: u64,
) -> Result<()> {
    if matches!(required_mode, AttestationMode::Noop) {
        anyhow::bail!("a no-attestation plan cannot produce trusted attestation evidence");
    }
    let expected_provider = match required_mode {
        AttestationMode::Noop => unreachable!("handled above"),
        AttestationMode::Tpm2 => "tpm2",
        AttestationMode::SevSnp => "sev_snp",
        AttestationMode::Tdx => "tdx",
        AttestationMode::AppleDeviceAttestation => "apple_device_attestation",
    };
    if verification.provider.as_str() != expected_provider {
        anyhow::bail!("runtime attestation provider does not match the admitted plan");
    }
    if &verification.challenge_digest != expected_digest {
        anyhow::bail!("runtime attestation challenge does not match the admitted session");
    }
    if !verification
        .trust_root_ref
        .as_str()
        .starts_with(TRUST_ROOT_REF_PREFIX)
    {
        anyhow::bail!("runtime attestation did not cite an enrolled trust root");
    }
    if verification.verified_at_unix_ms > now_unix_ms {
        anyhow::bail!("runtime attestation verification time is in the future");
    }
    if now_unix_ms >= verification.expires_at_unix_ms {
        anyhow::bail!("runtime attestation verification is stale");
    }
    if verification.expires_at_unix_ms > grant_expires_unix_ms {
        anyhow::bail!("runtime attestation outlives the admitted session grant");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", format!("{byte:02x}").repeat(32))).expect("digest")
    }

    fn verification() -> RuntimeAttestationVerification {
        RuntimeAttestationVerification {
            provider: HwProviderKind::Tpm2,
            challenge_digest: digest(1),
            quote_digest: digest(2),
            trust_root_ref: EvidenceRef::parse("mvm:attestation-root:operator-a")
                .expect("trust root reference"),
            verified_at_unix_ms: 10,
            expires_at_unix_ms: 20,
        }
    }

    #[test]
    fn exact_provider_challenge_root_and_freshness_are_required() {
        validate_verification(&verification(), &digest(1), &AttestationMode::Tpm2, 20, 10)
            .expect("verification should join");
    }

    #[test]
    fn configured_mode_is_not_attestation_evidence() {
        let error =
            validate_verification(&verification(), &digest(1), &AttestationMode::Noop, 20, 10)
                .expect_err("noop must not verify");
        assert!(error.to_string().contains("no-attestation plan"));
    }

    #[test]
    fn foreign_stale_and_overlong_verifications_fail_closed() {
        let mut foreign = verification();
        foreign.challenge_digest = digest(3);
        assert!(
            validate_verification(&foreign, &digest(1), &AttestationMode::Tpm2, 20, 10).is_err()
        );

        let mut stale = verification();
        stale.expires_at_unix_ms = 10;
        assert!(validate_verification(&stale, &digest(1), &AttestationMode::Tpm2, 20, 10).is_err());

        let mut overlong = verification();
        overlong.expires_at_unix_ms = 21;
        assert!(
            validate_verification(&overlong, &digest(1), &AttestationMode::Tpm2, 20, 10).is_err()
        );
    }

    #[test]
    fn wrong_provider_and_unenrolled_root_fail_closed() {
        let mut wrong_provider = verification();
        wrong_provider.provider = HwProviderKind::SevSnp;
        assert!(
            validate_verification(&wrong_provider, &digest(1), &AttestationMode::Tpm2, 20, 10,)
                .is_err()
        );

        let mut untrusted = verification();
        untrusted.trust_root_ref =
            EvidenceRef::parse("mvm:audit:not-a-root").expect("evidence reference");
        assert!(
            validate_verification(&untrusted, &digest(1), &AttestationMode::Tpm2, 20, 10).is_err()
        );
    }
}
