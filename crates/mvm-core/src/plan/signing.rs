//! `SignedExecutionPlan` — Ed25519-signed envelope around an
//! `ExecutionPlan`.
//!
//! Plan 37 §3.3 requires that every plan outside dev mode arrive
//! through a signed envelope. The supervisor verifies the signature
//! against a trusted-keys set before parsing the plan body — the
//! plan's content is never deserialised from attacker-controlled
//! bytes prior to signature check.
//!
//! Wire format mirrors `mvm-core::protocol::signing::SignedPayload`
//! so the same envelope shape used for control-plane messages can
//! carry plans, keeping the audit + transport surface uniform.

use crate::protocol::signing::SignedPayload;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::plan::execution_plan::{ExecutionPlan, SCHEMA_VERSION};
use crate::plan::types::SecretBinding;

/// Plan envelope. Wraps the canonical-JSON-encoded `ExecutionPlan`
/// alongside the Ed25519 signature and a signer identifier.
///
/// Concretely this is a `SignedPayload` reused via newtype rather
/// than a fresh struct so the same audit + transport code paths can
/// carry plans without learning a second envelope shape. The newtype
/// wrapper keeps the type system honest: a `SignedPayload` is
/// generic, a `SignedExecutionPlan` is specifically the wrapper for
/// `ExecutionPlan` and nothing else.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedExecutionPlan(pub SignedPayload);

#[derive(Debug, Error)]
pub enum PlanVerifyError {
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("plan parse failed: {0}")]
    Parse(String),

    #[error("schema version {found} is newer than this build supports ({supported})")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("no trusted key matched signer_id {signer_id}")]
    UnknownSigner { signer_id: String },
}

/// Sign an `ExecutionPlan` with the given key.
///
/// The plan is serialised to canonical JSON via `serde_json` (the
/// same encoding `verify_plan` round-trips through), signed, and
/// wrapped in a `SignedExecutionPlan` envelope. The `signer_id` is
/// the human-readable name of the key inside the envelope — used
/// by the verifier to look the corresponding `VerifyingKey` up in
/// the trusted-keys set.
pub fn sign_plan(plan: &ExecutionPlan, key: &SigningKey, signer_id: &str) -> SignedExecutionPlan {
    let payload = serde_json::to_vec(plan).expect("ExecutionPlan must serialise to JSON");
    let signature: Signature = key.sign(&payload);
    SignedExecutionPlan(SignedPayload {
        payload,
        signature: signature.to_bytes().to_vec(),
        signer_id: signer_id.to_string(),
    })
}

/// Extract the `secrets` bindings from a serialised `SignedExecutionPlan`
/// envelope JSON, decoding the inner `ExecutionPlan` from the signed payload.
///
/// Used by a backend to hand the per-VM substitution endpoint (Plan 129) only
/// the secret bindings it needs — never the rest of the plan. The signature is
/// **not** re-verified here: the host verified it at admission (ADR-041), and
/// the endpoint's security boundary is the local binding store (a secret is
/// only ever substituted toward a host-bound destination), not the plan
/// signature. The host is in the TCB per ADR-002.
pub fn secrets_from_signed_json(plan_json: &str) -> Result<Vec<SecretBinding>, serde_json::Error> {
    let signed: SignedExecutionPlan = serde_json::from_str(plan_json)?;
    let plan: ExecutionPlan = serde_json::from_slice(&signed.0.payload)?;
    Ok(plan.secrets)
}

/// Extract the `tenant` id from a serialised `SignedExecutionPlan` envelope.
///
/// The Firecracker launch path (Plan 129 Task 5B) reads the admitted plan from
/// disk (`plan.json`) and needs the tenant to scope the substitution endpoint's
/// binding store — but, unlike `VmStartConfig`, `FlakeRunConfig` carries no
/// out-of-band tenant field. Same trust posture as `secrets_from_signed_json`:
/// the signature was checked at admission (ADR-041); the host is in the TCB.
pub fn tenant_from_signed_json(plan_json: &str) -> Result<String, serde_json::Error> {
    let signed: SignedExecutionPlan = serde_json::from_str(plan_json)?;
    let plan: ExecutionPlan = serde_json::from_slice(&signed.0.payload)?;
    Ok(plan.tenant.0)
}

/// Verify a signed plan against a set of trusted keys, returning the
/// parsed `ExecutionPlan` on success.
///
/// The verification order is signature → schema version → JSON
/// parse. Older verifiers fail closed on a future schema version
/// rather than parsing unknown bytes — the `schema_version` field
/// is read separately *after* the signature check, before
/// `ExecutionPlan` deserialisation, so an attacker who manages to
/// bypass the sig check still can't smuggle in a v2 plan.
///
/// `trusted_keys` is a slice of `(signer_id, VerifyingKey)` pairs.
/// The verifier picks the key whose `signer_id` matches the
/// envelope's, then validates the signature against it. An empty
/// `trusted_keys` slice always errors with `UnknownSigner`.
pub fn verify_plan(
    signed: &SignedExecutionPlan,
    trusted_keys: &[(&str, &VerifyingKey)],
) -> Result<ExecutionPlan, PlanVerifyError> {
    let envelope = &signed.0;

    // Pick the trusted key matching the envelope's signer_id. If
    // none matches, the envelope is signed by an unknown party —
    // fail before exposing the payload bytes to a verifier.
    let key = trusted_keys
        .iter()
        .find_map(|(id, k)| (*id == envelope.signer_id).then_some(*k))
        .ok_or_else(|| PlanVerifyError::UnknownSigner {
            signer_id: envelope.signer_id.clone(),
        })?;

    let signature = Signature::from_slice(&envelope.signature).map_err(|e| {
        PlanVerifyError::SignatureInvalid(format!("malformed signature bytes: {e}"))
    })?;

    key.verify(&envelope.payload, &signature)
        .map_err(|e| PlanVerifyError::SignatureInvalid(e.to_string()))?;

    // Schema-version sniff before full parse. We read just
    // `{"schema_version": N, ...}` to see if the rest is something
    // this build understands. A future v2 plan will error with
    // UnsupportedSchema even though its signature is valid.
    #[derive(Deserialize)]
    struct VersionProbe {
        schema_version: u32,
    }
    let probe: VersionProbe = serde_json::from_slice(&envelope.payload)
        .map_err(|e| PlanVerifyError::Parse(format!("schema_version probe failed: {e}")))?;
    if probe.schema_version > SCHEMA_VERSION {
        return Err(PlanVerifyError::UnsupportedSchema {
            found: probe.schema_version,
            supported: SCHEMA_VERSION,
        });
    }

    let plan: ExecutionPlan = serde_json::from_slice(&envelope.payload)
        .map_err(|e| PlanVerifyError::Parse(e.to_string()))?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::types::*;
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    pub(crate) fn sample_plan() -> ExecutionPlan {
        ExecutionPlan {
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId("01HXTESTPLAN000000000000".to_string()),
            plan_version: 1,
            tenant: TenantId("tenant-a".to_string()),
            workload: WorkloadId("workload-1".to_string()),
            runtime_profile: RuntimeProfileRef("firecracker".to_string()),
            image: SignedImageRef {
                name: "tenant-worker-aarch64".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: Resources {
                cpus: 2,
                mem_mib: 1024,
                disk_mib: 4096,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 600,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "code:execute",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef("default-deny".to_string()),
            fs_policy: FsPolicyRef("default".to_string()),
            secrets: vec![],
            egress_policy: PolicyRef("agent-l7".to_string()),
            tool_policy: PolicyRef("read-only-tools".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: vec!["/artifacts".to_string()],
                retention_days: 30,
            },
            audit_labels: BTreeMap::from([("workflow".to_string(), "etl-1".to_string())]),
            key_rotation: KeyRotationSpec { interval_days: 7 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            valid_from: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
            nonce: Nonce::from_bytes([0xab; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
        }
    }

    fn fresh_key() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn plan_serde_roundtrip() {
        let plan = sample_plan();
        let bytes = serde_json::to_vec(&plan).unwrap();
        let parsed: ExecutionPlan = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, plan);
    }

    #[test]
    fn signed_plan_roundtrip() {
        let plan = sample_plan();
        let (sk, vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let recovered = verify_plan(&signed, &[("test-signer", &vk)]).unwrap();
        assert_eq!(recovered, plan);
    }

    #[test]
    fn secrets_extracted_from_signed_envelope() {
        let mut plan = sample_plan();
        plan.secrets = vec![SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }];
        let (sk, _vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let json = serde_json::to_string(&signed).unwrap();
        let secrets = secrets_from_signed_json(&json).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "OPENAI_API_KEY");
        assert!(matches!(
            &secrets[0].source,
            SecretSource::Keystore { address } if address == "openai"
        ));
    }

    #[test]
    fn tenant_extracted_from_signed_envelope() {
        let plan = sample_plan(); // tenant == "tenant-a"
        let (sk, _vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let json = serde_json::to_string(&signed).unwrap();
        assert_eq!(tenant_from_signed_json(&json).unwrap(), "tenant-a");
    }

    #[test]
    fn tenant_from_non_envelope_json_errors() {
        assert!(tenant_from_signed_json("{\"not\":\"a plan\"}").is_err());
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let plan = sample_plan();
        let (sk, vk) = fresh_key();
        let mut signed = sign_plan(&plan, &sk, "test-signer");
        // Flip a bit in the payload after signing.
        signed.0.payload[0] ^= 0x01;
        match verify_plan(&signed, &[("test-signer", &vk)]) {
            Err(PlanVerifyError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn unknown_signer_fails() {
        let plan = sample_plan();
        let (sk, _vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "alice");
        // Trusted set knows "bob" but not "alice".
        let (_other_sk, other_vk) = fresh_key();
        match verify_plan(&signed, &[("bob", &other_vk)]) {
            Err(PlanVerifyError::UnknownSigner { signer_id }) => {
                assert_eq!(signer_id, "alice");
            }
            other => panic!("expected UnknownSigner, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_fails_signature() {
        let plan = sample_plan();
        let (sk, _vk) = fresh_key();
        let (_sk2, vk2) = fresh_key();
        let signed = sign_plan(&plan, &sk, "alice");
        match verify_plan(&signed, &[("alice", &vk2)]) {
            Err(PlanVerifyError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_schema_version_fails_closed() {
        // Build a plan, sign it, then pretend a future build emitted
        // a schema_version 2 plan. The verifier should refuse before
        // the per-field deserialisation runs.
        let mut plan = sample_plan();
        plan.schema_version = SCHEMA_VERSION + 1;
        let (sk, vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        match verify_plan(&signed, &[("test-signer", &vk)]) {
            Err(PlanVerifyError::UnsupportedSchema { found, supported }) => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    #[test]
    fn unknown_field_in_plan_rejected() {
        // ExecutionPlan and its types use #[serde(deny_unknown_fields)],
        // so a future field added to the wire format fails closed in
        // older builds.
        let mut value: serde_json::Value = serde_json::to_value(sample_plan()).unwrap();
        value["new_future_field"] = serde_json::json!("hi");
        let bytes = serde_json::to_vec(&value).unwrap();
        let result: Result<ExecutionPlan, _> = serde_json::from_slice(&bytes);
        assert!(result.is_err(), "deny_unknown_fields must reject");
    }

    #[test]
    fn plan_with_deps_volume_signs_and_verifies() {
        // Plan 73 Followup A: ExecutionPlan carries
        // `deps_volume: Option<DepsVolumeBinding>`. A plan with a
        // populated binding must round-trip through sign → verify
        // unchanged, and the resulting bytes must canonicalize
        // deterministically so the host signer always produces the
        // same signature input for the same plan.
        let mut plan = sample_plan();
        plan.deps_volume = Some(
            crate::plan::DepsVolumeBinding::new("a".repeat(64), "b".repeat(64))
                .expect("valid binding"),
        );
        let (sk, vk) = fresh_key();
        let signed_a = sign_plan(&plan, &sk, "test-signer");
        let signed_b = sign_plan(&plan, &sk, "test-signer");
        // Deterministic signing input: identical bytes ⇒ identical
        // signatures (Ed25519 is deterministic; we'd lose that
        // property if canonicalization drifted).
        assert_eq!(signed_a.0.payload, signed_b.0.payload);
        assert_eq!(signed_a.0.signature, signed_b.0.signature);
        let recovered = verify_plan(&signed_a, &[("test-signer", &vk)]).unwrap();
        assert_eq!(recovered, plan);
        assert_eq!(
            recovered.deps_volume.as_ref().unwrap().volume_hash,
            "a".repeat(64)
        );
    }

    #[test]
    fn plan_without_deps_volume_omits_field_from_wire_format() {
        // `#[serde(default, skip_serializing_if = "Option::is_none")]`
        // means a `None` binding doesn't appear in the canonical
        // bytes — preserves byte compatibility for existing
        // claim-8-only plans signed before Followup A.
        let plan = sample_plan();
        assert!(plan.deps_volume.is_none());
        let bytes = serde_json::to_vec(&plan).unwrap();
        let json_str = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !json_str.contains("deps_volume"),
            "expected `deps_volume` absent from wire bytes for None binding"
        );
    }

    #[test]
    fn empty_trusted_set_fails() {
        let plan = sample_plan();
        let (sk, _vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "alice");
        match verify_plan(&signed, &[]) {
            Err(PlanVerifyError::UnknownSigner { .. }) => {}
            other => panic!("expected UnknownSigner, got {other:?}"),
        }
    }
}
