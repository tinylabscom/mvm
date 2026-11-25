//! `SignedExecutionPlan` — Ed25519-signed envelope around an
//! `ExecutionPlan`.
//!
//! Every plan outside dev mode must arrive through a signed envelope.
//! The supervisor verifies the signature
//! against a trusted-keys set before parsing the plan body — the
//! plan's content is never deserialised from attacker-controlled
//! bytes prior to signature check.
//!
//! Wire format mirrors `mvm-core::protocol::signing::SignedPayload`
//! so the same envelope shape used for control-plane messages can
//! carry plans, keeping the audit + transport surface uniform.

use crate::protocol::signing::SignedPayload;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mvm_contract::protocol::signing::{SignedPayloadError, verify_signed_payload};
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

impl From<SignedPayloadError> for PlanVerifyError {
    fn from(error: SignedPayloadError) -> Self {
        match error {
            SignedPayloadError::UnknownSigner { signer_id } => Self::UnknownSigner { signer_id },
            SignedPayloadError::SignatureInvalid(reason) => Self::SignatureInvalid(reason),
            SignedPayloadError::UnsupportedSchema { found, supported } => {
                Self::UnsupportedSchema { found, supported }
            }
            SignedPayloadError::Parse(reason) => Self::Parse(reason),
        }
    }
}

/// Sign an `ExecutionPlan` with the given key.
///
/// The `plan_id` is (re-)derived as the content-address of the plan body
/// immediately before signing, so a signed plan whose id does not address its
/// content is unrepresentable through this API — the sole way to mint a valid
/// envelope. A caller who already content-addressed the plan (e.g.
/// [`crate::plan::synthesize_plan`]) gets the same id back; one who hands a
/// stale or bogus id gets it corrected. The stamped plan is then serialised to
/// canonical JSON via `serde_json` (the same encoding `verify_plan` round-trips
/// through), signed, and wrapped in a `SignedExecutionPlan` envelope. The
/// `signer_id` is the human-readable name of the key inside the envelope — used
/// by the verifier to look the corresponding `VerifyingKey` up in the
/// trusted-keys set.
pub fn sign_plan(plan: &ExecutionPlan, key: &SigningKey, signer_id: &str) -> SignedExecutionPlan {
    let mut plan = plan.clone();
    plan.plan_id = crate::plan::compute_plan_id(&plan);
    let payload = serde_json::to_vec(&plan).expect("ExecutionPlan must serialise to JSON");
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
/// Used by a backend to hand the per-VM substitution endpoint only the secret
/// bindings it needs — never the rest of the plan. The signature is **not**
/// re-verified here: the host verified it at admission, and the endpoint's
/// security boundary is the local binding store (a secret is only ever
/// substituted toward a host-bound destination), not the plan signature. The
/// host is in the TCB.
pub fn secrets_from_signed_json(plan_json: &str) -> Result<Vec<SecretBinding>, serde_json::Error> {
    let signed: SignedExecutionPlan = serde_json::from_str(plan_json)?;
    let plan: ExecutionPlan = serde_json::from_slice(&signed.0.payload)?;
    Ok(plan.secrets)
}

/// Extract the per-destination redaction policy from a signed plan's payload,
/// without verifying the signature — the caller (backend endpoint spawn) has
/// already admitted the plan; this just reads the field the endpoint needs.
pub fn redaction_from_signed_json(
    plan_json: &str,
) -> Result<crate::policy::RedactionPolicy, serde_json::Error> {
    let signed: SignedExecutionPlan = serde_json::from_str(plan_json)?;
    let plan: ExecutionPlan = serde_json::from_slice(&signed.0.payload)?;
    Ok(plan.redaction)
}

/// Extract the cumulative action budget from a signed plan's payload, without
/// re-verifying the signature — same trust posture as
/// [`redaction_from_signed_json`]. Returns `None` for plans that carry no
/// budget, which is the default and the common case.
pub fn action_budget_from_signed_json(
    plan_json: &str,
) -> Result<Option<crate::policy::action_budget::ActionBudget>, serde_json::Error> {
    let signed: SignedExecutionPlan = serde_json::from_str(plan_json)?;
    let plan: ExecutionPlan = serde_json::from_slice(&signed.0.payload)?;
    Ok(plan.action_budget)
}

/// Extract the `tenant` id from a serialised `SignedExecutionPlan` envelope.
///
/// The Firecracker launch path reads the admitted plan from disk
/// (`plan.json`) and needs the tenant to scope the substitution endpoint's
/// binding store — but, unlike `VmStartConfig`, `FlakeRunConfig` carries no
/// out-of-band tenant field. Same trust posture as `secrets_from_signed_json`:
/// the signature was checked at admission; the host is in the TCB.
pub fn tenant_from_signed_json(plan_json: &str) -> Result<String, serde_json::Error> {
    let signed: SignedExecutionPlan = serde_json::from_str(plan_json)?;
    let plan: ExecutionPlan = serde_json::from_slice(&signed.0.payload)?;
    Ok(plan.tenant.0)
}

/// Decode an admitted plan from the per-VM `plan.json`, accepting both
/// on-disk shapes: the bare `ExecutionPlan` (what the post-admission
/// plan persist writes for lifecycle verbs, and what the firecracker
/// bridge parses) and the `SignedExecutionPlan` envelope (what the
/// gateway-bridge stash writes). The two shapes are disjoint — the
/// envelope lacks every required plan field and the bare plan lacks the
/// payload/signature fields — so trying bare first cannot misparse an
/// envelope. No signature re-verification: the host verified the
/// envelope at admission and the file is mode-0600 in the host TCB.
/// On failure, the bare-decode error is returned (the persisted bare
/// plan is the primary producer).
pub fn plan_from_admitted_json(plan_json: &str) -> Result<ExecutionPlan, serde_json::Error> {
    match serde_json::from_str::<ExecutionPlan>(plan_json) {
        Ok(plan) => Ok(plan),
        Err(bare_err) => match serde_json::from_str::<SignedExecutionPlan>(plan_json) {
            Ok(signed) => serde_json::from_slice(&signed.0.payload),
            Err(_) => Err(bare_err),
        },
    }
}

/// Verify a signed plan against a set of trusted keys, returning the
/// parsed `ExecutionPlan` on success.
///
/// Delegates to [`verify_signed_payload`], the routine topologies verify
/// through too. The verification order is signature → schema version → JSON
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
    Ok(verify_signed_payload(
        &signed.0,
        trusted_keys,
        SCHEMA_VERSION,
    )?)
}

/// Test-support fixtures shared across crates. Gated so it never ships in a
/// non-test build but is reachable from other crates' `#[cfg(test)]` code via
/// the `test-support` feature (e.g. `mvm-vm-host`'s prelaunch verify tests need
/// a valid `ExecutionPlan` to sign, and duplicating this ~50-line literal would
/// drift). `mvm-core`'s own tests use it through `test` directly.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use crate::plan::types::*;
    use std::collections::BTreeMap;

    /// A minimal valid `ExecutionPlan` with a fixed validity window + nonce.
    /// Callers override `valid_from`/`valid_until`/`nonce` for their scenario.
    pub fn sample_plan() -> ExecutionPlan {
        let from: mvm_contract::timestamp::UtcTimestamp = "2026-05-01T00:00:00Z".parse().unwrap();
        let mut plan = crate::plan::test_support::PlanFixture::new()
            .plan_id("01HXTESTPLAN000000000000")
            .tenant("tenant-a")
            .workload("workload-1")
            .nonce([0xab; 16])
            .validity(from, from.checked_add_secs(3_600).unwrap())
            .audit_labels(BTreeMap::from([("workflow".into(), "etl-1".into())]))
            .build();
        plan.image.name = "tenant-worker-aarch64".into();
        plan.resources.cpus = 2;
        plan.resources.mem_mib = 1024;
        plan.resources.disk_mib = 4096;
        plan.resources.timeouts.exec_secs = 600;
        plan.admission_profile =
            AdmissionProfile::local_default("code:execute", PlanSeccompTier::Standard);
        plan.network_policy = PolicyRef("default-deny".into());
        plan.fs_policy = FsPolicyRef("default".into());
        plan.egress_policy = PolicyRef("agent-l7".into());
        plan.artifact_policy.capture_paths = vec!["/artifacts".into()];
        plan.artifact_policy.retention_days = 30;
        plan.key_rotation.interval_days = 7;
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::sample_plan;
    use super::*;
    use crate::plan::types::*;
    use ed25519_dalek::SigningKey;
    use rand::Rng;

    fn fresh_key() -> (SigningKey, VerifyingKey) {
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        // sign_plan stamps the content-address; give the fixture that id up
        // front so the round-trip recovers a byte-identical plan.
        let mut plan = sample_plan();
        plan.plan_id = crate::plan::compute_plan_id(&plan);
        let (sk, vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let recovered = verify_plan(&signed, &[("test-signer", &vk)]).unwrap();
        assert_eq!(recovered, plan);
    }

    #[test]
    fn runtime_identity_is_inside_the_signed_plan_payload() {
        let mut plan = sample_plan();
        plan.environment = None;
        plan.runtime_identity = Some(RuntimeIdentity {
            archive_sha256: "a".repeat(64),
            version: "0.28.0".into(),
            arch: "x86_64".into(),
            declaration: RuntimeArtifactDigests {
                overlay_sha256: "b".repeat(64),
                overlay_verity_sha256: "c".repeat(64),
                overlay_roothash: "d".repeat(64),
                initramfs_sha256: "e".repeat(64),
            },
            selected: RuntimeArtifactDigests {
                overlay_sha256: "b".repeat(64),
                overlay_verity_sha256: "c".repeat(64),
                overlay_roothash: "d".repeat(64),
                initramfs_sha256: "e".repeat(64),
            },
            signer_identity: "release@example.org".into(),
            signer_issuer: "https://issuer.example.org".into(),
        });
        let (sk, vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let recovered = verify_plan(&signed, &[("test-signer", &vk)]).expect("signed pin");
        assert!(
            recovered.environment.is_none(),
            "fork has no fresh kernel pin"
        );
        assert_eq!(recovered.runtime_identity, plan.runtime_identity);
        let mut tampered = signed;
        let mut payload: serde_json::Value = serde_json::from_slice(&tampered.0.payload).unwrap();
        payload["runtime_identity"]["selected"]["overlay_roothash"] = "0".repeat(64).into();
        tampered.0.payload = serde_json::to_vec(&payload).unwrap();
        assert!(verify_plan(&tampered, &[("test-signer", &vk)]).is_err());
    }

    #[test]
    fn signed_legacy_tool_policy_does_not_become_an_unrestricted_grant() {
        let mut plan = sample_plan();
        plan.agent_verbs = Some(vec![crate::plan::VerbId::new("run-entrypoint").unwrap()]);
        let (sk, vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let round = verify_plan(&signed, &[("test-signer", &vk)]).expect("ordinary plan");
        assert_eq!(round.agent_verbs, plan.agent_verbs);
        assert_eq!(round.network_policy, plan.network_policy);
        assert_eq!(round.fs_policy, plan.fs_policy);
        assert_eq!(round.egress_policy, plan.egress_policy);
        assert_eq!(round.secrets, plan.secrets);

        for (field, value) in [
            ("tools", serde_json::json!({"allow": ["shell"]})),
            (
                "tools",
                serde_json::json!({"detail": {"shell": {"secrets": ["token"]}}}),
            ),
            ("tool_policy", serde_json::json!("read-only-tools")),
        ] {
            let mut legacy = serde_json::to_value(&plan).expect("plan serializes");
            legacy[field] = value;
            let mut signed = signed.clone();
            signed.0.payload = serde_json::to_vec(&legacy).expect("legacy plan serializes");
            signed.0.signature = sk.sign(&signed.0.payload).to_bytes().to_vec();
            assert!(
                matches!(
                    verify_plan(&signed, &[("test-signer", &vk)]),
                    Err(PlanVerifyError::Parse(_))
                ),
                "{field}"
            );
            let json = serde_json::to_string(&signed).expect("signed plan serializes");
            assert!(plan_from_admitted_json(&json).is_err(), "{field}");
            assert!(secrets_from_signed_json(&json).is_err(), "{field}");
        }
        let mut legacy = serde_json::to_value(&plan).expect("plan serializes");
        legacy["admission_profile"]["tool_policy"] = serde_json::json!("read-only-tools");
        let mut signed = signed;
        signed.0.payload = serde_json::to_vec(&legacy).expect("legacy plan serializes");
        signed.0.signature = sk.sign(&signed.0.payload).to_bytes().to_vec();
        assert!(matches!(
            verify_plan(&signed, &[("test-signer", &vk)]),
            Err(PlanVerifyError::Parse(_))
        ));
        let json = serde_json::to_string(&signed).expect("signed plan serializes");
        assert!(plan_from_admitted_json(&json).is_err());
        assert!(secrets_from_signed_json(&json).is_err());
    }

    #[test]
    fn sign_plan_stamps_content_address_over_a_bogus_id() {
        // Handing sign_plan a plan carrying a wrong id yields an envelope whose
        // inner plan is content-addressed — a mismatched signed plan cannot be
        // produced through this API.
        let mut plan = sample_plan();
        plan.plan_id = PlanId("sha256:not-the-real-address".to_string());
        let (sk, vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let recovered = verify_plan(&signed, &[("test-signer", &vk)]).unwrap();
        assert_ne!(recovered.plan_id.0, "sha256:not-the-real-address");
        assert!(crate::plan::verify_plan_id(&recovered).is_ok());
    }

    #[test]
    fn secrets_extracted_from_signed_envelope() {
        let mut plan = sample_plan();
        plan.secrets = vec![SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
            destinations: Vec::new(),
            approval_required: false,
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
    fn admitted_json_decodes_bare_plan() {
        let mut plan = sample_plan();
        plan.secrets = vec![SecretBinding {
            name: "API_KEY".into(),
            source: SecretSource::Keystore {
                address: "echo-key".into(),
            },
            destinations: Vec::new(),
            approval_required: false,
        }];
        let json = serde_json::to_string(&plan).unwrap();
        let decoded = plan_from_admitted_json(&json).unwrap();
        assert_eq!(decoded, plan);
    }

    #[test]
    fn admitted_json_decodes_signed_envelope() {
        let mut plan = sample_plan();
        plan.secrets = vec![SecretBinding {
            name: "API_KEY".into(),
            source: SecretSource::Keystore {
                address: "echo-key".into(),
            },
            destinations: Vec::new(),
            approval_required: false,
        }];
        // Content-address after the last body edit so the decoded plan matches.
        plan.plan_id = crate::plan::compute_plan_id(&plan);
        let (sk, _vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let json = serde_json::to_string(&signed).unwrap();
        let decoded = plan_from_admitted_json(&json).unwrap();
        assert_eq!(decoded, plan);
    }

    #[test]
    fn admitted_json_rejects_garbage_with_bare_error() {
        assert!(plan_from_admitted_json("{\"not\":\"a plan\"}").is_err());
        assert!(plan_from_admitted_json("not json").is_err());
    }

    #[test]
    fn redaction_extracted_from_signed_envelope() {
        use crate::policy::{EntropyMode, RedactionAction, RedactionPolicy, RedactionProfile};
        let mut plan = sample_plan();
        plan.redaction = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![RedactionProfile {
                host: "*.untrusted.example".to_string(),
                action: RedactionAction {
                    entropy: EntropyMode::Redact {
                        min_bits_per_char: 4.0,
                        min_run_len: 20,
                    },
                    ..Default::default()
                },
            }],
        };
        let (sk, _vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let json = serde_json::to_string(&signed).unwrap();
        let recovered = redaction_from_signed_json(&json).unwrap();
        assert_eq!(recovered, plan.redaction);
        assert_eq!(recovered.profiles.len(), 1);
        assert_eq!(recovered.profiles[0].host, "*.untrusted.example");
    }

    #[test]
    fn action_budget_extracted_from_signed_envelope() {
        use crate::policy::action_budget::ActionBudget;
        let mut plan = sample_plan();
        plan.action_budget = Some(
            ActionBudget::default()
                .with_max_egress_flows(3)
                .with_max_dns_queries(1_000),
        );
        let (sk, _vk) = fresh_key();
        let signed = sign_plan(&plan, &sk, "test-signer");
        let json = serde_json::to_string(&signed).unwrap();
        let recovered = action_budget_from_signed_json(&json).unwrap();
        assert_eq!(recovered, plan.action_budget);

        let (sk, _vk) = fresh_key();
        let signed = sign_plan(&sample_plan(), &sk, "test-signer");
        let json = serde_json::to_string(&signed).unwrap();
        assert!(action_budget_from_signed_json(&json).unwrap().is_none());
    }

    #[test]
    fn plan_without_redaction_field_defaults_to_all_off() {
        // A plan JSON missing `redaction` must deserialize via #[serde(default)].
        let plan = sample_plan();
        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().remove("redaction");
        assert!(value.get("redaction").is_none());
        let parsed: ExecutionPlan = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.redaction, crate::policy::RedactionPolicy::default());
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

    fn mailbox_grant() -> mvm_contract::protocol::mailbox::MailboxGrant {
        use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
        MailboxGrant {
            mailbox: MailboxId::from_bytes([7; 32]),
            authority_key: [9; 32],
            epoch: ExecutionEpoch::new(3).unwrap(),
            report: None,
            retention: None,
            service_blind: None,
        }
    }

    #[test]
    fn a_mailbox_grant_is_signature_bound_and_absence_stays_absent() {
        let (sk, vk) = fresh_key();
        let absent = sign_plan(&sample_plan(), &sk, "test-signer");
        assert!(!String::from_utf8_lossy(&absent.0.payload).contains("mailbox"));
        assert_eq!(
            verify_plan(&absent, &[("test-signer", &vk)])
                .unwrap()
                .mailbox,
            None
        );

        let mut plan = sample_plan();
        plan.mailbox = Some(mailbox_grant());
        let mut signed = sign_plan(&plan, &sk, "test-signer");
        assert_eq!(
            verify_plan(&signed, &[("test-signer", &vk)])
                .unwrap()
                .mailbox,
            Some(mailbox_grant())
        );

        // Widening the epoch, and adding a grant to a plan signed without
        // one, both break the signature.
        let mut payload: serde_json::Value = serde_json::from_slice(&signed.0.payload).unwrap();
        payload["mailbox"]["epoch"] = serde_json::json!(4);
        signed.0.payload = serde_json::to_vec(&payload).unwrap();
        assert!(matches!(
            verify_plan(&signed, &[("test-signer", &vk)]),
            Err(PlanVerifyError::SignatureInvalid(_))
        ));
        let mut forged = absent.clone();
        let mut payload: serde_json::Value = serde_json::from_slice(&forged.0.payload).unwrap();
        payload["mailbox"] = serde_json::to_value(mailbox_grant()).unwrap();
        forged.0.payload = serde_json::to_vec(&payload).unwrap();
        assert!(matches!(
            verify_plan(&forged, &[("test-signer", &vk)]),
            Err(PlanVerifyError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn selector_survives_real_plan_roundtrip_and_changes_signed_content_identity() {
        use mvm_contract::protocol::mailbox::service_blind::LaunchProfile;
        let (sk, vk) = fresh_key();
        let mut legacy = sample_plan();
        legacy.mailbox = Some(mailbox_grant());
        let old = sign_plan(&legacy, &sk, "test-signer");
        assert!(!String::from_utf8_lossy(&old.0.payload).contains("service_blind"));
        let mut selected = legacy.clone();
        selected.mailbox.as_mut().unwrap().service_blind =
            Some(LaunchProfile::new([1; 32], [2; 32]).unwrap());
        let signed = sign_plan(&selected, &sk, "test-signer");
        let verified = verify_plan(&signed, &[("test-signer", &vk)]).unwrap();
        assert_eq!(verified.mailbox, selected.mailbox);
        for raw in [
            serde_json::to_string(&signed).unwrap(),
            String::from_utf8(signed.0.payload.clone()).unwrap(),
        ] {
            assert_eq!(plan_from_admitted_json(&raw).unwrap(), verified);
        }
        assert_ne!(
            verified.plan_id,
            verify_plan(&old, &[("test-signer", &vk)]).unwrap().plan_id
        );
        for selection in [
            None,
            Some(LaunchProfile::new([3; 32], [2; 32]).unwrap()),
            Some(LaunchProfile::new([1; 32], [3; 32]).unwrap()),
        ] {
            let mut changed = selected.clone();
            changed.mailbox.as_mut().unwrap().service_blind = selection;
            let rebound = sign_plan(&changed, &sk, "test-signer");
            assert_ne!(rebound.0.payload, signed.0.payload);
            assert_ne!(
                verify_plan(&rebound, &[("test-signer", &vk)])
                    .unwrap()
                    .plan_id,
                verified.plan_id
            );
            let mut forged = signed.clone();
            forged.0.payload = rebound.0.payload;
            assert!(matches!(
                verify_plan(&forged, &[("test-signer", &vk)]),
                Err(PlanVerifyError::SignatureInvalid(_))
            ));
        }
        let mut forged = old;
        forged.0.payload = signed.0.payload;
        assert!(matches!(
            verify_plan(&forged, &[("test-signer", &vk)]),
            Err(PlanVerifyError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn selector_invalid_signed_payload_is_not_normalized_by_plan_decoding() {
        use mvm_contract::protocol::mailbox::service_blind::LaunchProfile;
        let (sk, vk) = fresh_key();
        let mut plan = sample_plan();
        let mut grant = mailbox_grant();
        grant.service_blind = Some(LaunchProfile::new([1; 32], [2; 32]).unwrap());
        plan.mailbox = Some(grant);
        let signed = sign_plan(&plan, &sk, "test-signer");
        let raw = String::from_utf8(signed.0.payload.clone()).unwrap();
        for replacement in [
            r#""version":3.0"#,
            r#""version":"3""#,
            r#""version":4"#,
            r#""version":3,"unknown":true"#,
            r#""version":3,"version":3"#,
            r#""version":3,"ver\u0073ion":3"#,
        ] {
            let malformed = raw.replace(
                r#""service_blind":{"version":3"#,
                &format!(r#""service_blind":{{{replacement}"#),
            );
            assert_ne!(malformed, raw);
            let mut signed = signed.clone();
            signed.0.payload = malformed.as_bytes().to_vec();
            signed.0.signature = sk.sign(&signed.0.payload).to_bytes().to_vec();
            assert!(matches!(
                verify_plan(&signed, &[("test-signer", &vk)]),
                Err(PlanVerifyError::Parse(_))
            ));
            assert!(plan_from_admitted_json(&malformed).is_err());
            assert!(plan_from_admitted_json(&serde_json::to_string(&signed).unwrap()).is_err());
        }
    }

    #[test]
    fn a_report_ceiling_cannot_be_added_or_widened_after_plan_signing() {
        use mvm_contract::protocol::mailbox::MailboxReportSendPolicy;

        let (sk, vk) = fresh_key();
        let mut plan = sample_plan();
        plan.mailbox = Some(mailbox_grant());
        let signed_legacy = sign_plan(&plan, &sk, "test-signer");
        let old: serde_json::Value = serde_json::from_slice(&signed_legacy.0.payload).unwrap();
        assert!(old["mailbox"].get("report").is_none());

        let mut forged = signed_legacy.clone();
        let mut payload = old;
        payload["mailbox"]["report"] = serde_json::json!({
            "version": 1,
            "max_payload_bytes": 16384
        });
        forged.0.payload = serde_json::to_vec(&payload).unwrap();
        assert!(matches!(
            verify_plan(&forged, &[("test-signer", &vk)]),
            Err(PlanVerifyError::SignatureInvalid(_))
        ));

        let mut report_grant = mailbox_grant();
        report_grant.report = Some(MailboxReportSendPolicy::new(16 * 1024).unwrap());
        plan.mailbox = Some(report_grant);
        let signed = sign_plan(&plan, &sk, "test-signer");
        assert_eq!(
            verify_plan(&signed, &[("test-signer", &vk)])
                .unwrap()
                .mailbox,
            Some(report_grant)
        );
        let mut forged = signed;
        let mut payload: serde_json::Value = serde_json::from_slice(&forged.0.payload).unwrap();
        payload["mailbox"]["report"]["max_payload_bytes"] = serde_json::json!(32768);
        forged.0.payload = serde_json::to_vec(&payload).unwrap();
        assert!(matches!(
            verify_plan(&forged, &[("test-signer", &vk)]),
            Err(PlanVerifyError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn secret_approval_requirement_is_signature_bound() {
        let mut plan = sample_plan();
        plan.secrets = vec![SecretBinding {
            name: "TOKEN".into(),
            source: SecretSource::Keystore {
                address: "token".into(),
            },
            destinations: Vec::new(),
            approval_required: true,
        }];
        let (sk, vk) = fresh_key();
        let mut signed = sign_plan(&plan, &sk, "test-signer");
        assert!(
            verify_plan(&signed, &[("test-signer", &vk)])
                .unwrap()
                .secrets[0]
                .approval_required
        );

        let mut payload: serde_json::Value = serde_json::from_slice(&signed.0.payload).unwrap();
        payload["secrets"][0]["approval_required"] = serde_json::json!(false);
        signed.0.payload = serde_json::to_vec(&payload).unwrap();
        assert!(matches!(
            verify_plan(&signed, &[("test-signer", &vk)]),
            Err(PlanVerifyError::SignatureInvalid(_))
        ));
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
    fn plan_without_network_mode_field_defaults_to_none() {
        use crate::plan::types::NetworkMode;
        // A plan serialized before `network_mode` existed (field absent) must
        // still deserialize, defaulting to the closed `None` (`serde(default)`).
        let plan = sample_plan();
        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().remove("network_mode");
        assert!(value.get("network_mode").is_none());
        let parsed: ExecutionPlan = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.network_mode, NetworkMode::None);
    }

    #[test]
    fn network_mode_round_trips_in_the_plan() {
        use crate::plan::types::NetworkMode;
        let mut plan = sample_plan();
        plan.network_mode = NetworkMode::HostVsockProxy;
        let json = serde_json::to_string(&plan).unwrap();
        let parsed: ExecutionPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.network_mode, NetworkMode::HostVsockProxy);
    }

    #[test]
    fn plan_without_snapshot_at_field_defaults_to_none() {
        // A plan whose JSON lacks `snapshot_at` must still deserialize,
        // defaulting to `None` via `serde(default)`.
        let plan = sample_plan();
        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().remove("snapshot_at");
        assert!(value.get("snapshot_at").is_none());
        let parsed: ExecutionPlan = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.snapshot_at, None);
    }

    #[test]
    fn snapshot_at_round_trips_in_the_plan() {
        use crate::lifecycle::SnapshotAt;
        let mut plan = sample_plan();
        plan.snapshot_at = Some(SnapshotAt::AfterWarmup);
        let json = serde_json::to_string(&plan).unwrap();
        assert!(
            json.contains("after_warmup"),
            "snake_case wire token: {json}"
        );
        let parsed: ExecutionPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.snapshot_at, Some(SnapshotAt::AfterWarmup));
    }

    #[test]
    fn plan_without_build_provenance_defaults_to_none() {
        let plan = sample_plan();
        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().remove("build_provenance");
        assert!(value.get("build_provenance").is_none());
        let parsed: ExecutionPlan = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.build_provenance, None);
    }

    #[test]
    fn build_provenance_round_trips_in_the_plan() {
        use crate::plan::types::{ArtifactDigests, BuildProvenance, InputKind};
        let mut plan = sample_plan();
        plan.build_provenance = Some(BuildProvenance {
            input_kind: InputKind::NixFlake,
            input_ref: ".#app".to_string(),
            lock_digest: Some("sha256:lock".to_string()),
            builder_id: Some("builder-01".to_string()),
            artifacts: ArtifactDigests {
                kernel: Some("k".repeat(64)),
                rootfs: Some("r".repeat(64)),
                ..Default::default()
            },
        });
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("nix_flake"), "snake_case input kind: {json}");
        let parsed: ExecutionPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.build_provenance, plan.build_provenance);
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
        // ExecutionPlan carries `deps_volume: Option<DepsVolumeBinding>`.
        // A plan with a populated binding must round-trip through
        // sign → verify unchanged, and the resulting bytes must
        // canonicalize deterministically so the host signer always
        // produces the same signature input for the same plan.
        let mut plan = sample_plan();
        plan.deps_volume = Some(
            crate::plan::DepsVolumeBinding::new("a".repeat(64), "b".repeat(64))
                .expect("valid binding"),
        );
        plan.plan_id = crate::plan::compute_plan_id(&plan);
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
        // claim-8-only plans signed before deps volumes existed.
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
