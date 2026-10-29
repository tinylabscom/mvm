//! Unauthenticated recovery requests, never native ownership or signing authority.
//!
//! Decoding checks bounded syntax and public binding consistency only. A receiver
//! must separately authenticate the connected peer, controlling principal and
//! owner lifetime, enforce freshness/replay rules, and apply the operation to its
//! original retained owner. No transport, launcher or credential operation is
//! provided here.

use alloc::string::String;
use core::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use super::hvf_control::HvfInstance;

/// Encoded request ceiling, independent of any native process resource profile.
pub const MAX_REQUEST_BYTES: usize = 4096;
/// Version of this request shape; no active endpoint is implied.
pub const REQUEST_VERSION: u8 = 1;

/// Public phase binding. A pre-birth request cannot invent a native generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryPhase {
    BeforeAdmission {
        proposed_plan_digest: [u8; 32],
    },
    Admitted {
        plan_digest: [u8; 32],
        effective_config_digest: [u8; 32],
    },
    Native {
        plan_digest: [u8; 32],
        effective_config_digest: [u8; 32],
        instance: HvfInstance,
    },
}

/// Public identifiers to compare with the original owner's retained context.
/// Possession of these values does not authorize any operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBinding {
    pub operation_id: [u8; 32],
    pub request_digest: [u8; 32],
    pub controlling_principal: [u8; 32],
    pub tenant_id: String,
    pub owner_incarnation: [u8; 32],
    pub phase: RecoveryPhase,
}

/// Recovery cannot start, redispatch, detach, sign, or adopt a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryOperation {
    // Empty struct variants reject extra fields that serde ignores on unit variants.
    Observe {},
    CancelStop {},
    /// Delivery bookkeeping only; never a request to release resources.
    AcknowledgeResult {
        revision: NonZeroU64,
    },
}

/// Still untrusted after successful decoding and public binding comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedRecoveryRequest {
    pub version: u8,
    pub binding: RecoveryBinding,
    pub sequence: NonZeroU64,
    pub action: RecoveryOperation,
}

/// Stable refusals intentionally omit untrusted request contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryDecodeError {
    #[error("recovery request exceeds its encoded size bound")]
    TooLarge,
    #[error("recovery request must be a strict JSON object")]
    Malformed,
    #[error("recovery request version is unsupported")]
    UnsupportedVersion,
    #[error("recovery request differs from the retained operation binding")]
    BindingMismatch,
    #[error("recovery result is not available for acknowledgement")]
    ResultNotReady,
    #[error("recovery acknowledgement names another result revision")]
    ResultRevisionMismatch,
}

/// Decode a bounded request and compare its public binding with retained state.
///
/// `terminal_revision` is delivery state supplied by the original owner, not a
/// terminal proof. An accepted acknowledgement grants no cleanup authority.
/// Cancellation does not depend on a terminal result being available.
///
/// The transport must also reject oversized declared lengths before allocating
/// its input buffer. This function checks an already-supplied slice before serde
/// allocates, and performs no I/O, authentication, replay tracking or mutation.
///
/// # Errors
///
/// Refuses malformed/oversized requests, unsupported versions, mismatched public
/// bindings and early/stale result acknowledgements.
pub fn decode_bound_request(
    bytes: &[u8],
    expected: &RecoveryBinding,
    terminal_revision: Option<NonZeroU64>,
) -> Result<UntrustedRecoveryRequest, RecoveryDecodeError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(RecoveryDecodeError::TooLarge);
    }
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return Err(RecoveryDecodeError::Malformed);
    }
    let request: UntrustedRecoveryRequest =
        serde_json::from_slice(bytes).map_err(|_| RecoveryDecodeError::Malformed)?;
    if request.version != REQUEST_VERSION {
        return Err(RecoveryDecodeError::UnsupportedVersion);
    }
    if &request.binding != expected {
        return Err(RecoveryDecodeError::BindingMismatch);
    }
    if let RecoveryOperation::AcknowledgeResult { revision } = request.action {
        let expected_revision = terminal_revision.ok_or(RecoveryDecodeError::ResultNotReady)?;
        if revision != expected_revision {
            return Err(RecoveryDecodeError::ResultRevisionMismatch);
        }
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use serde_json::json;

    fn revision(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    fn request(action: RecoveryOperation) -> UntrustedRecoveryRequest {
        UntrustedRecoveryRequest {
            version: REQUEST_VERSION,
            binding: RecoveryBinding {
                operation_id: [1; 32],
                request_digest: [2; 32],
                controlling_principal: [3; 32],
                tenant_id: "tenant-a".into(),
                owner_incarnation: [4; 32],
                phase: RecoveryPhase::Native {
                    plan_digest: [5; 32],
                    effective_config_digest: [7; 32],
                    instance: HvfInstance {
                        vm_id: "vm-a".into(),
                        boot_nonce: [6; 32],
                    },
                },
            },
            sequence: revision(1),
            action,
        }
    }

    #[test]
    fn observes_and_accepts_cancellation_in_each_phase_without_terminal_state() {
        let phases = [
            RecoveryPhase::BeforeAdmission {
                proposed_plan_digest: [5; 32],
            },
            RecoveryPhase::Admitted {
                plan_digest: [5; 32],
                effective_config_digest: [7; 32],
            },
            request(RecoveryOperation::Observe {}).binding.phase,
        ];
        for phase in phases {
            for action in [
                RecoveryOperation::Observe {},
                RecoveryOperation::CancelStop {},
            ] {
                let mut request = request(action);
                request.binding.phase = phase.clone();
                let bytes = serde_json::to_vec(&request).unwrap();
                assert_eq!(
                    decode_bound_request(&bytes, &request.binding, None).unwrap(),
                    request
                );
            }
        }
    }

    #[test]
    fn acknowledges_only_the_available_exact_result_revision() {
        let request = request(RecoveryOperation::AcknowledgeResult {
            revision: revision(2),
        });
        let bytes = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            decode_bound_request(&bytes, &request.binding, None),
            Err(RecoveryDecodeError::ResultNotReady)
        );
        assert_eq!(
            decode_bound_request(&bytes, &request.binding, Some(revision(1))),
            Err(RecoveryDecodeError::ResultRevisionMismatch)
        );
        assert_eq!(
            decode_bound_request(&bytes, &request.binding, Some(revision(2))).unwrap(),
            request
        );
    }

    #[test]
    fn refuses_each_changed_public_binding_without_authorizing_the_matching_one() {
        let request = request(RecoveryOperation::Observe {});
        let bytes = serde_json::to_vec(&request).unwrap();
        for field in 0..10 {
            let mut expected = request.binding.clone();
            match field {
                0 => expected.operation_id[0] ^= 1,
                1 => expected.request_digest[0] ^= 1,
                2 => expected.controlling_principal[0] ^= 1,
                3 => expected.tenant_id = "tenant-b".into(),
                4 => expected.owner_incarnation[0] ^= 1,
                5 => {
                    expected.phase = RecoveryPhase::Admitted {
                        plan_digest: [5; 32],
                        effective_config_digest: [7; 32],
                    };
                }
                6..=9 => {
                    let RecoveryPhase::Native {
                        plan_digest,
                        effective_config_digest,
                        instance,
                    } = &mut expected.phase
                    else {
                        unreachable!()
                    };
                    match field {
                        6 => plan_digest[0] ^= 1,
                        7 => instance.vm_id = "vm-b".into(),
                        8 => instance.boot_nonce[0] ^= 1,
                        9 => effective_config_digest[0] ^= 1,
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
            assert_eq!(
                decode_bound_request(&bytes, &expected, None),
                Err(RecoveryDecodeError::BindingMismatch),
                "field {field}"
            );
        }
    }

    #[test]
    fn checks_size_before_json_decoding_and_accepts_the_exact_ceiling() {
        let request = request(RecoveryOperation::Observe {});
        let mut bytes = serde_json::to_vec(&request).unwrap();
        assert!(bytes.len() < MAX_REQUEST_BYTES);
        bytes.resize(MAX_REQUEST_BYTES, b' ');
        assert!(decode_bound_request(&bytes, &request.binding, None).is_ok());
        bytes.push(b' ');
        assert_eq!(
            decode_bound_request(&bytes, &request.binding, None),
            Err(RecoveryDecodeError::TooLarge)
        );
        assert_eq!(
            decode_bound_request(&vec![b'!'; MAX_REQUEST_BYTES + 1], &request.binding, None),
            Err(RecoveryDecodeError::TooLarge)
        );
    }

    #[test]
    fn refuses_unknown_duplicate_missing_and_truncated_fields() {
        let request = request(RecoveryOperation::Observe {});
        let bytes = serde_json::to_vec(&request).unwrap();
        let value = serde_json::to_value(&request).unwrap();
        let mut malformed = vec![b"[]".to_vec(), b"null".to_vec()];
        malformed.push(
            serde_json::to_vec(&json!([
                value["version"],
                value["binding"],
                value["sequence"],
                value["action"]
            ]))
            .unwrap(),
        );
        for operation in ["start", "detach", "sign", "adopt"] {
            let mut altered = value.clone();
            altered["action"] = json!({"operation": operation});
            malformed.push(serde_json::to_vec(&altered).unwrap());
        }
        for (path, replacement) in [
            (vec!["pid"], json!(1234)),
            (vec!["sequence"], json!(0)),
            (
                vec!["action"],
                json!({"operation": "observe", "authorized": true}),
            ),
            (vec!["binding", "phase"], json!({"phase": "native"})),
            (
                vec!["action"],
                json!({"operation": "acknowledge_result", "revision": 0}),
            ),
        ] {
            let mut altered = value.clone();
            let mut slot = &mut altered;
            for key in path {
                slot = &mut slot[key];
            }
            *slot = replacement;
            malformed.push(serde_json::to_vec(&altered).unwrap());
        }
        let text = serde_json::to_string(&request).unwrap();
        malformed.push(
            text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
                .into_bytes(),
        );
        for encoded in malformed {
            assert_eq!(
                decode_bound_request(&encoded, &request.binding, None),
                Err(RecoveryDecodeError::Malformed),
                "encoded request: {encoded:?}"
            );
        }
        for end in 0..bytes.len() {
            assert_eq!(
                decode_bound_request(&bytes[..end], &request.binding, None),
                Err(RecoveryDecodeError::Malformed),
                "truncated at {end}"
            );
        }
        let mut unsupported = value;
        unsupported["version"] = json!(2);
        assert_eq!(
            decode_bound_request(
                &serde_json::to_vec(&unsupported).unwrap(),
                &request.binding,
                None
            ),
            Err(RecoveryDecodeError::UnsupportedVersion)
        );
    }

    #[test]
    fn refuses_changed_before_admission_and_admitted_digests() {
        for phase in [
            RecoveryPhase::BeforeAdmission {
                proposed_plan_digest: [5; 32],
            },
            RecoveryPhase::Admitted {
                plan_digest: [5; 32],
                effective_config_digest: [7; 32],
            },
        ] {
            let mut request = request(RecoveryOperation::Observe {});
            request.binding.phase = phase;
            let bytes = serde_json::to_vec(&request).unwrap();
            for change_config in [false, true] {
                let mut expected = request.binding.clone();
                match &mut expected.phase {
                    RecoveryPhase::BeforeAdmission {
                        proposed_plan_digest,
                    } => proposed_plan_digest[0] ^= 1,
                    RecoveryPhase::Admitted {
                        plan_digest,
                        effective_config_digest,
                    } => {
                        if change_config {
                            effective_config_digest[0] ^= 1;
                        } else {
                            plan_digest[0] ^= 1;
                        }
                    }
                    RecoveryPhase::Native { .. } => unreachable!(),
                }
                assert_eq!(
                    decode_bound_request(&bytes, &expected, None),
                    Err(RecoveryDecodeError::BindingMismatch)
                );
            }
        }
    }

    #[test]
    fn refuses_unknown_and_duplicate_nested_fields() {
        for action in [
            RecoveryOperation::Observe {},
            RecoveryOperation::CancelStop {},
            RecoveryOperation::AcknowledgeResult {
                revision: revision(1),
            },
        ] {
            let request = request(action);
            let value = serde_json::to_value(&request).unwrap();
            for path in [
                vec!["action"],
                vec!["binding"],
                vec!["binding", "phase"],
                vec!["binding", "phase", "instance"],
            ] {
                let mut altered = value.clone();
                let mut record = &mut altered;
                for key in path {
                    record = &mut record[key];
                }
                record["unexpected"] = json!(true);
                assert_eq!(
                    decode_bound_request(
                        &serde_json::to_vec(&altered).unwrap(),
                        &request.binding,
                        Some(revision(1)),
                    ),
                    Err(RecoveryDecodeError::Malformed)
                );
            }
        }
        let request = request(RecoveryOperation::Observe {});
        let text = serde_json::to_string(&request).unwrap();
        for field in [
            "\"tenant_id\":\"tenant-a\"",
            "\"phase\":\"native\"",
            "\"vm_id\":\"vm-a\"",
        ] {
            let duplicated = text.replacen(field, &alloc::format!("{field},{field}"), 1);
            assert_ne!(duplicated, text);
            assert_eq!(
                decode_bound_request(duplicated.as_bytes(), &request.binding, None),
                Err(RecoveryDecodeError::Malformed)
            );
        }
    }

    #[test]
    fn nested_sequences_remain_untrusted_noncanonical_public_data() {
        let request = request(RecoveryOperation::Observe {});
        let value = serde_json::to_value(&request).unwrap();
        let mut instance_sequence = value.clone();
        let instance = &value["binding"]["phase"]["instance"];
        instance_sequence["binding"]["phase"]["instance"] =
            json!([instance["vm_id"], instance["boot_nonce"]]);
        let mut binding_sequence = value.clone();
        let binding = &value["binding"];
        binding_sequence["binding"] = json!([
            binding["operation_id"],
            binding["request_digest"],
            binding["controlling_principal"],
            binding["tenant_id"],
            binding["owner_incarnation"],
            binding["phase"]
        ]);
        for encoded in [instance_sequence, binding_sequence] {
            assert_eq!(
                decode_bound_request(
                    &serde_json::to_vec(&encoded).unwrap(),
                    &request.binding,
                    None,
                )
                .unwrap(),
                request
            );
        }
    }

    #[test]
    fn repeated_decoding_does_not_claim_replay_protection() {
        let request = request(RecoveryOperation::CancelStop {});
        let bytes = serde_json::to_vec(&request).unwrap();
        for _ in 0..2 {
            let decoded: UntrustedRecoveryRequest =
                decode_bound_request(&bytes, &request.binding, None).unwrap();
            assert_eq!(decoded, request);
        }
    }
}
