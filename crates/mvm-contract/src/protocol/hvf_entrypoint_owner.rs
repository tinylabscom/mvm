//! Closed authority vocabulary for one protected cold-HVF owner operation.
//!
//! These values are public bindings, never capabilities. The protected
//! verifier and original live owner retain the non-serializable authority.

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::hvf_control::HvfInstance;

/// First supported owner-authority protocol.
pub const VERSION: u8 = 1;
/// Canonical plans retain the existing 64-KiB signing ceiling.
pub const MAX_CANONICAL_PLAN_BYTES: usize = 65_536;
const ADMISSION_DOMAIN: &[u8] = b"mvm.hvf-owner.fresh-admission.v1\0";

/// Provider-issued one-shot authority for one exact fresh-admission request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerGrant {
    /// Owner-authority protocol version.
    pub version: u8,
    /// Protected provider issuer selected by the deployment receipt.
    pub issuer: String,
    /// Monotonic commissioning generation from the root-owned deployment receipt.
    pub provider_epoch: u64,
    /// One-shot durable grant identity.
    pub grant_id: [u8; 32],
    /// Exact [`FreshAdmissionRequest::digest`] authorized by this grant.
    pub request_digest: [u8; 32],
    /// Inclusive Unix-seconds start bound.
    pub issued_at_secs: u64,
    /// Exclusive Unix-seconds expiry.
    pub expires_at_secs: u64,
}

/// Domain-separated provider signature over [`OwnerGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerGrant {
    /// Typed provider assertion.
    pub grant: OwnerGrant,
    /// Ed25519 signature over the provider-only grant domain and typed bytes.
    pub signature: Vec<u8>,
}

/// Complete public binding independently retained by the protected verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshOwnerBinding {
    pub version: u8,
    pub operation_id: [u8; 32],
    /// Fresh process incarnation selected before admission, not a native generation.
    pub owner_incarnation: [u8; 32],
    pub controlling_principal: [u8; 32],
    pub installation: [u8; 16],
    pub tenant_id: String,
    pub workload_id: String,
    pub canonical_plan_digest: [u8; 32],
    pub frozen_inputs_digest: [u8; 32],
    pub policy_revision: [u8; 32],
    pub expires_at_secs: u64,
}

impl FreshOwnerBinding {
    /// Validate bounded public fields before a protected verifier compares them.
    ///
    /// # Errors
    /// Refuses unsupported versions, empty identities and unbounded labels.
    pub fn validate(&self) -> Result<(), OwnerProtocolError> {
        if self.version != VERSION {
            return Err(OwnerProtocolError::Version);
        }
        for label in [&self.tenant_id, &self.workload_id] {
            if label.is_empty() || label.len() > 256 || label.chars().any(char::is_control) {
                return Err(OwnerProtocolError::Binding);
            }
        }
        if self.operation_id == [0; 32]
            || self.owner_incarnation == [0; 32]
            || self.controlling_principal == [0; 32]
            || self.installation == [0; 16]
            || self.canonical_plan_digest == [0; 32]
            || self.frozen_inputs_digest == [0; 32]
            || self.policy_revision == [0; 32]
            || self.expires_at_secs == 0
        {
            return Err(OwnerProtocolError::Binding);
        }
        Ok(())
    }
}

/// One exact fresh-admission request. Decoding it grants no authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshAdmissionRequest {
    pub binding: FreshOwnerBinding,
    pub canonical_plan: Vec<u8>,
}

impl FreshAdmissionRequest {
    /// Validate bounds and the plan commitment without admitting or signing it.
    ///
    /// # Errors
    /// Refuses invalid bindings, oversized plans and changed plan bytes.
    pub fn validate(&self) -> Result<(), OwnerProtocolError> {
        self.binding.validate()?;
        if self.canonical_plan.is_empty() || self.canonical_plan.len() > MAX_CANONICAL_PLAN_BYTES {
            return Err(OwnerProtocolError::PlanSize);
        }
        let digest: [u8; 32] = Sha256::digest(&self.canonical_plan).into();
        if digest != self.binding.canonical_plan_digest {
            return Err(OwnerProtocolError::PlanDigest);
        }
        Ok(())
    }

    /// Domain-separated commitment to the binding and exact canonical plan.
    ///
    /// # Errors
    /// Refuses the same invalid input as [`Self::validate`] or serialization
    /// failure.
    pub fn digest(&self) -> Result<[u8; 32], OwnerProtocolError> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(ADMISSION_DOMAIN);
        hasher.update(serde_json::to_vec(&self.binding).map_err(|_| OwnerProtocolError::Encoding)?);
        hasher.update(&self.canonical_plan);
        Ok(hasher.finalize().into())
    }
}

/// Lifecycle events whose immutable identity comes from retained owner state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerAuditEvent {
    BirthAdmitted {
        plan_digest: [u8; 32],
        frozen_inputs_digest: [u8; 32],
    },
    EntrypointCompleted {
        terminal_digest: [u8; 32],
    },
    EntrypointFailed {
        failure: OwnerFailure,
    },
}

/// Failures recorded before a native generation exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrebirthAuditEvent {
    AdmissionRefused,
    PreparationFailed,
    BirthUnknown,
}

/// Bounded failure classes; no guest-authored message crosses this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerFailure {
    Admission,
    Preparation,
    Dispatch,
    Execution,
    Stop,
    Cleanup,
    Audit,
    Unknown,
}

/// Terminal disposition. This value is not native exit or cleanup proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerTerminal {
    Completed { terminal_digest: [u8; 32] },
    Failed { failure: OwnerFailure },
}

/// Exact original-instance control vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum OriginalHvfCommand {
    Challenge {
        client_nonce: [u8; 32],
        connection_nonce: [u8; 32],
    },
    Stop {
        connection_nonce: [u8; 32],
        issued_at_secs: u64,
    },
    Finalize {},
}

/// Closed requests accepted by a future protected owner-authority provider.
///
/// The provider must compare every public field with retained state before
/// consuming a non-serializable one-shot capability. This enum contains no
/// path, PID, program, argument vector or arbitrary signing payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerOperation {
    AdmitFreshCanonical(FreshAdmissionRequest),
    AppendPrebirthAudit {
        binding: FreshOwnerBinding,
        event: PrebirthAuditEvent,
    },
    AppendOwnerAudit {
        instance: HvfInstance,
        event: OwnerAuditEvent,
    },
    CloseOwnerAudit {
        instance: HvfInstance,
        terminal: OwnerTerminal,
    },
    ControlOriginalHvf {
        instance: HvfInstance,
        command: OriginalHvfCommand,
    },
}

/// Structural protocol refusal. Authorization failures belong to the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OwnerProtocolError {
    #[error("unsupported HVF owner protocol version")]
    Version,
    #[error("invalid HVF owner authority binding")]
    Binding,
    #[error("canonical plan exceeds the HVF owner bound")]
    PlanSize,
    #[error("canonical plan digest differs from the HVF owner binding")]
    PlanDigest,
    #[error("HVF owner authority encoding failed")]
    Encoding,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString as _, vec};

    use super::*;

    fn request() -> FreshAdmissionRequest {
        let plan = br#"{"schema_version":1}"#.to_vec();
        FreshAdmissionRequest {
            binding: FreshOwnerBinding {
                version: VERSION,
                operation_id: [1; 32],
                owner_incarnation: [2; 32],
                controlling_principal: [3; 32],
                installation: [4; 16],
                tenant_id: "ténant".into(),
                workload_id: "work\"load".into(),
                canonical_plan_digest: Sha256::digest(&plan).into(),
                frozen_inputs_digest: [5; 32],
                policy_revision: [6; 32],
                expires_at_secs: 9_007_199_254_740_993,
            },
            canonical_plan: plan,
        }
    }

    #[test]
    fn exact_fresh_admission_has_a_stable_domain_separated_digest() {
        let request = request();
        assert_eq!(
            serde_json::to_string(&request.binding).unwrap(),
            concat!(
                "{\"version\":1,\"operation_id\":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,",
                "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],\"owner_incarnation\":[2,2,2,2,",
                "2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],",
                "\"controlling_principal\":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,",
                "3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],\"installation\":[4,4,4,4,",
                "4,4,4,4,4,4,4,4,4,4,4,4],\"tenant_id\":\"ténant\",",
                "\"workload_id\":\"work\\\"load\",\"canonical_plan_digest\":",
                "[169,213,246,208,2,217,86,184,175,87,135,160,94,12,160,0,",
                "212,92,3,151,127,250,84,238,143,190,215,25,254,213,253,35],",
                "\"frozen_inputs_digest\":[5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,",
                "5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],\"policy_revision\":",
                "[6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,",
                "6,6,6,6],\"expires_at_secs\":9007199254740993}"
            )
        );
        assert_eq!(
            request.digest().unwrap(),
            [
                246, 217, 223, 25, 241, 116, 107, 81, 59, 228, 94, 165, 103, 96, 184, 71, 135, 238,
                53, 147, 251, 83, 248, 159, 139, 21, 204, 78, 59, 155, 64, 64,
            ]
        );
        let original = request.digest().unwrap();
        let mutations: [fn(&mut FreshOwnerBinding); 9] = [
            |binding| binding.operation_id[0] ^= 1,
            |binding| binding.owner_incarnation[0] ^= 1,
            |binding| binding.controlling_principal[0] ^= 1,
            |binding| binding.installation[0] ^= 1,
            |binding| binding.tenant_id.push('x'),
            |binding| binding.workload_id.push('x'),
            |binding| binding.frozen_inputs_digest[0] ^= 1,
            |binding| binding.policy_revision[0] ^= 1,
            |binding| binding.expires_at_secs += 1,
        ];
        for mutate in mutations {
            let mut changed = request.clone();
            mutate(&mut changed.binding);
            assert!(changed.validate().is_ok());
            assert_ne!(changed.digest().unwrap(), original);
        }
        let mut changed = request.clone();
        changed.binding.version += 1;
        assert_eq!(changed.validate(), Err(OwnerProtocolError::Version));
        changed = request;
        changed.binding.canonical_plan_digest[0] ^= 1;
        assert_eq!(changed.validate(), Err(OwnerProtocolError::PlanDigest));
    }

    #[test]
    fn changed_or_unbounded_plan_never_matches_the_retained_binding() {
        let mut changed = request();
        changed.canonical_plan.push(b' ');
        assert_eq!(changed.validate(), Err(OwnerProtocolError::PlanDigest));
        changed.binding.canonical_plan_digest = Sha256::digest(&changed.canonical_plan).into();
        changed.canonical_plan = vec![0; MAX_CANONICAL_PLAN_BYTES + 1];
        assert_eq!(changed.validate(), Err(OwnerProtocolError::PlanSize));
        let mut exact = request();
        exact.canonical_plan = vec![b'x'; MAX_CANONICAL_PLAN_BYTES];
        exact.binding.canonical_plan_digest = Sha256::digest(&exact.canonical_plan).into();
        assert!(exact.validate().is_ok());
        exact.canonical_plan.clear();
        exact.binding.canonical_plan_digest = Sha256::digest(&exact.canonical_plan).into();
        assert_eq!(exact.validate(), Err(OwnerProtocolError::PlanSize));
    }

    #[test]
    fn zero_empty_future_and_control_labels_refuse() {
        for mutate in [
            |binding: &mut FreshOwnerBinding| binding.version += 1,
            |binding: &mut FreshOwnerBinding| binding.operation_id = [0; 32],
            |binding: &mut FreshOwnerBinding| binding.owner_incarnation = [0; 32],
            |binding: &mut FreshOwnerBinding| binding.controlling_principal = [0; 32],
            |binding: &mut FreshOwnerBinding| binding.installation = [0; 16],
            |binding: &mut FreshOwnerBinding| binding.tenant_id.clear(),
            |binding: &mut FreshOwnerBinding| binding.workload_id = "\n".to_string(),
            |binding: &mut FreshOwnerBinding| binding.expires_at_secs = 0,
        ] {
            let mut request = request();
            mutate(&mut request.binding);
            assert!(request.validate().is_err());
        }
        let mut request = request();
        request.binding.tenant_id = "x".repeat(256);
        assert!(request.validate().is_ok());
        request.binding.tenant_id.push('x');
        assert_eq!(request.validate(), Err(OwnerProtocolError::Binding));
    }

    #[test]
    fn closed_operations_roundtrip_and_reject_unknown_fields() {
        let instance = HvfInstance {
            vm_id: "workload".into(),
            boot_nonce: [8; 32],
        };
        let operations = [
            OwnerOperation::AdmitFreshCanonical(request()),
            OwnerOperation::AppendPrebirthAudit {
                binding: request().binding,
                event: PrebirthAuditEvent::PreparationFailed,
            },
            OwnerOperation::AppendOwnerAudit {
                instance: instance.clone(),
                event: OwnerAuditEvent::EntrypointFailed {
                    failure: OwnerFailure::Execution,
                },
            },
            OwnerOperation::CloseOwnerAudit {
                instance: instance.clone(),
                terminal: OwnerTerminal::Failed {
                    failure: OwnerFailure::Cleanup,
                },
            },
            OwnerOperation::ControlOriginalHvf {
                instance,
                command: OriginalHvfCommand::Stop {
                    connection_nonce: [9; 32],
                    issued_at_secs: 10,
                },
            },
        ];
        for operation in operations {
            let encoded = serde_json::to_vec(&operation).unwrap();
            assert_eq!(
                serde_json::from_slice::<OwnerOperation>(&encoded).unwrap(),
                operation
            );
        }
        assert!(
            serde_json::from_value::<OwnerOperation>(serde_json::json!({
                "operation": "control_original_hvf",
                "instance": {"vm_id":"workload","boot_nonce":vec![8;32]},
                "command": {"command":"finalize","pid":42}
            }))
            .is_err()
        );
        assert!(
            serde_json::from_str::<OwnerOperation>(
                r#"{"operation":"control_original_hvf","instance":{"vm_id":"w","boot_nonce":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"command":{"command":"finalize","command":"stop","connection_nonce":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"issued_at_secs":1}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<OwnerOperation>(serde_json::json!({
                "operation": "append_owner_audit",
                "instance": {"vm_id":"workload","boot_nonce":vec![8;32]},
                "event": {"event":"entrypoint_completed","terminal_digest":vec![7;32],"path":"/tmp/x"}
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<OwnerOperation>(serde_json::json!({
                "operation": "close_owner_audit",
                "instance": {"vm_id":"workload","boot_nonce":vec![8;32]},
                "terminal": {"outcome":"failed","failure":"cleanup","pid":1}
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<OwnerOperation>(serde_json::json!({
                "operation": "sign_arbitrary",
                "bytes": [1,2,3]
            }))
            .is_err()
        );
    }
}
