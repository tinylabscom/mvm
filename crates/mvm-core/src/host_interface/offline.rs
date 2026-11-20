//! Opt-in offline authority verification, without changing legacy signed records.
//!
//! This preview supplies decisions only. It does not admit a VM or authenticate
//! storage/ownership evidence. Trust roots, expectations and ceilings must come
//! from the existing policy owner, never from a workload or the supplied records.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    Denial, ExecutionEpoch, NodeState, SignedHostPolicy,
    error::OfflineRefusal,
    lease::{LeaseOp, OfflineLease, SignedLease},
};

const DOMAIN: &[u8] = b"mvm-offline-recovery-v1\0";

/// Signed restart constraints; the range is not an epoch allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestartAllowance {
    /// No replacement is authorized.
    Denied,
    /// Bounded same-package replacement within an inclusive delegated range.
    SamePackage {
        max_restarts: u32,
        first_epoch: ExecutionEpoch,
        last_epoch: ExecutionEpoch,
    },
}

impl RestartAllowance {
    pub(super) fn limit(self) -> u32 {
        match self {
            Self::Denied => 0,
            Self::SamePackage { max_restarts, .. } => max_restarts,
        }
    }

    fn validate(self, ceiling: u32) -> Result<(), Denial> {
        if let Self::SamePackage {
            max_restarts,
            first_epoch,
            last_epoch,
        } = self
        {
            let capacity = last_epoch
                .0
                .checked_sub(first_epoch.0)
                .and_then(|n| n.checked_add(1))
                .ok_or(OfflineRefusal::Bounds)?;
            if first_epoch.0 == 0
                || max_restarts == 0
                || max_restarts > ceiling
                || u64::from(max_restarts) > capacity
            {
                return Err(OfflineRefusal::Bounds.into());
            }
        }
        Ok(())
    }

    pub(super) fn check_epoch(self, epoch: ExecutionEpoch) -> Result<(), Denial> {
        match self {
            Self::SamePackage {
                first_epoch,
                last_epoch,
                ..
            } if epoch >= first_epoch && epoch <= last_epoch => Ok(()),
            Self::Denied => Err(OfflineRefusal::RestartExhausted.into()),
            Self::SamePackage { .. } => Err(OfflineRefusal::EpochAllocation.into()),
        }
    }
}

/// Losing connectivity never establishes ownership or authorizes a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyLoss {
    /// Keep only independently authorized work until its original expiry.
    ContinueAuthorized,
    /// Close effects and stop/reconcile exact owners.
    Stop,
}

/// A versioned companion to an unchanged signed lease and host policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    pub version: u32,
    pub issuer: String,
    pub lease_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub workload_id: String,
    /// Immutable package identity, not the host policy's image identity.
    pub package_digest: [u8; 32],
    pub restart: RestartAllowance,
    pub connection_attempts: u32,
    pub dependency_loss: DependencyLoss,
}

/// Signature over a domain-separated JCS companion body, not over a legacy lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecoveryPolicy {
    pub policy: RecoveryPolicy,
    pub signature: Vec<u8>,
}

impl SignedRecoveryPolicy {
    /// Sign a companion using explicitly supplied issuer custody.
    ///
    /// # Errors
    /// Returns canonical serialization errors; signing does not validate policy.
    pub fn sign(policy: RecoveryPolicy, key: &SigningKey) -> Result<Self, serde_json::Error> {
        let bytes = companion_bytes(&policy)?;
        Ok(Self {
            policy,
            signature: key.sign(&bytes).to_bytes().to_vec(),
        })
    }
}

fn companion_bytes(policy: &RecoveryPolicy) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_jcs::to_vec(policy)?);
    Ok(bytes)
}

/// SHA-256 commitment to the complete canonical signed envelope.
///
/// # Errors
/// Returns canonical serialization errors.
pub fn signed_record_digest(record: &impl Serialize) -> Result<[u8; 32], serde_json::Error> {
    Ok(Sha256::digest(serde_jcs::to_vec(record)?).into())
}

/// Injected conservative time bounds, including suspend or loss of continuity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockEvidence {
    /// No security-time assertion can be made.
    Unknown,
    /// Bounds in Unix seconds and monotonic elapsed seconds in one continuity domain.
    Bounded {
        earliest_unix: u64,
        latest_unix: u64,
        monotonic_seconds: u64,
        continuity: [u8; 16],
    },
}

impl ClockEvidence {
    fn parts(self) -> Result<(u64, u64, u64, [u8; 16]), Denial> {
        match self {
            Self::Bounded {
                earliest_unix,
                latest_unix,
                monotonic_seconds,
                continuity,
            } if earliest_unix <= latest_unix => {
                Ok((earliest_unix, latest_unix, monotonic_seconds, continuity))
            }
            Self::Unknown | Self::Bounded { .. } => Err(OfflineRefusal::ClockUncertain.into()),
        }
    }

    pub(super) fn follows(self, previous: Self) -> Result<(), Denial> {
        let (earliest, latest, monotonic, continuity) = self.parts()?;
        let (old_earliest, old_latest, old_monotonic, old_continuity) = previous.parts()?;
        if continuity != old_continuity {
            return Err(OfflineRefusal::ClockUncertain.into());
        }
        if earliest < old_earliest || latest < old_latest || monotonic < old_monotonic {
            return Err(OfflineRefusal::ClockRegression.into());
        }
        Ok(())
    }
}

/// Explicit host/organization ceilings; no inferred deployment defaults.
#[derive(Debug, Clone, Copy)]
pub struct OfflineCeilings {
    pub lease_seconds: u64,
    pub restarts: u32,
    pub connection_attempts: u32,
}

/// Expected identity and current policy floor from the trusted admission owner.
#[derive(Debug)]
pub struct AuthorityExpectation<'a> {
    pub issuer: &'a str,
    pub node_id: &'a str,
    pub workload_id: &'a str,
    pub package_digest: [u8; 32],
    pub min_policy_version: u64,
    pub node_state: NodeState,
}

/// Unverified records and independently supplied verification requirements.
#[derive(Debug)]
pub struct AuthorityInput<'a> {
    pub lease: Option<&'a SignedLease>,
    pub policy: Option<&'a SignedHostPolicy>,
    pub companion: Option<&'a SignedRecoveryPolicy>,
    pub lease_issuers: &'a [(String, VerifyingKey)],
    pub policy_issuers: &'a [(String, VerifyingKey)],
    pub expected: AuthorityExpectation<'a>,
    pub ceilings: OfflineCeilings,
}

/// Immutable verified bounds; possession is not admission or durable restart history.
#[derive(Debug)]
pub struct VerifiedOfflineAuthority {
    id: [u8; 32],
    policy: RecoveryPolicy,
    lease: OfflineLease,
    expiry: u64,
    deadline: u64,
    clock: ClockEvidence,
}

fn unique_key<'a>(
    trusted: &'a [(String, VerifyingKey)],
    issuer: &str,
) -> Result<&'a VerifyingKey, Denial> {
    let mut matches = trusted.iter().filter(|(id, _)| id == issuer);
    let key = matches.next().ok_or(OfflineRefusal::Issuer)?;
    if matches.next().is_some() {
        return Err(OfflineRefusal::Issuer.into());
    }
    Ok(&key.1)
}

impl VerifiedOfflineAuthority {
    /// Verify exact signed bindings and derive a single conservative deadline.
    ///
    /// # Errors
    /// Refuses missing, tampered, mismatched, unsupported, expired or unbounded
    /// authority, inactive nodes, ambiguous time and arithmetic overflow.
    pub fn verify(input: AuthorityInput<'_>, now: ClockEvidence) -> Result<Self, Denial> {
        let lease = input.lease.ok_or(OfflineRefusal::AuthorityMissing)?;
        let policy = input.policy.ok_or(OfflineRefusal::AuthorityMissing)?;
        let companion = input.companion.ok_or(OfflineRefusal::AuthorityMissing)?;
        let body = &companion.policy;
        let expected = &input.expected;
        if body.version != 1 {
            return Err(OfflineRefusal::Version.into());
        }
        if expected.issuer.is_empty()
            || body.issuer != expected.issuer
            || lease.issuer != body.issuer
        {
            return Err(OfflineRefusal::Issuer.into());
        }
        let key = unique_key(input.lease_issuers, &body.issuer)?;
        unique_key(input.policy_issuers, &policy.issuer)?;
        let signature =
            Signature::from_slice(&companion.signature).map_err(|_| OfflineRefusal::Signature)?;
        let bytes = companion_bytes(body).map_err(|_| OfflineRefusal::Signature)?;
        key.verify_strict(&bytes, &signature)
            .map_err(|_| OfflineRefusal::Signature)?;
        if body.lease_digest != signed_record_digest(lease).map_err(|_| OfflineRefusal::Binding)?
            || body.policy_digest
                != signed_record_digest(policy).map_err(|_| OfflineRefusal::Binding)?
            || body.workload_id.is_empty()
            || body.workload_id != expected.workload_id
            || body.package_digest != expected.package_digest
        {
            return Err(OfflineRefusal::Binding.into());
        }
        if expected.node_state != NodeState::Active {
            return Err(Denial::NodeNotActive(expected.node_state.label()));
        }
        let (earliest, latest, monotonic, _) = now.parts()?;
        // Existing verifiers retain their exact signed-byte meanings.
        let lease = lease.clone().verify(
            input.lease_issuers,
            expected.node_id,
            latest,
            expected.min_policy_version,
        )?;
        let policy =
            policy
                .clone()
                .verify(input.policy_issuers, latest, expected.min_policy_version)?;
        policy.check_launch_scope(expected.node_id, latest)?;
        if lease.policy_version != policy.version {
            return Err(OfflineRefusal::Binding.into());
        }
        let duration = lease
            .not_after
            .checked_sub(lease.issued_at)
            .ok_or(OfflineRefusal::Bounds)?;
        if duration == 0 || duration > input.ceilings.lease_seconds || earliest < lease.issued_at {
            return Err(OfflineRefusal::Bounds.into());
        }
        if lease.allowed.contains(&LeaseOp::Mailbox) || lease.max_queued_messages != 0 {
            return Err(Denial::LeaseOpNotAllowed("mailbox"));
        }
        body.restart.validate(input.ceilings.restarts)?;
        if body.connection_attempts == 0
            || body.connection_attempts > input.ceilings.connection_attempts
        {
            return Err(OfflineRefusal::Bounds.into());
        }
        let expiry = policy
            .not_after
            .map_or(lease.not_after, |t| t.min(lease.not_after));
        let remaining = expiry
            .checked_sub(latest)
            .filter(|n| *n > 0)
            .ok_or(Denial::LeaseExpired)?;
        let deadline = monotonic
            .checked_add(remaining)
            .ok_or(OfflineRefusal::Bounds)?;
        Ok(Self {
            id: signed_record_digest(companion).map_err(|_| OfflineRefusal::Binding)?,
            policy: body.clone(),
            lease,
            expiry,
            deadline,
            clock: now,
        })
    }

    /// Check only offline permission, never actual effect admission.
    ///
    /// # Errors
    /// Refuses uncertain time, expiry or an operation absent from the bound lease.
    pub(super) fn permits(&self, op: LeaseOp, now: ClockEvidence) -> Result<(), Denial> {
        self.check_time(now)?;
        let (_, latest, _, _) = now.parts()?;
        self.lease.permits(op, latest)
    }

    pub(super) fn check_time(&self, now: ClockEvidence) -> Result<(), Denial> {
        now.follows(self.clock)?;
        let (_, latest, monotonic, _) = now.parts()?;
        if latest >= self.expiry || monotonic >= self.deadline {
            return Err(Denial::LeaseExpired);
        }
        Ok(())
    }

    /// Monotonic deadline in the original clock continuity domain.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }
    /// Effective absolute expiry, never later than the original lease.
    pub fn expiry(&self) -> u64 {
        self.expiry
    }
    /// Original absolute signed lease expiry, retained for durable history.
    pub fn lease_expiry(&self) -> u64 {
        self.lease.not_after
    }
    /// Distinct connection retry allowance; does not replenish restart allowance.
    pub fn connection_attempts(&self) -> u32 {
        self.policy.connection_attempts
    }
    /// Exact companion identity required by recovery history.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    pub(super) fn policy(&self) -> &RecoveryPolicy {
        &self.policy
    }
    pub(super) fn clock(&self) -> ClockEvidence {
        self.clock
    }
}
