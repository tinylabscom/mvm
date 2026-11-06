//! Disconnected operation and reconnect.
//!
//! A node without its control plane may act only under a signed, preloaded
//! [`OfflineLease`] that names the operations it allows and when it ends.
//! Reachability never restores authorization by itself: after a reconnect the
//! node stays denied until [`Reconnect::complete`] has seen a fresh answer to a
//! fresh challenge, a node that is still `Active`, and a policy no older than
//! the floor. [`CommandGate`] rejects replayed, reordered and wrong-epoch
//! commands from either side of the partition.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{ExecutionEpoch, NodeState, error::Denial};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseOp {
    LocalLaunch,
    Mailbox,
    Egress,
    SecretUse,
}

impl LeaseOp {
    fn name(self) -> &'static str {
        match self {
            Self::LocalLaunch => "local_launch",
            Self::Mailbox => "mailbox",
            Self::Egress => "egress",
            Self::SecretUse => "secret_use",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineLease {
    pub node_id: String,
    pub policy_version: u64,
    /// Unix seconds.
    pub issued_at: u64,
    pub not_after: u64,
    pub allowed: Vec<LeaseOp>,
    /// Bound on messages queued while disconnected; reconciled on reconnect.
    pub max_queued_messages: u32,
}

impl OfflineLease {
    /// Is `op` allowed right now? An expired lease allows nothing.
    pub fn permits(&self, op: LeaseOp, now: u64) -> Result<(), Denial> {
        if now >= self.not_after {
            return Err(Denial::LeaseExpired);
        }
        if self.allowed.contains(&op) {
            Ok(())
        } else {
            Err(Denial::LeaseOpNotAllowed(op.name()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLease {
    pub lease: OfflineLease,
    pub issuer: String,
    pub signature: Vec<u8>,
}

impl SignedLease {
    pub fn sign(
        lease: OfflineLease,
        issuer: &str,
        key: &SigningKey,
    ) -> Result<Self, serde_json::Error> {
        let bytes = serde_jcs::to_vec(&lease)?;
        Ok(Self {
            lease,
            issuer: issuer.to_owned(),
            signature: key.sign(&bytes).to_bytes().to_vec(),
        })
    }

    /// Accept the lease only if a trusted issuer signed it for this node and
    /// it is currently valid and not older than `min_policy_version`.
    pub fn verify(
        self,
        trusted: &[(String, VerifyingKey)],
        node_id: &str,
        now: u64,
        min_policy_version: u64,
    ) -> Result<OfflineLease, Denial> {
        let (_, key) = trusted
            .iter()
            .find(|(id, _)| *id == self.issuer)
            .ok_or(Denial::LeaseInvalid("issuer not trusted"))?;
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| Denial::LeaseInvalid("malformed signature"))?;
        let bytes = serde_jcs::to_vec(&self.lease)
            .map_err(|_| Denial::LeaseInvalid("not canonicalizable"))?;
        key.verify_strict(&bytes, &sig)
            .map_err(|_| Denial::LeaseInvalid("signature does not verify"))?;
        let l = self.lease;
        if l.node_id != node_id {
            return Err(Denial::LeaseInvalid("issued to another node"));
        }
        if now >= l.not_after {
            return Err(Denial::LeaseExpired);
        }
        if now < l.issued_at {
            return Err(Denial::LeaseInvalid("not yet valid"));
        }
        if l.policy_version < min_policy_version {
            return Err(Denial::PolicyRollback {
                got: l.policy_version,
                min: min_policy_version,
            });
        }
        Ok(l)
    }
}

/// Accepts a command only if it carries the current epoch and a sequence
/// number strictly greater than every one accepted before.
#[derive(Debug, Clone)]
pub struct CommandGate {
    epoch: ExecutionEpoch,
    last_seq: u64,
}

impl CommandGate {
    pub fn new(epoch: ExecutionEpoch) -> Self {
        Self { epoch, last_seq: 0 }
    }

    pub fn accept(&mut self, epoch: ExecutionEpoch, seq: u64) -> Result<(), Denial> {
        if epoch != self.epoch {
            return Err(Denial::StaleEpoch {
                got: epoch.0,
                current: self.epoch.0,
            });
        }
        if seq <= self.last_seq {
            return Err(Denial::ReplayedCommand {
                got: seq,
                last: self.last_seq,
            });
        }
        self.last_seq = seq;
        Ok(())
    }
}

const RECONNECT_DOMAIN: &[u8] = b"mvm-reconnect-v1";

fn challenge_bytes(nonce: &[u8; 32]) -> Vec<u8> {
    [RECONNECT_DOMAIN, nonce.as_slice()].concat()
}

/// What the node signs to answer a reconnect challenge.
pub fn answer_challenge(key: &SigningKey, nonce: &[u8; 32]) -> Vec<u8> {
    key.sign(&challenge_bytes(nonce)).to_bytes().to_vec()
}

#[derive(Debug)]
enum Phase {
    AwaitingAuth([u8; 32]),
    Authorized,
}

/// Reconnect gate: denied until a fresh challenge has been answered.
#[derive(Debug)]
pub struct Reconnect(Phase);

impl Reconnect {
    /// Begin a reconnect with a random 32-byte challenge.
    pub fn begin() -> (Self, [u8; 32]) {
        use rand::Rng;
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        (Self::begin_with(nonce), nonce)
    }

    pub fn begin_with(nonce: [u8; 32]) -> Self {
        Self(Phase::AwaitingAuth(nonce))
    }

    pub fn is_authorized(&self) -> bool {
        matches!(self.0, Phase::Authorized)
    }

    /// Authorization returns only if the answer verifies under the node key
    /// for exactly this challenge, the node is `Active`, and the policy is not
    /// older than `min_policy_version`. The challenge is spent on success, so
    /// the same answer cannot be replayed into a later reconnect.
    pub fn complete(
        &mut self,
        node_key: &VerifyingKey,
        answer: &[u8],
        node_state: NodeState,
        policy_version: u64,
        min_policy_version: u64,
    ) -> Result<(), Denial> {
        let Phase::AwaitingAuth(nonce) = &self.0 else {
            return Err(Denial::ReauthRequired);
        };
        let sig = Signature::from_slice(answer).map_err(|_| Denial::ReauthRequired)?;
        node_key
            .verify(&challenge_bytes(nonce), &sig)
            .map_err(|_| Denial::ReauthRequired)?;
        if node_state != NodeState::Active {
            return Err(Denial::NodeNotActive(node_state.label()));
        }
        if policy_version < min_policy_version {
            return Err(Denial::PolicyRollback {
                got: policy_version,
                min: min_policy_version,
            });
        }
        self.0 = Phase::Authorized;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn trusted(k: &SigningKey) -> Vec<(String, VerifyingKey)> {
        vec![("ops".into(), k.verifying_key())]
    }
    fn lease() -> OfflineLease {
        OfflineLease {
            node_id: "ship".into(),
            policy_version: 4,
            issued_at: 100,
            not_after: 200,
            allowed: vec![LeaseOp::LocalLaunch, LeaseOp::Mailbox],
            max_queued_messages: 64,
        }
    }
    fn signed(k: &SigningKey) -> SignedLease {
        SignedLease::sign(lease(), "ops", k).unwrap()
    }

    #[test]
    fn a_valid_lease_permits_only_its_listed_operations() {
        let k = key(1);
        let l = signed(&k).verify(&trusted(&k), "ship", 150, 1).unwrap();
        assert!(l.permits(LeaseOp::LocalLaunch, 150).is_ok());
        assert_eq!(
            l.permits(LeaseOp::Egress, 150),
            Err(Denial::LeaseOpNotAllowed("egress"))
        );
        assert_eq!(
            l.permits(LeaseOp::SecretUse, 150),
            Err(Denial::LeaseOpNotAllowed("secret_use"))
        );
    }

    #[test]
    fn expiry_fails_closed_at_verify_and_at_use() {
        let k = key(1);
        assert_eq!(
            signed(&k).verify(&trusted(&k), "ship", 200, 1),
            Err(Denial::LeaseExpired)
        );
        let l = signed(&k).verify(&trusted(&k), "ship", 199, 1).unwrap();
        assert_eq!(
            l.permits(LeaseOp::LocalLaunch, 200),
            Err(Denial::LeaseExpired)
        );
    }

    #[test]
    fn tampered_wrong_key_wrong_node_early_and_rolled_back_leases_are_refused() {
        let k = key(1);
        let mut t = signed(&k);
        t.lease.not_after = 9_999;
        assert!(matches!(
            t.verify(&trusted(&k), "ship", 150, 1),
            Err(Denial::LeaseInvalid(_))
        ));
        assert!(matches!(
            signed(&key(2)).verify(&trusted(&k), "ship", 150, 1),
            Err(Denial::LeaseInvalid(_))
        ));
        assert_eq!(
            signed(&k).verify(&trusted(&k), "aircraft", 150, 1),
            Err(Denial::LeaseInvalid("issued to another node"))
        );
        assert_eq!(
            signed(&k).verify(&trusted(&k), "ship", 50, 1),
            Err(Denial::LeaseInvalid("not yet valid"))
        );
        assert_eq!(
            signed(&k).verify(&trusted(&k), "ship", 150, 9),
            Err(Denial::PolicyRollback { got: 4, min: 9 })
        );
    }

    #[test]
    fn the_command_gate_rejects_replay_reorder_and_stale_epochs() {
        let mut g = CommandGate::new(ExecutionEpoch(2));
        assert!(g.accept(ExecutionEpoch(2), 1).is_ok());
        assert!(g.accept(ExecutionEpoch(2), 3).is_ok());
        assert_eq!(
            g.accept(ExecutionEpoch(2), 3),
            Err(Denial::ReplayedCommand { got: 3, last: 3 })
        );
        assert_eq!(
            g.accept(ExecutionEpoch(2), 2),
            Err(Denial::ReplayedCommand { got: 2, last: 3 })
        );
        assert_eq!(
            g.accept(ExecutionEpoch(1), 9),
            Err(Denial::StaleEpoch { got: 1, current: 2 })
        );
    }

    #[test]
    fn reconnect_stays_denied_until_a_fresh_challenge_is_answered() {
        let node = key(5);
        let (mut r, nonce) = Reconnect::begin();
        assert!(!r.is_authorized(), "reachability alone authorizes nothing");
        let answer = answer_challenge(&node, &nonce);
        r.complete(&node.verifying_key(), &answer, NodeState::Active, 5, 4)
            .unwrap();
        assert!(r.is_authorized());
    }

    #[test]
    fn a_replayed_answer_to_an_old_challenge_does_not_authorize() {
        let node = key(5);
        let old = answer_challenge(&node, &[1; 32]);
        let mut r = Reconnect::begin_with([2; 32]);
        assert_eq!(
            r.complete(&node.verifying_key(), &old, NodeState::Active, 5, 4),
            Err(Denial::ReauthRequired)
        );
        assert!(!r.is_authorized());
    }

    #[test]
    fn a_wrong_key_a_revoked_node_and_an_old_policy_do_not_authorize() {
        let node = key(5);
        let nonce = [3; 32];
        let ans = answer_challenge(&node, &nonce);
        let attempt =
            |vk: &VerifyingKey, st, pv| Reconnect::begin_with(nonce).complete(vk, &ans, st, pv, 4);
        assert_eq!(
            attempt(&key(6).verifying_key(), NodeState::Active, 5),
            Err(Denial::ReauthRequired)
        );
        assert_eq!(
            attempt(&node.verifying_key(), NodeState::Revoked, 5),
            Err(Denial::NodeNotActive("revoked"))
        );
        assert_eq!(
            attempt(&node.verifying_key(), NodeState::Quarantined, 5),
            Err(Denial::NodeNotActive("quarantined"))
        );
        assert_eq!(
            attempt(&node.verifying_key(), NodeState::Active, 3),
            Err(Denial::PolicyRollback { got: 3, min: 4 })
        );
    }

    #[test]
    fn a_spent_challenge_cannot_be_completed_twice() {
        let node = key(5);
        let nonce = [4; 32];
        let ans = answer_challenge(&node, &nonce);
        let mut r = Reconnect::begin_with(nonce);
        r.complete(&node.verifying_key(), &ans, NodeState::Active, 5, 4)
            .unwrap();
        assert_eq!(
            r.complete(&node.verifying_key(), &ans, NodeState::Active, 5, 4),
            Err(Denial::ReauthRequired)
        );
    }

    #[test]
    fn lease_serde_rejects_unknown_fields() {
        assert!(serde_json::from_str::<OfflineLease>(
            r#"{"node_id":"n","policy_version":1,"issued_at":0,"not_after":1,"allowed":[],"max_queued_messages":0,"x":1}"#
        )
        .is_err());
    }
}
