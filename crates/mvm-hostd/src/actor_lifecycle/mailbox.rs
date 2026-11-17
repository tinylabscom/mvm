//! Required host mailbox custody, shared by plan attenuation and live serving.

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use mvm_contract::plan::ExecutionPlan;
use mvm_contract::protocol::mailbox::{MailboxAddress, MailboxGrant, SignedMailboxCapability};
use serde::{Deserialize, Serialize};

use crate::actor_authority::MailboxDerivation;

/// Exact mailbox authority installed for this child, retained in encrypted history.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedChildMailbox {
    pub grant: MailboxGrant,
    pub address: MailboxAddress,
    pub parent_capability: SignedMailboxCapability,
    pub child_capability: SignedMailboxCapability,
    pub parent_issuer_key: [u8; 32],
    pub child_issuer_key: [u8; 32],
}

impl DerivedChildMailbox {
    pub(super) fn validate(
        &self,
        validate: impl FnOnce(MailboxDerivation<'_>) -> Result<()>,
    ) -> Result<()> {
        anyhow::ensure!(
            self.address.mailbox == self.grant.mailbox,
            "child mailbox identity mismatch"
        );
        anyhow::ensure!(
            self.address == self.child_capability.grant.address,
            "child mailbox capability mismatch"
        );
        let parent_key = VerifyingKey::from_bytes(&self.parent_issuer_key)?;
        let child_key = VerifyingKey::from_bytes(&self.child_issuer_key)?;
        validate(MailboxDerivation {
            child_grant: &self.grant,
            parent_capability: &self.parent_capability,
            child_capability: &self.child_capability,
            parent_issuer_key: &parent_key,
            child_issuer_key: &child_key,
        })
    }
}

/// Trusted mailbox owner, not a guest hook or a proof-only capability factory.
///
/// Implementations must install these exact bindings in the ordinary mailbox
/// owner. Derivation runs only after transactional capacity is reserved. No
/// implementation may acknowledge cleanup while retained resources remain.
pub trait ActorMailboxes: Send + Sync {
    fn derive(&self, parent: &ExecutionPlan, child: &ExecutionPlan) -> Result<DerivedChildMailbox>;
    fn verify_current(&self, parent: &ExecutionPlan, child: &DerivedChildMailbox) -> Result<()>;
    fn reap(&self, child: &DerivedChildMailbox) -> Result<()>;
    /// Reconcile only the deterministic endpoint/pair of an interrupted preparation.
    /// No endpoint may be installed or launch retried by this operation.
    fn reap_attempt(&self, parent: &ExecutionPlan, child: &ExecutionPlan) -> Result<()>;
}
