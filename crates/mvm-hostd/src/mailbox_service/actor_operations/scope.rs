//! Scoped request helpers for the actor conversation endpoint: reader scope
//! construction, envelope addressing, the per-call mailbox open context, and
//! the history-key custody the retained journal uses.

use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    MailboxAddress, MailboxEnvelopeHeader, MailboxGuestReaderScope, MailboxOperation,
    SignedMailboxCapability,
};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::OpenContext;
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::journal::{HistoryKeyCustody, HistoryKeyRef, JournalError};

use super::super::MailboxPolicy;

use std::result::Result as StdResult;
type Result<T> = StdResult<T, Refusal>;
use super::super::durable::CurrentBootAuthority;
use crate::mailbox_launch::actor_template::ActorPeerBinding;

pub(super) fn reader_scope<'a>(
    authority: &'a CurrentBootAuthority,
    context: &OpenContext,
) -> MailboxGuestReaderScope<'a> {
    MailboxGuestReaderScope {
        plan: authority.grant(),
        plan_id: &authority.binding().reader.plan_id,
        plan_nonce: &authority.binding().reader.plan_nonce,
        receive: &authority.capability().grant,
        current_boot: authority.binding().reader.boot,
        current_session: authority.enrollment().enrollment.consumer_session,
        now_unix_ms: context.now_unix_ms,
    }
}

pub(super) fn address(header: &MailboxEnvelopeHeader) -> MailboxAddress {
    MailboxAddress {
        tenant: header.tenant,
        authorization_domain: header.authorization_domain,
        mailbox: header.mailbox,
        recipient: header.recipient,
    }
}

pub(super) struct ScopedHistory {
    pub(super) reference: HistoryKeyRef,
    pub(super) key: Key,
}
impl HistoryKeyCustody for ScopedHistory {
    fn load_existing(&self, reference: &HistoryKeyRef) -> std::result::Result<Key, JournalError> {
        if reference != &self.reference {
            return Err(JournalError::HistoryKeyMismatch);
        }
        Ok(Key::from_bytes(*self.key.expose_bytes()))
    }
}

pub(super) fn storage(_: impl std::fmt::Display) -> Refusal {
    Refusal::Unavailable
}
pub(super) fn key(bytes: [u8; 32]) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(&bytes).map_err(|_| Refusal::NotAuthorized)
}

impl super::ActorConversationEndpoint {
    /// The open context for one request. Its current epoch is this unit's,
    /// read from the epoch gate when the endpoint bound, never the header's.
    pub(super) fn context(
        &self,
        header: &MailboxEnvelopeHeader,
        capability: &SignedMailboxCapability,
        now: i64,
        operation: MailboxOperation,
    ) -> OpenContext {
        OpenContext {
            expected_tenant: header.tenant,
            expected_authorization_domain: header.authorization_domain,
            expected_mailbox: header.mailbox,
            expected_sender: header.sender,
            expected_recipient: header.recipient,
            acting_principal: if operation == MailboxOperation::Receive {
                header.recipient
            } else {
                header.sender
            },
            expected_capability_issuer: capability.grant.issuer,
            current_execution_epoch: self.config.current_epoch,
            current_policy_epoch: header.policy_epoch,
            required_operation: operation,
            now_unix_ms: now,
            accepted_content_types: capability.grant.content_types.clone(),
            revoked_capabilities: vec![],
        }
    }

    pub(super) fn call_policy(&self, peer: &ActorPeerBinding, now: i64) -> Result<MailboxPolicy> {
        Ok(MailboxPolicy {
            context: self.context(
                &peer.call.header,
                &peer.send_capability,
                now,
                MailboxOperation::Send,
            ),
            encryption_key: peer.call_key(),
            sender_key: key(peer.parent_sender_key)?,
            authority_key: key(peer.child_authority_key)?,
        })
    }
}
