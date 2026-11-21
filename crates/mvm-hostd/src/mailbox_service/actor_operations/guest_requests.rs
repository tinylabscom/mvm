//! The guest's requests to the actor conversation endpoint: receiving a
//! peer's call, replying to it, receiving a call's result and acknowledging a
//! delivery.

use super::*;

impl super::ActorConversationEndpoint {
    pub(super) fn receive_request(
        &mut self,
        authority: &CurrentBootAuthority,
    ) -> Result<ConversationResponse> {
        for index in 0..self.state.records.len() {
            let record = &self.state.records[index];
            if record.direction != Direction::Inbound || record.acknowledged {
                continue;
            }
            let peer = self.peer(record.peer)?;
            self.initialize_call(index, &peer)?;
            let record = &self.state.records[index];
            let context = self.context(
                &peer.call.header,
                authority.capability(),
                self.now()?,
                MailboxOperation::Receive,
            );
            let (mut journal, anchor) = self.journal(index)?;
            let payload_key = peer.call_key();
            let sender = key(peer.parent_sender_key)?;
            let signer = self.material.authority_key();
            let leased = journal
                .lease_next(
                    JournalGuestLease {
                        receive: JournalReceive {
                            capability: authority.capability(),
                            context: &context,
                            encryption_key: &payload_key,
                            sender_key: &sender,
                        },
                        plan: authority.grant(),
                        scope: reader_scope(authority, &context),
                        enrollment: authority.enrollment(),
                        challenge: authority.challenge(),
                        possession_signature: authority.possession_signature(),
                        signer: &signer,
                    },
                    |tip| anchor.advance(tip),
                )
                .map_err(storage)?;
            let Some(leased) = leased else {
                continue;
            };
            if leased.lease().lease.message_id != record.header.message_id {
                return Err(Refusal::Unavailable);
            }
            let response = ConversationResponse::Delivery {
                header: Box::new(record.header.clone()),
                payload: leased.payload().to_vec(),
                lease: Box::new(leased.lease().clone()),
            };
            let mut next = self.state.clone();
            next.records[index].delivery = Some(leased.lease().clone());
            self.commit(next)?;
            return Ok(response);
        }
        Ok(ConversationResponse::Pending)
    }

    pub(super) fn queue_reply(
        &mut self,
        boot: BootId,
        request: ReplyRequest<'_>,
    ) -> Result<ConversationResponse> {
        let index = self
            .state
            .records
            .iter()
            .position(|record| {
                record.direction == Direction::Inbound
                    && record.header.message_id == request.request_message_id
            })
            .ok_or(Refusal::NotAuthorized)?;
        let record = &self.state.records[index];
        if record.delivery.is_none() {
            return Err(Refusal::NotAuthorized);
        }
        if request.payload.len() > record.reply_capability.grant.max_payload_bytes as usize {
            return Err(Refusal::Oversized(
                record.reply_capability.grant.max_payload_bytes as usize,
            ));
        }
        let peer = self.peer(record.peer)?;
        let now = self.now()?;
        let context = self.context(
            &peer.reply_header,
            &record.reply_capability,
            now,
            MailboxOperation::Reply,
        );
        if let Some(envelope) = &record.reply {
            let opened = mvm_core::mailbox::open_authenticated_envelope(
                envelope,
                &record.reply_capability,
                &context,
                &peer.reply_key(),
                &self.material.sender_key().verifying_key(),
                &key(peer.parent_authority_key)?,
                &mut InMemoryReplayProtector::default(),
            )
            .map_err(|_| Refusal::NotAuthorized)?;
            if opened.header().message_id != request.message_id
                || opened.header().content_type != *request.content_type
                || opened.payload() != request.payload
            {
                return Err(Refusal::NotAuthorized);
            }
            return Ok(ConversationResponse::Queued {
                call_message_id: request.request_message_id,
            });
        }
        if request.message_id.as_bytes() == &[0; 32]
            || self.state.records.iter().any(|record| {
                record.header.message_id == request.message_id
                    || record
                        .reply_header
                        .as_ref()
                        .is_some_and(|header| header.message_id == request.message_id)
            })
        {
            return Err(Refusal::NotAuthorized);
        }
        let mut header = peer.reply_header.clone();
        header.sender_boot = boot;
        header.message_id = request.message_id;
        header.correlation_id = record.header.correlation_id;
        header.causation_id = CausationId::from_bytes(*record.header.message_id.as_bytes());
        header.capability_id = record.reply_capability.grant.capability_id;
        header.issued_at_unix_ms = now;
        header.expires_at_unix_ms = record.reply_capability.grant.expires_at_unix_ms;
        header.sequence = record.header.sequence;
        header.nonce = ReplayNonce::from_bytes(rand::random());
        header.content_type = request.content_type.clone();
        header.plaintext_len = request.payload.len().try_into().map_err(|_| {
            Refusal::Oversized(record.reply_capability.grant.max_payload_bytes as usize)
        })?;
        let mut routing = peer.reply_routing.clone();
        routing.expires_at_unix_ms = header.expires_at_unix_ms;
        routing.delivery_id = DeliveryId::from_bytes(rand::random());
        let envelope = mvm_core::mailbox::seal_envelope(
            SealRequest {
                routing,
                header: header.clone(),
                plaintext: request.payload,
            },
            &peer.reply_key(),
            &self.material.sender_key(),
        )
        .map_err(|_| Refusal::NotAuthorized)?;
        mvm_core::mailbox::open_authenticated_envelope(
            &envelope,
            &record.reply_capability,
            &context,
            &peer.reply_key(),
            &self.material.sender_key().verifying_key(),
            &key(peer.parent_authority_key)?,
            &mut InMemoryReplayProtector::default(),
        )
        .map_err(|_| Refusal::NotAuthorized)?;
        let mut next = self.state.clone();
        self.charge_message(&mut next, now)?;
        next.records[index].reply = Some(envelope);
        next.records[index].reply_header = Some(header);
        self.commit(next)?;
        Ok(ConversationResponse::Queued {
            call_message_id: request.request_message_id,
        })
    }

    pub(super) fn receive_result(
        &mut self,
        authority: &CurrentBootAuthority,
        id: MessageId,
    ) -> Result<ConversationResponse> {
        let index = self
            .state
            .records
            .iter()
            .position(|record| {
                record.direction == Direction::Outbound && record.header.message_id == id
            })
            .ok_or(Refusal::NotAuthorized)?;
        let record = &self.state.records[index];
        let peer = self.peer(record.peer)?;
        let context = self.context(
            &peer.reply_header,
            authority.capability(),
            self.now()?,
            MailboxOperation::Receive,
        );
        let mut conversation = self.conversation(index, &peer)?;
        let identity = ReplayIdentity::from_header(&record.header);
        match conversation
            .receive_result(identity, authority.capability(), &context)
            .map_err(storage)?
        {
            CallResult::Pending => Ok(ConversationResponse::Pending),
            CallResult::TimedOut => Ok(ConversationResponse::TimedOut),
            CallResult::Settled => Ok(ConversationResponse::Settled),
            CallResult::Reply(opened) => {
                let payload_key = peer.reply_key();
                let sender = key(peer.child_sender_key)?;
                let signer = self.material.authority_key();
                let leased = conversation
                    .lease_result(
                        identity,
                        JournalGuestLease {
                            receive: JournalReceive {
                                capability: authority.capability(),
                                context: &context,
                                encryption_key: &payload_key,
                                sender_key: &sender,
                            },
                            plan: authority.grant(),
                            scope: reader_scope(authority, &context),
                            enrollment: authority.enrollment(),
                            challenge: authority.challenge(),
                            possession_signature: authority.possession_signature(),
                            signer: &signer,
                        },
                    )
                    .map_err(storage)?
                    .ok_or(Refusal::Unavailable)?;
                if leased.lease().lease.message_id != opened.header().message_id {
                    return Err(Refusal::Unavailable);
                }
                let response = ConversationResponse::Delivery {
                    header: Box::new(opened.header().clone()),
                    payload: leased.payload().to_vec(),
                    lease: Box::new(leased.lease().clone()),
                };
                let mut next = self.state.clone();
                next.records[index].delivery = Some(leased.lease().clone());
                self.commit(next)?;
                Ok(response)
            }
        }
    }

    pub(super) fn acknowledge(
        &mut self,
        authority: &CurrentBootAuthority,
        request: AckRequest<'_>,
    ) -> Result<ConversationResponse> {
        let signed = request.signed.ok_or(Refusal::NotAuthorized)?;
        let index = self
            .state
            .records
            .iter()
            .position(|record| {
                record.direction == request.direction && record.header.message_id == request.call_id
            })
            .ok_or(Refusal::NotAuthorized)?;
        let record = &self.state.records[index];
        if record.delivery.as_ref() != Some(request.lease)
            || signed.ack.lease != *request.lease
            || request.lease.lease.message_id != request.delivered_id
        {
            return Err(Refusal::NotAuthorized);
        }
        let peer = self.peer(record.peer)?;
        let header = if request.direction == Direction::Outbound {
            &peer.reply_header
        } else {
            &peer.call.header
        };
        let context = self.context(
            header,
            authority.capability(),
            self.now()?,
            MailboxOperation::Receive,
        );
        let payload_key = if request.direction == Direction::Outbound {
            peer.reply_key()
        } else {
            peer.call_key()
        };
        let sender = key(if request.direction == Direction::Outbound {
            peer.child_sender_key
        } else {
            peer.parent_sender_key
        })?;
        let ack = JournalGuestAck {
            receive: JournalReceive {
                capability: authority.capability(),
                context: &context,
                encryption_key: &payload_key,
                sender_key: &sender,
            },
            plan: authority.grant(),
            scope: reader_scope(authority, &context),
            enrollment: authority.enrollment(),
            signed,
        };
        if request.direction == Direction::Outbound {
            let mut conversation = self.conversation(index, &peer)?;
            conversation
                .acknowledge_result_signed(ReplayIdentity::from_header(&record.header), ack)
                .map_err(storage)?;
        } else {
            let (mut journal, anchor) = self.journal(index)?;
            journal
                .acknowledge_signed(ack, |tip| anchor.advance(tip))
                .map_err(storage)?;
        }
        let mut next = self.state.clone();
        next.records[index].acknowledged = true;
        self.commit(next)?;
        Ok(ConversationResponse::Acknowledged)
    }
}

pub(super) struct ReplyRequest<'a> {
    pub(super) request_message_id: MessageId,
    pub(super) message_id: MessageId,
    pub(super) content_type: &'a ContentType,
    pub(super) payload: &'a [u8],
}

pub(super) struct AckRequest<'a> {
    pub(super) direction: Direction,
    pub(super) call_id: MessageId,
    pub(super) delivered_id: MessageId,
    pub(super) lease: &'a SignedMailboxDeliveryLease,
    pub(super) signed: Option<&'a SignedMailboxDeliveryAck>,
}
