//! Explicit guest-local Receive and ACK-after-processing over the existing
//! mailbox vsock port. The workload can read the socket, not the ACK key.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    DeliveryAckNonce, DeliveryLeaseNonce, MailboxDeliveryAck, MailboxGrant,
    MailboxGuestReaderScope, ProtocolVersion, SignatureAlgorithm, SignedMailboxDeliveryAck,
    SignedMailboxDeliveryLease,
};
use mvm_core::mailbox::MailboxError;
use mvm_core::mailbox::conversation_wire::{
    self, ConversationBinding, ConversationRequest, ConversationResponse, LocalRequest,
};
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::reader::{
    MailboxReaderBootBinding, sign_delivery_ack, sign_reader_possession,
    verify_delivery_lease_signature, verify_guest_reader_enrollment,
};
use mvm_core::mailbox::reader_wire::{
    ApplicationReaderRequest, GUEST_READER_SOCKET_PATH, ReaderRequest, ReaderResponse,
    read_response, write_request, write_response,
};
use zeroize::Zeroizing;

const LOCAL_TIMEOUT: Duration = Duration::from_secs(12);

enum ConversationRefusalStage {
    LocalBinding,
    Session,
    Enrollment,
    EnrollmentBinding,
    Destination,
    Challenge,
    EnrollmentNotYetValid,
    EnrollmentExpired,
}

fn report_conversation_refusal(stage: ConversationRefusalStage) {
    static REPORTED: AtomicU8 = AtomicU8::new(0);
    let (bit, label) = match stage {
        ConversationRefusalStage::LocalBinding => (1, "local-binding-absent"),
        ConversationRefusalStage::Session => (2, "authenticated-session"),
        ConversationRefusalStage::Enrollment => (4, "signed-reader-enrollment"),
        ConversationRefusalStage::EnrollmentBinding => (8, "enrollment-binding"),
        ConversationRefusalStage::Destination => (16, "destination-operation"),
        ConversationRefusalStage::Challenge => (32, "challenge-frame"),
        ConversationRefusalStage::EnrollmentNotYetValid => (64, "enrollment-not-yet-valid"),
        ConversationRefusalStage::EnrollmentExpired => (128, "enrollment-expired"),
    };
    if REPORTED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
        eprintln!("mvm-guest-agent: mailbox conversation refused at {label}");
    }
}

struct ActiveLease {
    lease: SignedMailboxDeliveryLease,
    ack: Option<SignedMailboxDeliveryAck>,
}

struct GuestReader {
    boot: MailboxReaderBootBinding,
    ack_seed: &'static Zeroizing<[u8; 32]>,
    active: Mutex<Option<ActiveLease>>,
    conversation: Option<ConversationBinding>,
    conversation_leases: Mutex<BTreeMap<DeliveryLeaseNonce, ActiveLease>>,
}

pub(crate) struct PendingReader {
    request: PendingOperation,
    reply: mpsc::SyncSender<LocalResponse>,
    reader: Arc<GuestReader>,
    deadline: Instant,
    caller: UnixStream,
    completed: UnixStream,
}

enum PendingOperation {
    Reader(ReaderRequest),
    Conversation(Box<ConversationRequest>),
}

#[derive(Debug, PartialEq, Eq)]
enum LocalResponse {
    Reader(ReaderResponse),
    Conversation(ConversationResponse),
}

fn now_unix_ms() -> Result<i64, Refusal> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Refusal::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| Refusal::Unavailable)
}

fn wait_for_clock(caller: &UnixStream, timeout: Duration) -> Result<(), Refusal> {
    let mut event = libc::pollfd {
        fd: caller.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = if timeout.is_zero() {
        0
    } else {
        timeout.as_millis().saturating_add(1)
    };
    let millis = libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX);
    // SAFETY: the descriptor remains borrowed from the live caller for this bounded poll.
    let count = unsafe { libc::poll(&mut event, 1, millis) };
    if count < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        return Err(Refusal::Unavailable);
    }
    if event.revents != 0 {
        return Err(Refusal::Unavailable);
    }
    Ok(())
}

/// Wait for authenticated issuance, never move the clock or accept authority early.
fn await_validity(
    caller: &UnixStream,
    deadline: Instant,
    issued_at_unix_ms: i64,
    mut verify: impl FnMut(i64) -> Result<(), MailboxError>,
) -> Result<(), Refusal> {
    use mvm_contract::protocol::mailbox::MailboxDeliveryError;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Refusal::Expired);
        }
        wait_for_clock(caller, Duration::ZERO)?;
        let now = now_unix_ms()?;
        match verify(now) {
            Ok(()) if Instant::now() < deadline => return Ok(()),
            Ok(()) => return Err(Refusal::Expired),
            Err(MailboxError::DeliveryContract(MailboxDeliveryError::NotYetValid))
                if now < issued_at_unix_ms =>
            {
                let until_issued = Duration::from_millis(
                    u64::try_from(issued_at_unix_ms.saturating_sub(now))
                        .map_err(|_| Refusal::NotAuthorized)?,
                );
                wait_for_clock(
                    caller,
                    until_issued.min(deadline.saturating_duration_since(Instant::now())),
                )?;
            }
            Err(MailboxError::DeliveryContract(MailboxDeliveryError::Expired)) => {
                return Err(Refusal::Expired);
            }
            Err(_) => return Err(Refusal::NotAuthorized),
        }
    }
}

/// Only start the local endpoint when the independently provisioned, root-only
/// boot key was captured by the agent. Send works without a reader.
pub(crate) fn start(
    boot: MailboxReaderBootBinding,
    ack_seed: &'static Zeroizing<[u8; 32]>,
    conversation: Option<ConversationBinding>,
) -> Option<mpsc::Receiver<PendingReader>> {
    let path = Path::new(GUEST_READER_SOCKET_PATH);
    let result = (|| {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
            Ok(_) => {
                return Err(std::io::Error::other(
                    "refusing to replace a non-socket guest reader path",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok::<_, std::io::Error>(listener)
    })();
    let listener = match result {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("mvm-guest-agent: mailbox reader socket unavailable: {error}");
            return None;
        }
    };
    let (tx, rx) = mpsc::sync_channel(1);
    let state = Arc::new(GuestReader {
        boot,
        ack_seed,
        active: Mutex::new(None),
        conversation,
        conversation_leases: Mutex::new(BTreeMap::new()),
    });
    std::thread::spawn(move || {
        serve_local_clients(listener.incoming(), tx, state);
    });
    Some(rx)
}

fn write_local_response(client: &mut UnixStream, response: LocalResponse) {
    match response {
        LocalResponse::Reader(response) => {
            let _ = write_response(client, &response);
        }
        LocalResponse::Conversation(response) => {
            let _ = conversation_wire::write_local_response(client, &response);
        }
    }
}

fn read_local_request(client: &mut UnixStream, deadline: Instant) -> Result<LocalRequest, Refusal> {
    conversation_wire::read_local_request(&mut crate::mailbox::MailboxDeadline::with_deadline(
        client, deadline,
    ))
}

/// One exchange worker; the listener refuses concurrent operations instead of hiding them in a backlog.
fn serve_local_clients(
    clients: impl Iterator<Item = std::io::Result<UnixStream>>,
    tx: mpsc::SyncSender<PendingReader>,
    state: Arc<GuestReader>,
) {
    let busy = Arc::new(AtomicBool::new(false));
    let (work, jobs) = mpsc::sync_channel::<UnixStream>(1);
    let worker_busy = Arc::clone(&busy);
    let worker = std::thread::spawn(move || {
        for mut client in jobs {
            let response = application_request(&mut client, &tx, &state)
                .unwrap_or_else(|reason| LocalResponse::Reader(ReaderResponse::Refused { reason }));
            write_local_response(&mut client, response);
            worker_busy.store(false, Ordering::Release);
            drop(client);
        }
    });
    for client in clients {
        let Ok(mut client) = client else { break };
        if client.set_read_timeout(Some(LOCAL_TIMEOUT)).is_err()
            || client.set_write_timeout(Some(LOCAL_TIMEOUT)).is_err()
        {
            continue;
        }
        if busy.swap(true, Ordering::AcqRel) {
            let response = match read_local_request(&mut client, Instant::now() + LOCAL_TIMEOUT) {
                Ok(LocalRequest::Conversation(_)) => {
                    LocalResponse::Conversation(ConversationResponse::Refused {
                        reason: Refusal::Unavailable,
                    })
                }
                _ => LocalResponse::Reader(ReaderResponse::Refused {
                    reason: Refusal::Unavailable,
                }),
            };
            write_local_response(&mut client, response);
        } else if work.send(client).is_err() {
            break;
        }
    }
    drop(work);
    let _ = worker.join();
}

fn application_request(
    stream: &mut UnixStream,
    tx: &mpsc::SyncSender<PendingReader>,
    reader: &Arc<GuestReader>,
) -> Result<LocalResponse, Refusal> {
    let received_at = Instant::now();
    let request = match read_local_request(stream, received_at + LOCAL_TIMEOUT)? {
        LocalRequest::Conversation(invocation) => {
            if reader.conversation.is_none() {
                report_conversation_refusal(ConversationRefusalStage::LocalBinding);
                return Ok(LocalResponse::Conversation(ConversationResponse::Refused {
                    reason: Refusal::NotAuthorized,
                }));
            }
            let deadline = invocation.deadline(received_at)?;
            return Ok(submit(
                PendingOperation::Conversation(Box::new(invocation.request)),
                tx,
                reader,
                stream,
                deadline,
            )
            .unwrap_or_else(|reason| {
                LocalResponse::Conversation(ConversationResponse::Refused { reason })
            }));
        }
        LocalRequest::Reader(_) if reader.conversation.is_some() => {
            return Ok(LocalResponse::Reader(ReaderResponse::Refused {
                reason: Refusal::NotAuthorized,
            }));
        }
        LocalRequest::Reader(request) => request,
    };
    let request = match request {
        ApplicationReaderRequest::Receive => ReaderRequest::Receive,
        ApplicationReaderRequest::Ack { lease } => {
            let mut active = reader.active.lock().expect("mailbox reader lock poisoned");
            let active = active.as_mut().ok_or(Refusal::NotAuthorized)?;
            if active.lease != *lease {
                return Err(Refusal::NotAuthorized);
            }
            let ack = if let Some(ack) = &active.ack {
                ack.clone()
            } else {
                verify_delivery_lease_signature(
                    &active.lease,
                    &VerifyingKey::from_bytes(&reader.boot.authority_key)
                        .map_err(|_| Refusal::NotAuthorized)?,
                )
                .map_err(|_| Refusal::NotAuthorized)?;
                let ack = sign_delivery_ack(
                    MailboxDeliveryAck {
                        protocol_version: ProtocolVersion::V1,
                        signature_algorithm: SignatureAlgorithm::ED25519,
                        lease: active.lease.clone(),
                        ack_nonce: DeliveryAckNonce::from_bytes(rand::random()),
                        acknowledged_at_unix_ms: now_unix_ms()?,
                    },
                    &SigningKey::from_bytes(reader.ack_seed),
                )
                .map_err(|_| Refusal::NotAuthorized)?;
                active.ack = Some(ack.clone());
                ack
            };
            ReaderRequest::Ack {
                signed: Box::new(ack),
            }
        }
    };
    submit(
        PendingOperation::Reader(request),
        tx,
        reader,
        stream,
        received_at + LOCAL_TIMEOUT,
    )
}

fn submit(
    request: PendingOperation,
    tx: &mpsc::SyncSender<PendingReader>,
    reader: &Arc<GuestReader>,
    caller: &UnixStream,
    deadline: Instant,
) -> Result<LocalResponse, Refusal> {
    let (reply, received) = mpsc::sync_channel(1);
    let (ready, completed) = UnixStream::pair().map_err(|_| Refusal::Unavailable)?;
    tx.try_send(PendingReader {
        request,
        reply,
        reader: reader.clone(),
        deadline,
        caller: caller.try_clone().map_err(|_| Refusal::Unavailable)?,
        completed,
    })
    .map_err(|_| Refusal::Unavailable)?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Refusal::Expired);
        }
        let mut events = [
            libc::pollfd {
                fd: ready.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: caller.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let millis = libc::c_int::try_from(remaining.as_millis().saturating_add(1))
            .unwrap_or(libc::c_int::MAX);
        // SAFETY: both UnixStream descriptors remain live throughout this bounded poll.
        let count = unsafe { libc::poll(events.as_mut_ptr(), 2, millis) };
        if count < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if count < 0 || events[1].revents != 0 {
            return Err(Refusal::Unavailable);
        }
        if events[0].revents != 0 {
            return received.try_recv().map_err(|_| Refusal::Unavailable);
        }
    }
}

/// The mailbox listener calls this only when an application operation is
/// pending; idle host dials continue to carry Send without an extra handshake.
pub(crate) fn exchange(
    stream: &mut (impl Read + Write + std::os::fd::AsRawFd),
    mut pending: PendingReader,
) -> Result<(), Refusal> {
    let response = match &pending.request {
        PendingOperation::Reader(request) => LocalResponse::Reader(
            perform_exchange(
                &mut crate::mailbox::MailboxDeadline::new(stream),
                &pending,
                request,
            )
            .unwrap_or_else(|reason| ReaderResponse::Refused { reason }),
        ),
        PendingOperation::Conversation(request) => LocalResponse::Conversation(
            conversation_exchange(stream, &pending, request)
                .unwrap_or_else(|reason| ConversationResponse::Refused { reason }),
        ),
    };
    let _ = pending.reply.send(response);
    let _ = pending.completed.write_all(&[1]);
    Ok(())
}

fn perform_exchange(
    stream: &mut (impl Read + Write),
    pending: &PendingReader,
    request: &ReaderRequest,
) -> Result<ReaderResponse, Refusal> {
    write_request(stream, request)?;
    match request {
        ReaderRequest::Receive => {
            let ReaderResponse::Challenge {
                enrollment,
                capability,
                challenge,
            } = read_response(stream)?
            else {
                return Err(Refusal::NotAuthorized);
            };
            let boot = &pending.reader.boot;
            let grant = MailboxGrant {
                mailbox: boot.mailbox,
                authority_key: boot.authority_key,
                epoch: boot.execution_epoch,
                report: None,
                retention: None,
                service_blind: None,
            };
            let authority = VerifyingKey::from_bytes(&boot.authority_key)
                .map_err(|_| Refusal::NotAuthorized)?;
            let scope = MailboxGuestReaderScope {
                plan: &grant,
                plan_id: &boot.plan_id,
                plan_nonce: &boot.plan_nonce,
                receive: &capability.grant,
                current_boot: boot.boot,
                current_session: enrollment.enrollment.consumer_session,
                now_unix_ms: now_unix_ms()?,
            };
            verify_guest_reader_enrollment(&enrollment, &capability, &scope, &authority, &[])
                .map_err(|_| Refusal::NotAuthorized)?;
            if enrollment.enrollment.ack_public_key != boot.ack_public_key {
                return Err(Refusal::NotAuthorized);
            }
            let possession = sign_reader_possession(
                &enrollment,
                &challenge,
                &SigningKey::from_bytes(pending.reader.ack_seed),
            )
            .map_err(|_| Refusal::NotAuthorized)?;
            write_request(
                stream,
                &ReaderRequest::Possession {
                    signature: possession.to_vec(),
                },
            )?;
            let response = read_response(stream)?;
            if let ReaderResponse::Delivery {
                lease,
                content_type,
                payload,
            } = &response
            {
                verify_delivery_lease_signature(lease, &authority)
                    .map_err(|_| Refusal::NotAuthorized)?;
                lease
                    .check_scope(
                        &grant,
                        &capability.grant,
                        scope.current_session,
                        now_unix_ms()?,
                    )
                    .map_err(|_| Refusal::NotAuthorized)?;
                if payload.len() > capability.grant.max_payload_bytes as usize {
                    return Err(Refusal::NotAuthorized);
                }
                if !capability.grant.content_types.contains(content_type) {
                    return Err(Refusal::NotAuthorized);
                }
                *pending
                    .reader
                    .active
                    .lock()
                    .expect("mailbox reader lock poisoned") = Some(ActiveLease {
                    lease: (**lease).clone(),
                    ack: None,
                });
            }
            Ok(response)
        }
        ReaderRequest::Ack { signed } => correlate_ack(read_response(stream)?, signed),
        ReaderRequest::Possession { .. } => Err(Refusal::NotAuthorized),
    }
}

fn conversation_exchange(
    stream: &mut (impl Read + Write + std::os::fd::AsRawFd),
    pending: &PendingReader,
    request: &ConversationRequest,
) -> Result<ConversationResponse, Refusal> {
    let reader = &pending.reader;
    let handshake_deadline = pending
        .deadline
        .min(Instant::now() + mvm_agentd::mailbox_outbox::MAILBOX_IO_TIMEOUT);
    let mut bounded = crate::mailbox::MailboxDeadline::for_conversation(
        stream,
        handshake_deadline,
        pending.caller.as_raw_fd(),
    );
    let stream = &mut bounded;
    let binding = reader.conversation.as_ref().ok_or(Refusal::NotAuthorized)?;
    if binding.reader != reader.boot {
        return Err(Refusal::NotAuthorized);
    }
    let request = prepare_conversation_request(reader, request)?;
    let mut session =
        conversation_wire::guest_session(stream, binding, SigningKey::from_bytes(reader.ack_seed))
            .inspect_err(|_| report_conversation_refusal(ConversationRefusalStage::Session))?;
    let invocation = conversation_wire::ConversationInvocation::new(
        request,
        pending.deadline.saturating_duration_since(Instant::now()),
    )?;
    conversation_wire::send_invocation(stream, &mut session, &invocation)?;
    let ConversationResponse::Challenge {
        enrollment,
        capability,
        challenge,
    } = conversation_wire::receive_response(stream, &mut session)
        .inspect_err(|_| report_conversation_refusal(ConversationRefusalStage::Challenge))?
    else {
        report_conversation_refusal(ConversationRefusalStage::Challenge);
        return Err(Refusal::NotAuthorized);
    };
    let boot = &reader.boot;
    let grant = MailboxGrant {
        mailbox: boot.mailbox,
        authority_key: boot.authority_key,
        epoch: boot.execution_epoch,
        report: None,
        retention: None,
        service_blind: None,
    };
    let authority =
        VerifyingKey::from_bytes(&boot.authority_key).map_err(|_| Refusal::NotAuthorized)?;
    let mut scope = MailboxGuestReaderScope {
        plan: &grant,
        plan_id: &boot.plan_id,
        plan_nonce: &boot.plan_nonce,
        receive: &capability.grant,
        current_boot: boot.boot,
        current_session: enrollment.enrollment.consumer_session,
        now_unix_ms: now_unix_ms()?,
    };
    if enrollment.enrollment.ack_public_key != boot.ack_public_key
        || capability.grant.address != binding.address
        || capability.grant.policy_epoch != binding.policy_epoch
        || enrollment.enrollment.issued_at_unix_ms < capability.grant.not_before_unix_ms
        || enrollment.enrollment.expires_at_unix_ms > capability.grant.expires_at_unix_ms
    {
        report_conversation_refusal(ConversationRefusalStage::EnrollmentBinding);
        return Err(Refusal::NotAuthorized);
    }
    let mut denied_stage = ConversationRefusalStage::Enrollment;
    await_validity(
        &pending.caller,
        handshake_deadline,
        enrollment.enrollment.issued_at_unix_ms,
        |now| {
            use mvm_contract::protocol::mailbox::MailboxDeliveryError;
            scope.now_unix_ms = now;
            let verified =
                verify_guest_reader_enrollment(&enrollment, &capability, &scope, &authority, &[]);
            denied_stage = match &verified {
                Err(MailboxError::DeliveryContract(MailboxDeliveryError::NotYetValid)) => {
                    ConversationRefusalStage::EnrollmentNotYetValid
                }
                Err(MailboxError::DeliveryContract(MailboxDeliveryError::Expired)) => {
                    ConversationRefusalStage::EnrollmentExpired
                }
                _ => ConversationRefusalStage::Enrollment,
            };
            verified.map(|_| ())
        },
    )
    .inspect_err(|_| {
        report_conversation_refusal(denied_stage);
    })?;
    let signature = sign_reader_possession(
        &enrollment,
        &challenge,
        &SigningKey::from_bytes(reader.ack_seed),
    )
    .map_err(|_| Refusal::NotAuthorized)?;
    conversation_wire::send_request(
        stream,
        &mut session,
        &ConversationRequest::Possession {
            signature: signature.to_vec(),
        },
    )?;
    if matches!(
        invocation.request,
        ConversationRequest::Receive {} | ConversationRequest::ReceiveResult { .. }
    ) {
        stream.authorize_wait(conversation_wire::bounded_wait_deadline(
            pending.deadline,
            capability
                .grant
                .expires_at_unix_ms
                .min(enrollment.enrollment.expires_at_unix_ms),
            now_unix_ms()?,
            Instant::now(),
        ));
    }
    let response =
        conversation_wire::receive_response(stream, &mut session).inspect_err(|reason| {
            if *reason == Refusal::NotAuthorized {
                report_conversation_refusal(ConversationRefusalStage::Session);
            }
        })?;
    if matches!(response, ConversationResponse::Refused { .. }) {
        report_conversation_refusal(ConversationRefusalStage::Destination);
    }
    if let ConversationResponse::Delivery {
        header,
        lease,
        payload,
    } = &response
    {
        if header.message_id != lease.lease.message_id
            || header.sender != lease.lease.sender
            || header.sender_boot != lease.lease.sender_boot
            || header.execution_epoch != lease.lease.execution_epoch
            || lease.lease.issued_at_unix_ms < capability.grant.not_before_unix_ms
            || lease.lease.expires_at_unix_ms > capability.grant.expires_at_unix_ms
            || payload.len() > capability.grant.max_payload_bytes as usize
            || !capability
                .grant
                .content_types
                .contains(&header.content_type)
        {
            return Err(Refusal::NotAuthorized);
        }
        let validation_deadline = pending
            .deadline
            .min(Instant::now() + mvm_agentd::mailbox_outbox::MAILBOX_IO_TIMEOUT);
        await_validity(
            &pending.caller,
            validation_deadline,
            lease
                .lease
                .issued_at_unix_ms
                .max(enrollment.enrollment.issued_at_unix_ms),
            |now| {
                use mvm_contract::protocol::mailbox::MailboxDeliveryError;
                scope.now_unix_ms = now;
                verify_delivery_lease_signature(lease, &authority)?;
                let enrollment_pending = match verify_guest_reader_enrollment(
                    &enrollment,
                    &capability,
                    &scope,
                    &authority,
                    &[],
                ) {
                    Ok(_) => false,
                    Err(MailboxError::DeliveryContract(MailboxDeliveryError::NotYetValid)) => true,
                    Err(error) => return Err(error),
                };
                lease.check_scope(&grant, &capability.grant, scope.current_session, now)?;
                if enrollment_pending {
                    Err(MailboxError::DeliveryContract(
                        MailboxDeliveryError::NotYetValid,
                    ))
                } else {
                    Ok(())
                }
            },
        )?;
        remember_conversation_lease(reader, lease)?;
    }
    Ok(response)
}

fn remember_conversation_lease(
    reader: &GuestReader,
    lease: &SignedMailboxDeliveryLease,
) -> Result<(), Refusal> {
    let now = now_unix_ms()?;
    let mut leases = reader
        .conversation_leases
        .lock()
        .expect("mailbox lease lock poisoned");
    leases.retain(|_, active| active.lease.lease.expires_at_unix_ms > now);
    if let Some(active) = leases.get(&lease.lease.lease_nonce) {
        return if active.lease == *lease {
            Ok(())
        } else {
            Err(Refusal::NotAuthorized)
        };
    }
    if leases.len() >= 64 {
        return Err(Refusal::QueueFull(64));
    }
    leases.insert(
        lease.lease.lease_nonce,
        ActiveLease {
            lease: lease.clone(),
            ack: None,
        },
    );
    Ok(())
}

fn prepare_conversation_request(
    reader: &GuestReader,
    request: &ConversationRequest,
) -> Result<ConversationRequest, Refusal> {
    let mut request = request.clone();
    let (lease, signed, message_id) = match &mut request {
        ConversationRequest::AckResult {
            result_message_id,
            lease,
            signed,
            ..
        } => (lease, signed, result_message_id),
        ConversationRequest::AckRequest {
            request_message_id,
            lease,
            signed,
        } => (lease, signed, request_message_id),
        ConversationRequest::Possession { .. } => return Err(Refusal::NotAuthorized),
        ConversationRequest::Call { .. }
        | ConversationRequest::Receive {}
        | ConversationRequest::Reply { .. }
        | ConversationRequest::ReceiveResult { .. } => return Ok(request),
    };
    if signed.is_some() || *message_id != lease.lease.message_id {
        return Err(Refusal::NotAuthorized);
    }
    let mut leases = reader
        .conversation_leases
        .lock()
        .expect("mailbox lease lock poisoned");
    let active = leases
        .get_mut(&lease.lease.lease_nonce)
        .ok_or(Refusal::NotAuthorized)?;
    if active.lease != **lease {
        return Err(Refusal::NotAuthorized);
    }
    if active.ack.is_none() {
        active.ack = Some(
            sign_delivery_ack(
                MailboxDeliveryAck {
                    protocol_version: ProtocolVersion::V1,
                    signature_algorithm: SignatureAlgorithm::ED25519,
                    lease: active.lease.clone(),
                    ack_nonce: DeliveryAckNonce::from_bytes(rand::random()),
                    acknowledged_at_unix_ms: now_unix_ms()?,
                },
                &SigningKey::from_bytes(reader.ack_seed),
            )
            .map_err(|_| Refusal::NotAuthorized)?,
        );
    }
    *signed = active.ack.clone().map(Box::new);
    Ok(request)
}

fn correlate_ack(
    response: ReaderResponse,
    signed: &SignedMailboxDeliveryAck,
) -> Result<ReaderResponse, Refusal> {
    match response {
        ReaderResponse::Acknowledged { ack } if *ack == *signed => {
            Ok(ReaderResponse::Acknowledged { ack })
        }
        refused @ ReaderResponse::Refused { .. } => Ok(refused),
        _ => Err(Refusal::NotAuthorized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::plan::{Nonce, PlanId};
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, BootId, CapabilityId, ConsumerSessionId, DeliveryId,
        DeliveryLeaseNonce, ExecutionEpoch, MailboxAddress, MailboxDeliveryLease, MailboxId,
        MessageId, PrincipalId, TenantId,
    };
    use mvm_core::mailbox::reader::sign_delivery_lease;
    use mvm_core::mailbox::reader_wire::write_application_request;
    use std::sync::OnceLock;

    static SEED: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

    fn reader_fixture() -> Arc<GuestReader> {
        let ack_seed = SEED.get_or_init(|| Zeroizing::new([7; 32]));
        Arc::new(GuestReader {
            boot: MailboxReaderBootBinding {
                plan_id: PlanId("current".into()),
                plan_nonce: Nonce::from_bytes([1; 16]),
                mailbox: MailboxId::from_bytes([2; 32]),
                authority_key: [3; 32],
                execution_epoch: ExecutionEpoch::new(1).unwrap(),
                boot: BootId::from_bytes([4; 32]),
                guest_identity_key: [5; 32],
                ack_public_key: SigningKey::from_bytes(ack_seed).verifying_key().to_bytes(),
            },
            ack_seed,
            active: Mutex::new(None),
            conversation: None,
            conversation_leases: Mutex::new(BTreeMap::new()),
        })
    }

    #[test]
    fn authenticated_issuance_waits_for_actual_clock_without_moving_deadline() {
        use mvm_contract::protocol::mailbox::MailboxDeliveryError;
        let (_client, caller) = UnixStream::pair().unwrap();
        let issued = now_unix_ms().unwrap() + 30;
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut observed = Vec::new();
        await_validity(&caller, deadline, issued, |now| {
            observed.push(now);
            if now < issued {
                Err(MailboxError::DeliveryContract(
                    MailboxDeliveryError::NotYetValid,
                ))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert!(*observed.last().unwrap() >= issued);
        assert!(Instant::now() < deadline);
        assert_eq!(
            await_validity(
                &caller,
                Instant::now() + Duration::from_millis(20),
                issued + 60_000,
                |_| {
                    Err(MailboxError::DeliveryContract(
                        MailboxDeliveryError::NotYetValid,
                    ))
                }
            ),
            Err(Refusal::Expired)
        );
    }

    #[test]
    fn validity_wait_refuses_bad_signature_expiry_and_cancel_without_waiting_for_future_time() {
        use mvm_contract::protocol::mailbox::MailboxDeliveryError;
        let (client, caller) = UnixStream::pair().unwrap();
        let issued = now_unix_ms().unwrap() + 60_000;
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            await_validity(&caller, deadline, issued, |_| Err(
                MailboxError::ReaderEnrollmentSignatureInvalid
            )),
            Err(Refusal::NotAuthorized)
        );
        assert_eq!(
            await_validity(&caller, deadline, issued, |_| Err(
                MailboxError::DeliveryLeaseSignatureInvalid
            )),
            Err(Refusal::NotAuthorized)
        );
        assert_eq!(
            await_validity(&caller, deadline, issued, |_| Err(
                MailboxError::DeliveryContract(MailboxDeliveryError::Expired)
            )),
            Err(Refusal::Expired)
        );
        assert_eq!(
            await_validity(&caller, deadline, now_unix_ms().unwrap() - 1, |_| {
                Err(MailboxError::DeliveryContract(
                    MailboxDeliveryError::NotYetValid,
                ))
            }),
            Err(Refusal::NotAuthorized),
            "a permanent scope contradiction is not a clock wait"
        );
        let (started, ready) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            await_validity(&caller, deadline, issued, |_| {
                let _ = started.try_send(());
                Err(MailboxError::DeliveryContract(
                    MailboxDeliveryError::NotYetValid,
                ))
            })
        });
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(client);
        assert_eq!(worker.join().unwrap(), Err(Refusal::Unavailable));
    }

    #[test]
    fn local_receive_is_explicit_and_an_empty_reply_does_not_sign_an_ack() {
        let reader = reader_fixture();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let (sender, pending) = mpsc::sync_channel(1);
        let state = reader.clone();
        let worker = std::thread::spawn(move || application_request(&mut server, &sender, &state));
        write_application_request(&mut client, &ApplicationReaderRequest::Receive).unwrap();
        let mut next = pending.recv_timeout(LOCAL_TIMEOUT).unwrap();
        assert!(matches!(
            next.request,
            PendingOperation::Reader(ReaderRequest::Receive)
        ));
        next.reply
            .send(LocalResponse::Reader(ReaderResponse::Empty))
            .unwrap();
        next.completed.write_all(&[1]).unwrap();
        assert_eq!(
            worker.join().unwrap(),
            Ok(LocalResponse::Reader(ReaderResponse::Empty))
        );
        assert!(reader.active.lock().unwrap().is_none(), "no automatic ACK");
    }

    #[test]
    fn waiting_local_caller_disconnect_releases_submit_without_a_host_reply() {
        let reader = reader_fixture();
        let (client, server) = UnixStream::pair().unwrap();
        let (sender, pending) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            submit(
                PendingOperation::Conversation(Box::new(ConversationRequest::Receive {})),
                &sender,
                &reader,
                &server,
                Instant::now() + Duration::from_secs(60),
            )
        });
        let queued = pending.recv_timeout(LOCAL_TIMEOUT).unwrap();
        drop(client);
        assert_eq!(worker.join().unwrap(), Err(Refusal::Unavailable));
        drop(queued);
    }

    #[test]
    fn waiting_local_caller_expires_without_restarting_queued_budget() {
        let reader = reader_fixture();
        let (_client, server) = UnixStream::pair().unwrap();
        let (sender, pending) = mpsc::sync_channel(1);
        let deadline = Instant::now() + Duration::from_millis(20);
        let worker = std::thread::spawn(move || {
            submit(
                PendingOperation::Conversation(Box::new(ConversationRequest::Receive {})),
                &sender,
                &reader,
                &server,
                deadline,
            )
        });
        let queued = pending.recv_timeout(LOCAL_TIMEOUT).unwrap();
        assert_eq!(queued.deadline, deadline);
        assert_eq!(worker.join().unwrap(), Err(Refusal::Expired));
    }

    #[test]
    fn local_frame_slow_drip_cannot_restart_the_absolute_decode_deadline() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut frame = Vec::new();
        conversation_wire::write_local_request(
            &mut frame,
            &conversation_wire::ConversationInvocation::new(
                ConversationRequest::Receive {},
                Duration::from_secs(60),
            )
            .unwrap(),
        )
        .unwrap();
        client.write_all(&frame[..1]).unwrap();
        let drip = std::thread::spawn(move || {
            for byte in &frame[1..] {
                // Deliberate adversarial arrival cadence, not a readiness poll.
                std::thread::sleep(Duration::from_millis(10));
                if client.write_all(&[*byte]).is_err() {
                    break;
                }
            }
        });
        let result = read_local_request(&mut server, Instant::now() + Duration::from_millis(50));
        drop(server);
        drip.join().unwrap();
        assert!(
            result.is_err(),
            "per-read progress must not renew a frame budget"
        );
    }

    #[test]
    fn single_active_exchange_refuses_concurrent_reply_then_reports_expiry_on_local_wire() {
        let mut reader = reader_fixture();
        let state = Arc::get_mut(&mut reader).unwrap();
        state.conversation = Some(ConversationBinding {
            reader: state.boot.clone(),
            address: MailboxAddress {
                tenant: TenantId::from_bytes([1; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
                mailbox: state.boot.mailbox,
                recipient: PrincipalId::from_bytes([3; 32]),
            },
            policy_epoch: 1,
        });
        let (accepted, clients) = mpsc::channel();
        let (tx, pending) = mpsc::sync_channel(1);
        let listener =
            std::thread::spawn(move || serve_local_clients(clients.into_iter(), tx, reader));
        let (mut first, first_server) = UnixStream::pair().unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        accepted.send(Ok(first_server)).unwrap();
        conversation_wire::write_local_request(
            &mut first,
            &conversation_wire::ConversationInvocation::new(
                ConversationRequest::ReceiveResult {
                    call_message_id: MessageId::from_bytes([6; 32]),
                },
                Duration::from_secs(2),
            )
            .unwrap(),
        )
        .unwrap();
        let first_pending = pending.recv_timeout(Duration::from_secs(1)).unwrap();
        let (mut second, second_server) = UnixStream::pair().unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        accepted.send(Ok(second_server)).unwrap();
        conversation_wire::write_local_request(
            &mut second,
            &conversation_wire::ConversationInvocation::new(
                ConversationRequest::Reply {
                    request_message_id: MessageId::from_bytes([8; 32]),
                    message_id: MessageId::from_bytes([9; 32]),
                    content_type: mvm_contract::protocol::mailbox::ContentType::parse(
                        "application/octet-stream",
                        1,
                    )
                    .unwrap(),
                    payload: b"reply".to_vec(),
                },
                Duration::from_secs(60),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            conversation_wire::read_local_response(&mut second).unwrap(),
            ConversationResponse::Refused {
                reason: Refusal::Unavailable
            }
        );
        assert_eq!(
            conversation_wire::read_local_response(&mut first).unwrap(),
            ConversationResponse::Refused {
                reason: Refusal::Expired
            }
        );
        drop(first_pending);
        let mut eof = [0; 1];
        assert_eq!(first.read(&mut eof).unwrap(), 0);
        let (mut third, third_server) = UnixStream::pair().unwrap();
        third
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        accepted.send(Ok(third_server)).unwrap();
        conversation_wire::write_local_request(
            &mut third,
            &conversation_wire::ConversationInvocation::new(
                ConversationRequest::Receive {},
                Duration::from_secs(1),
            )
            .unwrap(),
        )
        .unwrap();
        let mut next = pending.recv_timeout(Duration::from_secs(1)).unwrap();
        next.reply
            .send(LocalResponse::Conversation(ConversationResponse::Pending))
            .unwrap();
        next.completed.write_all(&[1]).unwrap();
        assert_eq!(
            conversation_wire::read_local_response(&mut third).unwrap(),
            ConversationResponse::Pending
        );
        drop(accepted);
        listener.join().unwrap();
    }

    #[test]
    fn ack_confirmation_must_echo_the_exact_signed_operation() {
        let authority = SigningKey::from_bytes(&[9; 32]);
        let guest = SigningKey::from_bytes(&[10; 32]);
        let lease = sign_delivery_lease(
            MailboxDeliveryLease {
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                address: MailboxAddress {
                    tenant: TenantId::from_bytes([1; 32]),
                    authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
                    mailbox: MailboxId::from_bytes([3; 32]),
                    recipient: PrincipalId::from_bytes([4; 32]),
                },
                sender: PrincipalId::from_bytes([5; 32]),
                sender_boot: BootId::from_bytes([6; 32]),
                message_id: MessageId::from_bytes([7; 32]),
                delivery_id: DeliveryId::from_bytes([8; 32]),
                execution_epoch: ExecutionEpoch::new(1).unwrap(),
                consumer: PrincipalId::from_bytes([4; 32]),
                consumer_session: ConsumerSessionId::from_bytes([11; 32]),
                receive_capability_id: CapabilityId::from_bytes([12; 32]),
                policy_epoch: 1,
                ciphertext_commitment: [13; 32],
                issued_at_unix_ms: 100,
                expires_at_unix_ms: 200,
                lease_nonce: DeliveryLeaseNonce::from_bytes([14; 16]),
            },
            &authority,
        )
        .unwrap();
        let ack = sign_delivery_ack(
            MailboxDeliveryAck {
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                lease,
                ack_nonce: DeliveryAckNonce::from_bytes([15; 16]),
                acknowledged_at_unix_ms: 150,
            },
            &guest,
        )
        .unwrap();
        let same = ReaderResponse::Acknowledged {
            ack: Box::new(ack.clone()),
        };
        let mut wire = Vec::new();
        write_response(&mut wire, &same).unwrap();
        assert_eq!(read_response(&mut wire.as_slice()), Ok(same.clone()));
        assert_eq!(correlate_ack(same.clone(), &ack), Ok(same));
        let mut changed = ack.ack.clone();
        changed.ack_nonce = DeliveryAckNonce::from_bytes([16; 16]);
        let changed = sign_delivery_ack(changed, &guest).unwrap();
        assert_eq!(
            correlate_ack(
                ReaderResponse::Acknowledged {
                    ack: Box::new(changed)
                },
                &ack,
            ),
            Err(Refusal::NotAuthorized),
            "a delayed success for a different signed ACK cannot confirm this one",
        );
        assert_eq!(
            correlate_ack(ReaderResponse::Empty, &ack),
            Err(Refusal::NotAuthorized)
        );
        let reader = reader_fixture();
        let now = now_unix_ms().unwrap();
        let mut live = ack.ack.lease.lease.clone();
        live.issued_at_unix_ms = now;
        live.expires_at_unix_ms = now + 30_000;
        let lease = sign_delivery_lease(live, &authority).unwrap();
        let request = ConversationRequest::AckRequest {
            request_message_id: lease.lease.message_id,
            lease: Box::new(lease.clone()),
            signed: None,
        };
        assert!(
            prepare_conversation_request(&reader, &request).is_err(),
            "unobserved lease cannot be ACKed"
        );
        remember_conversation_lease(&reader, &lease).unwrap();
        let first = prepare_conversation_request(&reader, &request).unwrap();
        assert_eq!(
            prepare_conversation_request(&reader, &request).unwrap(),
            first,
            "ACK retries retain exact signed bytes"
        );
        assert!(
            prepare_conversation_request(&reader, &first).is_err(),
            "application-supplied signature is not the agent's proof"
        );
    }
}
