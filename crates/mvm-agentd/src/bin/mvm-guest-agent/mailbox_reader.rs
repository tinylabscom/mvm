//! Explicit guest-local Receive and ACK-after-processing over the existing
//! mailbox vsock port. The workload can read the socket, not the ACK key.

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    DeliveryAckNonce, MailboxDeliveryAck, MailboxGrant, MailboxGuestReaderScope, ProtocolVersion,
    SignatureAlgorithm, SignedMailboxDeliveryAck, SignedMailboxDeliveryLease,
};
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::reader::{
    MailboxReaderBootBinding, sign_delivery_ack, sign_reader_possession,
    verify_delivery_lease_signature, verify_guest_reader_enrollment,
};
use mvm_core::mailbox::reader_wire::{
    ApplicationReaderRequest, GUEST_READER_SOCKET_PATH, ReaderRequest, ReaderResponse,
    read_application_request, read_response, write_request, write_response,
};
use zeroize::Zeroizing;

const LOCAL_TIMEOUT: Duration = Duration::from_secs(12);

struct ActiveLease {
    lease: SignedMailboxDeliveryLease,
    ack: Option<SignedMailboxDeliveryAck>,
}

struct GuestReader {
    boot: MailboxReaderBootBinding,
    ack_seed: &'static Zeroizing<[u8; 32]>,
    active: Mutex<Option<ActiveLease>>,
}

pub(crate) struct PendingReader {
    request: ReaderRequest,
    reply: mpsc::SyncSender<ReaderResponse>,
    reader: Arc<GuestReader>,
}

fn now_unix_ms() -> Result<i64, Refusal> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Refusal::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| Refusal::Unavailable)
}

/// Only start the local endpoint when the independently provisioned, root-only
/// boot key was captured by the agent. Send works without a reader.
pub(crate) fn start(
    boot: MailboxReaderBootBinding,
    ack_seed: &'static Zeroizing<[u8; 32]>,
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
    });
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(mut client) = client else { break };
            let _ = client.set_read_timeout(Some(LOCAL_TIMEOUT));
            let _ = client.set_write_timeout(Some(LOCAL_TIMEOUT));
            let response = application_request(&mut client, &tx, &state)
                .unwrap_or_else(|reason| ReaderResponse::Refused { reason });
            let _ = write_response(&mut client, &response);
        }
    });
    Some(rx)
}

fn application_request(
    stream: &mut UnixStream,
    tx: &mpsc::SyncSender<PendingReader>,
    reader: &Arc<GuestReader>,
) -> Result<ReaderResponse, Refusal> {
    let request = match read_application_request(stream)? {
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
    let (reply, received) = mpsc::sync_channel(1);
    tx.try_send(PendingReader {
        request,
        reply,
        reader: reader.clone(),
    })
    .map_err(|_| Refusal::Unavailable)?;
    received
        .recv_timeout(LOCAL_TIMEOUT)
        .map_err(|_| Refusal::Unavailable)
}

/// The mailbox listener calls this only when an application operation is
/// pending; idle host dials continue to carry Send without an extra handshake.
pub(crate) fn exchange(
    stream: &mut (impl Read + Write),
    pending: PendingReader,
) -> Result<(), Refusal> {
    let response = match perform_exchange(stream, &pending) {
        Ok(response) => response,
        Err(reason) => ReaderResponse::Refused { reason },
    };
    let _ = pending.reply.send(response);
    Ok(())
}

fn perform_exchange(
    stream: &mut (impl Read + Write),
    pending: &PendingReader,
) -> Result<ReaderResponse, Refusal> {
    write_request(stream, &pending.request)?;
    match &pending.request {
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

    #[test]
    fn local_receive_is_explicit_and_an_empty_reply_does_not_sign_an_ack() {
        let ack_seed = SEED.get_or_init(|| Zeroizing::new([7; 32]));
        let reader = Arc::new(GuestReader {
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
        });
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let (sender, pending) = mpsc::sync_channel(1);
        let state = reader.clone();
        let worker = std::thread::spawn(move || application_request(&mut server, &sender, &state));
        write_application_request(&mut client, &ApplicationReaderRequest::Receive).unwrap();
        let next = pending.recv_timeout(LOCAL_TIMEOUT).unwrap();
        assert_eq!(next.request, ReaderRequest::Receive);
        next.reply.send(ReaderResponse::Empty).unwrap();
        assert_eq!(worker.join().unwrap(), Ok(ReaderResponse::Empty));
        assert!(reader.active.lock().unwrap().is_none(), "no automatic ACK");
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
    }
}
