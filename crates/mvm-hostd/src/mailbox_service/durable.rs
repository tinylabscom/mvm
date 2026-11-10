//! Destination-owned local endpoint for receipt-bearing durable admission.
//!
//! This listener is separate from the ephemeral mailbox queue. It never
//! interprets a successful connection as authority or a signed verdict:
//! authorization, journal fsync, and external anchor publication precede the
//! destination signature being returned to the caller.

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    MailboxEnvelope, MailboxEnvelopeHeader, SignedDestinationReceipt, SignedMailboxCapability,
};
use mvm_core::mailbox::frame::{OutboxMessage, Refusal, decode_frame, send_receipted_frame};
use mvm_core::mailbox::journal::{
    FileJournalAnchor, JournalAdmission, JournalError, JournalReceive, JournalTip, MailboxJournal,
    ReceivedMailboxMessage,
};
use mvm_core::mailbox::{MailboxError, OpenContext, ReplayIdentity};

use super::{GuestSealer, IO_TIMEOUT, MailboxLimits, MailboxPolicy, read_frame};

/// A trusted anchor advances outside the journal's rollback domain.
pub trait JournalAnchor: Send + Sync {
    fn commit(&self, tip: JournalTip) -> Result<(), JournalError>;
}

impl<F> JournalAnchor for F
where
    F: Fn(JournalTip) -> Result<(), JournalError> + Send + Sync,
{
    fn commit(&self, tip: JournalTip) -> Result<(), JournalError> {
        self(tip)
    }
}

impl JournalAnchor for FileJournalAnchor {
    fn commit(&self, tip: JournalTip) -> Result<(), JournalError> {
        self.advance(tip)
    }
}

struct State {
    policy: MailboxPolicy,
    journal: MailboxJournal,
}

struct Shared {
    limits: MailboxLimits,
    state: Mutex<State>,
    signer: SigningKey,
    anchor: Box<dyn JournalAnchor>,
}

/// One destination authority's bounded, journal-backed local admission socket.
pub struct DurableMailboxService {
    shared: Arc<Shared>,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl DurableMailboxService {
    /// Bind a live destination. Caller provides an already-recovered journal
    /// and an anchor backed by a different rollback domain.
    pub fn bind(
        path: &Path,
        limits: MailboxLimits,
        policy: MailboxPolicy,
        signer: SigningKey,
        journal: MailboxJournal,
        anchor: impl JournalAnchor + 'static,
    ) -> std::io::Result<Self> {
        if signer.verifying_key() != policy.authority_key {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "destination signer does not match the trusted authority",
            ));
        }
        if limits.max_frame_bytes == 0 || limits.max_depth == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mailbox limits must be nonzero",
            ));
        }
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        let shared = Arc::new(Shared {
            limits,
            state: Mutex::new(State { policy, journal }),
            signer,
            anchor: Box::new(anchor),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (shared, stop) = (shared.clone(), stop.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        serve(&shared, stream);
                    }
                }
            })
        };
        Ok(Self {
            shared,
            path: path.to_owned(),
            stop,
            worker: Some(worker),
        })
    }

    /// Read one guest outbox operation over its dedicated mailbox port. The
    /// guest sees success only after the canonical ciphertext, dedup identity,
    /// and anchor have committed; an idle connection returns `false`.
    pub fn serve_guest(
        &self,
        per_port: &Path,
        firecracker_mux: &Path,
        sealer: &mut GuestSealer,
    ) -> std::io::Result<bool> {
        let mut stream = crate::telemetry_collector::dial_guest_port(
            per_port,
            firecracker_mux,
            mvm_contract::protocol::mailbox::MAILBOX_PORT,
        )?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(7)))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let body = read_frame(self.shared.limits.max_frame_bytes, &mut stream);
        let received = body.is_ok();
        let verdict: Result<(), Refusal> = body
            .and_then(|body| OutboxMessage::decode(&body))
            .and_then(|message| sealer.seal(message))
            .and_then(|(capability, envelope)| {
                admit(&self.shared, &capability, &envelope).map(|_| ())
            });
        if let Ok(reply) = serde_json::to_vec(&verdict) {
            let _ = stream.write_all(&reply);
        }
        Ok(received)
    }

    /// A trusted host caller may receive only with a separate signed Receive
    /// capability. This is not a transport-facing unauthenticated read.
    pub fn receive_next(
        &self,
        capability: &SignedMailboxCapability,
        reader: &OpenContext,
    ) -> Result<Option<ReceivedMailboxMessage>, JournalError> {
        let state = self
            .shared
            .state
            .lock()
            .expect("mailbox journal lock poisoned");
        let context = reader_context(&state.policy, reader)?;
        state.journal.receive_next(JournalReceive {
            capability,
            context: &context,
            encryption_key: &state.policy.encryption_key,
            sender_key: &state.policy.sender_key,
        })
    }

    /// Persist an ACK from a previously authenticated reader; a lost reply
    /// may be retried with the same identity without a second journal event.
    pub fn acknowledge(
        &self,
        identity: ReplayIdentity,
        capability: &SignedMailboxCapability,
        reader: &OpenContext,
    ) -> Result<JournalTip, JournalError> {
        let mut state = self
            .shared
            .state
            .lock()
            .expect("mailbox journal lock poisoned");
        let context = reader_context(&state.policy, reader)?;
        let State { policy, journal } = &mut *state;
        journal.acknowledge(
            identity,
            JournalReceive {
                capability,
                context: &context,
                encryption_key: &policy.encryption_key,
                sender_key: &policy.sender_key,
            },
            |tip| self.shared.anchor.commit(tip),
        )
    }
}

fn reader_context(
    policy: &MailboxPolicy,
    reader: &OpenContext,
) -> Result<OpenContext, JournalError> {
    if reader.expected_tenant != policy.context.expected_tenant
        || reader.expected_authorization_domain != policy.context.expected_authorization_domain
        || reader.expected_mailbox != policy.context.expected_mailbox
        || reader.expected_sender != policy.context.expected_sender
        || reader.expected_recipient != policy.context.expected_recipient
        || reader.current_execution_epoch != policy.context.current_execution_epoch
        || reader.current_policy_epoch != policy.context.current_policy_epoch
    {
        return Err(JournalError::WrongAuthority);
    }
    let mut context = reader.clone();
    context.required_operation = mvm_contract::protocol::mailbox::MailboxOperation::Receive;
    context.now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JournalError::Uncertain)?
        .as_millis()
        .try_into()
        .map_err(|_| JournalError::Uncertain)?;
    Ok(context)
}

impl Drop for DurableMailboxService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.path);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn serve(shared: &Shared, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let result = read_frame(shared.limits.max_frame_bytes, &mut stream)
        .and_then(|body| decode_frame(&body))
        .and_then(|(capability, envelope)| admit(shared, &capability, &envelope));
    if let Ok(reply) = serde_json::to_vec(&result) {
        let _ = stream.write_all(&reply);
    }
}

fn admit(
    shared: &Shared,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
) -> Result<SignedDestinationReceipt, Refusal> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Refusal::Unavailable)?
        .as_millis();
    let now: i64 = now.try_into().map_err(|_| Refusal::Unavailable)?;
    let mut state = shared.state.lock().expect("mailbox journal lock poisoned");
    state.policy.context.now_unix_ms = now;
    let State { policy, journal } = &mut *state;
    journal
        .admit(
            JournalAdmission {
                envelope,
                capability,
                context: &policy.context,
                encryption_key: &policy.encryption_key,
                sender_key: &policy.sender_key,
                signer: &shared.signer,
            },
            |tip| shared.anchor.commit(tip),
        )
        .map_err(|error| match error {
            JournalError::Mailbox(MailboxError::CapabilityPayloadExceeded) => {
                Refusal::Oversized(capability.grant.max_payload_bytes as usize)
            }
            JournalError::Mailbox(error) => Refusal::Mailbox(error.to_string()),
            JournalError::Full => Refusal::StorageFull,
            JournalError::ConflictingRetry => Refusal::Mailbox(error.to_string()),
            _ => Refusal::Unavailable,
        })
}

/// Send an immutable, already-sealed delivery to the local destination.
/// A transport connection alone is never enough: the signed receipt must
/// identify the exact expected header and ciphertext commitment.
pub fn send(
    path: &Path,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
    expected_header: &MailboxEnvelopeHeader,
    destination_key: &VerifyingKey,
) -> Result<SignedDestinationReceipt, Refusal> {
    let mut stream = UnixStream::connect(path).map_err(|_| Refusal::Unavailable)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Refusal::Unavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Refusal::Unavailable)?;
    send_receipted_frame(
        &mut stream,
        capability,
        envelope,
        expected_header,
        destination_key,
    )
}
