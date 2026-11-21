//! Destination-owned local endpoint for receipt-bearing durable admission.
//!
//! This listener is separate from the ephemeral mailbox queue. It never
//! interprets a successful connection as authority or a signed verdict:
//! authorization, journal fsync, and the tier's anchor publication precede
//! the destination signature being returned to the caller.

use std::io::{Read, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    MailboxEnvelope, MailboxEnvelopeHeader, MailboxGrant, MailboxGuestReaderScope, RevocationId,
    SignedDestinationReceipt, SignedMailboxCapability, SignedMailboxGuestReaderEnrollment,
};
use mvm_core::host_interface::epoch_gate::admit_at;
use mvm_core::mailbox::conversation_wire::{
    self, ConversationBinding, ConversationRequest, ConversationResponse,
};
use mvm_core::mailbox::frame::{OutboxMessage, Refusal, decode_frame, send_receipted_frame};
use mvm_core::mailbox::journal::{
    EncodedDestinationReceipt, FileJournalAnchor, JournalAdmission, JournalError, JournalGuestAck,
    JournalGuestLease, JournalReceive, JournalTip, MailboxJournal, ReceivedMailboxMessage,
};
use mvm_core::mailbox::reader::{
    MailboxReaderBootBinding, verify_guest_reader_enrollment, verify_reader_possession,
};
use mvm_core::mailbox::reader_wire::{
    ReaderRequest, ReaderResponse, decode_request_body, is_reader_frame, read_request,
    write_response,
};
use mvm_core::mailbox::{MailboxError, OpenContext, ReplayIdentity};
use mvm_core::vm_backend::HostDialRoute;

use super::{
    GUEST_HOLD_TIMEOUT, GuestSealer, IO_TIMEOUT, MailboxLimits, MailboxPolicy, await_first_byte,
    read_frame,
};

const ACCEPT_POLL: std::time::Duration = std::time::Duration::from_millis(20);
const GUEST_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_EXPIRY_RECORDS_PER_REQUEST: usize = 8;

struct GuestDeadline<'a> {
    stream: &'a mut UnixStream,
    until: Instant,
}

impl GuestDeadline<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        let remaining = self.until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "mailbox guest exchange deadline",
            ))
        } else {
            Ok(remaining)
        }
    }
}

impl Read for GuestDeadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}

impl Write for GuestDeadline<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream
            .set_write_timeout(Some(self.remaining()?.min(GUEST_EXCHANGE_TIMEOUT)))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl std::os::fd::AsRawFd for GuestDeadline<'_> {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.stream.as_raw_fd()
    }
}

/// Commit delivery-state events; this callback alone cannot authorize a
/// strong `accepted_durable` receipt.
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
    /// The receiving unit's gate, asked before each new acceptance or read.
    unit_gate: Option<super::UnitGate>,
    state: Mutex<State>,
    signer: SigningKey,
    anchor: Box<dyn JournalAnchor>,
    local_anchor: Option<Arc<FileJournalAnchor>>,
    reader: OnceLock<GuestReaderAuthority>,
    conversation: OnceLock<ConversationEndpoint>,
    dispatch_wake: OnceLock<SyncSender<()>>,
}

/// One VM-scoped owner executes immediately after current guest authority verification.
pub trait ConversationOperations: Send {
    fn wait_deadline_unix_ms(&self, request: &ConversationRequest) -> Result<Option<i64>, Refusal>;

    fn peer_for_route(
        &self,
        token: mvm_contract::protocol::mailbox::DestinationRouteToken,
    ) -> Result<crate::mailbox_launch::actor_template::ActorPeerBinding, Refusal>;

    fn pending_dispatches(
        &mut self,
    ) -> Result<Vec<super::actor_operations::ActorDispatch>, Refusal>;

    fn record_dispatch_receipt(
        &mut self,
        message_id: mvm_contract::protocol::mailbox::MessageId,
        receipt: mvm_contract::protocol::mailbox::SignedDestinationReceipt,
    ) -> Result<(), Refusal>;

    fn accept_peer(
        &mut self,
        frame: super::actor_operations::ActorPeerFrame,
    ) -> Result<mvm_contract::protocol::mailbox::SignedDestinationReceipt, Refusal>;

    fn execute(
        &mut self,
        authority: &CurrentBootAuthority,
        request: ConversationRequest,
    ) -> Result<ConversationResponse, Refusal>;
}

/// Immediate-dispatch verification snapshot, not reusable or transferable authority.
/// Constructed only after exact session identity and current enrollment checks.
///
/// ```compile_fail
/// use mvm_hostd::mailbox_service::durable::CurrentBootAuthority;
/// let authority: CurrentBootAuthority = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug)]
pub struct CurrentBootAuthority {
    binding: ConversationBinding,
    now_unix_ms: i64,
    grant: MailboxGrant,
    capability: SignedMailboxCapability,
    enrollment: SignedMailboxGuestReaderEnrollment,
    challenge: [u8; 32],
    possession_signature: Vec<u8>,
}

impl CurrentBootAuthority {
    /// Verify a host-side authenticated session and the current canonical reader proof.
    /// Admitted endpoint scope remains independently pinned by the operation owner.
    pub(crate) fn verify(
        session: &conversation_wire::ConversationSession,
        reader: &GuestReaderAuthority,
        now_unix_ms: i64,
        revoked: &[RevocationId],
        challenge: [u8; 32],
        signature: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let binding = session.authenticated_host_binding()?;
        let guest_key = verify_bound_reader(binding, reader, now_unix_ms, revoked)?;
        verify_reader_possession(&reader.enrollment, &challenge, &signature, &guest_key)
            .map_err(|_| Refusal::NotAuthorized)?;
        Ok(Self {
            binding: binding.clone(),
            now_unix_ms,
            grant: reader.grant,
            capability: reader.capability.clone(),
            enrollment: reader.enrollment.clone(),
            challenge,
            possession_signature: signature,
        })
    }

    pub fn binding(&self) -> &ConversationBinding {
        &self.binding
    }
    pub fn now_unix_ms(&self) -> i64 {
        self.now_unix_ms
    }
    pub fn grant(&self) -> &MailboxGrant {
        &self.grant
    }
    pub fn capability(&self) -> &SignedMailboxCapability {
        &self.capability
    }
    pub fn enrollment(&self) -> &SignedMailboxGuestReaderEnrollment {
        &self.enrollment
    }
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
    pub fn possession_signature(&self) -> &[u8] {
        &self.possession_signature
    }
}

struct ConversationEndpoint {
    binding: ConversationBinding,
    operations: Mutex<Box<dyn ConversationOperations>>,
    events: Mutex<UnixStream>,
    notify: UnixStream,
}

/// Enrollment pinned to the signed grant and current guest boot by the launcher.
pub(crate) struct GuestReaderAuthority {
    pub(crate) grant: MailboxGrant,
    pub(crate) boot: MailboxReaderBootBinding,
    pub(crate) capability: SignedMailboxCapability,
    pub(crate) enrollment: SignedMailboxGuestReaderEnrollment,
    /// Re-read at each operation so revocation works without helper restart.
    pub(crate) revocations_path: PathBuf,
}

/// One destination authority's bounded, journal-backed admission socket.
pub struct DurableMailboxService {
    shared: Arc<Shared>,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    delivery_worker: Mutex<Option<JoinHandle<()>>>,
}

impl DurableMailboxService {
    /// Install exactly one VM-scoped operation owner before publishing readiness.
    /// The address and boot must agree with already-installed reader authority.
    pub fn install_conversation(
        &self,
        binding: ConversationBinding,
        operations: impl ConversationOperations + 'static,
    ) -> std::io::Result<()> {
        verify_conversation_enrollment(&self.shared, &binding).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "conversation binding refused",
            )
        })?;
        let (events, notify) = UnixStream::pair()?;
        events.set_nonblocking(true)?;
        notify.set_nonblocking(true)?;
        self.shared
            .conversation
            .set(ConversationEndpoint {
                binding,
                operations: Mutex::new(Box::new(operations)),
                events: Mutex::new(events),
                notify,
            })
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "conversation owner already installed",
                )
            })?;
        let (wake, events) = mpsc::sync_channel(1);
        self.shared
            .dispatch_wake
            .set(wake)
            .map_err(|_| std::io::Error::other("delivery worker already installed"))?;
        let shared = Arc::clone(&self.shared);
        let stop = Arc::clone(&self.stop);
        let worker = std::thread::Builder::new()
            .name("mailbox-delivery".into())
            .spawn(move || {
                delivery_loop(&events, &stop, || drain_dispatches(&shared, &stop));
            });
        match worker {
            Ok(worker) => {
                *self
                    .delivery_worker
                    .lock()
                    .expect("mailbox worker lock poisoned") = Some(worker);
                Ok(())
            }
            Err(error) => {
                self.stop.store(true, Ordering::SeqCst);
                Err(error)
            }
        }
    }

    /// Install the verified, boot-bound Receive authority before advertising
    /// readiness to the guest. It cannot be replaced within this helper.
    pub(crate) fn install_guest_reader(&self, reader: GuestReaderAuthority) -> std::io::Result<()> {
        self.shared.reader.set(reader).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "mailbox guest reader was already installed",
            )
        })
    }

    /// Reclaim the bounded local prefix and settle expiry even when no guest
    /// connects. An incomplete expiry pass resumes on the helper's next loop.
    pub(crate) fn maintain_local(&self) -> Result<(), JournalError> {
        let anchor = self
            .shared
            .local_anchor
            .as_ref()
            .ok_or(JournalError::DurableAuthorityUnavailable)?;
        let now_unix_ms: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JournalError::Uncertain)?
            .as_millis()
            .try_into()
            .map_err(|_| JournalError::Uncertain)?;
        let mut state = self
            .shared
            .state
            .lock()
            .expect("mailbox journal lock poisoned");
        if state.journal.local_compaction_due(now_unix_ms)? {
            state
                .journal
                .compact_local(now_unix_ms, &self.shared.signer, anchor)?;
        }
        settle_expired(&self.shared, &mut state.journal, now_unix_ms)?;
        if state.journal.local_compaction_due(now_unix_ms)? {
            state
                .journal
                .compact_local(now_unix_ms, &self.shared.signer, anchor)?;
        }
        Ok(())
    }

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
        Self::bind_with(
            path,
            limits,
            policy,
            signer,
            journal,
            Box::new(anchor),
            None,
        )
    }

    /// Bind the existing mailbox endpoint to a verified local journal. The
    /// held anchor and journal must agree before the socket becomes visible.
    /// This tier does not claim independent whole-host rollback detection.
    pub fn bind_local(
        path: &Path,
        limits: MailboxLimits,
        policy: MailboxPolicy,
        signer: SigningKey,
        journal: MailboxJournal,
        anchor: FileJournalAnchor,
    ) -> std::io::Result<Self> {
        journal
            .local_ready(&anchor, &signer.verifying_key())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let anchor = Arc::new(anchor);
        let commit = {
            let anchor = Arc::clone(&anchor);
            move |tip| anchor.advance(tip)
        };
        Self::bind_with(
            path,
            limits,
            policy,
            signer,
            journal,
            Box::new(commit),
            Some(anchor),
        )
    }

    fn bind_with(
        path: &Path,
        limits: MailboxLimits,
        mut policy: MailboxPolicy,
        signer: SigningKey,
        journal: MailboxJournal,
        anchor: Box<dyn JournalAnchor>,
        local_anchor: Option<Arc<FileJournalAnchor>>,
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
        listener.set_nonblocking(true)?;
        let shared = Arc::new(Shared {
            limits,
            unit_gate: policy.unit_gate.take(),
            state: Mutex::new(State { policy, journal }),
            signer,
            anchor,
            local_anchor,
            reader: OnceLock::new(),
            conversation: OnceLock::new(),
            dispatch_wake: OnceLock::new(),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (shared, stop) = (shared.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // Some platforms inherit nonblocking on accepted sockets.
                            let _ = stream.set_nonblocking(false);
                            serve(&shared, stream);
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) =>
                        {
                            std::thread::sleep(ACCEPT_POLL);
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Ok(Self {
            shared,
            path: path.to_owned(),
            stop,
            worker: Some(worker),
            delivery_worker: Mutex::new(None),
        })
    }

    /// Read one guest outbox operation over its dedicated mailbox port. The
    /// guest sees success only after the canonical ciphertext, dedup identity,
    /// and anchor have committed; an idle connection returns `false`. Local
    /// admission returns its signed V2 receipt; the legacy branch retains its
    /// original unit-verdict wire.
    pub fn serve_guest(
        &self,
        route: &HostDialRoute,
        sealer: &mut GuestSealer,
    ) -> std::io::Result<bool> {
        self.serve_guest_waiting(route, sealer, GUEST_EXCHANGE_TIMEOUT, || true)
    }

    /// Keep one idle production connection open without redialing until this
    /// VM stops; the owner cancels it without an extra per-VM worker thread.
    pub(crate) fn serve_guest_while(
        &self,
        route: &HostDialRoute,
        sealer: &mut GuestSealer,
        active: impl Fn() -> bool,
    ) -> std::io::Result<bool> {
        self.serve_guest_waiting(route, sealer, GUEST_HOLD_TIMEOUT, active)
    }

    fn serve_guest_waiting(
        &self,
        route: &HostDialRoute,
        sealer: &mut GuestSealer,
        hold: Duration,
        active: impl Fn() -> bool,
    ) -> std::io::Result<bool> {
        let mut stream = crate::telemetry_collector::dial_route(
            route,
            mvm_contract::protocol::mailbox::MAILBOX_PORT,
        )?;
        if !await_first_byte(&stream, hold, active) {
            return Ok(false);
        }
        let mut stream = GuestDeadline {
            stream: &mut stream,
            until: Instant::now() + GUEST_EXCHANGE_TIMEOUT,
        };
        let body = read_frame(self.shared.limits.max_frame_bytes, &mut stream);
        let received = body.is_ok();
        let body = match body {
            Ok(body) if conversation_wire::is_session_request(&body) => {
                serve_conversation(&self.shared, &mut stream);
                return Ok(true);
            }
            Ok(_) if self.shared.conversation.get().is_some() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "actor mailbox requires an encrypted conversation session",
                ));
            }
            Ok(body) if is_reader_frame(&body) => {
                serve_reader(&self.shared, &mut stream, &body);
                return Ok(true);
            }
            other => other,
        };
        let verdict = body
            .and_then(|body| OutboxMessage::decode(&body))
            .and_then(|message| admit_guest(&self.shared, sealer, message));
        let format = if self.shared.local_anchor.is_some() {
            ReplyFormat::Receipt
        } else {
            ReplyFormat::LegacyUnit
        };
        if let Ok(reply) = admission_reply(verdict, format) {
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
        let mut state = self
            .shared
            .state
            .lock()
            .expect("mailbox journal lock poisoned");
        let context = reader_context(&state.policy, reader)?;
        settle_expired(&self.shared, &mut state.journal, context.now_unix_ms)?;
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
        settle_expired(&self.shared, journal, context.now_unix_ms)?;
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

fn verify_conversation_enrollment(
    shared: &Shared,
    binding: &ConversationBinding,
) -> Result<i64, Refusal> {
    let reader = shared.reader.get().ok_or(Refusal::NotAuthorized)?;
    let state = shared.state.lock().expect("mailbox journal lock poisoned");
    let context = guest_context(shared, &state.policy, reader)?;
    if binding.policy_epoch != context.current_policy_epoch {
        return Err(Refusal::NotAuthorized);
    }
    verify_bound_reader(
        binding,
        reader,
        context.now_unix_ms,
        &context.revoked_capabilities,
    )?;
    Ok(context.now_unix_ms)
}

fn verify_bound_reader(
    binding: &ConversationBinding,
    reader: &GuestReaderAuthority,
    now_unix_ms: i64,
    revoked: &[RevocationId],
) -> Result<VerifyingKey, Refusal> {
    if binding.reader != reader.boot
        || binding.address != reader.capability.grant.address
        || binding.policy_epoch != reader.capability.grant.policy_epoch
        || binding.address.mailbox != reader.grant.mailbox
        || binding.reader.execution_epoch != reader.grant.epoch
        || binding.reader.authority_key != reader.grant.authority_key
        || reader.enrollment.enrollment.ack_public_key != reader.boot.ack_public_key
    {
        return Err(Refusal::NotAuthorized);
    }
    verify_guest_reader_enrollment(
        &reader.enrollment,
        &reader.capability,
        &MailboxGuestReaderScope {
            plan: &reader.grant,
            plan_id: &reader.boot.plan_id,
            plan_nonce: &reader.boot.plan_nonce,
            receive: &reader.capability.grant,
            current_boot: reader.boot.boot,
            current_session: reader.enrollment.enrollment.consumer_session,
            now_unix_ms,
        },
        &VerifyingKey::from_bytes(&reader.grant.authority_key)
            .map_err(|_| Refusal::NotAuthorized)?,
        revoked,
    )
    .map_err(|_| Refusal::NotAuthorized)
}

fn serve_conversation(shared: &Shared, stream: &mut GuestDeadline<'_>) {
    let Some(endpoint) = shared.conversation.get() else {
        return;
    };
    if verify_conversation_enrollment(shared, &endpoint.binding).is_err() {
        return;
    }
    let Ok(mut session) =
        conversation_wire::host_session(stream, &endpoint.binding, shared.signer.clone())
    else {
        return;
    };
    let response = (|| {
        let received = Instant::now();
        let invocation = conversation_wire::receive_invocation(stream, &mut session)?;
        let caller_deadline = invocation.deadline(received)?;
        stream.until = stream.until.min(caller_deadline);
        let request = invocation.request;
        if matches!(request, ConversationRequest::Possession { .. }) {
            return Err(Refusal::NotAuthorized);
        }
        let reader = shared.reader.get().ok_or(Refusal::NotAuthorized)?;
        let challenge: [u8; 32] = rand::random();
        if challenge == [0; 32] {
            return Err(Refusal::Unavailable);
        }
        conversation_wire::send_response(
            stream,
            &mut session,
            &ConversationResponse::Challenge {
                enrollment: Box::new(reader.enrollment.clone()),
                capability: Box::new(reader.capability.clone()),
                challenge,
            },
        )?;
        let ConversationRequest::Possession { signature } =
            conversation_wire::receive_request(stream, &mut session)?
        else {
            return Err(Refusal::NotAuthorized);
        };
        let now_unix_ms = verify_conversation_enrollment(shared, &endpoint.binding)?;
        let revoked = reader_revocations(&reader.revocations_path)?;
        CurrentBootAuthority::verify(
            &session,
            reader,
            now_unix_ms,
            &revoked,
            challenge,
            signature.clone(),
        )?;
        if matches!(
            request,
            ConversationRequest::Receive {} | ConversationRequest::ReceiveResult { .. }
        ) {
            stream.until = conversation_wire::bounded_wait_deadline(
                caller_deadline,
                reader
                    .capability
                    .grant
                    .expires_at_unix_ms
                    .min(reader.enrollment.enrollment.expires_at_unix_ms),
                now_unix_ms,
                Instant::now(),
            );
        }
        execute_with_wait(
            shared,
            endpoint,
            request,
            ConversationExchange {
                fd: stream.as_raw_fd(),
                deadline: stream.until,
                challenge,
                signature,
                session: &session,
            },
        )
    })()
    .unwrap_or_else(|reason| ConversationResponse::Refused { reason });
    let _ = conversation_wire::send_response(stream, &mut session, &response);
}

struct ConversationExchange<'a> {
    fd: std::os::fd::RawFd,
    deadline: Instant,
    challenge: [u8; 32],
    signature: Vec<u8>,
    session: &'a conversation_wire::ConversationSession,
}

fn execute_with_wait(
    shared: &Shared,
    endpoint: &ConversationEndpoint,
    request: ConversationRequest,
    exchange: ConversationExchange<'_>,
) -> Result<ConversationResponse, Refusal> {
    let read = matches!(
        request,
        ConversationRequest::Receive {} | ConversationRequest::ReceiveResult { .. }
    );
    let mut exhausted = false;
    loop {
        let (response, wait_until) = {
            let mut operations = endpoint
                .operations
                .lock()
                .expect("conversation owner lock poisoned");
            let reader = shared.reader.get().ok_or(Refusal::NotAuthorized)?;
            let context = {
                let state = shared.state.lock().expect("mailbox journal lock poisoned");
                guest_context(shared, &state.policy, reader)?
            };
            let now_unix_ms = context.now_unix_ms;
            let authority = CurrentBootAuthority::verify(
                exchange.session,
                reader,
                now_unix_ms,
                &context.revoked_capabilities,
                exchange.challenge,
                exchange.signature.clone(),
            )?;
            let mut expires = reader
                .capability
                .grant
                .expires_at_unix_ms
                .min(reader.enrollment.enrollment.expires_at_unix_ms);
            if let Some(deadline) = operations.wait_deadline_unix_ms(&request)? {
                expires = expires.min(deadline);
            }
            let remaining = u64::try_from(expires.saturating_sub(now_unix_ms)).unwrap_or(0);
            let now = Instant::now();
            let remaining = Duration::from_millis(remaining)
                .min(exchange.deadline.saturating_duration_since(now));
            let wait_until = now + remaining;
            (operations.execute(&authority, request.clone())?, wait_until)
        };
        if !read {
            signal_change(shared);
            return Ok(response);
        }
        if !matches!(response, ConversationResponse::Pending) || exhausted {
            return Ok(response);
        }
        if !wait_for_change(&endpoint.events, exchange.fd, wait_until)? {
            if Instant::now() >= exchange.deadline {
                return Err(Refusal::Expired);
            }
            exhausted = true;
        }
    }
}

fn wait_for_change(
    events: &Mutex<UnixStream>,
    guest_fd: std::os::fd::RawFd,
    deadline: Instant,
) -> Result<bool, Refusal> {
    let mut events = events.try_lock().map_err(|_| Refusal::Unavailable)?;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(false);
        };
        let timeout = libc::c_int::try_from(remaining.as_millis().saturating_add(1))
            .unwrap_or(libc::c_int::MAX);
        let mut descriptors = [
            libc::pollfd {
                fd: events.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: guest_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: both descriptors remain borrowed and live throughout this bounded poll.
        let count = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, timeout) };
        if count == 0 {
            return Ok(false);
        }
        if count < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Refusal::Unavailable);
        }
        if descriptors[1].revents != 0 {
            return Err(Refusal::Unavailable);
        }
        if descriptors[0].revents & libc::POLLIN != 0 {
            match events.read(&mut [0; 128]) {
                Ok(0) => return Err(Refusal::Unavailable),
                Ok(_) => return Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => return Err(Refusal::Unavailable),
            }
        }
        if descriptors[0].revents != 0 {
            return Err(Refusal::Unavailable);
        }
    }
}

fn serve_reader(shared: &Shared, stream: &mut (impl Read + Write), body: &[u8]) {
    let result = decode_request_body(body).and_then(|request| {
        let reader = shared.reader.get().ok_or(Refusal::NotAuthorized)?;
        match request {
            ReaderRequest::Receive => {
                {
                    let mut state = shared.state.lock().expect("mailbox journal lock poisoned");
                    let context = guest_context(shared, &state.policy, reader)?;
                    verify_guest_reader_enrollment(
                        &reader.enrollment,
                        &reader.capability,
                        &guest_scope(reader, &context),
                        &shared.signer.verifying_key(),
                        &context.revoked_capabilities,
                    )
                    .map_err(|_| Refusal::NotAuthorized)?;
                    settle_expired(shared, &mut state.journal, context.now_unix_ms)
                        .map_err(reader_refusal)?;
                }
                let challenge: [u8; 32] = rand::random();
                if challenge == [0; 32] {
                    return Err(Refusal::Unavailable);
                }
                write_response(
                    stream,
                    &ReaderResponse::Challenge {
                        enrollment: Box::new(reader.enrollment.clone()),
                        capability: Box::new(reader.capability.clone()),
                        challenge,
                    },
                )?;
                let ReaderRequest::Possession { signature } = read_request(stream)? else {
                    return Err(Refusal::NotAuthorized);
                };
                let mut state = shared.state.lock().expect("mailbox journal lock poisoned");
                let context = guest_context(shared, &state.policy, reader)?;
                let scope = guest_scope(reader, &context);
                let State { policy, journal } = &mut *state;
                settle_expired(shared, journal, context.now_unix_ms).map_err(reader_refusal)?;
                let leased = journal
                    .lease_next(
                        JournalGuestLease {
                            receive: JournalReceive {
                                capability: &reader.capability,
                                context: &context,
                                encryption_key: &policy.encryption_key,
                                sender_key: &policy.sender_key,
                            },
                            plan: &reader.grant,
                            scope,
                            enrollment: &reader.enrollment,
                            challenge: &challenge,
                            possession_signature: &signature,
                            signer: &shared.signer,
                        },
                        |tip| shared.anchor.commit(tip),
                    )
                    .map_err(reader_refusal)?;
                Ok(match leased {
                    Some(message) => ReaderResponse::Delivery {
                        lease: Box::new(message.lease().clone()),
                        content_type: message.content_type().clone(),
                        payload: message.payload().to_vec(),
                    },
                    None => ReaderResponse::Empty,
                })
            }
            ReaderRequest::Ack { signed } => {
                let mut state = shared.state.lock().expect("mailbox journal lock poisoned");
                let context = guest_context(shared, &state.policy, reader)?;
                let scope = guest_scope(reader, &context);
                let State { policy, journal } = &mut *state;
                journal
                    .acknowledge_signed(
                        JournalGuestAck {
                            receive: JournalReceive {
                                capability: &reader.capability,
                                context: &context,
                                encryption_key: &policy.encryption_key,
                                sender_key: &policy.sender_key,
                            },
                            plan: &reader.grant,
                            scope,
                            enrollment: &reader.enrollment,
                            signed: &signed,
                        },
                        |tip| shared.anchor.commit(tip),
                    )
                    .map_err(reader_refusal)?;
                Ok(ReaderResponse::Acknowledged { ack: signed })
            }
            ReaderRequest::Possession { .. } => Err(Refusal::NotAuthorized),
        }
    });
    let response = result.unwrap_or_else(|reason| ReaderResponse::Refused { reason });
    let _ = write_response(stream, &response);
}

fn admit_unit(shared: &Shared) -> Result<(), Refusal> {
    shared
        .unit_gate
        .as_ref()
        .map_or(Ok(()), super::UnitGate::admit)
}

fn guest_context(
    shared: &Shared,
    policy: &MailboxPolicy,
    reader: &GuestReaderAuthority,
) -> Result<OpenContext, Refusal> {
    admit_unit(shared)?;
    // The reader acts at its plan's epoch; only the unit's current one, which
    // the policy took from the epoch gate at bind, may receive.
    if policy.context.expected_mailbox != reader.grant.mailbox
        || admit_at(policy.context.current_execution_epoch, reader.grant.epoch).is_err()
        || policy.context.expected_recipient != reader.capability.grant.address.recipient
        || policy.authority_key.to_bytes() != reader.grant.authority_key
    {
        return Err(Refusal::NotAuthorized);
    }
    let mut context = policy.context.clone();
    context.acting_principal = reader.capability.grant.subject;
    context.expected_capability_issuer = reader.capability.grant.issuer;
    context.required_operation = mvm_contract::protocol::mailbox::MailboxOperation::Receive;
    context.revoked_capabilities = reader_revocations(&reader.revocations_path)?;
    context.now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Refusal::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| Refusal::Unavailable)?;
    Ok(context)
}

fn reader_revocations(path: &Path) -> Result<Vec<RevocationId>, Refusal> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(Refusal::Unavailable),
    };
    let meta = file.metadata().map_err(|_| Refusal::Unavailable)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > 4096 {
        return Err(Refusal::NotAuthorized);
    }
    let mut body = Vec::new();
    file.take(4097)
        .read_to_end(&mut body)
        .map_err(|_| Refusal::Unavailable)?;
    if body.len() > 4096 {
        return Err(Refusal::NotAuthorized);
    }
    let revoked: Vec<RevocationId> =
        serde_json::from_slice(&body).map_err(|_| Refusal::NotAuthorized)?;
    if revoked.len() > 32 {
        return Err(Refusal::NotAuthorized);
    }
    Ok(revoked)
}

fn guest_scope<'a>(
    reader: &'a GuestReaderAuthority,
    context: &OpenContext,
) -> MailboxGuestReaderScope<'a> {
    MailboxGuestReaderScope {
        plan: &reader.grant,
        plan_id: &reader.boot.plan_id,
        plan_nonce: &reader.boot.plan_nonce,
        receive: &reader.capability.grant,
        current_boot: reader.boot.boot,
        current_session: reader.enrollment.enrollment.consumer_session,
        now_unix_ms: context.now_unix_ms,
    }
}

fn reader_refusal(error: JournalError) -> Refusal {
    match error {
        JournalError::Full => Refusal::StorageFull,
        JournalError::Mailbox(MailboxError::Expired) => Refusal::Expired,
        JournalError::Mailbox(_)
        | JournalError::WrongAuthority
        | JournalError::ConflictingRetry
        | JournalError::UnknownMessage
        | JournalError::NoActiveLease
        | JournalError::Busy => Refusal::NotAuthorized,
        _ => Refusal::Unavailable,
    }
}

fn settle_expired(
    shared: &Shared,
    journal: &mut MailboxJournal,
    now_unix_ms: i64,
) -> Result<(), JournalError> {
    for _ in 0..MAX_EXPIRY_RECORDS_PER_REQUEST {
        if journal
            .expire_next(now_unix_ms, &shared.signer, |tip| shared.anchor.commit(tip))?
            .is_none()
        {
            return Ok(());
        }
    }
    Err(JournalError::MaintenancePending)
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
        signal_change(&self.shared);
        if let Some(worker) = self
            .delivery_worker
            .lock()
            .expect("mailbox worker lock poisoned")
            .take()
        {
            let _ = worker.join();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn serve(shared: &Shared, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    if shared.conversation.get().is_some() {
        let deadline = Instant::now() + IO_TIMEOUT;
        let _ = mvm_agentd::vsock::run_with_stream_deadline(&mut stream, deadline, |stream| {
            let body = read_frame(super::peer_transport::PREFACE_BYTES, stream)?;
            let token = super::peer_transport::route_from_preface(&body)?;
            let endpoint = shared.conversation.get().ok_or(Refusal::NotAuthorized)?;
            let peer = endpoint
                .operations
                .lock()
                .expect("conversation owner lock poisoned")
                .peer_for_route(token)?;
            super::peer_transport::receive_peer(stream, &peer, shared.signer.clone(), |frame| {
                let receipt = {
                    let mut operations = endpoint
                        .operations
                        .lock()
                        .expect("conversation owner lock poisoned");
                    if operations.peer_for_route(token)? != peer {
                        return Err(Refusal::NotAuthorized);
                    }
                    operations.accept_peer(frame)?
                };
                signal_change(shared);
                Ok(receipt)
            })?;
            Ok(())
        });
        return;
    }
    let result = read_frame(shared.limits.max_frame_bytes, &mut stream)
        .and_then(|body| decode_frame(&body))
        .and_then(|(capability, envelope)| admit(shared, &capability, &envelope));
    if let Ok(reply) = admission_reply(result, ReplyFormat::Receipt) {
        let _ = stream.write_all(&reply);
    }
}

enum AdmissionReceipt {
    Retained(EncodedDestinationReceipt),
    Legacy(SignedDestinationReceipt),
}

enum ReplyFormat {
    Receipt,
    LegacyUnit,
}

fn admission_reply(
    result: Result<AdmissionReceipt, Refusal>,
    format: ReplyFormat,
) -> Result<Vec<u8>, serde_json::Error> {
    match result {
        Ok(AdmissionReceipt::Retained(receipt)) => {
            let mut reply = b"{\"Ok\":".to_vec();
            reply.extend_from_slice(receipt.encoded());
            reply.push(b'}');
            Ok(reply)
        }
        Ok(AdmissionReceipt::Legacy(signed)) => match format {
            ReplyFormat::Receipt => serde_json::to_vec(&Ok::<_, Refusal>(signed)),
            ReplyFormat::LegacyUnit => serde_json::to_vec(&Ok::<_, Refusal>(())),
        },
        Err(reason) => serde_json::to_vec(&Err::<(), _>(reason)),
    }
}

fn admit_guest(
    shared: &Shared,
    sealer: &mut GuestSealer,
    message: OutboxMessage,
) -> Result<AdmissionReceipt, Refusal> {
    if shared.local_anchor.is_some()
        && let Some((capability, envelope)) = sealer.retained_intent(&message)?
        && let Some(receipt) = operate(shared, &capability, &envelope, AdmissionOperation::Recover)?
    {
        return Ok(receipt);
    }
    let (capability, envelope) = sealer.seal(message)?;
    admit(shared, &capability, &envelope)
}

fn signal_change(shared: &Shared) {
    if let Some(endpoint) = shared.conversation.get() {
        let mut notify = &endpoint.notify;
        // A full nonblocking event socket already carries a pending wake.
        let _ = notify.write(&[1]);
    }
    if let Some(wake) = shared.dispatch_wake.get() {
        let _ = wake.try_send(());
    }
}

// Only the worker owns the timer; wakeups coalesce and never allocate retry jobs.
pub(super) fn delivery_loop(
    events: &mpsc::Receiver<()>,
    stop: &AtomicBool,
    mut drain: impl FnMut() -> bool,
) {
    use rand::RngExt as _;

    const INITIAL_RETRY_MS: u64 = 100;
    const MAX_RETRY_MS: u64 = 5_000;
    let mut failures = 0_u32;
    let mut rng = rand::rng();
    while !stop.load(Ordering::SeqCst) {
        let retry = drain();
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let result = if retry {
            // Equal jitter keeps retries spaced, with a total ceiling of five seconds.
            let ceiling_ms = INITIAL_RETRY_MS
                .saturating_mul(1_u64 << failures.min(16))
                .min(MAX_RETRY_MS);
            failures = failures.saturating_add(1);
            events.recv_timeout(Duration::from_millis(
                rng.random_range(ceiling_ms / 2..=ceiling_ms),
            ))
        } else {
            failures = 0;
            events
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        };
        if matches!(result, Err(mpsc::RecvTimeoutError::Disconnected)) {
            break;
        }
    }
}

fn drain_dispatches(shared: &Shared, stop: &AtomicBool) -> bool {
    let Some(endpoint) = shared.conversation.get() else {
        return false;
    };
    dispatch_pending(&endpoint.operations, &shared.signer, stop, &endpoint.notify)
}

pub(super) fn dispatch_pending(
    operations: &Mutex<Box<dyn ConversationOperations>>,
    signer: &SigningKey,
    stop: &AtomicBool,
    notify: &UnixStream,
) -> bool {
    let pending = operations
        .lock()
        .expect("conversation owner lock poisoned")
        .pending_dispatches();
    let Ok(pending) = pending else {
        return false;
    };
    let mut retry = false;
    for dispatch in pending {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        // Both the network exchange and its receipt verification happen outside
        // the endpoint transaction lock, preventing mutual-send deadlocks.
        let receipt = match super::peer_transport::send_peer(&dispatch, signer.clone()) {
            Ok(receipt) => receipt,
            Err(Refusal::Unavailable) => {
                retry = true;
                continue;
            }
            Err(_) => continue,
        };
        let committed = operations
            .lock()
            .expect("conversation owner lock poisoned")
            .record_dispatch_receipt(dispatch.message_id, receipt);
        if committed.is_err() {
            return false;
        }
        let mut notify = notify;
        let _ = notify.write(&[1]);
    }
    retry
}

fn admit(
    shared: &Shared,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
) -> Result<AdmissionReceipt, Refusal> {
    operate(shared, capability, envelope, AdmissionOperation::Send)?.ok_or(Refusal::Unavailable)
}

enum AdmissionOperation {
    Send,
    Recover,
}

fn operate(
    shared: &Shared,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
    operation: AdmissionOperation,
) -> Result<Option<AdmissionReceipt>, Refusal> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Refusal::Unavailable)?
        .as_millis();
    let now: i64 = now.try_into().map_err(|_| Refusal::Unavailable)?;
    let mut state = shared.state.lock().expect("mailbox journal lock poisoned");
    state.policy.context.now_unix_ms = now;
    let State { policy, journal } = &mut *state;
    let request = || JournalAdmission {
        envelope,
        capability,
        context: &policy.context,
        encryption_key: &policy.encryption_key,
        sender_key: &policy.sender_key,
        signer: &shared.signer,
    };
    if let Some(anchor) = &shared.local_anchor {
        match journal.recover_local_encoded(request(), anchor) {
            Ok(Some(receipt)) => return Ok(Some(AdmissionReceipt::Retained(receipt))),
            Ok(None) => {}
            Err(error) => return Err(admission_refusal(error, capability)),
        }
    }
    if matches!(operation, AdmissionOperation::Recover) {
        return Ok(None);
    }
    // After recovery, so a retry of a message already accepted still gets its
    // receipt; only a new acceptance needs the unit to be current.
    admit_unit(shared)?;
    settle_expired(shared, journal, now).map_err(reader_refusal)?;
    let accepted = match &shared.local_anchor {
        Some(anchor) => journal
            .admit_local_encoded(request(), anchor)
            .map(AdmissionReceipt::Retained),
        None => journal
            .admit(request(), |tip| shared.anchor.commit(tip))
            .map(AdmissionReceipt::Legacy),
    };
    accepted
        .map(Some)
        .map_err(|error| admission_refusal(error, capability))
}

fn admission_refusal(error: JournalError, capability: &SignedMailboxCapability) -> Refusal {
    match error {
        JournalError::Mailbox(MailboxError::WrongRecipient) => Refusal::NotAuthorized,
        JournalError::Mailbox(MailboxError::Expired) => Refusal::Expired,
        JournalError::Mailbox(MailboxError::CapabilityPayloadExceeded) => {
            Refusal::Oversized(capability.grant.max_payload_bytes as usize)
        }
        JournalError::Mailbox(error) => Refusal::Mailbox(error.to_string()),
        JournalError::Full => Refusal::StorageFull,
        JournalError::ConflictingRetry => Refusal::Mailbox(error.to_string()),
        // Unavailable does not assert nonacceptance. The sender keeps its
        // original operation until a signed success can be recovered.
        _ => Refusal::Unavailable,
    }
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

#[cfg(test)]
mod reader_tests {
    use super::*;

    #[test]
    fn accepted_intent_recovers_after_attempt_exhaustion_without_charging_again() {
        use mvm_contract::protocol::mailbox::{
            ExecutionEpoch, MailboxAddress, MailboxId, MailboxRetentionPolicy, MessageId,
        };
        use mvm_core::crypto::aead::Key;
        use mvm_core::mailbox::journal::{HistoryKeyCustody, HistoryKeyRef, JournalLimits};

        struct TestCustody {
            reference: HistoryKeyRef,
            key: Key,
        }
        impl HistoryKeyCustody for TestCustody {
            fn load_existing(&self, reference: &HistoryKeyRef) -> Result<Key, JournalError> {
                if reference != &self.reference {
                    return Err(JournalError::HistoryKeyMismatch);
                }
                Ok(Key::from_bytes(*self.key.expose_bytes()))
            }
        }

        let dir = tempfile::tempdir().expect("test-purpose host custody");
        crate::audit::host_keypair::load_or_init_at(dir.path()).expect("test-purpose signer");
        let mailbox = MailboxId::from_bytes([21; 32]);
        let epoch = ExecutionEpoch::new(1).expect("test epoch");
        let retention = MailboxRetentionPolicy::new(10_000).expect("finite test retention");
        let grant = MailboxGrant {
            mailbox,
            authority_key: crate::mailbox_launch::authority_key_for(dir.path(), &mailbox, epoch)
                .expect("test mailbox authority")
                .to_bytes(),
            epoch,
            report: None,
            retention: Some(retention),
            service_blind: None,
        };
        let keys = crate::mailbox_launch::derive_launch_keys(dir.path(), &grant, &Key::random())
            .expect("test-purpose launch keys");
        let (policy, sealer) = keys.trust(epoch);
        let policy = policy.with_grant(&grant).expect("legacy test policy");
        let mut sealer = sealer.with_grant(&grant).expect("legacy test sealer");
        let intents = dir.path().join("intents");
        sealer.intent_dir = Some(intents.clone());
        let address = MailboxAddress {
            tenant: policy.context.expected_tenant,
            authorization_domain: policy.context.expected_authorization_domain,
            mailbox,
            recipient: policy.context.expected_recipient,
        };
        let reference =
            HistoryKeyRef::new(address, epoch, rand::random(), 1).expect("test history identity");
        let custody = TestCustody {
            reference,
            key: Key::random(),
        };
        let anchor = Arc::new(
            FileJournalAnchor::open(
                &dir.path().join("anchor").join("tip"),
                address,
                rand::random(),
            )
            .expect("test anchor"),
        );
        let (signer, _, _) = keys.durable_material();
        let journal = MailboxJournal::open_local_with_custody(
            &dir.path().join("journal"),
            reference,
            signer.verifying_key(),
            JournalLimits {
                max_records: 64,
                max_bytes: 1024 * 1024,
            },
            &custody,
            &anchor,
            retention,
        )
        .expect("test journal");
        let commit = Arc::clone(&anchor);
        let shared = Shared {
            limits: MailboxLimits {
                max_depth: 64,
                max_frame_bytes: 64 * 1024,
            },
            unit_gate: None,
            state: Mutex::new(State { policy, journal }),
            signer,
            anchor: Box::new(move |tip| commit.advance(tip)),
            local_anchor: Some(anchor),
            reader: OnceLock::new(),
            conversation: OnceLock::new(),
            dispatch_wake: OnceLock::new(),
        };
        let operation = OutboxMessage {
            recipient: address.recipient,
            message_id: MessageId::from_bytes([22; 32]),
            body: b"test-purpose recovery".to_vec(),
        };
        let first = admission_reply(
            admit_guest(&shared, &mut sealer, operation.clone()),
            ReplyFormat::Receipt,
        )
        .expect("signed success bytes");
        let parsed: Result<SignedDestinationReceipt, Refusal> =
            serde_json::from_slice(&first).expect("unchanged success encoding");
        assert!(parsed.is_ok(), "first operation must be accepted");
        for _ in 1..super::super::MAX_SOURCE_ATTEMPTS {
            sealer
                .seal(operation.clone())
                .expect("consume remaining source attempts");
        }
        assert!(matches!(
            sealer.seal(operation.clone()),
            Err(Refusal::RetriesExhausted)
        ));
        let attempts = intents.join(format!(
            "{}.attempts",
            hex::encode(operation.message_id.as_bytes())
        ));
        let before = std::fs::read(&attempts).expect("retained attempt count");
        let recovered = admission_reply(
            admit_guest(&shared, &mut sealer, operation.clone()),
            ReplyFormat::Receipt,
        )
        .expect("recovered success encoding");
        assert_eq!(
            recovered, first,
            "wire success must contain the exact retained encoding"
        );
        assert_eq!(std::fs::read(&attempts).expect("attempt count"), before);
        {
            let mut state = shared.state.lock().expect("test state");
            assert_eq!(
                state.journal.tip().cursor,
                2,
                "recovery must not append or debit"
            );
            state.policy.context.current_policy_epoch += 1;
        }
        assert!(
            admit_guest(&shared, &mut sealer, operation.clone()).is_err(),
            "known identity cannot bypass current authorization"
        );
        shared
            .state
            .lock()
            .expect("test state")
            .policy
            .context
            .current_policy_epoch -= 1;
        let mut changed = operation.clone();
        changed.body.push(b'!');
        assert!(
            admit_guest(&shared, &mut sealer, changed).is_err(),
            "known identity cannot substitute different operation bytes"
        );
        assert_eq!(std::fs::read(&attempts).expect("attempt count"), before);

        let mut unseen = operation;
        unseen.message_id = MessageId::from_bytes([23; 32]);
        for _ in 0..super::super::MAX_SOURCE_ATTEMPTS {
            sealer
                .seal(unseen.clone())
                .expect("stage unseen bounded attempts");
        }
        assert!(
            matches!(
                admit_guest(&shared, &mut sealer, unseen),
                Err(Refusal::RetriesExhausted)
            ),
            "healthy unseen state must still take the charged send path"
        );
        assert_eq!(
            shared
                .state
                .lock()
                .expect("test state")
                .journal
                .tip()
                .cursor,
            2
        );
    }

    #[test]
    fn local_outbox_preserves_unresolved_operation() {
        use mvm_agentd::mailbox_outbox::{forward_local_outbox, write_outbox};
        use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxId, MessageId, PrincipalId};

        let signer = SigningKey::from_bytes(&rand::random());
        let operation = OutboxMessage {
            recipient: PrincipalId::from_bytes([1; 32]),
            message_id: MessageId::from_bytes([2; 32]),
            body: b"test-purpose operation".to_vec(),
        };
        let unavailable =
            serde_json::to_vec(&Err::<SignedDestinationReceipt, _>(Refusal::Unavailable))
                .expect("existing unavailable verdict");
        for reply in [unavailable, Vec::new(), b"{\"Ok\":".to_vec()] {
            let dir = tempfile::tempdir().expect("test-purpose outbox");
            let path = dir.path().join("outbox-local");
            write_outbox(&path, &operation).expect("retain original operation");
            let original = std::fs::read(&path).expect("original request bytes");
            let (mut guest, mut host) = UnixStream::pair().expect("mailbox exchange");
            guest
                .set_read_timeout(Some(IO_TIMEOUT))
                .expect("bounded guest read");
            host.set_read_timeout(Some(IO_TIMEOUT))
                .expect("bounded host read");
            let peer = std::thread::spawn(move || {
                let mut length = [0; 4];
                host.read_exact(&mut length).expect("request length");
                let mut body = vec![0; u32::from_be_bytes(length) as usize];
                host.read_exact(&mut body).expect("request body");
                host.write_all(&reply)
                    .expect("unavailable or incomplete reply");
                body
            });

            let result = forward_local_outbox(
                &mut guest,
                &path,
                &signer.verifying_key(),
                MailboxId::from_bytes([3; 32]),
                ExecutionEpoch::new(1).expect("test epoch"),
            );

            assert!(result.is_err(), "an unresolved operation is not success");
            assert_eq!(
                peer.join().expect("mailbox peer"),
                operation.encode(),
                "the exchange keeps the original operation identity and bytes"
            );
            assert_eq!(
                std::fs::read(&path).expect("unresolved request remains pending"),
                original,
                "unavailable, lost and truncated replies must not remove or replace the request"
            );
        }
    }
    #[test]
    fn delivery_worker_shutdown_interrupts_backoff_without_another_dispatch() {
        let (wake, events) = mpsc::sync_channel(1);
        let (attempted, attempts) = mpsc::sync_channel(1);
        let (finished, completion) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let mut count = 0;
            delivery_loop(&events, &worker_stop, || {
                count += 1;
                if count == 1 {
                    attempted.send(()).unwrap();
                }
                true
            });
            finished.send(count).unwrap();
        });
        attempts.recv_timeout(Duration::from_secs(1)).unwrap();
        stop.store(true, Ordering::SeqCst);
        wake.send(()).unwrap();
        assert_eq!(completion.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        worker.join().unwrap();
    }

    #[test]
    fn pending_read_waits_for_event_disconnect_or_deadline_without_polling_state() {
        let (events, mut notify) = UnixStream::pair().unwrap();
        events.set_nonblocking(true).unwrap();
        let events = Mutex::new(events);
        let (guest, peer) = UnixStream::pair().unwrap();
        notify.write_all(&[1]).unwrap();
        assert_eq!(
            wait_for_change(
                &events,
                guest.as_raw_fd(),
                Instant::now() + Duration::from_secs(1)
            ),
            Ok(true)
        );
        assert_eq!(
            wait_for_change(&events, guest.as_raw_fd(), Instant::now()),
            Ok(false)
        );
        drop(peer);
        assert_eq!(
            wait_for_change(
                &events,
                guest.as_raw_fd(),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Refusal::Unavailable)
        );
    }
    #[test]
    fn an_expired_guest_exchange_refuses_more_reads_and_writes() {
        let (mut socket, _peer) = UnixStream::pair().unwrap();
        let mut expired = GuestDeadline {
            stream: &mut socket,
            until: Instant::now() - Duration::from_millis(1),
        };
        assert_eq!(
            expired.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            expired.write(&[0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn revocations_are_reread_and_corrupt_or_oversized_state_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revoked.json");
        let revoked = RevocationId::from_bytes([5; 32]);
        assert!(reader_revocations(&file).unwrap().is_empty());
        std::fs::write(&file, serde_json::to_vec(&vec![revoked]).unwrap()).unwrap();
        assert_eq!(reader_revocations(&file).unwrap(), vec![revoked]);
        std::fs::write(&file, b"not a revocation list").unwrap();
        assert_eq!(reader_revocations(&file), Err(Refusal::NotAuthorized));
        std::fs::write(&file, vec![b' '; 4097]).unwrap();
        assert_eq!(reader_revocations(&file), Err(Refusal::NotAuthorized));
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink(dir.path().join("missing"), &file).unwrap();
        assert!(reader_revocations(&file).is_err());
    }
}
