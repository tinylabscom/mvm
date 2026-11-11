//! Per-node mailbox service: a bounded local queue behind a Unix domain socket.
//!
//! A peer connects, writes one length-prefixed frame (a capability and a
//! sealed envelope) and reads one typed verdict. A guest instead sends a
//! plaintext message the host seals itself ([`GuestSealer`]). The service opens the
//! envelope (capability, execution epoch, replay, expiry) before it enqueues
//! anything, so a refused message never occupies queue space. This socket
//! carries mailbox frames only; telemetry and control have their own planes.
//!
//! A host reader sends the other kind of frame, a JSON [`HostRequest`] (its
//! first byte is `{`, which no send frame can start with: it would read as a
//! capability length far above any frame limit). The guest's connection never
//! reaches that path, so a guest cannot read, or drain, the queue.
//!
//! Frame: `u32 BE length`, then `u32 BE capability length`, the capability as
//! JSON, and the envelope in its canonical `encode_envelope` form.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    BootId, CorrelationId, DeliveryId, ExecutionEpoch, MailboxCapabilityGrant, MailboxEnvelope,
    MailboxEnvelopeHeader, MailboxGrant, MailboxRoutingFrame, PrincipalId, ReplayNonce,
    SequenceNumber, SignedMailboxCapability,
};
use mvm_core::crypto::aead::Key;
pub use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::frame::{
    OWN_MAILBOX_RECIPIENT, OutboxMessage, decode_frame, encode_frame, send_frame,
};
use mvm_core::mailbox::{
    InMemoryReplayProtector, MailboxError, OpenContext, SealRequest, open_authenticated_envelope,
    open_envelope, seal_envelope, sign_capability,
};
use mvm_core::private_fs;
use mvm_core::util::atomic_io::{FileLock, atomic_write_durable, atomic_write_new, sync_dir};

/// Separate destination path that returns a signed, journal-backed verdict.
pub mod durable;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SOURCE_INTENTS: usize = 64;
const MAX_SOURCE_INTENT_BYTES: usize = 64 * 1024;
const MAX_SOURCE_ATTEMPTS: u8 = 8;

/// Bounds on what one node will hold or accept.
#[derive(Debug, Clone, Copy)]
pub struct MailboxLimits {
    pub max_depth: usize,
    pub max_frame_bytes: usize,
}

/// What the receiving node trusts when it opens a message.
pub struct MailboxPolicy {
    pub context: OpenContext,
    pub encryption_key: Key,
    pub sender_key: VerifyingKey,
    pub authority_key: VerifyingKey,
}

impl MailboxPolicy {
    /// Fold a signed plan's grant into host-held trust. The grant decides
    /// which mailbox, whose capabilities and which epoch; the keys and peer
    /// identities stay what the host already trusted.
    pub fn with_grant(mut self, grant: &MailboxGrant) -> std::io::Result<Self> {
        self.authority_key = VerifyingKey::from_bytes(&grant.authority_key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.context.expected_mailbox = grant.mailbox;
        self.context.current_execution_epoch = grant.epoch;
        Ok(self)
    }
}

/// Host-held material that turns a guest's plaintext message into a sealed,
/// signed one. The guest names a recipient and a body; the keys, the
/// capability and the header template never leave the host and never come
/// from the plan or the guest. Encryption is host to host: this is not
/// guest-to-guest encryption and gives no per-workload sender identity.
pub struct GuestSealer {
    pub encryption_key: Key,
    pub sender_key: SigningKey,
    pub authority_key: SigningKey,
    pub capability: MailboxCapabilityGrant,
    /// Template; recipient, ids, sequence and length are stamped per message.
    pub header: MailboxEnvelopeHeader,
    pub routing: MailboxRoutingFrame,
    /// Messages sealed so far; start at 0.
    pub sent: u64,
    /// Private, bounded source intents retain exact sealed bytes for retries.
    pub intent_dir: Option<PathBuf>,
}

impl GuestSealer {
    /// Bind to a plan's grant: its mailbox and epoch apply, and its authority
    /// key must be the verifying half of the host's own authority key.
    pub fn with_grant(mut self, grant: &MailboxGrant) -> std::io::Result<Self> {
        if self.authority_key.verifying_key().to_bytes() != grant.authority_key {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "grant authority is not the host's authority key",
            ));
        }
        self.capability.address.mailbox = grant.mailbox;
        self.header.mailbox = grant.mailbox;
        self.header.execution_epoch = grant.epoch;
        // The template is stable across restarts; its counter starts over in each
        // process. A fresh boot identity keeps those message/replay IDs distinct.
        self.header.sender_boot = BootId::from_bytes(rand::random());
        Ok(self)
    }

    /// Resolve only the guest's own mailbox alias; all other recipients are
    /// checked against the signed capability by destination admission.
    fn resolve_recipient(&self, named: PrincipalId) -> PrincipalId {
        if named.as_bytes() == self.header.mailbox.as_bytes()
            || named.as_bytes() == &OWN_MAILBOX_RECIPIENT
        {
            self.header.recipient
        } else {
            named
        }
    }

    pub(crate) fn seal(
        &mut self,
        message: OutboxMessage,
    ) -> Result<(SignedMailboxCapability, MailboxEnvelope), Refusal> {
        let Some(dir) = self.intent_dir.clone() else {
            let (capability, envelope, n) = self.seal_new(&message)?;
            self.sent = n;
            return Ok((capability, envelope));
        };
        private_fs::ensure_private_dir(&dir).map_err(|_| Refusal::Unavailable)?;
        sync_dir(dir.parent().ok_or(Refusal::Malformed)?).map_err(|_| Refusal::Unavailable)?;
        let _lock = FileLock::try_acquire(&dir.join("intent"))
            .map_err(|_| Refusal::Unavailable)?
            .ok_or(Refusal::Unavailable)?;
        let path = dir.join(hex::encode(message.message_id.as_bytes()));
        if path.exists() {
            let reused = self.read_intent(&path, &message)?;
            charge_source_attempt(&dir, &message)?;
            return Ok(reused);
        }
        let mut count = 0;
        for entry in std::fs::read_dir(&dir).map_err(|_| Refusal::Unavailable)? {
            let entry = entry.map_err(|_| Refusal::Unavailable)?;
            let name = entry.file_name();
            if name == "intent.lock" || name.to_string_lossy().ends_with(".attempts") {
                continue;
            }
            count += 1;
            if count >= MAX_SOURCE_INTENTS {
                return Err(Refusal::QueueFull(MAX_SOURCE_INTENTS));
            }
        }
        let (capability, envelope, n) = self.seal_new(&message)?;
        let bytes = encode_frame(&capability, &envelope)?;
        if bytes.len() > MAX_SOURCE_INTENT_BYTES {
            return Err(Refusal::Oversized(MAX_SOURCE_INTENT_BYTES));
        }
        atomic_write_new(&path, &bytes).map_err(|_| Refusal::Unavailable)?;
        sync_dir(&dir).map_err(|_| Refusal::Unavailable)?;
        charge_source_attempt(&dir, &message)?;
        self.sent = n;
        Ok((capability, envelope))
    }

    fn read_intent(
        &self,
        path: &Path,
        message: &OutboxMessage,
    ) -> Result<(SignedMailboxCapability, MailboxEnvelope), Refusal> {
        let meta = std::fs::symlink_metadata(path).map_err(|_| Refusal::Unavailable)?;
        if !meta.file_type().is_file()
            || meta.nlink() != 1
            || meta.len() > MAX_SOURCE_INTENT_BYTES as u64
        {
            return Err(Refusal::Malformed);
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| Refusal::Unavailable)?
            .take(MAX_SOURCE_INTENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Refusal::Unavailable)?;
        if bytes.len() > MAX_SOURCE_INTENT_BYTES {
            return Err(Refusal::Oversized(MAX_SOURCE_INTENT_BYTES));
        }
        let (capability, envelope) = decode_frame(&bytes)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Refusal::Unavailable)?
            .as_millis()
            .try_into()
            .map_err(|_| Refusal::Unavailable)?;
        let context = OpenContext {
            expected_tenant: self.header.tenant,
            expected_authorization_domain: self.header.authorization_domain,
            expected_mailbox: self.header.mailbox,
            expected_sender: self.header.sender,
            expected_recipient: self.resolve_recipient(message.recipient),
            acting_principal: self.capability.subject,
            expected_capability_issuer: self.capability.issuer,
            current_execution_epoch: self.header.execution_epoch,
            current_policy_epoch: self.header.policy_epoch,
            required_operation: mvm_contract::protocol::mailbox::MailboxOperation::Send,
            now_unix_ms: now,
            accepted_content_types: vec![self.header.content_type.clone()],
            revoked_capabilities: Vec::new(),
        };
        let opened = open_authenticated_envelope(
            &envelope,
            &capability,
            &context,
            &self.encryption_key,
            &self.sender_key.verifying_key(),
            &self.authority_key.verifying_key(),
            &mut InMemoryReplayProtector::default(),
        )
        .map_err(|e| Refusal::Mailbox(e.to_string()))?;
        if opened.header().message_id != message.message_id
            || opened.header().kind != self.header.kind
            || opened.payload() != message.body
        {
            return Err(Refusal::Mailbox(
                "message identity was reused with different bytes".into(),
            ));
        }
        Ok((capability, envelope))
    }

    fn seal_new(
        &self,
        message: &OutboxMessage,
    ) -> Result<(SignedMailboxCapability, MailboxEnvelope, u64), Refusal> {
        let gate = |e: mvm_core::mailbox::MailboxError| Refusal::Mailbox(e.to_string());
        let n = self.sent.checked_add(1).ok_or(Refusal::Malformed)?;
        let counter = |width: usize| {
            let mut bytes = vec![0; width];
            bytes[width - 8..].copy_from_slice(&n.to_be_bytes());
            bytes
        };
        let mut header = self.header.clone();
        header.recipient = self.resolve_recipient(message.recipient);
        header.message_id = message.message_id;
        header.correlation_id = CorrelationId::from_bytes(*message.message_id.as_bytes());
        header.nonce = ReplayNonce::from_bytes(counter(16).try_into().unwrap());
        header.sequence = SequenceNumber::new(n).map_err(|_| Refusal::Malformed)?;
        header.plaintext_len = message
            .body
            .len()
            .try_into()
            .map_err(|_| Refusal::Malformed)?;
        let capability =
            sign_capability(self.capability.clone(), &self.authority_key).map_err(gate)?;
        let mut routing = self.routing.clone();
        routing.delivery_id = DeliveryId::from_bytes(rand::random());
        let envelope = seal_envelope(
            SealRequest {
                routing,
                header,
                plaintext: &message.body,
            },
            &self.encryption_key,
            &self.sender_key,
        )
        .map_err(gate)?;
        Ok((capability, envelope, n))
    }
}

fn charge_source_attempt(dir: &Path, message: &OutboxMessage) -> Result<(), Refusal> {
    let path = dir.join(format!(
        "{}.attempts",
        hex::encode(message.message_id.as_bytes())
    ));
    let count = match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_file() && meta.len() <= 3 => {
            let raw = std::fs::read(&path).map_err(|_| Refusal::Unavailable)?;
            std::str::from_utf8(&raw)
                .ok()
                .and_then(|n| n.parse::<u8>().ok())
                .ok_or(Refusal::Malformed)?
        }
        Ok(_) => return Err(Refusal::Malformed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err(Refusal::Unavailable),
    };
    if count >= MAX_SOURCE_ATTEMPTS {
        return Err(Refusal::RetriesExhausted);
    }
    atomic_write_durable(&path, (count + 1).to_string().as_bytes())
        .map_err(|_| Refusal::Unavailable)
}

/// Launch-path entry: serve the guest's mailbox port only when the signed
/// plan's `grant` is present. No grant means no socket bound, no dial, and
/// `None`; a grant yields the service holding whatever the guest sent, sealed
/// by `sealer` and opened under `trust`, both host-held.
pub fn serve_granted_guest(
    grant: Option<&MailboxGrant>,
    trust: MailboxPolicy,
    sealer: GuestSealer,
    limits: MailboxLimits,
    socket: &Path,
    guest: (&Path, &Path),
) -> std::io::Result<Option<MailboxService>> {
    let Some(grant) = grant else {
        return Ok(None);
    };
    serve_grant(grant, trust, sealer, limits, socket, guest).map(Some)
}

/// [`serve_granted_guest`] for a caller that already holds the grant rather
/// than the whole plan: the separate mailbox process is handed the grant and
/// the derived trust, never the plan.
pub fn serve_grant(
    grant: &MailboxGrant,
    trust: MailboxPolicy,
    sealer: GuestSealer,
    limits: MailboxLimits,
    socket: &Path,
    guest: (&Path, &Path),
) -> std::io::Result<MailboxService> {
    let mut sealer = sealer.with_grant(grant)?;
    let service = MailboxService::bind_live(socket, limits, trust.with_grant(grant)?)?;
    let _ = service.serve_guest(guest.0, guest.1, &mut sealer)?;
    Ok(service)
}

/// Bind the service for `grant` without dialing the guest, and hand back the
/// grant-bound sealer to serve it with, so a caller can serve the same queue
/// and replay state over many connections.
pub fn bind_grant(
    grant: &MailboxGrant,
    trust: MailboxPolicy,
    sealer: GuestSealer,
    limits: MailboxLimits,
    socket: &Path,
) -> std::io::Result<(MailboxService, GuestSealer)> {
    let sealer = sealer.with_grant(grant)?;
    let service = MailboxService::bind(socket, limits, trust.with_grant(grant)?)?;
    Ok((service, sealer))
}

#[derive(Clone, Copy)]
enum Clock {
    Context,
    Wall,
}

struct State {
    queue: VecDeque<Vec<u8>>,
    accepted: u64,
    read: u64,
    replay: InMemoryReplayProtector,
    policy: MailboxPolicy,
}

struct Shared {
    limits: MailboxLimits,
    clock: Clock,
    state: Mutex<State>,
}

impl Shared {
    /// The oldest plaintext, with the queue's lifetime counters after the take.
    fn take(&self) -> (Option<Vec<u8>>, u64, u64) {
        let mut state = self.state.lock().unwrap();
        let message = state.queue.pop_front();
        state.read += u64::from(message.is_some());
        (message, state.accepted, state.read)
    }
}

/// What a host peer can ask of the queue. Strict: anything else is refused.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRequest {
    request: RequestKind,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum RequestKind {
    Recv,
}

/// The answer to [`HostRequest::Recv`]: the oldest message as hex, or none,
/// and how many messages the queue has accepted and handed out in all.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Received {
    pub message: Option<String>,
    pub accepted: u64,
    pub read: u64,
}

/// The largest reply a reader will take: a frame-limited message in hex.
const MAX_REPLY_BYTES: u64 = 1024 * 1024;

/// Ask the service at `path` for its oldest message. The caller can reach it
/// only as the user the socket belongs to.
pub fn recv(path: &Path) -> std::io::Result<Received> {
    let io_err = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = serde_json::to_vec(&HostRequest {
        request: RequestKind::Recv,
    })?;
    stream.write_all(&(request.len() as u32).to_be_bytes())?;
    stream.write_all(&request)?;
    let mut reply = Vec::new();
    stream.take(MAX_REPLY_BYTES).read_to_end(&mut reply)?;
    serde_json::from_slice::<Result<Received, Refusal>>(&reply)
        .map_err(|e| io_err(format!("mailbox reply: {e}")))?
        .map_err(|r| io_err(format!("mailbox refused the request: {r:?}")))
}

/// How often the accept loop looks for a connection and for the stop flag.
const ACCEPT_POLL: Duration = Duration::from_millis(20);

pub struct MailboxService {
    shared: Arc<Shared>,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl MailboxService {
    /// Bind `path` (replacing a stale socket file) with the caller-supplied
    /// context clock; useful for deterministic callers. The production launch
    /// uses `bind_live` to advance the clock at every admission.
    pub fn bind(
        path: &Path,
        limits: MailboxLimits,
        policy: MailboxPolicy,
    ) -> std::io::Result<Self> {
        Self::bind_with_clock(path, limits, policy, Clock::Context)
    }

    pub(crate) fn bind_live(
        path: &Path,
        limits: MailboxLimits,
        policy: MailboxPolicy,
    ) -> std::io::Result<Self> {
        Self::bind_with_clock(path, limits, policy, Clock::Wall)
    }

    fn bind_with_clock(
        path: &Path,
        limits: MailboxLimits,
        policy: MailboxPolicy,
        clock: Clock,
    ) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        // Polled rather than blocked on, so stopping never depends on the
        // socket path still existing.
        listener.set_nonblocking(true)?;
        let shared = Arc::new(Shared {
            limits,
            clock,
            state: Mutex::new(State {
                queue: VecDeque::new(),
                accepted: 0,
                read: 0,
                replay: InMemoryReplayProtector::default(),
                policy,
            }),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (shared, stop) = (shared.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // A listener's non-blocking mode is inherited on some hosts.
                            let _ = stream.set_nonblocking(false);
                            serve_peer(&shared, stream);
                        }
                        Err(_) => std::thread::sleep(ACCEPT_POLL),
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

    /// The execution epoch this node currently accepts.
    pub fn set_current_epoch(&self, epoch: ExecutionEpoch) {
        self.shared
            .state
            .lock()
            .unwrap()
            .policy
            .context
            .current_execution_epoch = epoch;
    }

    /// Serve one connection the host dialed to the guest's mailbox port
    /// (per-port socket, or the Firecracker mux), the way the telemetry
    /// collector attaches. The guest sends plaintext; `sealer` seals it, then
    /// admission and the queue are the service's own, so a guest that floods
    /// this port fills only this queue.
    ///
    /// Returns an error when the guest sent no frame at all, which is what a
    /// guest whose workload has not written its outbox yet looks like; the
    /// launch path dials again rather than miss a message written after the
    /// first dial. A frame the queue refuses is still a served connection.
    pub fn serve_guest(
        &self,
        per_port: &Path,
        firecracker_mux: &Path,
        sealer: &mut GuestSealer,
    ) -> std::io::Result<bool> {
        let stream = crate::telemetry_collector::dial_guest_port(
            per_port,
            firecracker_mux,
            mvm_contract::protocol::mailbox::MAILBOX_PORT,
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(7)))?;
        Ok(serve(&self.shared, stream, |body| {
            sealer.seal(OutboxMessage::decode(body)?)
        }))
    }

    /// Dev-only Send on the existing mailbox port. A reader frame is refused
    /// explicitly until independent durable authority can back guest leases.
    pub(crate) fn serve_guest_route(
        &self,
        route: &mvm_core::vm_backend::HostDialRoute,
        sealer: &mut GuestSealer,
    ) -> std::io::Result<bool> {
        let mut stream = crate::telemetry_collector::dial_guest_route(
            route,
            mvm_contract::protocol::mailbox::MAILBOX_PORT,
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(7)))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let frame = read_frame(self.shared.limits.max_frame_bytes, &mut stream);
        if let Ok(body) = &frame
            && mvm_core::mailbox::reader_wire::is_reader_frame(body)
        {
            mvm_core::mailbox::reader_wire::write_response(
                &mut stream,
                &mvm_core::mailbox::reader_wire::ReaderResponse::Refused {
                    reason: Refusal::Unavailable,
                },
            )
            .map_err(std::io::Error::other)?;
            return Ok(true);
        }
        let received = frame.is_ok();
        answer(&self.shared, &mut stream, frame, |body| {
            sealer.seal(OutboxMessage::decode(body)?)
        });
        Ok(received)
    }

    /// Take the oldest accepted plaintext, if any.
    pub fn receive(&self) -> Option<Vec<u8>> {
        self.shared.take().0
    }
}

impl Drop for MailboxService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Send one sealed envelope to the service at `path` and return its verdict.
pub fn send(
    path: &Path,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
) -> Result<(), Refusal> {
    send_on(
        UnixStream::connect(path).map_err(|_| Refusal::Malformed)?,
        capability,
        envelope,
    )
}

/// Write one frame on an already-connected `stream` and read the verdict.
pub fn send_on(
    mut stream: UnixStream,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
) -> Result<(), Refusal> {
    let io = |_| Refusal::Malformed;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    send_frame(&mut stream, capability, envelope)
}

/// Read one frame, turn it into a capability and envelope with `prepare`, and
/// answer with the admission verdict. Returns whether a frame arrived.
fn serve(
    shared: &Shared,
    mut stream: UnixStream,
    prepare: impl FnOnce(&[u8]) -> Result<(SignedMailboxCapability, MailboxEnvelope), Refusal>,
) -> bool {
    if stream.read_timeout().ok().flatten().is_none() {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    }
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let frame = read_frame(shared.limits.max_frame_bytes, &mut stream);
    let received = frame.is_ok();
    answer(shared, &mut stream, frame, prepare);
    received
}

/// A host peer's connection: a read request, or a sealed send.
fn serve_peer(shared: &Shared, mut stream: UnixStream) {
    arm(&stream);
    match read_frame(shared.limits.max_frame_bytes, &mut stream) {
        Ok(body) if body.first() == Some(&b'{') => {
            let reply = serde_json::from_slice::<HostRequest>(&body)
                .map(
                    |HostRequest {
                         request: RequestKind::Recv,
                     }| {
                        let (message, accepted, read) = shared.take();
                        Received {
                            message: message.map(hex::encode),
                            accepted,
                            read,
                        }
                    },
                )
                .map_err(|_| Refusal::Malformed);
            reply_with(&mut stream, &reply);
        }
        frame => answer(shared, &mut stream, frame, decode_frame),
    }
}

fn arm(stream: &UnixStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
}

fn answer(
    shared: &Shared,
    stream: &mut UnixStream,
    frame: Result<Vec<u8>, Refusal>,
    prepare: impl FnOnce(&[u8]) -> Result<(SignedMailboxCapability, MailboxEnvelope), Refusal>,
) {
    let verdict = frame
        .and_then(|body| prepare(&body))
        .and_then(|(capability, envelope)| admit(shared, &capability, &envelope));
    reply_with(stream, &verdict);
}

fn reply_with<T: serde::Serialize>(stream: &mut UnixStream, reply: &Result<T, Refusal>) {
    if let Ok(reply) = serde_json::to_vec(reply) {
        let _ = stream.write_all(&reply);
    }
}

fn read_frame(max: usize, stream: &mut impl Read) -> Result<Vec<u8>, Refusal> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|_| Refusal::Malformed)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(Refusal::Oversized(max));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|_| Refusal::Malformed)?;
    Ok(body)
}

fn admit(
    shared: &Shared,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
) -> Result<(), Refusal> {
    let mut guard = shared.state.lock().unwrap();
    let state = &mut *guard;
    if state.queue.len() >= shared.limits.max_depth {
        return Err(Refusal::QueueFull(shared.limits.max_depth));
    }
    if let Clock::Wall = shared.clock {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Refusal::Malformed)?
            .as_millis();
        state.policy.context.now_unix_ms = now.try_into().map_err(|_| Refusal::Malformed)?;
    }
    let p = &state.policy;
    let plaintext = open_envelope(
        envelope,
        capability,
        &p.context,
        &p.encryption_key,
        &p.sender_key,
        &p.authority_key,
        &mut state.replay,
    )
    .map_err(|error| match error {
        MailboxError::WrongRecipient => Refusal::NotAuthorized,
        _ => Refusal::Mailbox(error.to_string()),
    })?;
    state.queue.push_back(plaintext);
    state.accepted += 1;
    Ok(())
}
