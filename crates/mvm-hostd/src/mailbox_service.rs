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
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
use mvm_core::host_interface::epoch_gate::CommandGate;
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

/// VM-scoped actor call/reply storage and fixed-peer ingress.
pub mod actor_operations;
/// VM-scoped durable call correlation; never a shared scheduler key holder.
pub mod conversation;
/// Separate destination path that returns a signed, journal-backed verdict.
pub mod durable;
/// Scoped holder-to-holder encrypted transport over the existing mailbox endpoint.
pub mod peer_transport;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SOURCE_INTENTS: usize = 64;
const MAX_SOURCE_INTENT_BYTES: usize = 64 * 1024;
const MAX_SOURCE_ATTEMPTS: u8 = 8;
/// How long a dialed guest may hold its connection before sending a frame:
/// longer than the guest's own hold, so the guest ends it.
const GUEST_HOLD_TIMEOUT: Duration = Duration::from_secs(150);

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
    /// The receiving unit's epoch gate, asked again before each message is
    /// taken. `None` only for a caller that has no workload ledger.
    pub unit_gate: Option<UnitGate>,
}

impl MailboxPolicy {
    /// Accept messages only while `gate` admits its unit at its bound epoch,
    /// which also becomes the epoch this policy opens envelopes at.
    pub fn gated(mut self, gate: UnitGate) -> Self {
        self.context.current_execution_epoch = gate.epoch;
        self.unit_gate = Some(gate);
        self
    }

    /// Fold a signed plan's grant into host-held trust. The grant decides
    /// which mailbox and whose capabilities; the keys and peer identities stay
    /// what the host already trusted. The epoch the policy accepts is not the
    /// grant's: it is the receiving unit's current epoch, which the bind site
    /// reads from the epoch gate ([`bound_epoch`]).
    pub fn with_grant(mut self, grant: &MailboxGrant) -> std::io::Result<Self> {
        self.authority_key = VerifyingKey::from_bytes(&grant.authority_key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.context.expected_mailbox = grant.mailbox;
        Ok(self)
    }
}

/// The current execution epoch of `unit`, the unit whose service is binding
/// to check its incoming messages, read once from the workload ledger under
/// `home`. A quarantined unit is refused, so its service never binds.
///
/// A running service keeps checking it per message through [`UnitGate`].
pub fn bound_epoch(home: &Path, unit: &str) -> std::io::Result<ExecutionEpoch> {
    let gate = CommandGate::load_at(home).map_err(std::io::Error::other)?;
    gate.admit(unit, gate.current(unit))
        .map_err(|denial| std::io::Error::new(std::io::ErrorKind::PermissionDenied, denial))
}

/// A unit's epoch gate as a running service holds it: the unit, the epoch it
/// bound at, and the home whose ledger it re-reads before taking each message,
/// so a replacement or quarantine committed after bind refuses the next one.
///
/// The ledger is loaded on every check rather than cached behind a file
/// identity test: a commit renames a fresh file into place, and an inode the
/// filesystem reuses could make a cached view miss a commit.
#[derive(Debug, Clone)]
pub struct UnitGate {
    home: PathBuf,
    unit: String,
    epoch: ExecutionEpoch,
}

impl UnitGate {
    /// The gate for `unit` at its current epoch ([`bound_epoch`]); a
    /// quarantined unit is refused.
    pub fn bind(home: &Path, unit: &str) -> std::io::Result<Self> {
        Ok(Self {
            epoch: bound_epoch(home, unit)?,
            home: home.to_owned(),
            unit: unit.to_owned(),
        })
    }

    /// The epoch the unit was bound at.
    pub fn epoch(&self) -> ExecutionEpoch {
        self.epoch
    }

    /// Does the ledger still admit the bound epoch? A stale, unpromoted or
    /// quarantined unit is refused with the gate's reason; an unreadable
    /// ledger is unavailable, never admitted.
    pub(crate) fn admit(&self) -> Result<(), Refusal> {
        let gate = CommandGate::load_at(&self.home).map_err(|_| Refusal::Unavailable)?;
        gate.admit(&self.unit, self.epoch)
            .map(drop)
            .map_err(|denial| Refusal::Mailbox(denial.to_string()))
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

    pub(super) fn retained_intent(
        &self,
        message: &OutboxMessage,
    ) -> Result<Option<(SignedMailboxCapability, MailboxEnvelope)>, Refusal> {
        let Some(dir) = &self.intent_dir else {
            return Ok(None);
        };
        let path = dir.join(hex::encode(message.message_id.as_bytes()));
        match std::fs::symlink_metadata(&path) {
            Ok(_) => self.read_intent(&path, message).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Refusal::Unavailable),
        }
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
    guest: &mvm_core::vm_backend::HostDialRoute,
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
    guest: &mvm_core::vm_backend::HostDialRoute,
) -> std::io::Result<MailboxService> {
    let (service, mut sealer) = bind_grant(grant, trust, sealer, limits, socket)?;
    service.serve_guest(guest, &mut sealer)?;
    Ok(service)
}

/// Bind the service for `grant` without dialing the guest, and hand back the
/// grant-bound sealer to serve it with. Live admission uses the current wall
/// clock on every request, not the time the helper first bound the listener.
pub fn bind_grant(
    grant: &MailboxGrant,
    trust: MailboxPolicy,
    sealer: GuestSealer,
    limits: MailboxLimits,
    socket: &Path,
) -> std::io::Result<(MailboxService, GuestSealer)> {
    let sealer = sealer.with_grant(grant)?;
    let service = MailboxService::bind_live(socket, limits, trust.with_grant(grant)?)?;
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
    /// Taken out of the policy at bind so a check never holds the queue lock.
    unit_gate: Option<UnitGate>,
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

    /// Put a taken message back at the head, as if it had never been read.
    /// A concurrent admission may have used the freed slot, so the queue can
    /// briefly hold one past `max_depth`.
    fn restore(&self, message: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.queue.push_front(message);
        state.read -= 1;
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

/// Block until `listener` or `wake` is readable. Returns whether `listener` is.
fn wait_readable(listener: &UnixListener, wake: &UnixStream) -> bool {
    let mut fds = [listener.as_raw_fd(), wake.as_raw_fd()].map(|fd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    });
    // SAFETY: `fds` is a live array of two descriptors the caller owns for the call.
    let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
    ready > 0 && fds[0].revents & libc::POLLIN != 0
}

pub struct MailboxService {
    shared: Arc<Shared>,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    wake: UnixStream,
    /// Accept-loop wakeups; only the idle-cost test reads it.
    #[cfg_attr(not(test), allow(dead_code))]
    wakeups: Arc<AtomicU64>,
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
        mut policy: MailboxPolicy,
        clock: Clock,
    ) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        // Non-blocking so a connection that vanishes between poll and accept
        // cannot park the worker past a stop.
        listener.set_nonblocking(true)?;
        let (wake, wake_read) = UnixStream::pair()?;
        let wakeups = Arc::new(AtomicU64::new(0));
        let shared = Arc::new(Shared {
            limits,
            clock,
            unit_gate: policy.unit_gate.take(),
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
            let (shared, stop, wakeups) = (shared.clone(), stop.clone(), wakeups.clone());
            std::thread::spawn(move || {
                // Blocks on the listener and the wake end, so an idle service
                // costs no wakeups and a stop never depends on the socket path.
                while !stop.load(Ordering::SeqCst) {
                    let connection = wait_readable(&listener, &wake_read);
                    wakeups.fetch_add(1, Ordering::Relaxed);
                    if let (true, Ok((stream, _))) = (connection, listener.accept()) {
                        // A listener's non-blocking mode is inherited on some hosts.
                        let _ = stream.set_nonblocking(false);
                        serve_peer(&shared, stream);
                    }
                }
            })
        };
        Ok(Self {
            shared,
            path: path.to_owned(),
            stop,
            wake,
            wakeups,
            worker: Some(worker),
        })
    }

    /// Serve one connection the host dialed to the guest's mailbox port
    /// (the backend's `HostDialRoute`), the way the telemetry
    /// collector attaches. The guest sends plaintext; `sealer` seals it, then
    /// admission and the queue are the service's own, so a guest that floods
    /// this port fills only this queue.
    ///
    /// Returns an error when the guest sent no frame at all, which is what a
    /// guest whose workload has not written its outbox yet looks like; the
    /// launch path dials again rather than miss a message written after the
    /// first dial. A frame the queue refuses is still a served connection,
    /// except when the queue is full: the guest keeps that frame to resend, so
    /// the launch path treats it as no progress and backs off rather than
    /// redialing at the post-frame pace.
    pub fn serve_guest(
        &self,
        route: &mvm_core::vm_backend::HostDialRoute,
        sealer: &mut GuestSealer,
    ) -> std::io::Result<()> {
        self.serve_guest_waiting(route, sealer, IO_TIMEOUT, || true)
    }

    /// Keep one idle guest connection until it has a frame or this VM stops.
    pub(crate) fn serve_guest_while(
        &self,
        route: &mvm_core::vm_backend::HostDialRoute,
        sealer: &mut GuestSealer,
        active: impl Fn() -> bool,
    ) -> std::io::Result<()> {
        self.serve_guest_waiting(route, sealer, GUEST_HOLD_TIMEOUT, active)
    }

    /// [`Self::serve_guest`] for the launch path: waits up to
    /// [`GUEST_HOLD_TIMEOUT`] for a guest that holds its connection open until
    /// the workload writes, and gives the connection up within a poll of
    /// `stop` being set.
    pub fn serve_guest_until(
        &self,
        route: &mvm_core::vm_backend::HostDialRoute,
        sealer: &mut GuestSealer,
        stop: &AtomicBool,
    ) -> std::io::Result<()> {
        self.serve_guest_waiting(route, sealer, GUEST_HOLD_TIMEOUT, || {
            !stop.load(Ordering::SeqCst)
        })
    }

    fn serve_guest_waiting(
        &self,
        route: &mvm_core::vm_backend::HostDialRoute,
        sealer: &mut GuestSealer,
        first_byte: Duration,
        active: impl Fn() -> bool,
    ) -> std::io::Result<()> {
        let stream = crate::telemetry_collector::dial_route(
            route,
            mvm_contract::protocol::mailbox::MAILBOX_PORT,
        )?;
        if !await_first_byte(&stream, first_byte, active) {
            return Err(std::io::Error::other("the guest sent no mailbox frame"));
        }
        match serve(&self.shared, stream, |body| {
            sealer.seal(OutboxMessage::decode(body)?)
        }) {
            Served::Frame => Ok(()),
            Served::QueueFull => Err(std::io::Error::other(
                "the mailbox queue is full; the guest keeps its frame",
            )),
            Served::NoFrame => Err(std::io::Error::other("the guest sent no mailbox frame")),
        }
    }

    /// Take the oldest accepted plaintext, if any.
    pub fn receive(&self) -> Option<Vec<u8>> {
        self.shared.take().0
    }
}

impl Drop for MailboxService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = (&self.wake).write_all(&[0]);
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

/// How a guest connection ended.
enum Served {
    /// A frame arrived and was answered, delivered or refused for good.
    Frame,
    /// A frame arrived and the queue had no room for it.
    QueueFull,
    NoFrame,
}

/// Read one frame, turn it into a capability and envelope with `prepare`, and
/// answer with the admission verdict.
fn serve(
    shared: &Shared,
    mut stream: UnixStream,
    prepare: impl FnOnce(&[u8]) -> Result<(SignedMailboxCapability, MailboxEnvelope), Refusal>,
) -> Served {
    arm(&stream);
    let Some(frame) = read_queued_frame(shared, &mut stream) else {
        return Served::NoFrame;
    };
    if let Ok(body) = &frame
        && mvm_core::mailbox::reader_wire::is_reader_frame(body)
    {
        let _ = mvm_core::mailbox::reader_wire::write_response(
            &mut stream,
            &mvm_core::mailbox::reader_wire::ReaderResponse::Refused {
                reason: Refusal::Unavailable,
            },
        );
        return Served::Frame;
    }
    let received = frame.is_ok();
    let verdict = answer(shared, &mut stream, frame, prepare);
    match (received, verdict) {
        (false, _) => Served::NoFrame,
        (true, Err(Refusal::QueueFull(_))) => Served::QueueFull,
        (true, _) => Served::Frame,
    }
}

/// Wait for the first byte (or EOF) without consuming it, in short slices
/// while the owner still permits this guest connection.
fn await_first_byte(stream: &UnixStream, wait: Duration, active: impl Fn() -> bool) -> bool {
    const SLICE_MS: i32 = 200;
    let deadline = std::time::Instant::now() + wait;
    loop {
        let mut p = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `p` is one valid pollfd for an fd `stream` keeps open, and
        // the slice bounds how long the call blocks.
        let rc = unsafe { libc::poll(&mut p, 1, SLICE_MS) };
        if rc > 0 {
            // Readable: a byte, or EOF, which `read_queued_frame` reports as no frame.
            return active() && p.revents & libc::POLLIN != 0;
        }
        let interrupted =
            rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted;
        if interrupted || !active() || std::time::Instant::now() >= deadline {
            return false;
        }
    }
}

/// A host peer's connection: a read request, or a sealed send.
fn serve_peer(shared: &Shared, mut stream: UnixStream) {
    arm(&stream);
    let Some(frame) = read_queued_frame(shared, &mut stream) else {
        return;
    };
    match frame {
        Ok(body) if body.first() == Some(&b'{') => {
            match serde_json::from_slice::<HostRequest>(&body) {
                Ok(HostRequest {
                    request: RequestKind::Recv,
                }) => serve_recv(shared, &mut stream),
                Err(_) => {
                    let _ = reply_with(&mut stream, &Err::<Received, _>(Refusal::Malformed));
                }
            }
        }
        frame => {
            let _ = answer(shared, &mut stream, frame, decode_frame);
        }
    }
}

/// Hand out the oldest message, keeping it queued unless the reply was written.
fn serve_recv(shared: &Shared, out: &mut impl Write) {
    let (message, accepted, read) = shared.take();
    let reply = Received {
        message: message.as_deref().map(hex::encode),
        accepted,
        read,
    };
    if reply_with(out, &Ok::<_, Refusal>(reply)).is_err()
        && let Some(message) = message
    {
        shared.restore(message);
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
) -> Result<(), Refusal> {
    let verdict = frame
        .and_then(|body| prepare(&body))
        .and_then(|(capability, envelope)| admit(shared, &capability, &envelope));
    let _ = reply_with(stream, &verdict);
    verdict
}

fn reply_with<T: serde::Serialize>(
    out: &mut impl Write,
    reply: &Result<T, Refusal>,
) -> std::io::Result<()> {
    out.write_all(&serde_json::to_vec(reply)?)
}

/// `None` means the peer sent not one byte (hung up, reset or timed out), so
/// there is nobody to answer; a peer that began a frame gets its refusal.
fn read_queued_frame(shared: &Shared, stream: &mut UnixStream) -> Option<Result<Vec<u8>, Refusal>> {
    let max = shared.limits.max_frame_bytes;
    let mut len = [0u8; 4];
    match stream.read(&mut len[..1]) {
        Ok(1) => {}
        _ => return None,
    }
    Some(read_rest(stream, &mut len, max))
}

fn read_frame(max: usize, stream: &mut impl Read) -> Result<Vec<u8>, Refusal> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len[..1])
        .map_err(|_| Refusal::Malformed)?;
    read_rest(stream, &mut len, max)
}

fn read_rest(stream: &mut impl Read, len: &mut [u8; 4], max: usize) -> Result<Vec<u8>, Refusal> {
    stream
        .read_exact(&mut len[1..])
        .map_err(|_| Refusal::Malformed)?;
    let len = u32::from_be_bytes(*len) as usize;
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
    if let Some(gate) = &shared.unit_gate {
        gate.admit()?;
    }
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

#[cfg(test)]
mod accept_loop_tests {
    use super::*;

    fn test_secret() -> mvm_core::crypto::aead::Key {
        mvm_core::crypto::aead::Key::from_bytes([5; 32])
    }
    use std::time::Instant;

    fn service(dir: &Path) -> MailboxService {
        crate::audit::host_keypair::load_or_init_at(dir).unwrap();
        let mailbox = mvm_contract::protocol::mailbox::MailboxId::from_bytes([5; 32]);
        let grant = MailboxGrant {
            mailbox,
            authority_key: crate::mailbox_launch::authority_key_for(
                dir,
                &mailbox,
                ExecutionEpoch::new(1).unwrap(),
            )
            .unwrap()
            .to_bytes(),
            epoch: ExecutionEpoch::new(1).unwrap(),
            report: None,
            retention: None,
            service_blind: None,
        };
        let (trust, _) =
            crate::mailbox_launch::host_trust(dir, &grant, &test_secret(), grant.epoch).unwrap();
        let limits = MailboxLimits {
            max_depth: 4,
            max_frame_bytes: 1024,
        };
        MailboxService::bind(&dir.join("m.sock"), limits, trust).unwrap()
    }

    #[test]
    fn an_idle_service_blocks_instead_of_polling() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        std::thread::sleep(Duration::from_millis(300));
        assert!(service.wakeups.load(Ordering::Relaxed) <= 2);
    }

    #[test]
    fn stopping_is_prompt_with_the_socket_path_already_gone() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        std::fs::remove_file(dir.path().join("m.sock")).unwrap();
        let start = Instant::now();
        drop(service);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_burst_of_sequential_requests_is_served() {
        let dir = tempfile::tempdir().unwrap();
        let _service = service(dir.path());
        for _ in 0..50 {
            let got = recv(&dir.path().join("m.sock")).unwrap();
            assert!(got.message.is_none());
        }
    }

    /// Feed `bytes` to `f` over a pair, half-close, and return what `f` wrote
    /// back, read to EOF under a deadline.
    fn exchange(bytes: &[u8], f: impl FnOnce(UnixStream)) -> Vec<u8> {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(bytes).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        f(server);
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        got
    }

    fn guest(service: &MailboxService, bytes: &[u8]) -> (Vec<u8>, bool) {
        let mut no_frame = false;
        let got = exchange(bytes, |s| {
            no_frame = matches!(
                serve(&service.shared, s, |_| Err(Refusal::Malformed)),
                Served::NoFrame
            );
        });
        (got, no_frame)
    }

    #[test]
    fn a_silent_guest_is_not_answered() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        assert_eq!(guest(&service, b""), (Vec::new(), true));
    }

    #[test]
    fn a_partial_guest_frame_still_gets_its_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let (got, no_frame) = guest(&service, &[0, 0]);
        assert_eq!(got, br#"{"Err":"Malformed"}"#);
        assert!(no_frame);
    }

    #[test]
    fn an_oversized_guest_frame_still_gets_its_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let (got, _) = guest(&service, &u32::MAX.to_be_bytes());
        assert!(String::from_utf8(got).unwrap().contains("Oversized"));
    }

    #[test]
    fn a_whole_guest_frame_is_answered() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let (got, no_frame) = guest(&service, &[0, 0, 0, 1, 7]);
        assert_eq!(got, br#"{"Err":"Malformed"}"#);
        assert!(!no_frame);
    }

    #[test]
    fn a_silent_host_peer_is_not_answered_and_recv_is_still_served() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        assert!(exchange(b"", |s| serve_peer(&service.shared, s)).is_empty());
        let req = br#"{"request":"Recv"}"#;
        let mut framed = (req.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(req);
        let got = exchange(&framed, |s| serve_peer(&service.shared, s));
        assert!(!got.is_empty());
    }

    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn queue_two(service: &MailboxService) {
        let mut state = service.shared.state.lock().unwrap();
        state.queue.extend([b"one".to_vec(), b"two".to_vec()]);
        state.accepted = 2;
    }

    fn recv_via(service: &MailboxService, out: &mut impl Write) {
        serve_recv(&service.shared, out);
    }

    #[test]
    fn a_failed_recv_reply_leaves_the_message_queued_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        queue_two(&service);
        recv_via(&service, &mut FailingWriter);
        {
            let state = service.shared.state.lock().unwrap();
            assert_eq!((state.accepted, state.read), (2, 0));
        }
        assert_eq!(service.receive().as_deref(), Some(&b"one"[..]));
        assert_eq!(service.receive().as_deref(), Some(&b"two"[..]));
    }

    #[test]
    fn a_delivered_recv_reply_consumes_the_message_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        queue_two(&service);
        let mut out = Vec::new();
        recv_via(&service, &mut out);
        let got: Result<Received, Refusal> = serde_json::from_slice(&out).unwrap();
        let got = got.unwrap();
        assert_eq!(got.message, Some(hex::encode(b"one")));
        assert_eq!((got.accepted, got.read), (2, 1));
        assert_eq!(service.receive().as_deref(), Some(&b"two"[..]));
        assert_eq!(service.receive(), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox_launch::{LAUNCH_LIMITS, authority_key_for, derive_launch_keys};
    use mvm_contract::protocol::mailbox::{MailboxId, MessageId};

    fn test_secret() -> mvm_core::crypto::aead::Key {
        mvm_core::crypto::aead::Key::from_bytes([5; 32])
    }

    const MAILBOX: [u8; 32] = [4; 32];

    fn grant_at(keys: &Path, epoch: u64) -> MailboxGrant {
        let mailbox = MailboxId::from_bytes(MAILBOX);
        let epoch = ExecutionEpoch::new(epoch).unwrap();
        MailboxGrant {
            mailbox,
            authority_key: authority_key_for(keys, &mailbox, epoch).unwrap().to_bytes(),
            epoch,
            report: None,
            retention: None,
            service_blind: None,
        }
    }

    fn greeting() -> OutboxMessage {
        OutboxMessage {
            recipient: PrincipalId::from_bytes(OWN_MAILBOX_RECIPIENT),
            message_id: MessageId::from_bytes([7; 32]),
            body: b"epoch one secret".to_vec(),
        }
    }

    // These historical-epoch fixtures use their fixed context time; production
    // bind_grant instead consults the current wall clock on every admission.
    fn bind_fixture_grant(
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

    fn launch(keys: &Path, socket: &Path, epoch: u64) -> (MailboxService, GuestSealer) {
        let grant = grant_at(keys, epoch);
        let (policy, sealer) = derive_launch_keys(keys, &grant, &test_secret())
            .unwrap()
            .trust(grant.epoch);
        bind_fixture_grant(&grant, policy, sealer, LAUNCH_LIMITS, socket).unwrap()
    }

    /// A unit's service bound the way the mailbox process binds it: its
    /// current epoch read once from the ledger under `home`. Its guest seals
    /// under a grant at `sealed`.
    fn bind_unit(
        home: &Path,
        unit: &str,
        socket: &Path,
        sealed: u64,
    ) -> std::io::Result<(MailboxService, GuestSealer)> {
        let grant = grant_at(home, sealed);
        let (policy, sealer) = derive_launch_keys(home, &grant, &test_secret())
            .unwrap()
            .trust(bound_epoch(home, unit)?);
        bind_fixture_grant(&grant, policy, sealer, LAUNCH_LIMITS, socket)
    }

    /// Send one guest message through a unit's service; the refusal, if any.
    fn deliver(home: &Path, unit: &str, sealed: u64) -> std::result::Result<(), Refusal> {
        let socket = home.join(format!("{unit}-{sealed}.sock"));
        let (service, mut sealer) = bind_unit(home, unit, &socket, sealed).unwrap();
        let (capability, envelope) = sealer.seal(greeting()).unwrap();
        send(&socket, &capability, &envelope)?;
        assert!(service.receive().is_some(), "an accepted message is queued");
        Ok(())
    }

    fn refused(error: mvm_core::mailbox::MailboxError) -> std::result::Result<(), Refusal> {
        Err(Refusal::Mailbox(error.to_string()))
    }

    /// A home whose ledger has replaced unit `a` once, to epoch 2, and has
    /// never touched unit `b`.
    fn ledger_with_a_replaced() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(home.path()).unwrap();
        crate::policy_generation::workload_store::OwnedWorkloadStore::open(home.path())
            .unwrap()
            .commit(
                &mvm_core::host_interface::workload::WorkloadChange::Replace {
                    workload: "a".into(),
                    from_epoch: ExecutionEpoch::FIRST,
                },
            )
            .unwrap();
        home
    }

    #[test]
    fn a_service_binds_at_its_units_ledger_epoch_and_refuses_any_other() {
        use mvm_core::mailbox::MailboxError::{ExecutionEpochNotPromoted, StaleExecutionEpoch};
        let home = ledger_with_a_replaced();
        let home = home.path();
        assert_eq!(
            bound_epoch(home, "a").unwrap(),
            ExecutionEpoch::new(2).unwrap()
        );
        assert_eq!(deliver(home, "a", 2), Ok(()));
        assert_eq!(deliver(home, "a", 1), refused(StaleExecutionEpoch));
        assert_eq!(deliver(home, "a", 3), refused(ExecutionEpochNotPromoted));
    }

    #[test]
    fn two_units_are_gated_by_their_own_ledger_epochs() {
        use mvm_core::mailbox::MailboxError::{ExecutionEpochNotPromoted, StaleExecutionEpoch};
        let home = ledger_with_a_replaced();
        let home = home.path();
        assert_eq!(bound_epoch(home, "b").unwrap(), ExecutionEpoch::FIRST);
        assert_eq!(deliver(home, "b", 1), Ok(()));
        assert_eq!(deliver(home, "b", 2), refused(ExecutionEpochNotPromoted));
        assert_eq!(deliver(home, "a", 2), Ok(()));
        assert_eq!(deliver(home, "a", 1), refused(StaleExecutionEpoch));
    }

    #[test]
    fn a_quarantined_units_service_does_not_bind() {
        let home = ledger_with_a_replaced();
        crate::policy_generation::workload_store::OwnedWorkloadStore::open(home.path())
            .unwrap()
            .commit(
                &mvm_core::host_interface::workload::WorkloadChange::Quarantine {
                    workload: "a".into(),
                },
            )
            .unwrap();
        let socket = home.path().join("a.sock");
        let refused = bind_unit(home.path(), "a", &socket, 2).err().unwrap();
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!socket.exists(), "a quarantined unit binds no listener");
        assert!(
            bound_epoch(home.path(), "b").is_ok(),
            "bystander unaffected"
        );
    }

    fn message(n: u8) -> OutboxMessage {
        OutboxMessage {
            message_id: MessageId::from_bytes([n; 32]),
            ..greeting()
        }
    }

    fn commit(home: &Path, change: mvm_core::host_interface::workload::WorkloadChange) {
        crate::policy_generation::workload_store::OwnedWorkloadStore::open(home)
            .unwrap()
            .commit(&change)
            .unwrap();
    }

    /// Unit `a`'s service bound the way the mailbox process binds it, gated
    /// on the ledger under `home`, with its guest sealing at the bound epoch.
    fn gated_unit(home: &Path) -> (MailboxService, GuestSealer, PathBuf) {
        crate::audit::host_keypair::load_or_init_at(home).unwrap();
        let gate = UnitGate::bind(home, "a").unwrap();
        let grant = grant_at(home, gate.epoch().get());
        let (policy, sealer) = derive_launch_keys(home, &grant, &test_secret())
            .unwrap()
            .trust(gate.epoch());
        let socket = home.join("a.sock");
        let (service, sealer) =
            bind_fixture_grant(&grant, policy.gated(gate), sealer, LAUNCH_LIMITS, &socket).unwrap();
        (service, sealer, socket)
    }

    fn send_next(
        sealer: &mut GuestSealer,
        socket: &Path,
        n: u8,
    ) -> std::result::Result<(), Refusal> {
        let (capability, envelope) = sealer.seal(message(n)).unwrap();
        send(socket, &capability, &envelope)
    }

    #[test]
    fn a_gated_service_admits_while_its_unit_stays_current() {
        let home = tempfile::tempdir().unwrap();
        let (service, mut sealer, socket) = gated_unit(home.path());
        assert_eq!(send_next(&mut sealer, &socket, 1), Ok(()));
        // Replacing another unit changes nothing for this one.
        commit(
            home.path(),
            mvm_core::host_interface::workload::WorkloadChange::Replace {
                workload: "b".into(),
                from_epoch: ExecutionEpoch::FIRST,
            },
        );
        assert_eq!(send_next(&mut sealer, &socket, 2), Ok(()));
        assert!(service.receive().is_some() && service.receive().is_some());
    }

    #[test]
    fn a_running_service_refuses_its_old_epoch_once_the_unit_is_replaced() {
        let home = tempfile::tempdir().unwrap();
        let (service, mut sealer, socket) = gated_unit(home.path());
        assert_eq!(send_next(&mut sealer, &socket, 1), Ok(()));
        commit(
            home.path(),
            mvm_core::host_interface::workload::WorkloadChange::Replace {
                workload: "a".into(),
                from_epoch: ExecutionEpoch::FIRST,
            },
        );
        assert_eq!(
            send_next(&mut sealer, &socket, 2),
            Err(Refusal::Mailbox(
                mvm_core::host_interface::Denial::StaleEpoch { got: 1, current: 2 }.to_string()
            ))
        );
        assert!(service.receive().is_some());
        assert!(
            service.receive().is_none(),
            "the refused message is not queued"
        );
    }

    #[test]
    fn a_running_service_refuses_once_its_unit_is_quarantined() {
        let home = tempfile::tempdir().unwrap();
        let (service, mut sealer, socket) = gated_unit(home.path());
        commit(
            home.path(),
            mvm_core::host_interface::workload::WorkloadChange::Quarantine {
                workload: "a".into(),
            },
        );
        assert_eq!(
            send_next(&mut sealer, &socket, 1),
            Err(Refusal::Mailbox(
                mvm_core::host_interface::Denial::WorkloadQuarantined("a".into()).to_string()
            ))
        );
        assert!(service.receive().is_none());
    }

    #[test]
    fn a_gate_bound_above_the_units_current_epoch_is_not_promoted() {
        let home = tempfile::tempdir().unwrap();
        let gate = UnitGate {
            home: home.path().to_owned(),
            unit: "a".into(),
            epoch: ExecutionEpoch::new(2).unwrap(),
        };
        assert_eq!(
            gate.admit(),
            Err(Refusal::Mailbox(
                mvm_core::host_interface::Denial::EpochNotPromoted { got: 2, current: 1 }
                    .to_string()
            ))
        );
    }

    #[test]
    fn an_unreadable_ledger_is_unavailable_not_admitted() {
        let home = tempfile::tempdir().unwrap();
        let gate = UnitGate::bind(home.path(), "a").unwrap();
        let dir = mvm_core::host_interface::workload::canonical_dir_at(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(mvm_core::host_interface::workload::LEDGER_FILE),
            b"not json",
        )
        .unwrap();
        assert_eq!(gate.admit(), Err(Refusal::Unavailable));
    }

    #[test]
    fn an_old_epoch_envelope_is_refused_by_the_replacement_and_a_fresh_one_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();

        // The replaced workload's mailbox, at epoch 1, seals a message.
        let (old_service, mut old_sealer) = launch(dir.path(), &dir.path().join("old.sock"), 1);
        let (capability, envelope) = old_sealer.seal(greeting()).unwrap();
        send(&dir.path().join("old.sock"), &capability, &envelope).expect("the old epoch opens it");
        assert_eq!(
            old_service.receive().as_deref(),
            Some(&b"epoch one secret"[..])
        );
        drop(old_service);

        // The replacement runs under epoch 2: it cannot open the captured
        // envelope, and nothing is queued for it.
        let socket = dir.path().join("new.sock");
        let (new_service, mut new_sealer) = launch(dir.path(), &socket, 2);
        assert!(send(&socket, &capability, &envelope).is_err());
        assert!(new_service.receive().is_none());

        // Its own message, sealed under its own epoch, is accepted.
        let (capability, envelope) = new_sealer.seal(greeting()).unwrap();
        send(&socket, &capability, &envelope).expect("the replacement's own epoch opens");
        assert!(new_service.receive().is_some());
    }

    #[test]
    fn the_same_keys_at_a_newer_epoch_are_refused_as_stale() {
        let dir = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let (_service, mut sealer) = launch(dir.path(), &dir.path().join("a.sock"), 1);
        let (capability, envelope) = sealer.seal(greeting()).unwrap();

        let socket = dir.path().join("b.sock");
        commit(
            dir.path(),
            mvm_core::host_interface::workload::WorkloadChange::Replace {
                workload: "a".into(),
                from_epoch: ExecutionEpoch::FIRST,
            },
        );
        let (policy, _) = derive_launch_keys(dir.path(), &grant_at(dir.path(), 1), &test_secret())
            .unwrap()
            .trust(bound_epoch(dir.path(), "a").unwrap());
        let _service = MailboxService::bind(&socket, LAUNCH_LIMITS, policy).unwrap();
        assert_eq!(
            send(&socket, &capability, &envelope),
            Err(Refusal::Mailbox(
                mvm_core::mailbox::MailboxError::StaleExecutionEpoch.to_string()
            ))
        );
    }

    fn open_under(
        keys: &Path,
        secret: &mvm_core::crypto::aead::Key,
        name: &str,
        sealed: &(
            mvm_contract::protocol::mailbox::SignedMailboxCapability,
            mvm_contract::protocol::mailbox::MailboxEnvelope,
        ),
    ) -> std::result::Result<(), Refusal> {
        let grant = grant_at(keys, 1);
        let (policy, sealer) = derive_launch_keys(keys, &grant, secret)
            .unwrap()
            .trust(grant.epoch);
        let socket = keys.join(name);
        let _bound = bind_fixture_grant(&grant, policy, sealer, LAUNCH_LIMITS, &socket).unwrap();
        send(&socket, &sealed.0, &sealed.1)
    }

    fn sealed_under(
        keys: &Path,
        secret: &mvm_core::crypto::aead::Key,
    ) -> (
        mvm_contract::protocol::mailbox::SignedMailboxCapability,
        mvm_contract::protocol::mailbox::MailboxEnvelope,
    ) {
        let grant = grant_at(keys, 1);
        let (_, mut sealer) = derive_launch_keys(keys, &grant, secret)
            .unwrap()
            .trust(grant.epoch);
        sealer.seal(greeting()).unwrap()
    }

    #[test]
    fn a_frame_sealed_before_the_secret_was_erased_cannot_be_reopened_without_it() {
        let dir = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let secret = mvm_core::crypto::aead::Key::from_bytes([9; 32]);
        let sealed = sealed_under(dir.path(), &secret);
        // Positive control: the surviving secret opens it.
        assert!(open_under(dir.path(), &secret, "with.sock", &sealed).is_ok());
        // The seed and the encryption root, with a re-minted secret, do not.
        let reminted = mvm_core::crypto::aead::Key::from_bytes([8; 32]);
        assert!(open_under(dir.path(), &reminted, "without.sock", &sealed).is_err());
    }

    #[test]
    fn restarted_mailbox_refuses_old_frame_and_accepts_new_frame() {
        let keys = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(keys.path()).unwrap();
        let grant = grant_at(keys.path(), 1);
        let socket = keys.path().join("restart.sock");

        let old_secret = crate::mailbox_launch::mint_epoch_secret(state.path()).unwrap();
        let (policy, mut sealer) = derive_launch_keys(keys.path(), &grant, &old_secret)
            .unwrap()
            .trust(grant.epoch);
        let service = MailboxService::bind(&socket, LAUNCH_LIMITS, policy).unwrap();
        let (capability, envelope) = sealer.seal(greeting()).unwrap();
        send(&socket, &capability, &envelope).expect("first send accepted");
        assert_eq!(
            send(&socket, &capability, &envelope),
            Err(Refusal::Mailbox(
                mvm_core::mailbox::MailboxError::Replay.to_string()
            ))
        );
        assert_eq!(
            recv(&socket).unwrap().message,
            Some(hex::encode(b"epoch one secret"))
        );
        drop(service);

        let new_secret = crate::mailbox_launch::mint_epoch_secret(state.path()).unwrap();
        assert_ne!(old_secret.expose_bytes(), new_secret.expose_bytes());
        let (policy, mut sealer) = derive_launch_keys(keys.path(), &grant, &new_secret)
            .unwrap()
            .trust(grant.epoch);
        let _restarted = MailboxService::bind(&socket, LAUNCH_LIMITS, policy).unwrap();
        assert_eq!(
            send(&socket, &capability, &envelope),
            Err(Refusal::Mailbox(
                mvm_core::mailbox::MailboxError::DecryptionFailed.to_string()
            ))
        );
        assert_eq!(recv(&socket).unwrap().message, None);

        let (capability, envelope) = sealer.seal(greeting()).unwrap();
        send(&socket, &capability, &envelope).expect("new launch frame accepted");
        assert_eq!(
            recv(&socket).unwrap().message,
            Some(hex::encode(b"epoch one secret"))
        );
    }

    #[test]
    fn the_signing_seed_alone_cannot_open_and_the_encryption_root_alone_cannot_forge() {
        let host = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(host.path()).unwrap();
        let secret = mvm_core::crypto::aead::Key::from_bytes([9; 32]);
        let sealed = sealed_under(host.path(), &secret);

        // Same seed, own encryption root: cannot open what the host sealed.
        let seed_only = tempfile::tempdir().unwrap();
        for f in ["host-signer.ed25519", "host-signer.pub"] {
            std::fs::copy(host.path().join(f), seed_only.path().join(f)).unwrap();
        }
        assert!(open_under(seed_only.path(), &secret, "a.sock", &sealed).is_err());

        // Same encryption root, own signing seed: what it seals is refused.
        let root_only = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(root_only.path()).unwrap();
        std::fs::copy(
            host.path().join("mailbox-encryption.root"),
            root_only.path().join("mailbox-encryption.root"),
        )
        .unwrap();
        let forged = sealed_under(root_only.path(), &secret);
        assert!(open_under(host.path(), &secret, "b.sock", &forged).is_err());

        // Positive control: the host's own seed and root open its own frame.
        assert!(open_under(host.path(), &secret, "c.sock", &sealed).is_ok());
    }
}
