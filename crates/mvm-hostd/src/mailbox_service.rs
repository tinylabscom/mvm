//! Per-node mailbox service: a bounded local queue behind a Unix domain socket.
//!
//! A peer connects, writes one length-prefixed frame (a capability and a
//! sealed envelope) and reads one typed verdict. A guest instead sends a
//! plaintext message the host seals itself ([`GuestSealer`]). The service opens the
//! envelope (capability, execution epoch, replay, expiry) before it enqueues
//! anything, so a refused message never occupies queue space. This socket
//! carries mailbox frames only; telemetry and control have their own planes.
//!
//! Frame: `u32 BE length`, then `u32 BE capability length`, the capability as
//! JSON, and the envelope in its canonical `encode_envelope` form.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    ExecutionEpoch, MailboxCapabilityGrant, MailboxEnvelope, MailboxEnvelopeHeader, MailboxGrant,
    MailboxRoutingFrame, MessageId, ReplayNonce, SequenceNumber, SignedMailboxCapability,
};
use mvm_core::crypto::aead::Key;
pub use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::frame::{OutboxMessage, decode_frame, send_frame};
use mvm_core::mailbox::{
    InMemoryReplayProtector, OpenContext, SealRequest, open_envelope, seal_envelope,
    sign_capability,
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

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
        Ok(self)
    }

    fn seal(
        &mut self,
        message: OutboxMessage,
    ) -> Result<(SignedMailboxCapability, MailboxEnvelope), Refusal> {
        let gate = |e: mvm_core::mailbox::MailboxError| Refusal::Mailbox(e.to_string());
        self.sent += 1;
        let n = self.sent;
        let counter = |width: usize| {
            let mut bytes = vec![0; width];
            bytes[width - 8..].copy_from_slice(&n.to_be_bytes());
            bytes
        };
        let mut header = self.header.clone();
        header.recipient = message.recipient;
        header.message_id = MessageId::from_bytes(counter(32).try_into().unwrap());
        header.nonce = ReplayNonce::from_bytes(counter(16).try_into().unwrap());
        header.sequence = SequenceNumber::new(n).map_err(|_| Refusal::Malformed)?;
        header.plaintext_len = message.body.len() as u32;
        let capability =
            sign_capability(self.capability.clone(), &self.authority_key).map_err(gate)?;
        let envelope = seal_envelope(
            SealRequest {
                routing: self.routing.clone(),
                header,
                plaintext: &message.body,
            },
            &self.encryption_key,
            &self.sender_key,
        )
        .map_err(gate)?;
        Ok((capability, envelope))
    }
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
    let service = MailboxService::bind(socket, limits, trust.with_grant(grant)?)?;
    service.serve_guest(guest.0, guest.1, &mut sealer)?;
    Ok(service)
}

struct State {
    queue: VecDeque<Vec<u8>>,
    replay: InMemoryReplayProtector,
    policy: MailboxPolicy,
}

struct Shared {
    limits: MailboxLimits,
    state: Mutex<State>,
}

pub struct MailboxService {
    shared: Arc<Shared>,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl MailboxService {
    /// Bind `path` (replacing a stale socket file) and serve until dropped.
    pub fn bind(
        path: &Path,
        limits: MailboxLimits,
        policy: MailboxPolicy,
    ) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        let shared = Arc::new(Shared {
            limits,
            state: Mutex::new(State {
                queue: VecDeque::new(),
                replay: InMemoryReplayProtector::default(),
                policy,
            }),
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
                        let _ = serve(&shared, stream, decode_frame);
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
    ) -> std::io::Result<()> {
        let stream = crate::telemetry_collector::dial_guest_port(
            per_port,
            firecracker_mux,
            mvm_contract::protocol::mailbox::MAILBOX_PORT,
        )?;
        serve(&self.shared, stream, |body| {
            sealer.seal(OutboxMessage::decode(body)?)
        })
        .then_some(())
        .ok_or_else(|| std::io::Error::other("the guest sent no mailbox frame"))
    }

    /// Take the oldest accepted plaintext, if any.
    pub fn receive(&self) -> Option<Vec<u8>> {
        self.shared.state.lock().unwrap().queue.pop_front()
    }
}

impl Drop for MailboxService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.path); // wake the accept loop
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
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let frame = read_frame(shared, &mut stream);
    let received = frame.is_ok();
    let verdict = frame
        .and_then(|body| prepare(&body))
        .and_then(|(capability, envelope)| admit(shared, &capability, &envelope));
    if let Ok(reply) = serde_json::to_vec(&verdict) {
        let _ = stream.write_all(&reply);
    }
    received
}

fn read_frame(shared: &Shared, stream: &mut UnixStream) -> Result<Vec<u8>, Refusal> {
    let max = shared.limits.max_frame_bytes;
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
    .map_err(|e| Refusal::Mailbox(e.to_string()))?;
    state.queue.push_back(plaintext);
    Ok(())
}
