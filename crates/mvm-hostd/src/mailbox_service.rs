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
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    ExecutionEpoch, MailboxCapabilityGrant, MailboxEnvelope, MailboxEnvelopeHeader, MailboxGrant,
    MailboxRoutingFrame, MessageId, PrincipalId, ReplayNonce, SequenceNumber,
    SignedMailboxCapability,
};
use mvm_core::crypto::aead::Key;
pub use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::frame::{OWN_MAILBOX_RECIPIENT, OutboxMessage, decode_frame, send_frame};
use mvm_core::mailbox::{
    InMemoryReplayProtector, OpenContext, SealRequest, open_envelope, seal_envelope,
    sign_capability,
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
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

    /// The guest names its mailbox by what it can know: the mailbox id, or
    /// [`OWN_MAILBOX_RECIPIENT`]. Either means the template's recipient, a
    /// value derived from host keys the guest never sees. Anything else is
    /// passed through unchanged for admission to refuse.
    fn resolve_recipient(&self, named: PrincipalId) -> PrincipalId {
        if named.as_bytes() == self.header.mailbox.as_bytes()
            || named.as_bytes() == &OWN_MAILBOX_RECIPIENT
        {
            self.header.recipient
        } else {
            named
        }
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
        header.recipient = self.resolve_recipient(message.recipient);
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

struct State {
    queue: VecDeque<Vec<u8>>,
    accepted: u64,
    read: u64,
    replay: InMemoryReplayProtector,
    policy: MailboxPolicy,
}

struct Shared {
    limits: MailboxLimits,
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
    /// Bind `path` (replacing a stale socket file) and serve until dropped.
    pub fn bind(
        path: &Path,
        limits: MailboxLimits,
        policy: MailboxPolicy,
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

    /// The execution epoch this node currently accepts, for a service that
    /// outlives a workload replacement (the scripted three-node demo). The
    /// per-VM mailbox process never calls it: it takes its epoch from its
    /// grant, and a replacement is a new process under a grant whose epoch
    /// and keys are both new.
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
        self.serve_guest_waiting(route, sealer, IO_TIMEOUT, &AtomicBool::new(false))
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
        self.serve_guest_waiting(route, sealer, GUEST_HOLD_TIMEOUT, stop)
    }

    fn serve_guest_waiting(
        &self,
        route: &mvm_core::vm_backend::HostDialRoute,
        sealer: &mut GuestSealer,
        first_byte: Duration,
        stop: &AtomicBool,
    ) -> std::io::Result<()> {
        let stream = crate::telemetry_collector::dial_route(
            route,
            mvm_contract::protocol::mailbox::MAILBOX_PORT,
        )?;
        if !await_first_byte(&stream, first_byte, stop) {
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
    let Some(frame) = read_frame(shared, &mut stream) else {
        return Served::NoFrame;
    };
    let received = frame.is_ok();
    let verdict = answer(shared, &mut stream, frame, prepare);
    match (received, verdict) {
        (false, _) => Served::NoFrame,
        (true, Err(Refusal::QueueFull(_))) => Served::QueueFull,
        (true, _) => Served::Frame,
    }
}

/// Wait for the first byte (or EOF) of a dialed connection without consuming
/// it, in short slices so `stop` is honoured. False when the peer sent nothing
/// within `wait`, hung up, or `stop` was set.
fn await_first_byte(stream: &UnixStream, wait: Duration, stop: &AtomicBool) -> bool {
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
            // Readable: a byte, or EOF, which `read_frame` then reports as no frame.
            return p.revents & libc::POLLIN != 0;
        }
        let interrupted =
            rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted;
        if interrupted || stop.load(Ordering::SeqCst) || std::time::Instant::now() >= deadline {
            return false;
        }
    }
}

/// A host peer's connection: a read request, or a sealed send.
fn serve_peer(shared: &Shared, mut stream: UnixStream) {
    arm(&stream);
    let Some(frame) = read_frame(shared, &mut stream) else {
        return;
    };
    match frame {
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
        frame => {
            let _ = answer(shared, &mut stream, frame, decode_frame);
        }
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
    reply_with(stream, &verdict);
    verdict
}

fn reply_with<T: serde::Serialize>(stream: &mut UnixStream, reply: &Result<T, Refusal>) {
    if let Ok(reply) = serde_json::to_vec(reply) {
        let _ = stream.write_all(&reply);
    }
}

/// `None` means the peer sent not one byte (hung up, reset or timed out), so
/// there is nobody to answer; a peer that began a frame gets its refusal.
fn read_frame(shared: &Shared, stream: &mut UnixStream) -> Option<Result<Vec<u8>, Refusal>> {
    let max = shared.limits.max_frame_bytes;
    let mut len = [0u8; 4];
    match stream.read(&mut len[..1]) {
        Ok(1) => {}
        _ => return None,
    }
    Some(read_rest(stream, &mut len, max))
}

fn read_rest(stream: &mut UnixStream, len: &mut [u8; 4], max: usize) -> Result<Vec<u8>, Refusal> {
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
        };
        let (trust, _) = crate::mailbox_launch::host_trust(dir, &grant, &test_secret()).unwrap();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox_launch::{LAUNCH_LIMITS, authority_key_for, derive_launch_keys};
    use mvm_contract::protocol::mailbox::MailboxId;

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
        }
    }

    fn greeting() -> OutboxMessage {
        OutboxMessage {
            recipient: PrincipalId::from_bytes(OWN_MAILBOX_RECIPIENT),
            body: b"epoch one secret".to_vec(),
        }
    }

    /// What the real launch path builds for one epoch: the service and the
    /// sealer, both from the host key directory through the grant.
    fn launch(keys: &Path, socket: &Path, epoch: u64) -> (MailboxService, GuestSealer) {
        let grant = grant_at(keys, epoch);
        let (policy, sealer) = derive_launch_keys(keys, &grant, &test_secret())
            .unwrap()
            .trust();
        bind_grant(&grant, policy, sealer, LAUNCH_LIMITS, socket).unwrap()
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
        let (policy, _) = derive_launch_keys(dir.path(), &grant_at(dir.path(), 1), &test_secret())
            .unwrap()
            .trust();
        let service = MailboxService::bind(&socket, LAUNCH_LIMITS, policy).unwrap();
        service.set_current_epoch(ExecutionEpoch::new(2).unwrap());
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
        let (policy, sealer) = derive_launch_keys(keys, &grant, secret).unwrap().trust();
        let socket = keys.join(name);
        let _bound = bind_grant(&grant, policy, sealer, LAUNCH_LIMITS, &socket).unwrap();
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
        let (_, mut sealer) = derive_launch_keys(keys, &grant, secret).unwrap().trust();
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
            .trust();
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
            .trust();
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
