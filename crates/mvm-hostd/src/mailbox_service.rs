//! Per-node mailbox service: a bounded local queue behind a Unix domain socket.
//!
//! A peer connects, writes one length-prefixed frame (a capability and a
//! sealed envelope) and reads one typed verdict. The service opens the
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

use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxEnvelope, SignedMailboxCapability};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::{
    InMemoryReplayProtector, OpenContext, decode_envelope, encode_envelope, open_envelope,
};
use serde::{Deserialize, Serialize};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a frame was not queued. Sent back to the peer verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Refusal {
    #[error("frame exceeds the {0}-byte limit")]
    Oversized(usize),
    #[error("mailbox queue is full ({0} messages)")]
    QueueFull(usize),
    #[error("frame is malformed")]
    Malformed,
    /// The mailbox gate refused it; carries the gate's own reason text.
    #[error("{0}")]
    Mailbox(String),
}

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
    let io = |_| Refusal::Malformed;
    let cap = serde_json::to_vec(capability).map_err(io_json)?;
    let env = encode_envelope(envelope).map_err(|e| Refusal::Mailbox(e.to_string()))?;
    let mut body = (cap.len() as u32).to_be_bytes().to_vec();
    body.extend_from_slice(&cap);
    body.extend_from_slice(&env);
    let mut stream = UnixStream::connect(path).map_err(io)?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    // A service that refuses on length alone closes early; the verdict is
    // still readable, so a failed write is not itself the answer.
    let _ = stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(&body));
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).map_err(io)?;
    serde_json::from_slice::<Result<(), Refusal>>(&reply).map_err(io_json)?
}

fn io_json(_: serde_json::Error) -> Refusal {
    Refusal::Malformed
}

fn serve(shared: &Shared, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let verdict = read_frame(shared, &mut stream).and_then(|body| admit(shared, &body));
    if let Ok(reply) = serde_json::to_vec(&verdict) {
        let _ = stream.write_all(&reply);
    }
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

fn admit(shared: &Shared, body: &[u8]) -> Result<(), Refusal> {
    let (len, rest) = body.split_at_checked(4).ok_or(Refusal::Malformed)?;
    let cap_len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
    let (cap, env) = rest.split_at_checked(cap_len).ok_or(Refusal::Malformed)?;
    let capability: SignedMailboxCapability =
        serde_json::from_slice(cap).map_err(|_| Refusal::Malformed)?;
    let envelope = decode_envelope(env).map_err(|_| Refusal::Malformed)?;

    let mut guard = shared.state.lock().unwrap();
    let state = &mut *guard;
    if state.queue.len() >= shared.limits.max_depth {
        return Err(Refusal::QueueFull(shared.limits.max_depth));
    }
    let p = &state.policy;
    let plaintext = open_envelope(
        &envelope,
        &capability,
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
