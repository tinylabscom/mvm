//! App-session stdout/stderr observation over the canonical DevOnly process RPC.
//! This is not a recorder, a transcript reader, or execution/stop authority.

use super::*;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

const MAX_RECORDS: usize = 400;
const MAX_BYTES: usize = 1_048_576;
const MAX_MACHINES: usize = 32;
const STOP_GRACE: Duration = Duration::from_secs(1);

/// A process's own output channel; console and recorded sources are separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOutputStream {
    Stdout,
    Stderr,
}

/// How the observed process or its reader ended. Closed is not a process exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOutputEnd {
    Exited { code: i32 },
    Killed { signal: i32 },
    TimedOut,
    Unavailable,
    Closed,
}

/// One source-local chunk, retained only in the app-session window.
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessOutputRecord {
    pub seq: u64,
    pub stream: ProcessOutputStream,
    pub data: Vec<u8>,
}

impl fmt::Debug for ProcessOutputRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessOutputRecord")
            .field("seq", &self.seq)
            .field("stream", &self.stream)
            .field("bytes", &self.data.len())
            .finish()
    }
}

/// The newest bounded window, not verified or durable history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutputSnapshot {
    pub token: String,
    pub records: Vec<ProcessOutputRecord>,
    pub end: Option<ProcessOutputEnd>,
    pub dropped_records: u64,
    pub dropped_bytes: u64,
    pub backpressure: bool,
}

#[derive(Default)]
struct Window {
    records: VecDeque<ProcessOutputRecord>,
    bytes: usize,
    seq: u64,
    dropped_records: u64,
    dropped_bytes: u64,
    backpressure: bool,
    end: Option<ProcessOutputEnd>,
}

impl Window {
    fn push(&mut self, stream: ProcessOutputStream, bytes: &[u8]) {
        let Some(seq) = self.seq.checked_add(1) else {
            self.end = Some(ProcessOutputEnd::Unavailable);
            return;
        };
        self.seq = seq;
        self.backpressure = false;
        let omitted = bytes.len().saturating_sub(MAX_BYTES);
        self.dropped_bytes = self.dropped_bytes.saturating_add(omitted as u64);
        let bytes = &bytes[omitted..];
        while self.records.len() >= MAX_RECORDS || self.bytes + bytes.len() > MAX_BYTES {
            let Some(old) = self.records.pop_front() else {
                break;
            };
            self.bytes -= old.data.len();
            self.dropped_records = self.dropped_records.saturating_add(1);
            self.dropped_bytes = self.dropped_bytes.saturating_add(old.data.len() as u64);
        }
        self.bytes += bytes.len();
        self.records.push_back(ProcessOutputRecord {
            seq,
            stream,
            data: bytes.to_vec(),
        });
    }

    fn event(&mut self, event: &ProcWaitEvent) {
        match event {
            ProcWaitEvent::Stdout { chunk } => self.push(ProcessOutputStream::Stdout, chunk),
            ProcWaitEvent::Stderr { chunk } => self.push(ProcessOutputStream::Stderr, chunk),
            ProcWaitEvent::Exit { code } => {
                self.end = Some(ProcessOutputEnd::Exited { code: *code })
            }
            ProcWaitEvent::Killed { signal } => {
                self.end = Some(ProcessOutputEnd::Killed { signal: *signal });
            }
            ProcWaitEvent::TimedOut => self.end = Some(ProcessOutputEnd::TimedOut),
            ProcWaitEvent::Error { .. } => self.end = Some(ProcessOutputEnd::Unavailable),
            ProcWaitEvent::Backpressure { .. } => self.backpressure = true,
        }
    }

    fn snapshot(&self, token: &str) -> ProcessOutputSnapshot {
        ProcessOutputSnapshot {
            token: token.into(),
            records: if self.end == Some(ProcessOutputEnd::Unavailable) {
                Vec::new()
            } else {
                self.records.iter().cloned().collect()
            },
            end: self.end,
            dropped_records: self.dropped_records,
            dropped_bytes: self.dropped_bytes,
            backpressure: self.backpressure,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Worker {
    socket: UnixStream,
    stopped: Arc<AtomicBool>,
    done: mpsc::Receiver<()>,
    thread: JoinHandle<()>,
}

struct Completion {
    sender: mpsc::Sender<()>,
    window: Arc<Mutex<Window>>,
    stopped: Arc<AtomicBool>,
}
impl Drop for Completion {
    fn drop(&mut self) {
        let mut window = lock(&self.window);
        if window.end.is_none() {
            window.end = Some(if self.stopped.load(Ordering::Acquire) {
                ProcessOutputEnd::Closed
            } else {
                ProcessOutputEnd::Unavailable
            });
        }
        drop(window);
        let _ = self.sender.send(());
    }
}

/// Owns one authenticated process wait and a 400-record/1-MiB newest window.
///
/// Keep it through process termination, even while a view is hidden. ProcWait
/// consumes the guest's output buffers: a competing reader or a new app cannot
/// recover bytes this reader already consumed. No capture writer is created.
/// Close/drop shuts down this reader's socket, never signals the guest process,
/// and bounds its local join to one second. It does not withdraw an already
/// dispatched guest wait or promise complete output after app disconnection.
pub struct ProcessOutputReader {
    token: String,
    window: Arc<Mutex<Window>>,
    worker: Option<Worker>,
    close_confirmed: bool,
}

impl ProcessOutputReader {
    /// Open the normal capability-checked, authenticated DevOnly process RPC.
    pub fn open(name: &str, token: &str) -> Result<Self> {
        validate_selection(name, token)?;
        let mut stream = if let Some(dir) = mock_agent_dir(name) {
            mvm_agentd::vsock::connect_to(&mvm_agentd::vsock::vsock_uds_path(&dir), 10)?
        } else {
            connect(name)?
        };
        mvm_agentd::vsock::require_capabilities(&mut stream, &[GuestCapability::ProcessRpc])?;
        let mut session = ControlSession::open(&mut stream)?;
        // Handshake bounds must not become a lifetime limit on a quiet program.
        // The owned duplicate interrupts a blocked read at reader retirement.
        stream.set_read_timeout(None)?;
        let request = GuestRequest::ProcWait {
            pid_token: token.into(),
            timeout_secs: None,
        };
        emit_vsock_rpc_audit(name, &request);
        Self::spawn(stream, token.into(), move |stream, window| {
            session.call_streaming(stream, &request, |response| {
                if let GuestResponse::ProcWaitEvent(event) = response {
                    lock(window).event(event);
                }
            })?;
            Ok(())
        })
    }

    fn spawn(
        mut stream: UnixStream,
        token: String,
        read: impl FnOnce(&mut UnixStream, &Mutex<Window>) -> Result<()> + Send + 'static,
    ) -> Result<Self> {
        let socket = stream.try_clone()?;
        let window = Arc::new(Mutex::new(Window::default()));
        let output = Arc::clone(&window);
        let stopped = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::clone(&stopped);
        let (finished, done) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("mvm-process-output".into())
            .spawn(move || {
                let _completion = Completion {
                    sender: finished,
                    window: Arc::clone(&output),
                    stopped: Arc::clone(&cancelled),
                };
                let result = read(&mut stream, &output);
                let mut window = lock(&output);
                if window.end.is_none() {
                    window.end = Some(if cancelled.load(Ordering::Acquire) {
                        ProcessOutputEnd::Closed
                    } else {
                        ProcessOutputEnd::Unavailable
                    });
                }
                if result.is_err() && !cancelled.load(Ordering::Acquire) {
                    window.end = Some(ProcessOutputEnd::Unavailable);
                }
            })?;
        Ok(Self {
            token,
            window,
            worker: Some(Worker {
                socket,
                stopped,
                done,
                thread,
            }),
            close_confirmed: false,
        })
    }

    /// Copy the current bounded window without consuming it or doing guest I/O.
    pub fn snapshot(&self) -> ProcessOutputSnapshot {
        lock(&self.window).snapshot(&self.token)
    }

    fn finished(&self) -> bool {
        lock(&self.window).end.is_some()
    }

    /// Retire this local reader. True means its worker joined, not that the
    /// guest process or machine stopped.
    pub fn close(&mut self) -> bool {
        let Some(worker) = self.worker.take() else {
            return self.close_confirmed;
        };
        worker.stopped.store(true, Ordering::Release);
        let _ = worker.socket.shutdown(Shutdown::Both);
        let joined = worker.thread.is_finished()
            || !matches!(
                worker.done.recv_timeout(STOP_GRACE),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
        if joined {
            self.close_confirmed = worker.thread.join().is_ok();
            return self.close_confirmed;
        }
        tracing::warn!("process output reader shutdown was not confirmed");
        false
    }
}

impl Drop for ProcessOutputReader {
    fn drop(&mut self) {
        self.close();
    }
}

struct Tracked {
    token: String,
    reader: OnceLock<Result<Mutex<ProcessOutputReader>, ()>>,
    retired: AtomicBool,
}

impl Tracked {
    fn finished(&self) -> bool {
        match self.reader.get() {
            Some(Ok(reader)) => lock(reader).finished(),
            Some(Err(())) => true,
            None => false,
        }
    }

    fn snapshot(&self) -> ProcessOutputSnapshot {
        match self.reader.get() {
            Some(Ok(reader)) => lock(reader).snapshot(),
            Some(Err(())) => Window {
                end: Some(ProcessOutputEnd::Unavailable),
                ..Window::default()
            }
            .snapshot(&self.token),
            None => Window {
                end: self
                    .retired
                    .load(Ordering::Acquire)
                    .then_some(ProcessOutputEnd::Closed),
                ..Window::default()
            }
            .snapshot(&self.token),
        }
    }
}

/// Bounded app-session ownership of one followed process per machine.
///
/// Reopening a view reuses the reader; it never dispatches a second ProcWait.
/// Terminal windows may be evicted when all 32 slots are occupied. If every
/// slot is still reading, following another machine refuses. Replacing a
/// machine's token retires only its previous local observation.
#[derive(Default)]
pub struct ProcessOutputs {
    machines: Mutex<HashMap<String, Arc<Tracked>>>,
}

impl ProcessOutputs {
    /// Follow an existing process token once. This performs guest read RPCs,
    /// never starts a process, and refuses invalid selections or capacity loss.
    pub fn follow(&self, name: &str, token: &str) -> Result<()> {
        validate_selection(name, token)?;
        self.follow_with(name, token, || ProcessOutputReader::open(name, token))
    }

    fn follow_with(
        &self,
        name: &str,
        token: &str,
        open: impl FnOnce() -> Result<ProcessOutputReader>,
    ) -> Result<()> {
        let (tracked, retired) = {
            let mut machines = lock(&self.machines);
            if let Some(current) = machines.get(name).filter(|entry| entry.token == token) {
                (Arc::clone(current), None)
            } else {
                let mut retired = None;
                if !machines.contains_key(name) && machines.len() >= MAX_MACHINES {
                    let finished = machines
                        .iter()
                        .find(|(_, entry)| entry.finished())
                        .map(|(name, _)| name.clone());
                    let Some(finished) = finished else {
                        bail!("process output reader limit reached")
                    };
                    retired = machines.remove(&finished);
                }
                let tracked = Arc::new(Tracked {
                    token: token.into(),
                    reader: OnceLock::new(),
                    retired: AtomicBool::new(false),
                });
                let previous = machines.insert(name.into(), Arc::clone(&tracked));
                (tracked, previous.or(retired))
            }
        };
        drop(retired); // Closing a socket or joining never holds the registry lock.
        if tracked
            .reader
            .get_or_init(|| open().map(Mutex::new).map_err(|_| ()))
            .is_err()
        {
            bail!("process output reader unavailable");
        }
        if tracked.retired.load(Ordering::Acquire) {
            if let Some(Ok(reader)) = tracked.reader.get() {
                lock(reader).close();
            }
            bail!("process output reader was retired while opening");
        }
        if !lock(&self.machines)
            .get(name)
            .is_some_and(|entry| Arc::ptr_eq(entry, &tracked))
        {
            bail!("process output selection changed while opening");
        }
        Ok(())
    }

    /// Read the app-session window without guest I/O. None means this service
    /// holds no observation, not that the machine produced no output.
    pub fn snapshot(&self, name: &str) -> Option<ProcessOutputSnapshot> {
        let tracked = lock(&self.machines).get(name).cloned()?;
        Some(tracked.snapshot())
    }

    /// Close a machine's active local reader after the caller's lifecycle
    /// operation, retaining its bounded window and any known process terminal.
    /// This operation itself never stops the guest process or machine.
    pub fn retire(&self, name: &str) {
        let tracked = lock(&self.machines).get(name).cloned();
        if let Some(tracked) = tracked {
            tracked.retired.store(true, Ordering::Release);
            if let Some(Ok(reader)) = tracked.reader.get() {
                lock(reader).close();
            }
        }
    }

    /// Forget one observation; this never stops a machine or guest process.
    pub fn forget(&self, name: &str) {
        let retired = lock(&self.machines).remove(name);
        drop(retired);
    }
}

fn validate_selection(name: &str, token: &str) -> Result<()> {
    validate(name)?;
    if token.is_empty() || token.len() > 256 || token.chars().any(char::is_control) {
        bail!("invalid process output token");
    }
    Ok(())
}

#[cfg(test)]
#[path = "process_output_tests.rs"]
mod tests;
