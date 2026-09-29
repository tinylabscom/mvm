//! Output delivered while it is produced, as a handle and a poll.
//!
//! One C call returns once, so output that arrives over time is a handle and
//! a poll rather than a callback into the binding. Two families share the
//! machinery:
//!
//! - `guest.proc.stream.*` — a guest process's stdout and stderr. `open`
//!   starts a reader that waits on the process through the same
//!   `wait_process` the buffered `guest.proc.wait` uses; the stream ends with
//!   how the process ended. DevOnly, like every guest process method.
//! - `machine.logs.stream.*` — a machine's captured output, replayed from its
//!   durable transcript and then followed live, through the same
//!   `open_vm_output` reader `mvmctl machine logs --follow` uses. The stream
//!   ends when the output does. ProdSafe, like `machine.logs`.
//!
//! `next` hands back whatever has arrived, waiting up to a bound for the first
//! chunk; `close` drops the handle. A handle belongs to the family that opened
//! it, so a log handle cannot be polled through the DevOnly process methods or
//! the reverse.
//!
//! The queue is bounded. A binding that stops polling stalls the reader, and
//! through it the producer, rather than growing this process without bound.
//! Closing the handle unblocks the reader, which then discards the rest: a
//! wait already in flight on the guest agent, or a follow on a live broker,
//! cannot be withdrawn, so the reader outlives the handle until its source
//! ends.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_agentd::vsock::ProcWaitEvent;
use mvm_contract::stream::StreamKind;
use mvm_core::client::MvmError;
use mvm_core::stream_client::{KindFilter, OutputRecord, OutputRequest, StreamError, StreamOpts};
use serde::{Deserialize, Serialize};

use crate::guest::{GuestOps, WaitOutcome, guest_error};
use crate::status::{MVM_HOSTLIB_INTERNAL, Outcome};

/// Opens a stream over a process's output. Request: `{"id", "token",
/// "timeout_secs"?}`. Reply: `{"stream"}`.
pub const STREAM_OPEN: &str = "guest.proc.stream.open";
/// Returns the output that has arrived. Request: `{"stream", "wait_ms"?}`.
/// Reply: `{"events", "done", "outcome"?}`.
pub const STREAM_NEXT: &str = "guest.proc.stream.next";
/// Closes a stream. Request: `{"stream"}`. Reply: `{}`. Idempotent.
pub const STREAM_CLOSE: &str = "guest.proc.stream.close";

/// Opens a stream over a machine's captured output. Request: `{"id",
/// "follow"?, "tail_lines"?, "streams"?}`. Reply: `{"stream"}`.
pub const LOGS_OPEN: &str = "machine.logs.stream.open";
/// Returns the captured output that has arrived. Request and reply as
/// `guest.proc.stream.next`; a log stream's final reply carries no outcome.
pub const LOGS_NEXT: &str = "machine.logs.stream.next";
/// Closes a log stream. Request: `{"stream"}`. Reply: `{}`. Idempotent.
pub const LOGS_CLOSE: &str = "machine.logs.stream.close";

/// Every process-stream method.
pub const METHODS: [&str; 3] = [STREAM_OPEN, STREAM_NEXT, STREAM_CLOSE];
/// Every log-stream method.
pub const LOG_METHODS: [&str; 3] = [LOGS_OPEN, LOGS_NEXT, LOGS_CLOSE];

/// Chunks a reader may queue before it waits for the binding to poll. Each is
/// at most one agent frame or one captured record, so this bounds what one
/// stream holds in memory.
const QUEUE_CHUNKS: usize = 64;
/// Streams open at once, across both families. Past this, `open` refuses and
/// says to close one.
pub const MAX_OPEN_STREAMS: usize = 256;
/// How long `next` waits for a first chunk when the request names no bound.
const DEFAULT_WAIT_MS: u64 = 1_000;
/// The longest `next` may be asked to wait.
pub const MAX_WAIT_MS: u64 = 30_000;
/// Bytes `next` returns in one reply before leaving the rest for the next
/// call, so one reply stays a bounded allocation on both sides of the ABI.
const REPLY_BUDGET: usize = 4 * 1024 * 1024;

/// Whether `method` is a process-stream method.
pub(crate) fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

/// Whether `method` is a log-stream method.
pub(crate) fn is_log_method(method: &str) -> bool {
    LOG_METHODS.contains(&method)
}

/// Which channel a chunk came from.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StreamName {
    Stdout,
    Stderr,
    /// A structured control record from the workload's runtime (log streams
    /// only).
    Trace,
    /// An encoded display frame (log streams only).
    Frame,
}

impl From<StreamKind> for StreamName {
    fn from(kind: StreamKind) -> Self {
        match kind {
            StreamKind::Stdout => Self::Stdout,
            StreamKind::Stderr => Self::Stderr,
            StreamKind::Trace => Self::Trace,
            StreamKind::Frame => Self::Frame,
        }
    }
}

impl From<StreamName> for StreamKind {
    fn from(name: StreamName) -> Self {
        match name {
            StreamName::Stdout => Self::Stdout,
            StreamName::Stderr => Self::Stderr,
            StreamName::Trace => Self::Trace,
            StreamName::Frame => Self::Frame,
        }
    }
}

/// How a stream's source ended: with a process outcome, with the end of the
/// output (`None`), or with why the read failed.
type End = Result<Option<WaitOutcome>, String>;

/// What a reader queues.
enum Item {
    Chunk(StreamName, Vec<u8>),
    End(End),
}

/// Which method family a handle belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Process,
    Logs,
}

/// One open stream: its family, the reader's queue, and an end the last
/// `next` read but could not report because it was already returning output.
struct Stream {
    family: Family,
    queue: Mutex<Receiver<Item>>,
    held_end: Mutex<Option<End>>,
}

/// The open streams, by id. The process-wide table is [`streams`]; tests make
/// their own.
pub(crate) struct StreamTable {
    inner: Mutex<TableState>,
}

#[derive(Default)]
struct TableState {
    next_id: u64,
    open: HashMap<u64, Arc<Stream>>,
}

impl StreamTable {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(TableState::default()),
        }
    }

    fn state(&self) -> MutexGuard<'_, TableState> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserve an id for a new stream, or refuse when too many are open.
    fn insert(&self, stream: Stream) -> Result<u64, Outcome> {
        let mut state = self.state();
        if state.open.len() >= MAX_OPEN_STREAMS {
            return Err(Outcome::from(MvmError::Unavailable {
                reason: format!("{MAX_OPEN_STREAMS} streams are already open; close one first"),
            }));
        }
        state.next_id = state.next_id.wrapping_add(1);
        let id = state.next_id;
        state.open.insert(id, Arc::new(stream));
        Ok(id)
    }

    /// The open stream `id`, when it belongs to `family`. A handle from the
    /// other family reads as absent, so neither family's methods can reach
    /// the other's streams.
    fn get(&self, id: u64, family: Family) -> Result<Arc<Stream>, Outcome> {
        self.state()
            .open
            .get(&id)
            .filter(|stream| stream.family == family)
            .cloned()
            .ok_or_else(|| Outcome::invalid_input(&format!("no open stream {id}")))
    }

    fn remove(&self, id: u64, family: Family) {
        let mut state = self.state();
        if state
            .open
            .get(&id)
            .is_some_and(|stream| stream.family == family)
        {
            state.open.remove(&id);
        }
    }

    #[cfg(test)]
    fn open_count(&self) -> usize {
        self.state().open.len()
    }
}

/// The streams this process has open.
pub(crate) fn streams() -> &'static StreamTable {
    static TABLE: OnceLock<StreamTable> = OnceLock::new();
    TABLE.get_or_init(StreamTable::new)
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenRequest {
    id: String,
    token: String,
    /// Bounds the wait on the guest; the stream ends `timed_out` past it.
    #[serde(default)]
    timeout_secs: Option<u64>,
}

/// A `machine.logs.stream.open` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogsOpenRequest {
    id: String,
    /// Keep reading past the end of what has been captured so far. `true`
    /// when absent; `false` replays the transcript and ends.
    #[serde(default = "follow_by_default")]
    follow: bool,
    /// Replay only the last N captured records first. The whole transcript
    /// when absent.
    #[serde(default)]
    tail_lines: Option<u32>,
    /// Which channels to deliver. Every channel when absent or empty.
    #[serde(default)]
    streams: Vec<StreamName>,
}

fn follow_by_default() -> bool {
    true
}

/// Roughly how many bytes one captured record is worth, for turning a line
/// tail into the console fallback's byte tail — the same estimate
/// `mvmctl machine logs -n` uses.
const CONSOLE_BYTES_PER_RECORD: u64 = 512;

impl LogsOpenRequest {
    /// The request the output reader takes.
    fn output_request(&self) -> OutputRequest {
        let kinds = if self.streams.is_empty() {
            KindFilter::all()
        } else {
            self.streams
                .iter()
                .fold(KindFilter::none(), |filter, name| {
                    filter.with((*name).into())
                })
        };
        OutputRequest {
            opts: StreamOpts::builder()
                .follow(self.follow)
                .kinds(kinds)
                .build(),
            history_tail: self.tail_lines.map(|lines| lines as usize),
            console_tail_bytes: self
                .tail_lines
                .map(|lines| u64::from(lines) * CONSOLE_BYTES_PER_RECORD),
            console_tail_lines: self.tail_lines.map(|lines| lines as usize),
        }
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextRequest {
    stream: u64,
    /// How long to wait for a first chunk. At most [`MAX_WAIT_MS`].
    #[serde(default)]
    wait_ms: Option<u64>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloseRequest {
    stream: u64,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct OpenReply {
    stream: u64,
}

/// One chunk of output.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct StreamEvent {
    stream: StreamName,
    data_b64: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct NextReply {
    events: Vec<StreamEvent>,
    /// The source has ended and the stream is closed.
    done: bool,
    /// How a process ended; present when a process stream is done, absent
    /// otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<WaitOutcome>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct Empty {}

/// Where a log stream's records come from. One production implementation,
/// over `open_vm_output`; the tests supply records directly.
///
/// `open` runs on the stream's reader thread, because the output reader holds
/// the broker connection and is not `Send`; its result is handed back to the
/// opening call before `open` returns, so the binding still hears a refusal
/// from `open` rather than from its first poll.
pub(crate) trait LogSource: Send + Sync {
    /// Open `id`'s output. A machine with no capture at all is refused here.
    fn open(&self, id: &str, request: OutputRequest) -> Result<Box<dyn RecordReader>, Outcome>;
}

/// The records of one open log stream, in order. `Ok(None)` is the end.
pub(crate) trait RecordReader {
    fn next_record(&mut self) -> Result<Option<OutputRecord>, String>;
}

/// This host's machines' captured output.
pub(crate) struct LocalLogs;

impl LogSource for LocalLogs {
    fn open(&self, id: &str, request: OutputRequest) -> Result<Box<dyn RecordReader>, Outcome> {
        mvm_core::naming::validate_vm_name(id)
            .map_err(|e| Outcome::invalid_input(&format!("invalid machine name {id:?}: {e}")))?;
        match mvm_core::stream_client::open_vm_output(id, request) {
            Ok(stream) => Ok(Box::new(stream)),
            Err(StreamError::NoCapture { .. }) => Err(Outcome::from(MvmError::NotFound {
                id: format!("{id}: no captured output (no live broker, transcript or console)"),
            })),
            Err(e) => Err(Outcome::from(MvmError::Backend {
                reason: format!("opening output for {id:?}: {e}"),
            })),
        }
    }
}

impl RecordReader for mvm_core::stream_client::VmOutputStream {
    fn next_record(&mut self) -> Result<Option<OutputRecord>, String> {
        self.next_output().map_err(|e| e.to_string())
    }
}

/// Answer the process-stream method `method`, opening readers over `ops`.
pub(crate) fn dispatch(
    table: &StreamTable,
    ops: Arc<dyn GuestOps>,
    method: &str,
    request: &[u8],
) -> Outcome {
    let answered = match method {
        STREAM_OPEN => parse::<OpenRequest>(request)
            .and_then(|r| open_process(table, ops, r))
            .map(|stream| Outcome::ok(&OpenReply { stream })),
        STREAM_NEXT => poll(table, Family::Process, request),
        STREAM_CLOSE => close(table, Family::Process, request),
        other => Err(Outcome::invalid_input(&format!("unknown method `{other}`"))),
    };
    answered.unwrap_or_else(|outcome| outcome)
}

/// Answer the log-stream method `method`, opening readers over `source`.
pub(crate) fn dispatch_logs(
    table: &StreamTable,
    source: Arc<dyn LogSource>,
    method: &str,
    request: &[u8],
) -> Outcome {
    let answered = match method {
        LOGS_OPEN => parse::<LogsOpenRequest>(request)
            .and_then(|r| open_logs(table, source, r))
            .map(|stream| Outcome::ok(&OpenReply { stream })),
        LOGS_NEXT => poll(table, Family::Logs, request),
        LOGS_CLOSE => close(table, Family::Logs, request),
        other => Err(Outcome::invalid_input(&format!("unknown method `{other}`"))),
    };
    answered.unwrap_or_else(|outcome| outcome)
}

fn poll(table: &StreamTable, family: Family, request: &[u8]) -> Result<Outcome, Outcome> {
    let r: NextRequest = parse(request)?;
    let wait = Duration::from_millis(r.wait_ms.unwrap_or(DEFAULT_WAIT_MS).min(MAX_WAIT_MS));
    Ok(Outcome::ok(&next(table, family, r.stream, wait)?))
}

fn close(table: &StreamTable, family: Family, request: &[u8]) -> Result<Outcome, Outcome> {
    let r: CloseRequest = parse(request)?;
    table.remove(r.stream, family);
    Ok(Outcome::ok(&Empty {}))
}

/// Register a stream of `family` and start `read` on a thread of its own,
/// handing it the sending half of the stream's queue.
fn spawn_reader(
    table: &StreamTable,
    family: Family,
    read: impl FnOnce(&SyncSender<Item>) + Send + 'static,
) -> Result<u64, Outcome> {
    let (sender, receiver) = sync_channel(QUEUE_CHUNKS);
    let id = table.insert(Stream {
        family,
        queue: Mutex::new(receiver),
        held_end: Mutex::new(None),
    })?;
    let spawned = std::thread::Builder::new()
        .name("mvm-hostlib-stream".into())
        .spawn(move || read(&sender));
    if let Err(e) = spawned {
        table.remove(id, family);
        return Err(Outcome::failure(
            MVM_HOSTLIB_INTERNAL,
            mvm_core::error_codes::INTERNAL,
            &format!("the stream reader would not start: {e}"),
            false,
        ));
    }
    Ok(id)
}

fn open_process(
    table: &StreamTable,
    ops: Arc<dyn GuestOps>,
    request: OpenRequest,
) -> Result<u64, Outcome> {
    spawn_reader(table, Family::Process, move |sender| {
        read_process(ops.as_ref(), &request, sender);
    })
}

fn open_logs(
    table: &StreamTable,
    source: Arc<dyn LogSource>,
    request: LogsOpenRequest,
) -> Result<u64, Outcome> {
    let (opened_tx, opened_rx) = std::sync::mpsc::channel();
    let id = spawn_reader(table, Family::Logs, move |sender| {
        match source.open(&request.id, request.output_request()) {
            Ok(reader) => {
                let _ = opened_tx.send(Ok(()));
                read_records(reader, sender);
            }
            Err(refused) => {
                let _ = opened_tx.send(Err(refused));
            }
        }
    })?;
    let opened = opened_rx.recv().unwrap_or_else(|_| {
        Err(Outcome::failure(
            MVM_HOSTLIB_INTERNAL,
            mvm_core::error_codes::INTERNAL,
            "the log reader stopped before opening the output",
            false,
        ))
    });
    match opened {
        Ok(()) => Ok(id),
        Err(refused) => {
            table.remove(id, Family::Logs);
            Err(refused)
        }
    }
}

/// The process reader: wait on the process, queueing each chunk, then how it
/// ended. A send that fails means the handle was closed; the rest is
/// discarded.
fn read_process(ops: &dyn GuestOps, request: &OpenRequest, sender: &SyncSender<Item>) {
    let ended = ops.wait_process(
        &request.id,
        &request.token,
        request.timeout_secs,
        &mut |event| {
            let item = match event {
                ProcWaitEvent::Stdout { chunk } => Item::Chunk(StreamName::Stdout, chunk.clone()),
                ProcWaitEvent::Stderr { chunk } => Item::Chunk(StreamName::Stderr, chunk.clone()),
                _ => return,
            };
            let _ = sender.send(item);
        },
    );
    let end = match ended {
        Ok(terminal) => terminal_outcome(terminal).map(Some),
        Err(e) => Err(format!("{e:#}")),
    };
    let _ = sender.send(Item::End(end));
}

/// The log reader: queue each record until the output ends. A closed handle
/// stops it at the next record rather than reading on into nothing.
fn read_records(mut reader: Box<dyn RecordReader>, sender: &SyncSender<Item>) {
    loop {
        match reader.next_record() {
            Ok(Some(record)) => {
                if sender
                    .send(Item::Chunk(record.kind.into(), record.payload))
                    .is_err()
                {
                    return;
                }
            }
            Ok(None) => {
                let _ = sender.send(Item::End(Ok(None)));
                return;
            }
            Err(message) => {
                let _ = sender.send(Item::End(Err(message)));
                return;
            }
        }
    }
}

/// How a waited-on process ended, or why the wait itself failed.
fn terminal_outcome(terminal: ProcWaitEvent) -> Result<WaitOutcome, String> {
    match terminal {
        ProcWaitEvent::Exit { code } => Ok(WaitOutcome::Exited { code }),
        ProcWaitEvent::Killed { signal } => Ok(WaitOutcome::Killed { signal }),
        ProcWaitEvent::TimedOut => Ok(WaitOutcome::TimedOut),
        ProcWaitEvent::Error { kind, message } => {
            Err(format!("ProcWait error ({kind:?}): {message}"))
        }
        other => Err(format!("unexpected terminal wait event: {other:?}")),
    }
}

/// Collect what has arrived on stream `id`, waiting up to `wait` for the
/// first chunk.
fn next(
    table: &StreamTable,
    family: Family,
    id: u64,
    wait: Duration,
) -> Result<NextReply, Outcome> {
    let stream = table.get(id, family)?;
    let mut held = stream
        .held_end
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(end) = held.take() {
        table.remove(id, family);
        return finish(Vec::new(), end);
    }
    let queue = stream.queue.lock().unwrap_or_else(PoisonError::into_inner);
    let mut events = Vec::new();
    let mut bytes = 0_usize;
    let mut end = None;
    let first = match queue.recv_timeout(wait) {
        Ok(item) => Some(item),
        Err(RecvTimeoutError::Timeout) => None,
        Err(RecvTimeoutError::Disconnected) => Some(lost_reader()),
    };
    let mut pending = first;
    while let Some(item) = pending.take() {
        match item {
            Item::Chunk(name, chunk) => {
                bytes = bytes.saturating_add(chunk.len());
                events.push(StreamEvent {
                    stream: name,
                    data_b64: B64.encode(chunk),
                });
            }
            Item::End(result) => {
                end = Some(result);
                break;
            }
        }
        if bytes >= REPLY_BUDGET {
            break;
        }
        pending = match queue.try_recv() {
            Ok(item) => Some(item),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(lost_reader()),
        };
    }
    let Some(end) = end else {
        return Ok(NextReply {
            events,
            done: false,
            outcome: None,
        });
    };
    // A failed read is an error reply, which cannot also carry output. Hand
    // back the output first and report the failure on the next call.
    if end.is_err() && !events.is_empty() {
        *held = Some(end);
        return Ok(NextReply {
            events,
            done: false,
            outcome: None,
        });
    }
    table.remove(id, family);
    finish(events, end)
}

/// The reader went away without saying how its source ended.
fn lost_reader() -> Item {
    Item::End(Err("the stream reader ended without a result".into()))
}

/// The final reply for a stream whose source has ended.
fn finish(events: Vec<StreamEvent>, end: End) -> Result<NextReply, Outcome> {
    let outcome = end.map_err(|message| guest_error(anyhow::anyhow!(message)))?;
    Ok(NextReply {
        events,
        done: true,
        outcome,
    })
}

fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(request)
        .map_err(|e| Outcome::invalid_input(&format!("request did not parse: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{
        MVM_HOSTLIB_BACKEND, MVM_HOSTLIB_INVALID_INPUT, MVM_HOSTLIB_OK, MVM_HOSTLIB_UNAVAILABLE,
    };
    use anyhow::Result;
    use mvm_agentd::vsock::{FsStat, ProcInfo};
    use mvm_client::guest::{Listing, ProcStart, WriteOptions};
    use std::sync::mpsc::Receiver as StdReceiver;

    /// Streams a fixed event sequence. When `gate` is set, the reader emits
    /// each event only after the test releases it, so a test can observe a
    /// stream mid-flight.
    struct Scripted {
        events: Vec<ProcWaitEvent>,
        fail: Option<String>,
        gate: Option<Mutex<StdReceiver<()>>>,
    }

    impl Scripted {
        fn new(events: Vec<ProcWaitEvent>) -> Self {
            Self {
                events,
                fail: None,
                gate: None,
            }
        }
    }

    impl GuestOps for Scripted {
        fn start_process(&self, _: &str, _: ProcStart) -> Result<String> {
            unreachable!()
        }
        fn list_processes(&self, _: &str) -> Result<Vec<ProcInfo>> {
            unreachable!()
        }
        fn signal_process(&self, _: &str, _: &str, _: i32) -> Result<()> {
            unreachable!()
        }
        fn kill_process(&self, _: &str, _: &str) -> Result<()> {
            unreachable!()
        }
        fn send_process_input(&self, _: &str, _: &str, _: &[u8]) -> Result<u64> {
            unreachable!()
        }
        fn wait_process(
            &self,
            _id: &str,
            _token: &str,
            _timeout: Option<u64>,
            on_event: &mut dyn FnMut(&ProcWaitEvent),
        ) -> Result<ProcWaitEvent> {
            let (terminal, streamed) = self.events.split_last().expect("a terminal event");
            for event in streamed {
                if let Some(gate) = &self.gate {
                    gate.lock()
                        .unwrap()
                        .recv()
                        .expect("the test releases each event");
                }
                on_event(event);
            }
            if let Some(message) = &self.fail {
                anyhow::bail!("{message}");
            }
            Ok(terminal.clone())
        }
        fn read_file(&self, _: &str, _: &str, _: u64, _: u64, _: bool) -> Result<Vec<u8>> {
            unreachable!()
        }
        fn write_file(&self, _: &str, _: &str, _: &[u8], _: WriteOptions) -> Result<u64> {
            unreachable!()
        }
        fn list_dir(&self, _: &str, _: &str) -> Result<Listing> {
            unreachable!()
        }
        fn stat(&self, _: &str, _: &str, _: bool) -> Result<FsStat> {
            unreachable!()
        }
        fn make_dir(&self, _: &str, _: &str, _: u32, _: bool) -> Result<()> {
            unreachable!()
        }
        fn remove(&self, _: &str, _: &str, _: bool) -> Result<u64> {
            unreachable!()
        }
        fn rename(&self, _: &str, _: &str, _: &str) -> Result<()> {
            unreachable!()
        }
    }

    fn call(
        table: &StreamTable,
        ops: Arc<dyn GuestOps>,
        method: &str,
        request: serde_json::Value,
    ) -> (i32, serde_json::Value) {
        let outcome = dispatch(table, ops, method, &serde_json::to_vec(&request).unwrap());
        let body = serde_json::from_slice(&outcome.body).unwrap_or(serde_json::Value::Null);
        (outcome.status, body)
    }

    fn open_on(table: &StreamTable, ops: Arc<dyn GuestOps>) -> u64 {
        let (status, body) = call(
            table,
            ops,
            STREAM_OPEN,
            serde_json::json!({"id": "web", "token": "tok", "timeout_secs": 5}),
        );
        assert_eq!(status, MVM_HOSTLIB_OK, "{body}");
        body["stream"].as_u64().expect("a stream id")
    }

    fn unused() -> Arc<dyn GuestOps> {
        Arc::new(Scripted::new(vec![ProcWaitEvent::Exit { code: 0 }]))
    }

    /// Poll until the stream ends, returning every event and the final body.
    fn drain(table: &StreamTable, stream: u64) -> (Vec<serde_json::Value>, serde_json::Value) {
        let mut events = Vec::new();
        for _ in 0..100 {
            let (status, body) = call(
                table,
                unused(),
                STREAM_NEXT,
                serde_json::json!({"stream": stream, "wait_ms": 2000}),
            );
            assert_eq!(status, MVM_HOSTLIB_OK, "{body}");
            events.extend(body["events"].as_array().unwrap().iter().cloned());
            if body["done"] == true {
                return (events, body);
            }
        }
        panic!("the stream never ended");
    }

    #[test]
    fn a_stream_delivers_every_chunk_in_order_then_the_exit() {
        let table = StreamTable::new();
        let ops = Arc::new(Scripted::new(vec![
            ProcWaitEvent::Stdout {
                chunk: b"hel".to_vec(),
            },
            ProcWaitEvent::Stderr {
                chunk: b"warn".to_vec(),
            },
            ProcWaitEvent::Stdout {
                chunk: b"lo".to_vec(),
            },
            ProcWaitEvent::Exit { code: 3 },
        ]));
        let stream = open_on(&table, ops);
        let (events, last) = drain(&table, stream);
        let decoded: Vec<(String, Vec<u8>)> = events
            .iter()
            .map(|e| {
                (
                    e["stream"].as_str().unwrap().to_string(),
                    B64.decode(e["data_b64"].as_str().unwrap()).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            decoded,
            vec![
                ("stdout".into(), b"hel".to_vec()),
                ("stderr".into(), b"warn".to_vec()),
                ("stdout".into(), b"lo".to_vec()),
            ]
        );
        assert_eq!(
            last["outcome"],
            serde_json::json!({"kind": "exited", "code": 3})
        );
        assert_eq!(table.open_count(), 0, "an ended stream is closed");
    }

    /// Output arrives while the process still runs: `next` returns it without
    /// waiting for the end.
    #[test]
    fn output_is_delivered_before_the_process_ends() {
        let table = StreamTable::new();
        let (release, gate) = std::sync::mpsc::channel();
        let ops = Arc::new(Scripted {
            events: vec![
                ProcWaitEvent::Stdout {
                    chunk: b"first".to_vec(),
                },
                ProcWaitEvent::Stdout {
                    chunk: b"second".to_vec(),
                },
                ProcWaitEvent::Killed { signal: 9 },
            ],
            fail: None,
            gate: Some(Mutex::new(gate)),
        });
        let stream = open_on(&table, ops);
        release.send(()).unwrap();
        let (status, body) = call(
            &table,
            unused(),
            STREAM_NEXT,
            serde_json::json!({"stream": stream, "wait_ms": 5000}),
        );
        assert_eq!(status, MVM_HOSTLIB_OK);
        assert_eq!(body["done"], false);
        assert_eq!(body["events"][0]["data_b64"], B64.encode("first"));
        assert!(body.get("outcome").is_none());

        release.send(()).unwrap();
        let (_, last) = drain(&table, stream);
        assert_eq!(
            last["outcome"],
            serde_json::json!({"kind": "killed", "signal": 9})
        );
    }

    #[test]
    fn a_poll_with_nothing_new_returns_empty_after_its_wait() {
        let table = StreamTable::new();
        let (release, gate) = std::sync::mpsc::channel();
        let ops = Arc::new(Scripted {
            events: vec![
                ProcWaitEvent::Stdout {
                    chunk: b"x".to_vec(),
                },
                ProcWaitEvent::Exit { code: 0 },
            ],
            fail: None,
            gate: Some(Mutex::new(gate)),
        });
        let stream = open_on(&table, ops);
        let (status, body) = call(
            &table,
            unused(),
            STREAM_NEXT,
            serde_json::json!({"stream": stream, "wait_ms": 10}),
        );
        assert_eq!(status, MVM_HOSTLIB_OK);
        assert_eq!(body, serde_json::json!({"events": [], "done": false}));
        release.send(()).unwrap();
        drain(&table, stream);
    }

    /// A wait that fails after some output delivers the output, then reports
    /// the failure as the backend's error and closes the stream.
    #[test]
    fn a_failed_wait_reports_its_output_before_its_error() {
        let table = StreamTable::new();
        let ops = Arc::new(Scripted {
            events: vec![
                ProcWaitEvent::Stdout {
                    chunk: b"partial".to_vec(),
                },
                ProcWaitEvent::Exit { code: 0 },
            ],
            fail: Some("the agent went away".into()),
            gate: None,
        });
        let stream = open_on(&table, ops);
        // Whether the first poll sees the failure queued behind the chunk or
        // not, it returns the chunk and leaves the failure for the next poll.
        let (status, body) = call(
            &table,
            unused(),
            STREAM_NEXT,
            serde_json::json!({"stream": stream, "wait_ms": 2000}),
        );
        assert_eq!(status, MVM_HOSTLIB_OK, "{body}");
        assert_eq!(body["events"][0]["data_b64"], B64.encode("partial"));
        let (status, body) = call(
            &table,
            unused(),
            STREAM_NEXT,
            serde_json::json!({"stream": stream}),
        );
        assert_eq!(status, MVM_HOSTLIB_BACKEND);
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("the agent went away")
        );
        assert_eq!(table.open_count(), 0);
    }

    #[test]
    fn an_agent_error_ending_the_wait_is_a_backend_error() {
        let table = StreamTable::new();
        let ops = Arc::new(Scripted::new(vec![ProcWaitEvent::Error {
            kind: mvm_agentd::vsock::ProcErrorKind::UnknownToken,
            message: "no such process".into(),
        }]));
        let stream = open_on(&table, ops);
        let (status, body) = call(
            &table,
            unused(),
            STREAM_NEXT,
            serde_json::json!({"stream": stream, "wait_ms": 2000}),
        );
        assert_eq!(status, MVM_HOSTLIB_BACKEND);
        assert_eq!(body["code"], "BACKEND_ERROR");
    }

    #[test]
    fn close_is_idempotent_and_an_unknown_stream_is_refused() {
        let table = StreamTable::new();
        let stream = open_on(&table, unused());
        for _ in 0..2 {
            let (status, _) = call(
                &table,
                unused(),
                STREAM_CLOSE,
                serde_json::json!({"stream": stream}),
            );
            assert_eq!(status, MVM_HOSTLIB_OK);
        }
        let (status, _) = call(
            &table,
            unused(),
            STREAM_NEXT,
            serde_json::json!({"stream": stream}),
        );
        assert_eq!(status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn opening_past_the_cap_is_refused_as_retryable() {
        let table = StreamTable::new();
        for _ in 0..MAX_OPEN_STREAMS {
            table
                .insert(Stream {
                    family: Family::Process,
                    queue: Mutex::new(sync_channel(1).1),
                    held_end: Mutex::new(None),
                })
                .unwrap();
        }
        let (status, body) = call(
            &table,
            unused(),
            STREAM_OPEN,
            serde_json::json!({"id": "web", "token": "tok"}),
        );
        assert_eq!(status, MVM_HOSTLIB_UNAVAILABLE);
        assert_eq!(body["retryable"], true);
    }

    #[test]
    fn requests_refuse_unknown_fields() {
        let table = StreamTable::new();
        for (method, request) in [
            (
                STREAM_OPEN,
                serde_json::json!({"id": "w", "token": "t", "follow": true}),
            ),
            (STREAM_NEXT, serde_json::json!({"stream": 1, "extra": 1})),
            (STREAM_CLOSE, serde_json::json!({"stream": 1, "extra": 1})),
        ] {
            let (status, _) = call(&table, unused(), method, request);
            assert_eq!(status, MVM_HOSTLIB_INVALID_INPUT, "{method}");
        }
    }

    /// Serves a fixed record sequence, then the end or a failure.
    struct Records {
        records: Vec<OutputRecord>,
        fail: Option<String>,
        requested: Mutex<Vec<(String, OutputRequest)>>,
    }

    struct ScriptedReader {
        records: std::vec::IntoIter<OutputRecord>,
        fail: Option<String>,
    }

    impl RecordReader for ScriptedReader {
        fn next_record(&mut self) -> Result<Option<OutputRecord>, String> {
            match self.records.next() {
                Some(record) => Ok(Some(record)),
                None => match self.fail.take() {
                    Some(message) => Err(message),
                    None => Ok(None),
                },
            }
        }
    }

    impl LogSource for Records {
        fn open(&self, id: &str, request: OutputRequest) -> Result<Box<dyn RecordReader>, Outcome> {
            if id == "ghost" {
                return Err(Outcome::from(MvmError::NotFound { id: id.into() }));
            }
            self.requested
                .lock()
                .unwrap()
                .push((id.to_string(), request));
            Ok(Box::new(ScriptedReader {
                records: self.records.clone().into_iter(),
                fail: self.fail.clone(),
            }))
        }
    }

    fn record(seq: u64, kind: StreamKind, payload: &str) -> OutputRecord {
        OutputRecord {
            seq,
            kind,
            origin: mvm_core::stream_client::RecordOrigin::Console,
            payload: payload.as_bytes().to_vec(),
        }
    }

    fn logs_call(
        table: &StreamTable,
        source: &Arc<Records>,
        method: &str,
        request: serde_json::Value,
    ) -> (i32, serde_json::Value) {
        let source: Arc<dyn LogSource> = source.clone();
        let outcome = dispatch_logs(
            table,
            source,
            method,
            &serde_json::to_vec(&request).unwrap(),
        );
        let body = serde_json::from_slice(&outcome.body).unwrap_or(serde_json::Value::Null);
        (outcome.status, body)
    }

    fn records(list: Vec<OutputRecord>) -> Arc<Records> {
        Arc::new(Records {
            records: list,
            fail: None,
            requested: Mutex::new(Vec::new()),
        })
    }

    #[test]
    fn a_log_stream_delivers_every_channel_in_order_then_ends_without_an_outcome() {
        let table = StreamTable::new();
        let source = records(vec![
            record(0, StreamKind::Stdout, "boot"),
            record(1, StreamKind::Stderr, "warn"),
            record(2, StreamKind::Trace, "{}"),
        ]);
        let (status, body) =
            logs_call(&table, &source, LOGS_OPEN, serde_json::json!({"id": "web"}));
        assert_eq!(status, MVM_HOSTLIB_OK, "{body}");
        let stream = body["stream"].as_u64().unwrap();
        let mut events = Vec::new();
        let last = loop {
            let (status, body) = logs_call(
                &table,
                &source,
                LOGS_NEXT,
                serde_json::json!({"stream": stream, "wait_ms": 2000}),
            );
            assert_eq!(status, MVM_HOSTLIB_OK, "{body}");
            events.extend(body["events"].as_array().unwrap().iter().cloned());
            if body["done"] == true {
                break body;
            }
        };
        let names: Vec<&str> = events
            .iter()
            .map(|e| e["stream"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["stdout", "stderr", "trace"]);
        assert_eq!(events[0]["data_b64"], B64.encode("boot"));
        assert!(
            last.get("outcome").is_none(),
            "a log stream has no process outcome"
        );
        assert_eq!(table.open_count(), 0);
    }

    /// Follow is the default, a tail and a channel filter reach the reader.
    #[test]
    fn a_log_request_carries_follow_tail_and_channels_to_the_reader() {
        let table = StreamTable::new();
        let source = records(Vec::new());
        logs_call(
            &table,
            &source,
            LOGS_OPEN,
            serde_json::json!({"id": "web", "tail_lines": 20, "streams": ["stderr"]}),
        );
        logs_call(
            &table,
            &source,
            LOGS_OPEN,
            serde_json::json!({"id": "web", "follow": false}),
        );
        let requested = source.requested.lock().unwrap();
        let (first, second) = (&requested[0].1, &requested[1].1);
        assert!(first.opts.follow);
        assert_eq!(first.history_tail, Some(20));
        assert_eq!(first.console_tail_lines, Some(20));
        assert!(first.opts.kinds.matches(StreamKind::Stderr));
        assert!(!first.opts.kinds.matches(StreamKind::Stdout));
        assert!(!second.opts.follow);
        assert!(second.opts.kinds.matches(StreamKind::Stdout));
        assert_eq!(second.history_tail, None);
    }

    #[test]
    fn a_machine_with_no_capture_is_refused_at_open() {
        let table = StreamTable::new();
        let source = records(Vec::new());
        let (status, _) = logs_call(
            &table,
            &source,
            LOGS_OPEN,
            serde_json::json!({"id": "ghost"}),
        );
        assert_eq!(status, crate::status::MVM_HOSTLIB_NOT_FOUND);
        assert_eq!(table.open_count(), 0);
    }

    /// A read that fails after output (a broken chain, a vanished broker)
    /// delivers the output, then reports the failure.
    #[test]
    fn a_failed_read_reports_its_output_before_its_error() {
        let table = StreamTable::new();
        let source = Arc::new(Records {
            records: vec![record(0, StreamKind::Stdout, "partial")],
            fail: Some("stream chain broken at seq 1".into()),
            requested: Mutex::new(Vec::new()),
        });
        let (_, body) = logs_call(&table, &source, LOGS_OPEN, serde_json::json!({"id": "web"}));
        let stream = body["stream"].as_u64().unwrap();
        let (status, body) = logs_call(
            &table,
            &source,
            LOGS_NEXT,
            serde_json::json!({"stream": stream, "wait_ms": 2000}),
        );
        assert_eq!(status, MVM_HOSTLIB_OK, "{body}");
        assert_eq!(body["events"][0]["data_b64"], B64.encode("partial"));
        let (status, body) = logs_call(
            &table,
            &source,
            LOGS_NEXT,
            serde_json::json!({"stream": stream}),
        );
        assert_eq!(status, MVM_HOSTLIB_BACKEND);
        assert!(body["message"].as_str().unwrap().contains("chain broken"));
    }

    /// A handle belongs to the family that opened it: a log handle cannot be
    /// polled or closed through the DevOnly process methods, nor the reverse.
    #[test]
    fn a_handle_is_only_reachable_through_its_own_family() {
        let table = StreamTable::new();
        let source = records(vec![record(0, StreamKind::Stdout, "x")]);
        let (_, body) = logs_call(&table, &source, LOGS_OPEN, serde_json::json!({"id": "web"}));
        let log_stream = body["stream"].as_u64().unwrap();
        let (status, _) = call(
            &table,
            unused(),
            STREAM_NEXT,
            serde_json::json!({"stream": log_stream}),
        );
        assert_eq!(status, MVM_HOSTLIB_INVALID_INPUT);
        call(
            &table,
            unused(),
            STREAM_CLOSE,
            serde_json::json!({"stream": log_stream}),
        );
        assert_eq!(
            table.open_count(),
            1,
            "the process family cannot close a log stream"
        );

        let proc_stream = open_on(&table, unused());
        let (status, _) = logs_call(
            &table,
            &source,
            LOGS_NEXT,
            serde_json::json!({"stream": proc_stream}),
        );
        assert_eq!(status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn log_requests_refuse_unknown_fields_and_unknown_channels() {
        let table = StreamTable::new();
        let source = records(Vec::new());
        for request in [
            serde_json::json!({"id": "web", "since": 1}),
            serde_json::json!({"id": "web", "streams": ["console"]}),
        ] {
            let (status, _) = logs_call(&table, &source, LOGS_OPEN, request);
            assert_eq!(status, MVM_HOSTLIB_INVALID_INPUT);
        }
    }

    #[test]
    fn every_stream_method_is_known() {
        for method in LOG_METHODS {
            assert!(is_log_method(method));
            assert!(!is_known(method));
        }
        for method in METHODS {
            assert!(is_known(method));
        }
    }
}
