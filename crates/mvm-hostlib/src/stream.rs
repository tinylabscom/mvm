//! `guest.proc.stream.*`: a guest process's output, delivered while it runs.
//!
//! One C call returns once, so output that arrives over time is a handle and
//! a poll rather than a callback into the binding. `open` starts a reader
//! thread that waits on the process through the same `wait_process` the
//! buffered `guest.proc.wait` uses, and queues each chunk. `next` hands back
//! whatever has arrived, waiting up to a bound for the first chunk, and says
//! when the process has ended and how. `close` drops the handle.
//!
//! The queue is bounded. A binding that stops polling stalls the reader, and
//! through it the guest process's pipe, rather than growing this process
//! without bound. Closing the handle unblocks the reader, which then discards
//! the rest of the output until the process ends or its wait times out: a wait
//! already in flight on the guest agent cannot be withdrawn, so the reader
//! outlives the handle by at most that long.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_agentd::vsock::ProcWaitEvent;
use mvm_core::client::MvmError;
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

/// Every stream method.
pub const METHODS: [&str; 3] = [STREAM_OPEN, STREAM_NEXT, STREAM_CLOSE];

/// Chunks a reader may queue before it waits for the binding to poll. Each is
/// at most one agent frame, so this bounds what one stream holds in memory.
const QUEUE_CHUNKS: usize = 64;
/// Streams open at once. Past this, `open` refuses and says to close one.
pub const MAX_OPEN_STREAMS: usize = 256;
/// How long `next` waits for a first chunk when the request names no bound.
const DEFAULT_WAIT_MS: u64 = 1_000;
/// The longest `next` may be asked to wait.
pub const MAX_WAIT_MS: u64 = 30_000;
/// Bytes `next` returns in one reply before leaving the rest for the next
/// call, so one reply stays a bounded allocation on both sides of the ABI.
const REPLY_BUDGET: usize = 4 * 1024 * 1024;

/// Whether `method` is a stream method.
pub(crate) fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

/// Which output stream a chunk came from.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StreamName {
    Stdout,
    Stderr,
}

/// What a reader queues.
enum Item {
    Chunk(StreamName, Vec<u8>),
    /// The wait's terminal event, or why the wait itself failed.
    End(Result<ProcWaitEvent, String>),
}

/// One open stream: the reader's queue, and an end the last `next` read but
/// could not report because it was already returning output.
struct Stream {
    queue: Mutex<Receiver<Item>>,
    held_end: Mutex<Option<Result<ProcWaitEvent, String>>>,
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
                reason: format!(
                    "{MAX_OPEN_STREAMS} process streams are already open; close one first"
                ),
            }));
        }
        state.next_id = state.next_id.wrapping_add(1);
        let id = state.next_id;
        state.open.insert(id, Arc::new(stream));
        Ok(id)
    }

    fn get(&self, id: u64) -> Result<Arc<Stream>, Outcome> {
        self.state()
            .open
            .get(&id)
            .cloned()
            .ok_or_else(|| Outcome::invalid_input(&format!("no open stream {id}")))
    }

    fn remove(&self, id: u64) {
        self.state().open.remove(&id);
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
    /// The process has ended and the stream is closed.
    done: bool,
    /// How it ended; present exactly when `done`.
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<WaitOutcome>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct Empty {}

/// Answer the stream method `method`, opening readers over `ops`.
pub(crate) fn dispatch(
    table: &StreamTable,
    ops: Arc<dyn GuestOps>,
    method: &str,
    request: &[u8],
) -> Outcome {
    match answer(table, ops, method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(
    table: &StreamTable,
    ops: Arc<dyn GuestOps>,
    method: &str,
    request: &[u8],
) -> Result<Outcome, Outcome> {
    Ok(match method {
        STREAM_OPEN => {
            let r: OpenRequest = parse(request)?;
            Outcome::ok(&OpenReply {
                stream: open(table, ops, r)?,
            })
        }
        STREAM_NEXT => {
            let r: NextRequest = parse(request)?;
            let wait = Duration::from_millis(r.wait_ms.unwrap_or(DEFAULT_WAIT_MS).min(MAX_WAIT_MS));
            Outcome::ok(&next(table, r.stream, wait)?)
        }
        STREAM_CLOSE => {
            let r: CloseRequest = parse(request)?;
            table.remove(r.stream);
            Outcome::ok(&Empty {})
        }
        other => return Err(Outcome::invalid_input(&format!("unknown method `{other}`"))),
    })
}

/// Start the reader and register its queue.
fn open(table: &StreamTable, ops: Arc<dyn GuestOps>, request: OpenRequest) -> Result<u64, Outcome> {
    let (sender, receiver) = sync_channel(QUEUE_CHUNKS);
    let id = table.insert(Stream {
        queue: Mutex::new(receiver),
        held_end: Mutex::new(None),
    })?;
    let spawned = std::thread::Builder::new()
        .name("mvm-hostlib-proc-stream".into())
        .spawn(move || read_until_end(ops.as_ref(), &request, &sender));
    if let Err(e) = spawned {
        table.remove(id);
        return Err(Outcome::failure(
            MVM_HOSTLIB_INTERNAL,
            mvm_core::error_codes::INTERNAL,
            &format!("the stream reader would not start: {e}"),
            false,
        ));
    }
    Ok(id)
}

/// The reader: wait on the process, queueing each chunk, then its end. A send
/// that fails means the handle was closed; the rest is discarded.
fn read_until_end(ops: &dyn GuestOps, request: &OpenRequest, sender: &SyncSender<Item>) {
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
    let _ = sender.send(Item::End(ended.map_err(|e| format!("{e:#}"))));
}

/// Collect what has arrived on stream `id`, waiting up to `wait` for the
/// first chunk.
fn next(table: &StreamTable, id: u64, wait: Duration) -> Result<NextReply, Outcome> {
    let stream = table.get(id)?;
    let mut held = stream
        .held_end
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(end) = held.take() {
        table.remove(id);
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
    // A failed wait is an error reply, which cannot also carry output. Hand
    // back the output first and report the failure on the next call.
    if end.is_err() && !events.is_empty() {
        *held = Some(end);
        return Ok(NextReply {
            events,
            done: false,
            outcome: None,
        });
    }
    table.remove(id);
    finish(events, end)
}

/// The reader went away without saying how the process ended.
fn lost_reader() -> Item {
    Item::End(Err("the stream reader ended without a result".into()))
}

/// The final reply for a stream whose process has ended.
fn finish(
    events: Vec<StreamEvent>,
    end: Result<ProcWaitEvent, String>,
) -> Result<NextReply, Outcome> {
    let terminal = end.map_err(|message| guest_error(anyhow::anyhow!(message)))?;
    let outcome = match terminal {
        ProcWaitEvent::Exit { code } => WaitOutcome::Exited { code },
        ProcWaitEvent::Killed { signal } => WaitOutcome::Killed { signal },
        ProcWaitEvent::TimedOut => WaitOutcome::TimedOut,
        ProcWaitEvent::Error { kind, message } => {
            return Err(guest_error(anyhow::anyhow!(
                "ProcWait error ({kind:?}): {message}"
            )));
        }
        other => {
            return Err(guest_error(anyhow::anyhow!(
                "unexpected terminal wait event: {other:?}"
            )));
        }
    };
    Ok(NextReply {
        events,
        done: true,
        outcome: Some(outcome),
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

    #[test]
    fn every_stream_method_is_known() {
        for method in METHODS {
            assert!(is_known(method));
        }
    }
}
