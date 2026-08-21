//! Streaming output pump for a spawned workload.
//!
//! The shape this replaces drained stdout and stderr into capped buffers on
//! their own threads and joined them only once the child had exited, so not
//! one byte left the guest until the workload was dead. A workload that runs
//! for an hour looked silent for an hour. Here, one reader thread per fd emits
//! an [`EntrypointEvent`] per read and a single drain loop hands those to the
//! sink while the child is still running.
//!
//! Three properties the shape exists to guarantee:
//!
//! - **Output is observable before exit.** The sink sees a chunk as soon as
//!   the kernel has one, not when the child is reaped.
//! - **A slow sink never stalls the workload.** Reader threads only hand off
//!   through a channel; they never call the sink. A consumer that blocks
//!   therefore cannot let the child's pipe fill and wedge it mid-write.
//! - **A byte cap never kills a workload.** Retention is a ring
//!   ([`RingState`]): an over-cap stream evicts its oldest retained chunks and
//!   records a [`GapMarker`]. A workload killed for producing too much output
//!   is unobservable exactly when it is most interesting.
//!
//! Ordering within one stream is preserved because that stream has exactly one
//! reader, the channel is FIFO, and the sink is invoked from one place. No
//! ordering is defined *between* stdout and stderr — the kernel defines none
//! either, they are two independent pipes.

use std::collections::VecDeque;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::process::{Child, ExitStatus};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Instant;

use mvm_core::transcript::{Admission, CaptureBounds, GapMarker, GapTally, RingState};

use crate::entrypoint::{
    CallCaps, CancellationToken, ControlRecord, signal_of, signal_process_group,
};
use crate::vsock::{EntrypointEvent, GuestResponse, MAX_DATA_CHUNK_SIZE, MAX_FRAME_SIZE};

/// Bytes pulled from a pipe in one `read`. Larger than the frame budget on
/// purpose: a chatty workload costs fewer syscalls, and the read is split into
/// frame-sized events on the way out.
const READ_BUF_BYTES: usize = 64 * 1024;

/// Events handed to the sink between two child-liveness checks. Bounds how
/// long a producer fast enough to keep the queue non-empty can defer the
/// deadline check — without it, a workload that never stops writing would
/// never reach its own timeout.
const EVENTS_PER_POLL: usize = 64;

/// Per-frame header limit on the fd-3 control channel. Defense in depth: a
/// wrapper writes short envelope JSON there, never arbitrary blobs.
const FD3_HEADER_MAX: usize = 64 * 1024;

/// Per-frame payload limit on the fd-3 control channel. A `Control` event is
/// handed to the sink as one unit — unlike stdout/stderr it is never split
/// across events — so its payload is held to the same single-frame wire
/// budget a stdout/stderr chunk already is.
const FD3_PAYLOAD_MAX: usize = MAX_DATA_CHUNK_SIZE;

/// Control-record `kind` namespace reserved for the agent.
///
/// The child holds fd 3 by construction, so it writes the same channel the
/// agent's own records ride. Framing separates records; it does not establish
/// authorship. Anything arriving from the child under this prefix is a forgery
/// and is dropped at the parse site, which is why an agent-authored record must
/// never travel through fd 3 — it is constructed in-process and handed to the
/// sink directly.
pub const RESERVED_KIND_PREFIX: &str = "mvm.";

/// Control-record `kind` the agent stamps on a retention gap.
pub const GAP_RECORD_KIND: &str = "mvm.stream.gap";

/// Control-record `kind` the agent stamps on a record it could not frame.
pub const CONTROL_DROPPED_KIND: &str = "mvm.stream.control_dropped";

/// Header bytes kept from a record too big to frame. Enough to carry the
/// `kind` field a reader identifies the record by, and short enough that the
/// replacement fits whatever escaping the original demanded.
const DROPPED_HEADER_PREFIX_MAX: usize = 256;

/// How a pumped child ended. Deliberately has no cap-breach variant: output
/// volume is not a way for a call to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpOutcome {
    /// The child exited on its own with this status code.
    Exited(i32),
    /// The child died on a signal (segfault, OOM kill, an external `kill`).
    Crashed { signal: i32 },
    /// The child outlived its deadline and was killed.
    Timeout,
    /// The owning controller canceled the call and the child was killed.
    Canceled,
}

/// Which of a workload's two byte streams a chunk or a gap belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedStream {
    Stdout,
    Stderr,
}

impl CapturedStream {
    fn event(self, chunk: Vec<u8>) -> EntrypointEvent {
        match self {
            CapturedStream::Stdout => EntrypointEvent::Stdout { chunk },
            CapturedStream::Stderr => EntrypointEvent::Stderr { chunk },
        }
    }

    /// Which byte stream an event belongs to, or `None` for one that belongs
    /// to neither (a control record, a terminal). The inverse of [`event`].
    ///
    /// [`event`]: CapturedStream::event
    pub fn of(event: &EntrypointEvent) -> Option<Self> {
        match event {
            EntrypointEvent::Stdout { .. } => Some(CapturedStream::Stdout),
            EntrypointEvent::Stderr { .. } => Some(CapturedStream::Stderr),
            EntrypointEvent::Control { .. }
            | EntrypointEvent::Exit { .. }
            | EntrypointEvent::Error { .. } => None,
        }
    }

    /// Wire name used in a gap record's header.
    pub fn name(self) -> &'static str {
        match self {
            CapturedStream::Stdout => "stdout",
            CapturedStream::Stderr => "stderr",
        }
    }
}

/// Bytes of a stream's byte bound that buy one retained chunk.
///
/// A byte bound cannot see what a chunk costs beyond its payload. Every
/// retained chunk is an event slot plus its own allocation — call it a hundred
/// bytes — so a workload writing one byte per `write` fits a million chunks
/// inside a 1 MiB byte bound and pays tens of megabytes of overhead for a
/// megabyte of output, on top of leaving a queue long enough that touching it
/// stops being free. Charging a page per chunk holds that overhead near a
/// fiftieth of the byte bound whatever the write size, and never binds for
/// chunks a page or larger — which is every chunk a pipe read of a chatty
/// workload produces.
pub(crate) const RETENTION_BYTES_PER_CHUNK: u64 = 4096;

/// Chunks a stream may retain however small its byte bound is.
///
/// Below this the overhead being bounded is a couple of kilobytes in absolute
/// terms, so there is nothing to amplify and the byte bound alone should decide
/// what a small capture keeps.
pub(crate) const MIN_RETENTION_CHUNKS: u64 = 32;

/// A [`RingState`] bounding one stream's retention by bytes and by chunk count.
///
/// The chunk bound is derived from the byte bound rather than asked for
/// separately: it exists to bound per-chunk overhead the caller's byte figure
/// silently excludes, not to express a second policy. Reaching it prunes the
/// oldest chunks exactly as the byte bound does — [`RingState`] has no refusing
/// variant, so a cap here can never silence a workload.
pub fn stream_retention_ring(max_bytes: usize) -> RingState {
    let max_bytes = max_bytes as u64;
    RingState::new(CaptureBounds {
        // `RingState` reads only the byte and chunk bounds.
        max_duration_secs: 0,
        max_bytes,
        max_chunks: (max_bytes / RETENTION_BYTES_PER_CHUNK).max(MIN_RETENTION_CHUNKS),
    })
}

/// Clamp one control record to something that provably fits a single response
/// frame, replacing it with an agent-authored notice when it does not.
///
/// A header only has to be valid UTF-8, and JSON escaping costs up to six
/// characters per control byte — so a record well inside the fd-3 field caps
/// can still encode past the frame cap. The writer's own overflow handling
/// substitutes a generic error response for such a frame, which a host reading
/// until terminal treats as the end of the call: one unframeable record would
/// discard every event behind it. Replacing it here keeps the record count and
/// the terminal intact, and tells the reader exactly what was lost.
///
/// The notice claims the agent's reserved namespace, which is legitimate
/// precisely because this runs after the authorship gate — a workload's own
/// record can never reach this function still claiming that prefix.
pub fn control_within_frame_budget(header_json: String, payload: Vec<u8>) -> EntrypointEvent {
    let candidate = EntrypointEvent::Control {
        header_json,
        payload,
    };
    if frames_within_cap(&candidate) {
        return candidate;
    }
    // Take the fields back out to describe what was dropped. The other arm is
    // unreachable — the value was built as a `Control` three lines up — and
    // handing it back unchanged is the honest thing to do if that ever stops
    // being true.
    let (header_json, payload) = match candidate {
        EntrypointEvent::Control {
            header_json,
            payload,
        } => (header_json, payload),
        other => return other,
    };
    let header = serde_json::json!({
        "kind": CONTROL_DROPPED_KIND,
        "header_bytes": header_json.len(),
        "payload_bytes": payload.len(),
        "header_prefix": char_bounded_prefix(&header_json, DROPPED_HEADER_PREFIX_MAX),
    });
    EntrypointEvent::Control {
        header_json: header.to_string(),
        payload: Vec::new(),
    }
}

/// Whether the event encodes inside the response frame cap. Measured against
/// the same envelope the writer frames, so the answer is the writer's answer
/// rather than an estimate that can drift from it — worth one copy on a path
/// that runs once per control record and never per output chunk.
fn frames_within_cap(event: &EntrypointEvent) -> bool {
    let framed = GuestResponse::EntrypointEvent(event.clone());
    serde_json::to_vec(&framed).is_ok_and(|encoded| encoded.len() <= MAX_FRAME_SIZE)
}

/// Apply the frame budget to a decoded control record, leaving anything else
/// untouched.
fn bound_to_one_frame(event: EntrypointEvent) -> EntrypointEvent {
    match event {
        EntrypointEvent::Control {
            header_json,
            payload,
        } => control_within_frame_budget(header_json, payload),
        other => other,
    }
}

/// The longest prefix of `text` that is at most `max_bytes` long and does not
/// split a UTF-8 character.
fn char_bounded_prefix(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Bytes one stream's retention ring evicted over the life of a call. Its
/// presence means output was dropped — never that the workload was stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamGap {
    pub stream: CapturedStream,
    pub marker: GapMarker,
}

impl StreamGap {
    /// The at-most-one gap each stream reports, stdout first. Both `None` —
    /// the normal case — gives an empty vec.
    pub fn from_markers(stdout: Option<GapMarker>, stderr: Option<GapMarker>) -> Vec<StreamGap> {
        [
            (CapturedStream::Stdout, stdout),
            (CapturedStream::Stderr, stderr),
        ]
        .into_iter()
        .filter_map(|(stream, marker)| marker.map(|marker| StreamGap { stream, marker }))
        .collect()
    }

    /// Render the gap as a control record. It rides fd-3's channel rather than
    /// stdout or stderr because it is agent-authored metadata about the
    /// capture, not workload output, and injecting it inline would corrupt the
    /// very bytes it is reporting on.
    pub fn control_record(&self) -> ControlRecord {
        let header = serde_json::json!({
            "kind": GAP_RECORD_KIND,
            "stream": self.stream.name(),
            "after_seq": self.marker.after_seq,
            "dropped_chunks": self.marker.dropped_chunks,
            "dropped_bytes": self.marker.dropped_bytes,
        });
        ControlRecord {
            header_json: header.to_string(),
            payload: Vec::new(),
        }
    }
}

/// Everything one call captured, independent of how the call ended.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CapturedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub controls: Vec<ControlRecord>,
    /// One entry per stream whose ring evicted bytes. Empty is the normal
    /// case.
    pub gaps: Vec<StreamGap>,
}

/// Pump one child's output to a sink.
///
/// The three-argument form runs without a deadline and without a control
/// channel; [`Pump`] is the builder for the rest.
pub fn pump_child(
    child: &mut Child,
    sink: &mut dyn FnMut(EntrypointEvent),
    caps: &CallCaps,
) -> PumpOutcome {
    Pump::new(caps).run(child, sink)
}

/// Builder for a pump run. Optional pieces — the fd-3 control channel and the
/// wall-clock deadline — are set here rather than threaded through the call so
/// a caller that wants neither writes [`pump_child`].
pub struct Pump<'a> {
    caps: &'a CallCaps,
    control: Option<OwnedFd>,
    deadline: Option<Instant>,
    cancellation: Option<CancellationToken>,
}

impl<'a> Pump<'a> {
    pub fn new(caps: &'a CallCaps) -> Self {
        Self {
            caps,
            control: None,
            deadline: None,
            cancellation: None,
        }
    }

    /// Read end of the pipe whose write end the child holds at fd 3. Framed
    /// records parsed from it are emitted as [`EntrypointEvent::Control`].
    pub fn control_channel(mut self, read_fd: OwnedFd) -> Self {
        self.control = Some(read_fd);
        self
    }

    /// Kill the child's process group and report [`PumpOutcome::Timeout`] once
    /// this instant passes. Without it the pump waits for the child forever.
    ///
    /// The child must have been spawned with `process_group(0)`: the kill
    /// addresses `-pgid` so it reaches descendants still holding the pipes
    /// open, and a child that is not its own group leader is not reachable
    /// that way at all.
    pub fn deadline(mut self, at: Instant) -> Self {
        self.deadline = Some(at);
        self
    }

    /// Cancel this call when the owning controller requests it.
    pub fn cancellation(mut self, token: CancellationToken) -> Self {
        self.cancellation = Some(token);
        self
    }

    pub fn run(mut self, child: &mut Child, sink: &mut dyn FnMut(EntrypointEvent)) -> PumpOutcome {
        // Close any stdin still attached to the `Child`. The pump waits for the
        // child to exit, and a workload that reads to EOF never gets there
        // while the agent holds the write end open — the wait would outlast the
        // call. Whoever intends to keep writing takes the handle out first
        // (`stream_input::InputSink`), which makes owning stdin a decision
        // rather than something a caller forgets to undo.
        drop(child.stdin.take());

        let (tx, rx) = mpsc::channel();
        if let Some(stdout) = child.stdout.take() {
            spawn_stream_reader(stdout, CapturedStream::Stdout, tx.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_stream_reader(stderr, CapturedStream::Stderr, tx.clone());
        }
        if let Some(control) = self.control.take() {
            spawn_control_reader(control, self.caps.fd3_max, tx.clone());
        }
        // Every reader hanging up is how the drain below learns it has seen
        // the last byte, so the pump must not keep a sender of its own.
        drop(tx);

        let mut ladder = KillLadder::Running;
        let outcome = loop {
            let drained = drain_batch(&rx, sink);
            if let Some(outcome) = self.poll_child_once(child, &mut ladder) {
                break outcome;
            }
            if drained == 0 {
                std::thread::sleep(self.caps.poll_interval);
            }
        };

        // The child is reaped, but bytes it already wrote can still be in
        // flight, and a process-group survivor can still hold a pipe open.
        // Drain to EOF so nothing written is lost to the exit.
        while let Ok(event) = rx.recv() {
            sink(event);
        }
        outcome
    }

    /// One non-blocking look at the child, advancing the kill ladder if it is
    /// overdue. `None` means keep pumping.
    ///
    /// Nothing here blocks. A blocking SIGTERM→grace→SIGKILL wait would park
    /// the only consumer for the whole grace period while the child keeps
    /// writing at pipe speed, and in-flight bytes would grow by grace ×
    /// throughput — unbounded, in a guest with a fixed memory budget. A
    /// wrapper that traps SIGTERM and keeps printing is all it takes.
    fn poll_child_once(&self, child: &mut Child, ladder: &mut KillLadder) -> Option<PumpOutcome> {
        // Through `child_wait`, never the inherent method: when the agent is
        // PID 1 its orphan reaper can consume the status first, and only the
        // shared waiter can then say what the workload actually exited with.
        match crate::child_wait::try_wait(child) {
            // A child we signalled is reported by *why* we signalled it, not
            // by the signal that finally landed.
            Ok(Some(status)) => Some(match ladder {
                KillLadder::Running => outcome_from_status(&status),
                KillLadder::Terminated { reason, .. } | KillLadder::Killed { reason } => {
                    reason.outcome()
                }
            }),
            Ok(None) => {
                self.step_kill_ladder(child, ladder);
                None
            }
            // We cannot read this child's status, so we cannot reap it either.
            // Signal the group so the readers reach EOF and give up on it
            // rather than pump a process we can never observe again.
            Err(_) => {
                signal_process_group(child, libc::SIGKILL);
                Some(
                    self.cancellation
                        .as_ref()
                        .filter(|token| token.is_requested())
                        .map_or(PumpOutcome::Timeout, |_| PumpOutcome::Canceled),
                )
            }
        }
    }

    /// Advance the SIGTERM → grace → SIGKILL ladder by at most one rung. Each
    /// rung is a signal delivery and returns immediately; the caller's loop
    /// supplies the waiting, and keeps draining while it waits.
    fn step_kill_ladder(&self, child: &Child, ladder: &mut KillLadder) {
        match ladder {
            KillLadder::Running => {
                let reason = if self
                    .cancellation
                    .as_ref()
                    .is_some_and(CancellationToken::is_requested)
                {
                    Some(TerminationReason::Canceled)
                } else if self.deadline.is_some_and(|at| Instant::now() >= at) {
                    Some(TerminationReason::Timeout)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    signal_process_group(child, libc::SIGTERM);
                    *ladder = KillLadder::Terminated {
                        escalate_at: Instant::now() + self.caps.kill_grace_period,
                        reason,
                    };
                }
            }
            KillLadder::Terminated {
                escalate_at,
                reason,
            } => {
                if Instant::now() >= *escalate_at {
                    signal_process_group(child, libc::SIGKILL);
                    *ladder = KillLadder::Killed { reason: *reason };
                }
            }
            KillLadder::Killed { .. } => {}
        }
    }
}

#[derive(Clone, Copy)]
enum TerminationReason {
    Timeout,
    Canceled,
}

impl TerminationReason {
    fn outcome(self) -> PumpOutcome {
        match self {
            Self::Timeout => PumpOutcome::Timeout,
            Self::Canceled => PumpOutcome::Canceled,
        }
    }
}

/// How far a pump run has walked the kill ladder. Held across loop iterations
/// so the wait between rungs happens in the drain loop rather than inside a
/// blocking call.
enum KillLadder {
    /// Nothing signalled; the child is inside its deadline or has none.
    Running,
    /// SIGTERM delivered; escalate to SIGKILL at this instant.
    Terminated {
        escalate_at: Instant,
        reason: TerminationReason,
    },
    /// SIGKILL delivered; only reaping is left.
    Killed { reason: TerminationReason },
}

/// Hand at most [`EVENTS_PER_POLL`] queued events to the sink and report how
/// many moved. Never blocks: an empty or hung-up channel just returns.
fn drain_batch(rx: &Receiver<EntrypointEvent>, sink: &mut dyn FnMut(EntrypointEvent)) -> usize {
    let mut drained = 0;
    while drained < EVENTS_PER_POLL {
        match rx.try_recv() {
            Ok(event) => {
                sink(event);
                drained += 1;
            }
            Err(_) => break,
        }
    }
    drained
}

fn outcome_from_status(status: &ExitStatus) -> PumpOutcome {
    match status.code() {
        Some(code) => PumpOutcome::Exited(code),
        None => PumpOutcome::Crashed {
            signal: signal_of(status),
        },
    }
}

/// One reader thread for one pipe. It touches only the channel, never the
/// sink, so no consumer can stall it and let the child's pipe fill.
fn spawn_stream_reader<R: Read + Send + 'static>(
    mut reader: R,
    stream: CapturedStream,
    tx: Sender<EntrypointEvent>,
) {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; READ_BUF_BYTES];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    // One event has to fit one vsock data frame, so a read
                    // wider than the frame budget is split rather than handed
                    // on as an unsendable event. Order is preserved.
                    for part in buf[..n].chunks(MAX_DATA_CHUNK_SIZE) {
                        if tx.send(stream.event(part.to_vec())).is_err() {
                            return; // the pump is gone; nothing left to feed
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    });
}

/// Why [`decode_fd3_frame`] could not produce a record from the front of its
/// input.
///
/// [`Fd3Error::Incomplete`] means "not yet": `buf` simply hasn't accumulated a
/// whole frame, and the same bytes are still good once more have arrived. The
/// other three variants mean the frame at the front of `buf` is bad, but each
/// carries the length(s) `decode_fd3_frame` already parsed before giving up —
/// exactly what a caller needs to walk past the bad frame and resync on the
/// one behind it, without ever buffering the bytes it is skipping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fd3Error {
    /// `header_len` exceeds [`FD3_HEADER_MAX`]. Carries the declared length so
    /// a caller can walk past the whole header field without buffering it.
    HeaderTooLarge { header_len: usize },
    /// `payload_len` exceeds [`FD3_PAYLOAD_MAX`]. The header behind it already
    /// validated, so both lengths are carried for a caller to skip the whole
    /// record.
    PayloadTooLarge {
        header_len: usize,
        payload_len: usize,
    },
    /// The header bytes are not valid UTF-8. Framing is intact — the header is
    /// already fully buffered — so the declared length is carried for a
    /// caller to skip past it.
    NonUtf8Header { header_len: usize },
    /// `buf` does not yet hold a complete frame.
    Incomplete,
}

impl std::fmt::Display for Fd3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fd3Error::HeaderTooLarge { header_len } => {
                write!(f, "header of {header_len} bytes exceeds {FD3_HEADER_MAX}")
            }
            Fd3Error::PayloadTooLarge { payload_len, .. } => {
                write!(
                    f,
                    "payload of {payload_len} bytes exceeds {FD3_PAYLOAD_MAX}"
                )
            }
            Fd3Error::NonUtf8Header { header_len } => {
                write!(f, "{header_len}-byte header is not valid UTF-8")
            }
            Fd3Error::Incomplete => write!(f, "frame is incomplete"),
        }
    }
}

impl std::error::Error for Fd3Error {}

/// Decode one fd-3 control-channel frame from the front of `buf`. Frame
/// layout:
///
/// ```text
///   header_len:  u32 LE   (4 bytes; max 64 KiB)
///   header_json: bytes    (header_len bytes; UTF-8 JSON)
///   payload_len: u32 LE   (4 bytes; max 48 KiB)
///   payload:     bytes    (payload_len bytes)
/// ```
///
/// Pure: no I/O, no allocation ahead of what `buf` already holds, no panic on
/// adversarial input. `Ok((consumed, event))` means `buf[..consumed]` was
/// exactly one frame; the caller advances by `consumed` and may call again
/// immediately, since one read often lands more than one frame.
/// `Err(Fd3Error::Incomplete)` means the opposite of advancing: the caller
/// must retry the same bytes once more have arrived, not skip any of them.
/// Every declared length is bounds-checked before the allocation it gates, so
/// a hostile length never buys more than one rejected comparison. The other
/// `Err` variants carry the length(s) already parsed, so a caller can skip
/// exactly that many bytes and resync on the frame behind this one instead of
/// abandoning the rest of the stream.
pub fn decode_fd3_frame(buf: &[u8]) -> Result<(usize, EntrypointEvent), Fd3Error> {
    const LEN: usize = 4;

    if buf.len() < LEN {
        return Err(Fd3Error::Incomplete);
    }
    let header_len = read_u32_le(&buf[..LEN]) as usize;
    if header_len > FD3_HEADER_MAX {
        return Err(Fd3Error::HeaderTooLarge { header_len });
    }

    let header_end = LEN + header_len;
    if buf.len() < header_end {
        return Err(Fd3Error::Incomplete);
    }
    let header_json = String::from_utf8(buf[LEN..header_end].to_vec())
        .map_err(|_| Fd3Error::NonUtf8Header { header_len })?;

    let payload_len_end = header_end + LEN;
    if buf.len() < payload_len_end {
        return Err(Fd3Error::Incomplete);
    }
    let payload_len = read_u32_le(&buf[header_end..payload_len_end]) as usize;
    if payload_len > FD3_PAYLOAD_MAX {
        return Err(Fd3Error::PayloadTooLarge {
            header_len,
            payload_len,
        });
    }

    let payload_end = payload_len_end + payload_len;
    if buf.len() < payload_end {
        return Err(Fd3Error::Incomplete);
    }
    let payload = buf[payload_len_end..payload_end].to_vec();

    Ok((
        payload_end,
        EntrypointEvent::Control {
            header_json,
            payload,
        },
    ))
}

/// `src` must be exactly 4 bytes — every call site slices it that way.
fn read_u32_le(src: &[u8]) -> u32 {
    u32::from_le_bytes(src.try_into().expect("caller sliced exactly 4 bytes"))
}

/// Reader thread for the fd-3 control channel. [`decode_fd3_frame`] owns the
/// wire layout and every bounds check; this loop owns the policy around it —
/// read, decode whatever is buffered, apply the reserved-kind gate, hand the
/// rest to the sink, and enforce the per-call byte budget.
///
/// A frame [`decode_fd3_frame`] refuses for its size, or for its header not
/// being valid UTF-8, does not end the channel: the length(s) that condemned
/// it are exactly what is needed to walk past it and land on the frame behind
/// it, so one bad record costs one record. Only two things stop the reader
/// outright: the cumulative byte budget (`total_max`) being exceeded — by an
/// accepted frame or a skipped one, since both occupy real bytes on the wire
/// — and the stream ending before a skip in progress can finish, because at
/// that point there genuinely is no byte offset left for "the next frame" to
/// resync onto.
///
/// A record claiming [`RESERVED_KIND_PREFIX`] is dropped and parsing
/// continues. This is the boundary at which fd-3's bytes stop being
/// untrusted, so it is the only place the rule can hold without every
/// downstream consumer having to remember it: a workload that could mint an
/// agent-authored record would be able to forge a gap marker, and a verifier
/// that trusts one will bless a chain skipping output it never saw.
fn spawn_control_reader(read_fd: OwnedFd, total_max: usize, tx: Sender<EntrypointEvent>) {
    std::thread::spawn(move || {
        let mut reader = std::fs::File::from(read_fd);
        let mut pending: Vec<u8> = Vec::new();
        let mut read_buf = vec![0u8; READ_BUF_BYTES];
        let mut cap = CumulativeCap::new(total_max);

        loop {
            match decode_fd3_frame(&pending) {
                Ok((consumed, event)) => {
                    pending.drain(..consumed);
                    if !cap.bump(consumed) {
                        cap.log_exceeded();
                        return;
                    }
                    // Framing is intact, so keep parsing — only this record is refused.
                    let is_reserved = matches!(
                        &event,
                        EntrypointEvent::Control { header_json, .. }
                            if claims_reserved_kind(header_json)
                    );
                    if !is_reserved && tx.send(bound_to_one_frame(event)).is_err() {
                        return; // the pump is gone; nothing left to feed
                    }
                    continue; // `pending` may already hold the next frame
                }
                Err(Fd3Error::Incomplete) => {} // fall through and read more
                Err(
                    err @ (Fd3Error::HeaderTooLarge { header_len }
                    | Fd3Error::NonUtf8Header { header_len }),
                ) => {
                    if !skip_header_record(
                        &mut reader,
                        &mut pending,
                        &mut read_buf,
                        &mut cap,
                        header_len,
                        err,
                    ) {
                        return;
                    }
                    continue; // `pending` now starts at the frame behind the bad one
                }
                Err(
                    err @ Fd3Error::PayloadTooLarge {
                        header_len,
                        payload_len,
                    },
                ) => {
                    if !skip_payload_record(
                        &mut reader,
                        &mut pending,
                        &mut read_buf,
                        &mut cap,
                        header_len,
                        payload_len,
                        err,
                    ) {
                        return;
                    }
                    continue;
                }
            }

            match reader.read(&mut read_buf) {
                Ok(0) => {
                    if !pending.is_empty() {
                        eprintln!(
                            "mvm-guest-agent: fd-3 control channel closed: {} leftover byte(s) \
                             at EOF never formed a complete frame",
                            pending.len()
                        );
                    }
                    return;
                }
                Ok(n) => pending.extend_from_slice(&read_buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    eprintln!("mvm-guest-agent: fd-3 control channel closed: read error: {e}");
                    return;
                }
            }
        }
    });
}

/// Running tally against the fd-3 control channel's per-call byte budget.
/// Every byte a record occupies counts here — accepted, reserved-kind-
/// dropped, or skipped for being malformed — so the cap bounds total channel
/// activity rather than just the frames that reached the sink. Without that,
/// a stream of nothing but oversized headers would never be capped, since it
/// would never produce an accepted frame to count.
struct CumulativeCap {
    consumed: usize,
    max: usize,
}

impl CumulativeCap {
    fn new(max: usize) -> Self {
        Self { consumed: 0, max }
    }

    /// Add `n` wire bytes to the running total. `false` means the cap no
    /// longer holds.
    fn bump(&mut self, n: usize) -> bool {
        self.consumed = self.consumed.saturating_add(n);
        self.consumed <= self.max
    }

    fn log_exceeded(&self) {
        eprintln!(
            "mvm-guest-agent: fd-3 control channel closed: cumulative cap of {} bytes exceeded",
            self.max
        );
    }
}

/// Skip a record refused for its header — too large, or not valid UTF-8 —
/// then the payload field behind it, whose length is unknowable until the
/// header is behind us. `false` means the reader must stop: either the
/// cumulative cap was exceeded, or the stream ended before the skip could
/// complete, in which case there is no reliable offset left to resync onto.
fn skip_header_record(
    reader: &mut impl Read,
    pending: &mut Vec<u8>,
    scratch: &mut [u8],
    cap: &mut CumulativeCap,
    header_len: usize,
    reason: Fd3Error,
) -> bool {
    let header_field_len = 4 + header_len;
    if !cap.bump(header_field_len) {
        cap.log_exceeded();
        return false;
    }
    if !discard_exact(reader, pending, header_field_len, scratch) {
        eprintln!(
            "mvm-guest-agent: fd-3 control channel closed: stream ended while skipping a \
             malformed header ({reason})"
        );
        return false;
    }
    let Some(payload_len) = read_len_prefix(reader, pending, scratch) else {
        eprintln!(
            "mvm-guest-agent: fd-3 control channel closed: stream ended while skipping the \
             payload behind a malformed header ({reason})"
        );
        return false;
    };
    if !cap.bump(4 + payload_len) {
        cap.log_exceeded();
        return false;
    }
    if !discard_exact(reader, pending, payload_len, scratch) {
        eprintln!(
            "mvm-guest-agent: fd-3 control channel closed: stream ended while skipping the \
             payload behind a malformed header ({reason})"
        );
        return false;
    }
    eprintln!("mvm-guest-agent: fd-3 dropped a malformed header ({reason}); continuing");
    true
}

/// Skip a record refused only for its payload. The header behind it and both
/// length prefixes already validated in full and sit in `pending` in their
/// entirety, so only the oversized payload itself remains unread. See
/// [`skip_header_record`] for the cap/logging shape this mirrors.
fn skip_payload_record(
    reader: &mut impl Read,
    pending: &mut Vec<u8>,
    scratch: &mut [u8],
    cap: &mut CumulativeCap,
    header_len: usize,
    payload_len: usize,
    reason: Fd3Error,
) -> bool {
    let prefix_len = 4 + header_len + 4;
    if !cap.bump(prefix_len + payload_len) {
        cap.log_exceeded();
        return false;
    }
    pending.drain(..prefix_len);
    if !discard_exact(reader, pending, payload_len, scratch) {
        eprintln!(
            "mvm-guest-agent: fd-3 control channel closed: stream ended while skipping an \
             oversized payload ({reason})"
        );
        return false;
    }
    eprintln!("mvm-guest-agent: fd-3 dropped an oversized payload ({reason}); continuing");
    true
}

/// Discard exactly `n` bytes from the logical stream — whatever `pending`
/// already holds, then directly from `reader` — without ever holding more
/// than one `scratch`-sized read in memory at once. This is what lets a
/// hostile declared length cost this thread time, never memory: the bytes
/// themselves are worthless, but their count on the wire is real, and reading
/// past them (rather than buffering them) is the only way to know where the
/// next frame starts. `false` means the stream ended or errored before all
/// `n` bytes were seen.
fn discard_exact(
    reader: &mut impl Read,
    pending: &mut Vec<u8>,
    n: usize,
    scratch: &mut [u8],
) -> bool {
    let from_pending = n.min(pending.len());
    pending.drain(..from_pending);
    let mut remaining = n - from_pending;
    while remaining > 0 {
        let want = remaining.min(scratch.len());
        match reader.read(&mut scratch[..want]) {
            Ok(0) => return false,
            Ok(read) => remaining -= read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// Read and consume the next 4-byte little-endian length prefix from the
/// logical stream — `pending` first, then `reader`. `None` means the stream
/// ended before a full prefix arrived. Bytes read past the prefix itself are
/// left in `pending` rather than discarded, since they belong to whatever
/// comes next (typically the payload the caller is about to skip).
fn read_len_prefix(
    reader: &mut impl Read,
    pending: &mut Vec<u8>,
    scratch: &mut [u8],
) -> Option<usize> {
    while pending.len() < 4 {
        match reader.read(scratch) {
            Ok(0) => return None,
            Ok(n) => pending.extend_from_slice(&scratch[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    let len = read_u32_le(&pending[..4]) as usize;
    pending.drain(..4);
    Some(len)
}

/// Whether a control-record header claims a `kind` inside the agent's
/// reserved namespace.
///
/// Public because fd 3 is not the only channel a workload's control records
/// arrive on — a warm worker sends its own over the worker protocol — and the
/// rule has to hold wherever they enter, not just here.
///
/// A header that is not a JSON object with a string `kind` claims nothing: no
/// consumer can read a kind out of it either, so it passes through as the
/// opaque record it has always been. Matching on the parsed value rather than
/// the raw text is deliberate — `mvm.` and a duplicate `kind` key both
/// decode to the same string a consumer would see, and a textual check would
/// miss both.
pub fn claims_reserved_kind(header_json: &str) -> bool {
    let Ok(header) = serde_json::from_str::<serde_json::Value>(header_json) else {
        return false;
    };
    header
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kind| kind.starts_with(RESERVED_KIND_PREFIX))
}

/// A pump sink that keeps a bounded tail of each stream.
///
/// This is what turns a streaming pump back into the buffered result a
/// per-call RPC has to answer with. Retention is the only place a cap applies:
/// what the sink emits is never capped, so nothing is withheld from a live
/// consumer.
pub struct RetainingSink {
    stdout: RetainedStream,
    stderr: RetainedStream,
    controls: Vec<ControlRecord>,
}

impl RetainingSink {
    pub fn new(caps: &CallCaps) -> Self {
        Self {
            stdout: RetainedStream::new(caps.stdout_max),
            stderr: RetainedStream::new(caps.stderr_max),
            controls: Vec::new(),
        }
    }

    /// The sink itself. Pass as `&mut |event| sink.accept(event)`.
    pub fn accept(&mut self, event: EntrypointEvent) {
        match event {
            EntrypointEvent::Stdout { chunk } => self.stdout.push(chunk),
            EntrypointEvent::Stderr { chunk } => self.stderr.push(chunk),
            EntrypointEvent::Control {
                header_json,
                payload,
            } => self.controls.push(ControlRecord {
                header_json,
                payload,
            }),
            // The pump never emits a terminal event — the caller synthesizes
            // one from the `PumpOutcome` — so there is nothing to retain.
            EntrypointEvent::Exit { .. } | EntrypointEvent::Error { .. } => {}
        }
    }

    pub fn finish(self) -> CapturedOutput {
        let gaps = StreamGap::from_markers(self.stdout.gap.marker(), self.stderr.gap.marker());
        CapturedOutput {
            stdout: self.stdout.into_bytes(),
            stderr: self.stderr.into_bytes(),
            controls: self.controls,
            gaps,
        }
    }
}

/// One stream's ring-bounded tail. `RingState` owns the eviction policy; this
/// holds the payloads it decides to keep.
struct RetainedStream {
    ring: RingState,
    chunks: VecDeque<Vec<u8>>,
    gap: GapTally,
}

impl RetainedStream {
    fn new(max_bytes: usize) -> Self {
        Self {
            ring: stream_retention_ring(max_bytes),
            chunks: VecDeque::new(),
            gap: GapTally::default(),
        }
    }

    fn push(&mut self, chunk: Vec<u8>) {
        let admission = self.ring.admit(chunk.len() as u64);
        if let Admission::AcceptAfterPruning { pruned_seqs, .. } = &admission {
            // The ring hands back sequence numbers; this queue is pushed in
            // lockstep with it, so the evicted seqs are exactly its front.
            for _ in 0..pruned_seqs.len() {
                self.chunks.pop_front();
            }
        }
        self.gap.record(&admission);
        self.chunks.push_back(chunk);
    }

    fn into_bytes(self) -> Vec<u8> {
        self.chunks.into_iter().flatten().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    /// Spawn a shell child shaped like a production wrapper: its own process
    /// group, both streams piped. The group matters for the deadline path —
    /// `kill_and_reap` signals `-pgid`.
    fn sh(script: &str) -> Child {
        use std::os::unix::process::CommandExt;
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child")
    }

    fn caps_with_stdout_max(stdout_max: usize) -> CallCaps {
        CallCaps {
            stdout_max,
            poll_interval: Duration::from_millis(10),
            ..CallCaps::default()
        }
    }

    /// Encode one fd-3 frame with an empty payload.
    fn control_frame(header_json: &str) -> Vec<u8> {
        let header = header_json.as_bytes();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(header.len() as u32).to_le_bytes());
        frame.extend_from_slice(header);
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame
    }

    /// Drive `spawn_control_reader` over a real pipe — the same fd the child
    /// writes — and collect what it lets through.
    fn read_control_frames(wire: &[u8]) -> Vec<ControlRecord> {
        read_control_frames_with_cap(wire, 64 * 1024)
    }

    /// As [`read_control_frames`], with an explicit cumulative cap — for
    /// fixtures whose wire is deliberately bigger than the default (a skipped
    /// oversized record still counts its bytes against the cap, so a fixture
    /// built around one needs enough headroom to prove resync rather than the
    /// cap itself).
    fn read_control_frames_with_cap(wire: &[u8], total_max: usize) -> Vec<ControlRecord> {
        use std::io::Write;
        let (reader, mut writer) = std::io::pipe().expect("pipe");
        let (tx, rx) = mpsc::channel();
        spawn_control_reader(OwnedFd::from(reader), total_max, tx);
        writer.write_all(wire).expect("write frames");
        drop(writer);
        rx.into_iter()
            .map(|event| match event {
                EntrypointEvent::Control {
                    header_json,
                    payload,
                } => ControlRecord {
                    header_json,
                    payload,
                },
                other => panic!("expected a control event, got {other:?}"),
            })
            .collect()
    }

    /// Encode one fd-3 frame with an arbitrary payload.
    fn frame_bytes(header_json: &str, payload: &[u8]) -> Vec<u8> {
        let header = header_json.as_bytes();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(header.len() as u32).to_le_bytes());
        frame.extend_from_slice(header);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    // -- decode_fd3_frame: pure, no thread or pipe involved ------------

    #[test]
    fn decode_well_formed_frame_reports_bytes_consumed() {
        let frame = frame_bytes(r#"{"kind":"app.log"}"#, b"payload-bytes");
        let (consumed, event) = decode_fd3_frame(&frame).expect("well-formed frame decodes");
        assert_eq!(consumed, frame.len());
        match event {
            EntrypointEvent::Control {
                header_json,
                payload,
            } => {
                assert_eq!(header_json, r#"{"kind":"app.log"}"#);
                assert_eq!(payload, b"payload-bytes");
            }
            other => panic!("expected Control, got {other:?}"),
        }
    }

    #[test]
    fn decode_refuses_a_header_over_the_size_cap() {
        // The length prefix alone is enough to refuse — no header bytes,
        // let alone a payload, ever need to arrive.
        let oversized = ((FD3_HEADER_MAX + 1) as u32).to_le_bytes();
        assert_eq!(
            decode_fd3_frame(&oversized),
            Err(Fd3Error::HeaderTooLarge {
                header_len: FD3_HEADER_MAX + 1
            })
        );
    }

    #[test]
    fn decode_accepts_a_header_at_exactly_the_size_cap() {
        // A boundary check that only ever tests `cap + 1` cannot catch an
        // off-by-one that also rejects the legal boundary value itself.
        let header = "x".repeat(FD3_HEADER_MAX);
        let frame = frame_bytes(&header, b"");
        let (consumed, event) = decode_fd3_frame(&frame).expect("boundary-sized header decodes");
        assert_eq!(consumed, frame.len());
        match event {
            EntrypointEvent::Control { header_json, .. } => {
                assert_eq!(header_json.len(), FD3_HEADER_MAX)
            }
            other => panic!("expected Control, got {other:?}"),
        }
    }

    #[test]
    fn decode_refuses_a_payload_over_the_size_cap() {
        let header = br#"{"kind":"app.log"}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(header.len() as u32).to_le_bytes());
        frame.extend_from_slice(header);
        frame.extend_from_slice(&((FD3_PAYLOAD_MAX + 1) as u32).to_le_bytes());
        // No payload bytes needed — same fail-fast property as the header.
        assert_eq!(
            decode_fd3_frame(&frame),
            Err(Fd3Error::PayloadTooLarge {
                header_len: header.len(),
                payload_len: FD3_PAYLOAD_MAX + 1,
            })
        );
    }

    #[test]
    fn decode_accepts_a_payload_at_exactly_the_size_cap() {
        let payload = vec![0xab_u8; FD3_PAYLOAD_MAX];
        let frame = frame_bytes(r#"{"kind":"app.log"}"#, &payload);
        let (consumed, event) = decode_fd3_frame(&frame).expect("boundary-sized payload decodes");
        assert_eq!(consumed, frame.len());
        match event {
            EntrypointEvent::Control { payload, .. } => assert_eq!(payload.len(), FD3_PAYLOAD_MAX),
            other => panic!("expected Control, got {other:?}"),
        }
    }

    #[test]
    fn decode_refuses_a_non_utf8_header() {
        let bad_header: [u8; 3] = [0xff, 0xfe, 0xfd];
        let mut frame = Vec::new();
        frame.extend_from_slice(&(bad_header.len() as u32).to_le_bytes());
        frame.extend_from_slice(&bad_header);
        assert_eq!(
            decode_fd3_frame(&frame),
            Err(Fd3Error::NonUtf8Header {
                header_len: bad_header.len()
            })
        );
    }

    #[test]
    fn decode_reports_incomplete_without_consuming_a_truncated_frame() {
        let full = frame_bytes(r#"{"kind":"app.log"}"#, b"payload");
        for cut in 0..full.len() {
            assert_eq!(
                decode_fd3_frame(&full[..cut]),
                Err(Fd3Error::Incomplete),
                "a {cut}-byte prefix must report Incomplete, not a fatal error"
            );
        }
        // The full frame decodes cleanly once every byte is present — proof
        // the prefixes above were genuinely awaiting more bytes, not silently
        // rejecting a frame no `Err` variant carries a byte count for.
        let (consumed, _) = decode_fd3_frame(&full).expect("complete frame decodes");
        assert_eq!(consumed, full.len());
    }

    #[test]
    fn decode_reads_back_to_back_frames_from_one_buffer() {
        let first = frame_bytes(r#"{"kind":"a"}"#, b"");
        let second = frame_bytes(r#"{"kind":"b"}"#, b"xyz");
        let mut both = first.clone();
        both.extend_from_slice(&second);

        let (consumed_first, event_first) = decode_fd3_frame(&both).expect("first frame decodes");
        assert_eq!(consumed_first, first.len());
        match event_first {
            EntrypointEvent::Control { header_json, .. } => {
                assert_eq!(header_json, r#"{"kind":"a"}"#);
            }
            other => panic!("expected Control, got {other:?}"),
        }

        let (consumed_second, event_second) =
            decode_fd3_frame(&both[consumed_first..]).expect("second frame decodes");
        assert_eq!(consumed_second, second.len());
        match event_second {
            EntrypointEvent::Control {
                header_json,
                payload,
            } => {
                assert_eq!(header_json, r#"{"kind":"b"}"#);
                assert_eq!(payload, b"xyz");
            }
            other => panic!("expected Control, got {other:?}"),
        }
        assert_eq!(consumed_first + consumed_second, both.len());
    }

    // -- spawn_control_reader: malformed records are skipped, not fatal ---

    #[test]
    fn a_header_too_large_frame_ends_the_stream_when_the_wire_runs_out_mid_skip() {
        // The declared header is bigger than the rest of the wire actually
        // supplies, so the reader is still walking past it when it hits EOF.
        // There is no byte offset for "the next frame" in that case — the
        // stream simply stopped short — so this, not the oversized length by
        // itself, is what must end the reader.
        let mut wire = ((FD3_HEADER_MAX + 1) as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(&control_frame(r#"{"kind":"app.log"}"#));
        assert!(
            read_control_frames(&wire).is_empty(),
            "the stream ended before the oversized header could be fully skipped"
        );
    }

    #[test]
    fn a_record_after_an_oversized_header_still_arrives() {
        // Unlike the fixture above, this wire actually supplies every byte
        // the bad record declares, so the reader can walk all the way past it
        // and land on the frame behind it — proof that one oversized header
        // costs one record, not the rest of the channel.
        let oversized_len = FD3_HEADER_MAX + 1;
        let mut wire = (oversized_len as u32).to_le_bytes().to_vec();
        wire.extend(std::iter::repeat_n(b'x', oversized_len)); // discarded regardless of content
        wire.extend_from_slice(&0u32.to_le_bytes()); // the bad record's own (empty) payload
        wire.extend_from_slice(&control_frame(r#"{"kind":"survivor"}"#));

        let records = read_control_frames_with_cap(&wire, 1024 * 1024);
        assert_eq!(
            records.len(),
            1,
            "the oversized header must be dropped but the record behind it must survive, got \
             {records:?}"
        );
        assert_eq!(records[0].header_json, r#"{"kind":"survivor"}"#);
    }

    #[test]
    fn a_record_after_an_oversized_payload_still_arrives() {
        // Same property as the header case, exercised on the other resync
        // path: the payload declares more than FD3_PAYLOAD_MAX, the wire
        // supplies every byte of it, and the frame behind it must still
        // arrive.
        let header = br#"{"kind":"app.log"}"#;
        let oversized_payload_len = FD3_PAYLOAD_MAX + 1;
        let mut wire = Vec::new();
        wire.extend_from_slice(&(header.len() as u32).to_le_bytes());
        wire.extend_from_slice(header);
        wire.extend_from_slice(&(oversized_payload_len as u32).to_le_bytes());
        wire.extend(std::iter::repeat_n(0u8, oversized_payload_len));
        wire.extend_from_slice(&control_frame(r#"{"kind":"survivor"}"#));

        let records = read_control_frames_with_cap(&wire, 1024 * 1024);
        assert_eq!(
            records.len(),
            1,
            "the oversized payload must be dropped but the record behind it must survive, got \
             {records:?}"
        );
        assert_eq!(records[0].header_json, r#"{"kind":"survivor"}"#);
    }

    #[test]
    fn a_truncated_frame_at_eof_yields_no_records() {
        // Header promises 10 bytes; the wire closes 5 bytes short.
        let mut wire = 10u32.to_le_bytes().to_vec();
        wire.extend_from_slice(b"short");
        assert!(read_control_frames(&wire).is_empty());
    }

    #[test]
    fn the_cumulative_cap_stops_the_stream_once_exceeded() {
        use std::io::Write;
        let small = control_frame(r#"{"kind":"a"}"#);
        let (reader, mut writer) = std::io::pipe().expect("pipe");
        let (tx, rx) = mpsc::channel();
        // Two frames fit exactly; a third pushes cumulative bytes over.
        spawn_control_reader(OwnedFd::from(reader), small.len() * 2, tx);
        for _ in 0..3 {
            writer.write_all(&small).expect("write frame");
        }
        drop(writer);

        let records: Vec<_> = rx.into_iter().collect();
        assert_eq!(
            records.len(),
            2,
            "expected exactly the two frames the cap admits, got {records:?}"
        );
    }

    #[test]
    fn stdout_reaches_the_sink_before_the_child_exits() {
        // A child that prints, holds the process open, then exits. If the pump
        // buffers, the sink stays empty until the sleep completes.
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("printf early; sleep 3")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child");

        let (tx, rx) = std::sync::mpsc::channel();
        let pump = std::thread::spawn(move || {
            let mut sink = |e: EntrypointEvent| {
                let _ = tx.send(e);
            };
            pump_child(&mut child, &mut sink, &CallCaps::default())
        });

        let first = rx
            .recv_timeout(Duration::from_millis(1500))
            .expect("a chunk must arrive well before the child exits");
        match first {
            EntrypointEvent::Stdout { chunk } => assert_eq!(chunk, b"early"),
            other => panic!("expected stdout, got {other:?}"),
        }

        // Everything above is the assertion; this only reaps. Returning here
        // would end the test process while the pump thread still owns a live
        // child, leaving `sleep 3` orphaned onto init — measured, not assumed.
        assert_eq!(pump.join().expect("pump thread"), PumpOutcome::Exited(0));
    }

    #[test]
    fn the_pump_closes_a_stdin_its_caller_left_attached() {
        // A `Child` still holding the write end keeps the workload's stdin
        // open, so a read-to-EOF child never exits and this call never
        // returns. The hang is the assertion; the outcome is the receipt.
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cat");
        let outcome = pump_child(&mut child, &mut |_| {}, &caps_with_stdout_max(1024));
        assert_eq!(outcome, PumpOutcome::Exited(0));
    }

    #[test]
    fn bytes_of_one_stream_arrive_in_order() {
        let mut child = sh("printf a; printf b; printf c >&2; printf d");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let outcome = pump_child(
            &mut child,
            &mut |e| match e {
                EntrypointEvent::Stdout { chunk } => stdout.extend_from_slice(&chunk),
                EntrypointEvent::Stderr { chunk } => stderr.extend_from_slice(&chunk),
                other => panic!("unexpected event {other:?}"),
            },
            &caps_with_stdout_max(1024),
        );
        assert_eq!(outcome, PumpOutcome::Exited(0));
        assert_eq!(stdout, b"abd");
        assert_eq!(stderr, b"c");
    }

    #[test]
    fn a_cap_breach_prunes_and_marks_a_gap_without_killing_the_child() {
        // 256 KiB of output against a 128 KiB retention bound. The old shape
        // killed the wrapper here; the child must now run to its own clean
        // exit and the loss must show up as a gap.
        let caps = caps_with_stdout_max(128 * 1024);
        let mut child = sh("head -c 262144 /dev/zero");
        let mut retained = RetainingSink::new(&caps);
        let outcome = pump_child(&mut child, &mut |e| retained.accept(e), &caps);
        let output = retained.finish();

        assert_eq!(
            outcome,
            PumpOutcome::Exited(0),
            "a cap breach must not terminate the workload"
        );
        assert_eq!(
            output.gaps.len(),
            1,
            "expected one gap, got {:?}",
            output.gaps
        );
        assert_eq!(output.gaps[0].stream, CapturedStream::Stdout);
        assert!(output.gaps[0].marker.dropped_bytes > 0);
        assert!(
            output.stdout.len() <= caps.stdout_max,
            "retained {} bytes against a {} byte bound",
            output.stdout.len(),
            caps.stdout_max
        );
        assert!(!output.stdout.is_empty(), "the newest bytes must survive");
    }

    #[test]
    fn the_ring_keeps_the_newest_bytes_and_reports_what_it_dropped() {
        // Process-level output is uniform, so pruning order is asserted here
        // against distinguishable chunks instead.
        let caps = caps_with_stdout_max(10);
        let mut sink = RetainingSink::new(&caps);
        for chunk in [b"aaaa", b"bbbb", b"cccc"] {
            sink.accept(EntrypointEvent::Stdout {
                chunk: chunk.to_vec(),
            });
        }
        let output = sink.finish();
        assert_eq!(
            output.stdout, b"bbbbcccc",
            "oldest chunk must be the one lost"
        );
        assert_eq!(
            output.gaps,
            vec![StreamGap {
                stream: CapturedStream::Stdout,
                marker: GapMarker {
                    after_seq: 0,
                    dropped_chunks: 1,
                    dropped_bytes: 4,
                },
            }]
        );
    }

    #[test]
    fn a_stream_of_one_byte_writes_is_bounded_in_chunks_as_well_as_bytes() {
        // `RetainedStream` holds one `Vec<u8>` per chunk, and a byte bound
        // counts only what those vectors contain. 64 Ki single-byte chunks sit
        // inside a 64 KiB byte bound while costing megabytes of slots and
        // allocations to hold — the byte figure would be off by a factor of a
        // hundred. The chunk bound is what keeps it honest.
        let caps = caps_with_stdout_max(64 * 1024);
        let chunk_bound =
            (caps.stdout_max as u64 / RETENTION_BYTES_PER_CHUNK).max(MIN_RETENTION_CHUNKS);

        let mut sink = RetainingSink::new(&caps);
        for _ in 0..100_000 {
            sink.accept(EntrypointEvent::Stdout { chunk: vec![b'x'] });
        }
        let output = sink.finish();

        // One byte per chunk, so the retained byte count *is* the chunk count.
        assert!(
            output.stdout.len() as u64 <= chunk_bound,
            "retained {} one-byte chunks against a {chunk_bound} chunk bound",
            output.stdout.len()
        );
        assert!(!output.stdout.is_empty(), "the newest writes must survive");
        assert_eq!(
            output.gaps.len(),
            1,
            "the loss must be reported, got {:?}",
            output.gaps
        );
    }

    #[test]
    fn a_stream_under_its_bound_reports_no_gap() {
        let caps = caps_with_stdout_max(1024);
        let mut sink = RetainingSink::new(&caps);
        sink.accept(EntrypointEvent::Stdout {
            chunk: b"small".to_vec(),
        });
        let output = sink.finish();
        assert_eq!(output.stdout, b"small");
        assert!(output.gaps.is_empty());
    }

    #[test]
    fn a_gap_renders_as_a_control_record() {
        let gap = StreamGap {
            stream: CapturedStream::Stderr,
            marker: GapMarker {
                after_seq: 7,
                dropped_chunks: 3,
                dropped_bytes: 4096,
            },
        };
        let record = gap.control_record();
        assert!(record.payload.is_empty());
        let header: serde_json::Value =
            serde_json::from_str(&record.header_json).expect("header is JSON");
        assert_eq!(header["kind"], GAP_RECORD_KIND);
        assert_eq!(header["stream"], "stderr");
        assert_eq!(header["after_seq"], 7);
        assert_eq!(header["dropped_chunks"], 3);
        assert_eq!(header["dropped_bytes"], 4096);
    }

    #[test]
    fn a_slow_sink_receives_every_byte_exactly_once() {
        // Delivery, not non-stalling: a pump that ran the sink on the reader
        // thread would also pass this. What it does catch is loss or
        // duplication when the consumer trails far behind the producer —
        // 512 KiB is eight pipe buffers, so the reader is always well ahead.
        // `a_blocked_sink_does_not_stall_the_child` is the non-stalling
        // witness.
        let mut child = sh("head -c 524288 /dev/zero");
        let mut total = 0usize;
        let outcome = pump_child(
            &mut child,
            &mut |e| {
                if let EntrypointEvent::Stdout { chunk } = e {
                    total += chunk.len();
                    std::thread::sleep(Duration::from_millis(5));
                }
            },
            &caps_with_stdout_max(1024),
        );
        assert_eq!(outcome, PumpOutcome::Exited(0));
        assert_eq!(total, 524288);
    }

    #[test]
    fn a_blocked_sink_does_not_stall_the_child() {
        // The witness that discriminates. The sink blocks forever on its first
        // event; the child writes eight pipe buffers and then touches a marker
        // file. Were the sink invoked from the reader thread, the reader would
        // be parked inside it, the pipe would fill at 64 KiB, the child would
        // block on write, and the marker would never appear.
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("child-finished");
        let mut child = sh(&format!(
            "head -c 524288 /dev/zero; : > {}",
            marker.display()
        ));

        let (reached_sink_tx, reached_sink_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let pump = std::thread::spawn(move || {
            let mut held = false;
            pump_child(
                &mut child,
                &mut |_| {
                    if !held {
                        held = true;
                        let _ = reached_sink_tx.send(());
                        let _ = release_rx.recv();
                    }
                },
                &caps_with_stdout_max(1024),
            )
        });

        reached_sink_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the sink must see a first chunk");

        let wait_until = Instant::now() + Duration::from_secs(10);
        while !marker.exists() && Instant::now() < wait_until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            marker.exists(),
            "the child must finish writing while the sink is still blocked"
        );

        release_tx.send(()).expect("pump thread is alive");
        assert_eq!(pump.join().expect("pump thread"), PumpOutcome::Exited(0));
    }

    #[test]
    fn the_sink_keeps_receiving_while_a_doomed_child_is_being_killed() {
        // A wrapper that ignores SIGTERM and keeps printing. The kill ladder
        // spans the full grace period, and the child writes at pipe speed for
        // all of it — so a pump that waits out the grace inside a blocking
        // kill stops draining while a writer runs, and in-flight bytes grow by
        // grace × throughput with nothing to bound them.
        let caps = CallCaps {
            kill_grace_period: Duration::from_millis(2000),
            poll_interval: Duration::from_millis(10),
            ..CallCaps::default()
        };
        let mut child = sh("trap '' TERM; while :; do printf aaaaaaaaaaaaaaaa; done");

        let started = Instant::now();
        let mut arrivals = Vec::new();
        let outcome = Pump::new(&caps)
            .deadline(started + Duration::from_millis(200))
            .run(&mut child, &mut |_| arrivals.push(started.elapsed()));

        assert_eq!(outcome, PumpOutcome::Timeout);
        // Strictly inside the grace window: after the deadline has certainly
        // passed, and well before a blocking SIGTERM→SIGKILL wait would have
        // returned. A parked consumer delivers nothing in here.
        let window = Duration::from_millis(400)..Duration::from_millis(1200);
        assert!(
            arrivals.iter().any(|at| window.contains(at)),
            "no chunk reached the sink during the kill grace; arrivals: {arrivals:?}"
        );
    }

    #[test]
    fn a_child_written_record_cannot_claim_the_agent_namespace() {
        // fd 3 is the child's to write, so this is where a forged gap marker
        // would enter. A verifier downstream cannot tell a forged one from an
        // agent-authored one, so the refusal has to happen here.
        let forged = control_frame(r#"{"kind":"mvm.stream.gap","after_seq":99}"#);
        let genuine = control_frame(r#"{"kind":"app.log"}"#);
        let mut wire = forged;
        wire.extend_from_slice(&genuine);

        let records = read_control_frames(&wire);
        assert_eq!(
            records.len(),
            1,
            "only the workload's own record survives, got {records:?}"
        );
        assert_eq!(records[0].header_json, r#"{"kind":"app.log"}"#);
    }

    #[test]
    fn a_forged_kind_is_matched_after_decoding_not_as_raw_text() {
        // Both spellings decode to the reserved kind a consumer would read, so
        // a textual prefix check on the header would let both through.
        let escaped = control_frame(r#"{"kind":"mvm.stream.gap"}"#);
        let shadowed = control_frame(r#"{"kind":"app.log","kind":"mvm.stream.gap"}"#);
        let mut wire = escaped;
        wire.extend_from_slice(&shadowed);
        assert!(
            read_control_frames(&wire).is_empty(),
            "a decoded reserved kind must be refused however it was spelled"
        );
    }

    #[test]
    fn a_header_that_is_not_json_still_passes_through() {
        // The agent has never parsed fd-3 headers beyond UTF-8, and a header
        // no consumer can read a `kind` out of claims nothing.
        let records = read_control_frames(&control_frame("not json at all"));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].header_json, "not json at all");
    }

    #[test]
    fn the_agent_gap_kind_lives_inside_the_reserved_namespace() {
        // Drift here would silently reopen the forgery path: a gap kind
        // outside the refused prefix is a kind a child may write.
        assert!(GAP_RECORD_KIND.starts_with(RESERVED_KIND_PREFIX));
        assert!(CONTROL_DROPPED_KIND.starts_with(RESERVED_KIND_PREFIX));
    }

    // -- frame budget: an unframeable record must not end the call ---------

    /// The encoded size of the frame the response writer would emit for one
    /// event.
    fn framed_len(event: &EntrypointEvent) -> usize {
        serde_json::to_vec(&GuestResponse::EntrypointEvent(event.clone()))
            .expect("an event serializes")
            .len()
    }

    #[test]
    fn a_control_record_that_fits_is_framed_verbatim() {
        let event =
            control_within_frame_budget(r#"{"kind":"app.log"}"#.to_string(), b"payload".to_vec());
        assert_eq!(
            event,
            EntrypointEvent::Control {
                header_json: r#"{"kind":"app.log"}"#.to_string(),
                payload: b"payload".to_vec(),
            }
        );
    }

    #[test]
    fn a_header_within_the_fd3_cap_can_still_blow_the_frame_cap() {
        // Headers only have to be valid UTF-8, and a control byte costs six
        // characters escaped. A header the fd-3 decoder accepts is therefore
        // no evidence the frame fits, which is the whole reason for the
        // second bound.
        let hostile = "\u{1}".repeat(FD3_HEADER_MAX);
        assert_eq!(hostile.len(), FD3_HEADER_MAX, "one byte per character");
        let verbatim = EntrypointEvent::Control {
            header_json: hostile.clone(),
            payload: Vec::new(),
        };
        assert!(
            framed_len(&verbatim) > MAX_FRAME_SIZE,
            "fixture no longer exceeds the frame cap; it proves nothing"
        );

        let bounded = control_within_frame_budget(hostile, Vec::new());
        assert!(
            framed_len(&bounded) <= MAX_FRAME_SIZE,
            "the replacement must fit: {} bytes",
            framed_len(&bounded)
        );
    }

    #[test]
    fn an_unframeable_record_becomes_an_agent_notice_naming_what_was_lost() {
        let header = format!(
            r#"{{"kind":"app.log","blob":"{}"}}"#,
            "\u{1}".repeat(60_000)
        );
        let payload = vec![0xff_u8; 1024];
        let bounded = control_within_frame_budget(header.clone(), payload.clone());
        match bounded {
            EntrypointEvent::Control {
                header_json,
                payload: notice_payload,
            } => {
                assert!(notice_payload.is_empty(), "the payload is not carried over");
                let decoded: serde_json::Value =
                    serde_json::from_str(&header_json).expect("the notice header is JSON");
                assert_eq!(decoded["kind"], CONTROL_DROPPED_KIND);
                assert_eq!(decoded["header_bytes"], header.len());
                assert_eq!(decoded["payload_bytes"], payload.len());
                // Enough of the original to identify it, never all of it.
                let prefix = decoded["header_prefix"]
                    .as_str()
                    .expect("prefix is a string");
                assert!(prefix.starts_with(r#"{"kind":"app.log""#), "{prefix:?}");
                assert!(prefix.len() <= DROPPED_HEADER_PREFIX_MAX);
            }
            other => panic!("expected a control record, got {other:?}"),
        }
    }

    #[test]
    fn a_prefix_never_splits_a_utf8_character() {
        // A multi-byte character straddling the cut would make the notice
        // itself unencodable — the failure it exists to prevent.
        let text = "é".repeat(400);
        let prefix = char_bounded_prefix(&text, DROPPED_HEADER_PREFIX_MAX);
        assert!(prefix.len() <= DROPPED_HEADER_PREFIX_MAX);
        assert!(prefix.len() > DROPPED_HEADER_PREFIX_MAX - 2);
        assert!(text.starts_with(prefix));
    }

    #[test]
    fn a_child_written_unframeable_record_reaches_the_sink_as_a_notice() {
        // End to end through the fd-3 reader: the substitution has to happen
        // after the authorship gate, or the agent's own notice would be
        // refused as a forgery and the record would vanish silently.
        let wire = control_frame(&"\u{1}".repeat(FD3_HEADER_MAX));
        let records = read_control_frames_with_cap(&wire, 1024 * 1024);
        assert_eq!(records.len(), 1, "one record in, one record out");
        let header: serde_json::Value =
            serde_json::from_str(&records[0].header_json).expect("the notice header is JSON");
        assert_eq!(header["kind"], CONTROL_DROPPED_KIND);
    }

    #[test]
    fn a_signalled_child_reports_the_signal() {
        let mut child = sh("kill -9 $$");
        let outcome = pump_child(&mut child, &mut |_| {}, &caps_with_stdout_max(1024));
        assert_eq!(outcome, PumpOutcome::Crashed { signal: 9 });
    }

    #[test]
    fn a_child_past_its_deadline_is_killed_and_reported_as_timeout() {
        let caps = CallCaps {
            kill_grace_period: Duration::from_millis(200),
            poll_interval: Duration::from_millis(10),
            ..CallCaps::default()
        };
        let mut child = sh("sleep 300");
        let started = Instant::now();
        let outcome = Pump::new(&caps)
            .deadline(Instant::now() + Duration::from_millis(200))
            .run(&mut child, &mut |_| {});
        assert_eq!(outcome, PumpOutcome::Timeout);
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "timeout took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_nonzero_exit_code_survives_the_pump() {
        let mut child = sh("printf out; exit 7");
        let outcome = pump_child(&mut child, &mut |_| {}, &caps_with_stdout_max(1024));
        assert_eq!(outcome, PumpOutcome::Exited(7));
    }
}
