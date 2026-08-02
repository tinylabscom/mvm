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

use mvm_core::transcript::{Admission, CaptureBounds, GapMarker, RingState};

use crate::entrypoint::{CallCaps, ControlRecord, kill_and_reap, signal_of};
use crate::vsock::{EntrypointEvent, MAX_DATA_CHUNK_SIZE};

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

/// Control-record `kind` the agent stamps on a retention gap.
pub const GAP_RECORD_KIND: &str = "mvm.stream.gap";

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

    /// Wire name used in a gap record's header.
    pub fn name(self) -> &'static str {
        match self {
            CapturedStream::Stdout => "stdout",
            CapturedStream::Stderr => "stderr",
        }
    }
}

/// Bytes one stream's retention ring evicted over the life of a call. Its
/// presence means output was dropped — never that the workload was stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamGap {
    pub stream: CapturedStream,
    pub marker: GapMarker,
}

impl StreamGap {
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
}

impl<'a> Pump<'a> {
    pub fn new(caps: &'a CallCaps) -> Self {
        Self {
            caps,
            control: None,
            deadline: None,
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

    pub fn run(self, child: &mut Child, sink: &mut dyn FnMut(EntrypointEvent)) -> PumpOutcome {
        let (tx, rx) = mpsc::channel();
        if let Some(stdout) = child.stdout.take() {
            spawn_stream_reader(stdout, CapturedStream::Stdout, tx.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_stream_reader(stderr, CapturedStream::Stderr, tx.clone());
        }
        if let Some(control) = self.control {
            spawn_control_reader(control, self.caps.fd3_max, tx.clone());
        }
        // Every reader hanging up is how the drain below learns it has seen
        // the last byte, so the pump must not keep a sender of its own.
        drop(tx);

        let outcome = loop {
            let drained = drain_batch(&rx, sink);
            if let Some(outcome) = poll_child_once(child, self.deadline, self.caps) {
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

/// One non-blocking check of the child. `None` means it is still running and
/// still inside its deadline.
fn poll_child_once(
    child: &mut Child,
    deadline: Option<Instant>,
    caps: &CallCaps,
) -> Option<PumpOutcome> {
    match child.try_wait() {
        Ok(Some(status)) => Some(outcome_from_status(&status)),
        Ok(None) => {
            if deadline.is_some_and(|at| Instant::now() >= at) {
                kill_and_reap(child, caps.kill_grace_period);
                Some(PumpOutcome::Timeout)
            } else {
                None
            }
        }
        // `try_wait` failing leaves the child in a state we cannot reason
        // about; kill it rather than pump an unreapable process forever.
        Err(_) => {
            kill_and_reap(child, caps.kill_grace_period);
            Some(PumpOutcome::Timeout)
        }
    }
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

/// Reader thread for the fd-3 control channel. Frame layout:
///
/// ```text
///   header_len:  u32 LE   (4 bytes; max 64 KiB)
///   header_json: bytes    (header_len bytes; UTF-8 JSON)
///   payload_len: u32 LE   (4 bytes)
///   payload:     bytes    (payload_len bytes)
/// ```
///
/// Reads until EOF or `total_max` bytes, whichever comes first, emitting each
/// complete record as it is parsed. Past the cap it simply stops reading: the
/// channel carries structured records the host correlates by kind, so dropping
/// later ones beats killing the wrapper. A partial record at EOF, an oversized
/// header, or a non-UTF-8 header ends the stream — all three are corruption
/// signals, and the host already tolerates a response that stops at any point.
fn spawn_control_reader(read_fd: OwnedFd, total_max: usize, tx: Sender<EntrypointEvent>) {
    std::thread::spawn(move || {
        let file = std::fs::File::from(read_fd);
        let mut reader = std::io::BufReader::new(file);
        let mut consumed: usize = 0;

        loop {
            let mut len_buf = [0u8; 4];
            if reader.read_exact(&mut len_buf).is_err() {
                break; // EOF or transient I/O error
            }
            let header_len = u32::from_le_bytes(len_buf) as usize;
            if header_len > FD3_HEADER_MAX {
                break; // refuse oversized header — likely corrupt
            }
            consumed = consumed.saturating_add(4 + header_len);
            if consumed > total_max {
                break;
            }

            let mut header_bytes = vec![0u8; header_len];
            if reader.read_exact(&mut header_bytes).is_err() {
                break;
            }
            let Ok(header_json) = String::from_utf8(header_bytes) else {
                break;
            };

            if reader.read_exact(&mut len_buf).is_err() {
                break;
            }
            let payload_len = u32::from_le_bytes(len_buf) as usize;
            consumed = consumed.saturating_add(4 + payload_len);
            if consumed > total_max {
                break;
            }

            let mut payload = vec![0u8; payload_len];
            if reader.read_exact(&mut payload).is_err() {
                break;
            }

            if tx
                .send(EntrypointEvent::Control {
                    header_json,
                    payload,
                })
                .is_err()
            {
                return;
            }
        }
    });
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
        let mut gaps = Vec::new();
        if let Some(marker) = self.stdout.gap {
            gaps.push(StreamGap {
                stream: CapturedStream::Stdout,
                marker,
            });
        }
        if let Some(marker) = self.stderr.gap {
            gaps.push(StreamGap {
                stream: CapturedStream::Stderr,
                marker,
            });
        }
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
    gap: Option<GapMarker>,
}

impl RetainedStream {
    fn new(max_bytes: usize) -> Self {
        Self {
            ring: RingState::new(CaptureBounds {
                // `RingState` reads only the byte and chunk bounds. Bounding
                // by bytes alone is the whole intent here: a chunk count
                // follows from the read size, so a second bound would evict on
                // a dimension the caller never asked about.
                max_duration_secs: 0,
                max_bytes: max_bytes as u64,
                max_chunks: u64::MAX,
            }),
            chunks: VecDeque::new(),
            gap: None,
        }
    }

    fn push(&mut self, chunk: Vec<u8>) {
        if let Admission::AcceptAfterPruning {
            pruned_seqs,
            dropped_bytes,
        } = self.ring.admit(chunk.len() as u64)
        {
            // The ring hands back sequence numbers; this queue is pushed in
            // lockstep with it, so the evicted seqs are exactly its front.
            for _ in 0..pruned_seqs.len() {
                self.chunks.pop_front();
            }
            self.record_gap(&pruned_seqs, dropped_bytes);
        }
        self.chunks.push_back(chunk);
    }

    /// Fold one eviction into the running gap. A call reports at most one gap
    /// per stream: a consumer needs to know output was lost and where the
    /// surviving window starts, not the eviction history that got it there.
    fn record_gap(&mut self, pruned_seqs: &[u64], dropped_bytes: u64) {
        let Some(&after_seq) = pruned_seqs.last() else {
            return;
        };
        let dropped_chunks = pruned_seqs.len() as u64;
        self.gap = Some(match self.gap {
            Some(prev) => GapMarker {
                after_seq,
                dropped_chunks: prev.dropped_chunks.saturating_add(dropped_chunks),
                dropped_bytes: prev.dropped_bytes.saturating_add(dropped_bytes),
            },
            None => GapMarker {
                after_seq,
                dropped_chunks,
                dropped_bytes,
            },
        });
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
        std::thread::spawn(move || {
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
    fn a_slow_sink_loses_no_bytes_and_the_child_still_exits_cleanly() {
        // 512 KiB is eight pipe buffers: if the sink ran on the reader thread,
        // this child would spend the whole run blocked on a full pipe. Timing
        // is not asserted (it would be flaky); byte-for-byte delivery plus a
        // clean exit is what a stalled or wedged pump would fail.
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
