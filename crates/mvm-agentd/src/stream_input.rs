//! Delivery of admitted input bytes into a running workload's stdin.
//!
//! The one-shot path writes the whole payload once and drops the pipe
//! immediately (`entrypoint::execute`), so EOF is implicit in "there was never
//! going to be more". Continuous input has no such moment: bytes keep arriving
//! for as long as a writer holds the lease, and nothing in the byte stream says
//! where it ends. Three properties carry that difference.
//!
//! - **EOF is explicit and it really closes the fd.** [`InputSink::close`] is
//!   the only thing that ends the stream, and it ends it by dropping the
//!   `ChildStdin` — a flag, a zero-length write or a sentinel byte would leave
//!   a `cat`-shaped workload blocked on a `read` that never returns. Closing
//!   the fd is the signal; there is no second mechanism.
//! - **Delivery order is acceptance order.** Frames are written in the order
//!   they were offered, never re-sorted by [`InputFrame::seq`]. The host gate
//!   scans for secret material across frame boundaries by concatenating what it
//!   accepted, in that order, so a sink that re-sorted could reassemble inside
//!   the guest a secret the gate saw as non-contiguous. The gate holds up its
//!   end by refusing any frame whose `seq` does not advance; this side holds up
//!   its end by not reordering, and neither can drift from what was scanned.
//! - **A child that is not reading cannot stall anything else.** A pipe holds
//!   a page or two, so a `write` into a wedged stdin blocks — and blocking on
//!   the caller's thread would park whichever loop it shares. Writes therefore
//!   happen on this sink's own thread, fed by a channel, and the enqueue side
//!   never waits on the child. What the channel must not do is grow without
//!   bound in a guest with a fixed memory budget, so a queue past
//!   [`MAX_PENDING_INPUT_BYTES`] is refused rather than accepted: backpressure
//!   the writer can see, instead of memory it cannot.
//!
//! [`InputDesk`] is where the two halves meet. The entrypoint runner spawns
//! the child and opens the desk; the host's frames arrive later, each on its
//! own control connection, and find the sink by name. One desk per guest,
//! because one guest is one workload.

use std::io::{self, Write};
use std::process::ChildStdin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use mvm_protocol::stream::input::{CloseInput, InputFrame};
use zeroize::Zeroize;

use crate::vsock::{StreamInputRefusal, StreamInputResult};

/// Bytes that may sit queued for a workload that is not reading its stdin.
///
/// Matches the one-shot payload cap (`CallCaps::stdin_max`), because it bounds
/// the same thing: how much undelivered input the agent will hold on a
/// workload's behalf. Generous enough that a writer streaming at any sane rate
/// never sees it, small enough that a workload which stopped reading costs the
/// guest a megabyte rather than everything it has.
pub const MAX_PENDING_INPUT_BYTES: usize = 1024 * 1024;

/// The writing half of one workload's stdin.
///
/// Owns the `ChildStdin` for the life of the stream — the `Child` must not
/// still hold it, or the fd stays open past [`close`](InputSink::close) and the
/// EOF never lands.
pub struct InputSink {
    tx: Sender<Vec<u8>>,
    pending: Arc<AtomicUsize>,
}

impl InputSink {
    /// Take ownership of a spawned child's stdin and start delivering to it.
    #[must_use]
    pub fn new(stdin: ChildStdin) -> Self {
        let (tx, rx) = mpsc::channel();
        let pending = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&pending);
        std::thread::spawn(move || write_until_closed(stdin, &rx, &counted));
        Self { tx, pending }
    }

    /// Queue one admitted frame's payload for the workload.
    ///
    /// Returns as soon as the bytes are queued; it does not wait for the child
    /// to read them. `WouldBlock` means the queue is at its budget and the
    /// caller should offer the frame again later; `BrokenPipe` means the
    /// workload's stdin is gone and offering it again will not help.
    ///
    /// Frames are delivered in call order. Callers must offer them in the order
    /// the gate accepted them, which is also `seq` order — see the module docs
    /// for why the two must not be allowed to differ.
    pub fn write_frame(&mut self, frame: InputFrame) -> io::Result<()> {
        self.enqueue(frame.payload)
    }

    /// Queue bytes the gate withheld and released at close.
    ///
    /// Separate from [`write_frame`](Self::write_frame) because these bytes
    /// carry no `seq` of their own: the gate holds back a tail that is still a
    /// live prefix of a known secret and releases it when closing proves it was
    /// only ever a prefix. They belong immediately after the highest frame the
    /// gate accepted, which is where calling this before `close` puts them.
    pub fn deliver_tail(&mut self, tail: &[u8]) -> io::Result<()> {
        self.enqueue(tail.to_vec())
    }

    /// Bytes queued for the workload but not yet written to its pipe.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    /// End the input stream: deliver what is queued, then close the fd.
    ///
    /// Dropping the sender is what the writer thread reads as end-of-stream. It
    /// finishes the queue first — a channel hands over everything buffered
    /// before it reports the disconnect — and then drops the `ChildStdin`, and
    /// that fd close *is* the EOF. Bytes handed to
    /// [`deliver_tail`](Self::deliver_tail) therefore land ahead of it rather
    /// than being lost to the close.
    ///
    /// Deliberately does not wait for the writer to drain. A workload that
    /// stopped reading its stdin would make that wait as long as the workload
    /// itself, and closing input is not a reason to block the agent for the
    /// rest of a call. The fd is closed by the thread that owns it, whenever
    /// the last queued byte lands or the child goes away first.
    pub fn close(self) {
        drop(self);
    }

    fn enqueue(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let queued = self.pending.load(Ordering::Relaxed);
        if queued.saturating_add(bytes.len()) > MAX_PENDING_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("workload input queue is full ({queued} bytes undelivered)"),
            ));
        }
        let len = bytes.len();
        self.pending.fetch_add(len, Ordering::Relaxed);
        self.tx.send(bytes).map_err(|_| {
            self.pending.fetch_sub(len, Ordering::Relaxed);
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the workload is no longer reading its stdin",
            )
        })
    }
}

/// Write queued bytes to the workload until the stream ends, then close the fd.
///
/// Runs on its own thread precisely so the blocking `write_all` here is the
/// only thing a full pipe can stall.
fn write_until_closed(mut stdin: ChildStdin, rx: &Receiver<Vec<u8>>, pending: &AtomicUsize) {
    while let Ok(mut bytes) = rx.recv() {
        let delivered = stdin.write_all(&bytes);
        pending.fetch_sub(bytes.len(), Ordering::Relaxed);
        // Delivered input does not linger on the guest heap, mirroring the
        // hygiene the host gate applies to the same bytes on its side.
        bytes.zeroize();
        if delivered.is_err() {
            // The workload closed its stdin or died. Nothing queued behind
            // this will ever be delivered, so drop it out of the accounting:
            // a caller that kept seeing a full queue would retry forever
            // instead of learning the pipe is gone.
            while let Ok(mut undelivered) = rx.try_recv() {
                pending.fetch_sub(undelivered.len(), Ordering::Relaxed);
                undelivered.zeroize();
            }
            break;
        }
    }
    // Dropping `stdin` closes the write end, and that close is the EOF a
    // read-to-EOF workload has been waiting for.
}

/// The workload whose stdin this guest is currently accepting input for, and
/// how far through its stream the agent has got.
///
/// One per guest, because one guest is one workload. Frames arrive on their
/// own control connections — the production listener answers one operational
/// request per connection — so the running entrypoint call and the frames
/// destined for it never share a stack. This is the join.
struct OpenInput {
    sink: InputSink,
    /// Highest `seq` handed to the sink, or `None` before the first frame.
    ///
    /// The host's gate already refuses a frame whose `seq` does not advance,
    /// so this is the same rule checked at the other end of the wire. That is
    /// the point: the gate scans for secret material over the concatenation of
    /// what it accepted, in acceptance order, so a transport that delivered
    /// two frames out of order could reassemble inside the guest a secret the
    /// gate saw as two harmless halves. Refusing here means such a transport
    /// is caught by the end that would suffer from it, not only promised
    /// against by the end that would cause it.
    delivered_seq: Option<u64>,
}

/// Where a host-admitted input frame lands. Reached by name rather than by
/// handle so there is exactly one of it per guest.
pub struct InputDesk;

impl InputDesk {
    /// Accept streamed input for the workload owning `stdin`.
    ///
    /// Called by the entrypoint runner for a call that asked to keep its stdin
    /// open. Replaces whatever was there: the previous call's child has been
    /// reaped by the time a new one spawns, and a stale sink kept around would
    /// answer frames for a workload that no longer exists.
    pub fn open(stdin: ChildStdin) {
        *desk() = Some(OpenInput {
            sink: InputSink::new(stdin),
            delivered_seq: None,
        });
    }

    /// Stop accepting input because the workload is gone.
    ///
    /// Not a close: nothing is delivered and no EOF is synthesized, because
    /// the child that would have read it is already reaped. Dropping the sink
    /// discards whatever was still queued, which is the honest outcome —
    /// there is nowhere left to put it.
    pub fn abandon() {
        *desk() = None;
    }

    /// Queue one admitted frame for the workload.
    pub fn write_frame(frame: InputFrame) -> StreamInputResult {
        let mut slot = desk();
        let Some(open) = slot.as_mut() else {
            return no_workload();
        };
        if let Some(last) = open.delivered_seq
            && frame.seq <= last
        {
            return refused(
                StreamInputRefusal::OutOfOrder,
                format!(
                    "input frame seq {} does not advance past the delivered {last}",
                    frame.seq
                ),
            );
        }
        let seq = frame.seq;
        match open.sink.write_frame(frame) {
            Ok(()) => {
                open.delivered_seq = Some(seq);
                StreamInputResult::Accepted {
                    queued_bytes: open.sink.queued_bytes() as u64,
                }
            }
            Err(err) => refused(refusal_for(&err), err.to_string()),
        }
    }

    /// Deliver the tail the host's gate withheld, then close the workload's
    /// stdin.
    ///
    /// The order is the whole point and the types enforce half of it:
    /// `deliver_tail` takes `&mut self` and `close` takes `self`, so the tail
    /// cannot be shipped after EOF. What no type enforces is that the tail is
    /// handed over at all — those bytes are the writer's last ones, cleared by
    /// the gate and held back only until closing proved they were a prefix of
    /// a secret rather than one.
    pub fn close(close: CloseInput) -> StreamInputResult {
        let mut slot = desk();
        let Some(delivered) = slot.as_ref().map(|open| open.delivered_seq) else {
            return no_workload();
        };
        if close.after_seq < delivered {
            // The close claims to sit before a frame already delivered, so it
            // overtook one in flight. Ending the stream here would cut off
            // bytes the writer sent before it.
            return refused(
                StreamInputRefusal::OutOfOrder,
                format!(
                    "close after_seq {:?} precedes the delivered {delivered:?}",
                    close.after_seq
                ),
            );
        }
        let mut open = slot
            .take()
            .expect("the desk observed under this same lock is still there");
        let tail = open.sink.deliver_tail(&close.trailing);
        // The fd closes either way: the stream is over, and a workload left
        // waiting on a stdin that never EOFs would hang until its deadline.
        open.sink.close();
        match tail {
            Ok(()) => StreamInputResult::Closed,
            Err(err) => refused(refusal_for(&err), err.to_string()),
        }
    }
}

/// The guest's single input desk, recovered rather than propagated on poison:
/// a panicking writer must not make the workload's stdin permanently
/// unreachable, and the slot is one `Option` that a partial update cannot
/// leave inconsistent.
fn desk() -> MutexGuard<'static, Option<OpenInput>> {
    static DESK: OnceLock<Mutex<Option<OpenInput>>> = OnceLock::new();
    DESK.get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn no_workload() -> StreamInputResult {
    refused(
        StreamInputRefusal::NoWorkload,
        "no workload in this guest is accepting streamed input".to_string(),
    )
}

fn refused(kind: StreamInputRefusal, message: String) -> StreamInputResult {
    StreamInputResult::Refused { kind, message }
}

/// Which refusal a sink error is. The two the sink distinguishes mean
/// different things to a writer: one is worth retrying and one never is.
fn refusal_for(err: &io::Error) -> StreamInputRefusal {
    match err.kind() {
        io::ErrorKind::WouldBlock => StreamInputRefusal::QueueFull,
        _ => StreamInputRefusal::WorkloadGone,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    fn frame(seq: u64, payload: &[u8]) -> InputFrame {
        InputFrame {
            seq,
            payload: payload.to_vec(),
        }
    }

    /// A child shaped like a workload: stdin piped, stdout piped.
    fn spawn(program: &str, args: &[&str]) -> std::process::Child {
        Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child")
    }

    #[test]
    fn close_input_delivers_eof_so_a_read_to_end_child_terminates() {
        // Without an explicit EOF this hangs forever — the trap this test exists for.
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn cat");
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        sink.write_frame(InputFrame {
            seq: 0,
            payload: b"hi".to_vec(),
        })
        .expect("write");
        sink.close();
        let status = child.wait().expect("cat must exit after EOF");
        assert!(status.success());
    }

    #[test]
    fn bytes_arrive_in_acceptance_order_not_seq_order() {
        // A sink that re-sorted by `seq` would emit "secondfirst" here — and a
        // secret split across two frames would reassemble in the guest that the
        // gate scanned as two separate, harmless halves.
        let mut child = spawn("/bin/cat", &[]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        sink.write_frame(frame(9, b"first"))
            .expect("first accepted");
        sink.write_frame(frame(3, b"second"))
            .expect("second accepted");
        sink.close();
        let out = child.wait_with_output().expect("cat exits after EOF");
        assert_eq!(out.stdout, b"firstsecond");
    }

    #[test]
    fn a_tail_withheld_at_the_gate_is_delivered_before_eof() {
        // The gate holds back a tail that is still a live prefix of a known
        // secret and releases it at close. Those bytes are the caller's last
        // ones; closing must ship them, not swallow them.
        let mut child = spawn("/bin/cat", &[]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        sink.write_frame(frame(0, b"he")).expect("frame accepted");
        sink.deliver_tail(b"llo").expect("tail accepted");
        sink.close();
        let out = child.wait_with_output().expect("cat exits after EOF");
        assert_eq!(out.stdout, b"hello");
    }

    #[test]
    fn a_child_that_never_reads_stalls_neither_delivery_nor_its_own_output() {
        let mut child = spawn("/bin/sh", &["-c", "echo ready; echo more; sleep 5"]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        let mut out = BufReader::new(child.stdout.take().expect("piped stdout"));

        let mut first = String::new();
        out.read_line(&mut first).expect("child output flows");
        assert_eq!(first.trim_end(), "ready");

        // Far more than a pipe buffer holds, into a child that will never read
        // a byte of it. If delivery waited on the child this loop would not
        // return, so the absence of a hang is the assertion.
        for seq in 0..8 {
            sink.write_frame(frame(seq, &vec![b'x'; 64 * 1024]))
                .expect("delivery never waits on the workload");
        }

        // And the wedged input path leaves the output path exactly where it was.
        let mut second = String::new();
        out.read_line(&mut second)
            .expect("child output still flows past a wedged stdin");
        assert_eq!(second.trim_end(), "more");

        sink.close();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn input_past_the_queue_budget_is_refused_rather_than_queued() {
        let mut child = spawn("/bin/sh", &["-c", "sleep 5"]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));

        // Four times the budget, into a child that reads none of it. The pipe
        // absorbs a page or two and the rest has nowhere to go.
        let mut refusal = None;
        for seq in 0..64 {
            if let Err(e) = sink.write_frame(frame(seq, &vec![b'x'; 64 * 1024])) {
                refusal = Some(e);
                break;
            }
        }
        let refusal = refusal.expect("an unread queue must stop growing at its budget");
        assert_eq!(refusal.kind(), io::ErrorKind::WouldBlock);
        assert!(sink.queued_bytes() <= MAX_PENDING_INPUT_BYTES);

        sink.close();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_sink_whose_workload_died_reports_the_broken_pipe() {
        let mut child = spawn("/bin/sh", &["-c", "exit 0"]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut drained = Vec::new();
        let _ = stdout.read_to_end(&mut drained);
        child.wait().expect("reap the child");

        // The writer learns the pipe is gone by writing into it, so the first
        // offer may still be accepted; what must not happen is that every
        // subsequent one is.
        let mut last = Ok(());
        for seq in 0..200 {
            last = sink.write_frame(frame(seq, b"x"));
            if last.is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let err = last.expect_err("a sink with no workload behind it must say so");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    // --- the desk: where a host frame finds the running workload ----------

    /// The desk is one per guest, so two tests driving it at once would be
    /// driving each other's workload. Serialized rather than made per-test:
    /// "there is exactly one" is the property, and a desk a test could have
    /// its own copy of would not be it.
    fn desk_test() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Open the desk over a fresh `/bin/cat`, returning the child so the test
    /// can read back exactly what reached its stdin.
    fn desk_over_cat() -> std::process::Child {
        let mut child = spawn("/bin/cat", &[]);
        InputDesk::open(child.stdin.take().expect("piped stdin"));
        child
    }

    fn queued(result: &StreamInputResult) -> u64 {
        match result {
            StreamInputResult::Accepted { queued_bytes } => *queued_bytes,
            other => panic!("expected an accepted frame, got {other:?}"),
        }
    }

    fn refusal_kind(result: &StreamInputResult) -> StreamInputRefusal {
        match result {
            StreamInputResult::Refused { kind, .. } => *kind,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn frames_reach_the_workloads_stdin_in_the_order_they_were_offered() {
        // The host gate scans for secret material over the concatenation of
        // what it accepted, in acceptance order. A desk that delivered two
        // frames in any other order would reassemble in the guest what the
        // gate saw as two harmless halves.
        let _guard = desk_test();
        let child = desk_over_cat();

        let _ = queued(&InputDesk::write_frame(frame(0, b"AKIAIOSFODNN")));
        let _ = queued(&InputDesk::write_frame(frame(1, b"7EXAMPLE")));
        assert_eq!(
            InputDesk::close(CloseInput {
                after_seq: Some(1),
                trailing: Vec::new(),
            }),
            StreamInputResult::Closed
        );

        let out = child.wait_with_output().expect("cat exits after EOF");
        assert_eq!(out.stdout, b"AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn a_frame_that_does_not_advance_the_sequence_is_refused_and_delivers_nothing() {
        // The receiving end of the ordering contract. A transport that
        // reordered two frames is caught here, at the end that would suffer
        // from it, rather than only promised against by the end that would
        // cause it.
        let _guard = desk_test();
        let child = desk_over_cat();

        let _ = queued(&InputDesk::write_frame(frame(4, b"first")));
        let refused = InputDesk::write_frame(frame(4, b"replayed"));
        assert_eq!(refusal_kind(&refused), StreamInputRefusal::OutOfOrder);
        let earlier = InputDesk::write_frame(frame(1, b"overtaking"));
        assert_eq!(refusal_kind(&earlier), StreamInputRefusal::OutOfOrder);
        let _ = queued(&InputDesk::write_frame(frame(5, b"second")));
        InputDesk::close(CloseInput {
            after_seq: Some(5),
            trailing: Vec::new(),
        });

        let out = child.wait_with_output().expect("cat exits after EOF");
        assert_eq!(
            out.stdout, b"firstsecond",
            "a refused frame must contribute no bytes at all"
        );
    }

    #[test]
    fn the_withheld_tail_is_delivered_before_the_eof() {
        // The gate holds back the tail of the stream that is still a live
        // prefix of a known secret. Those are the writer's last bytes; a close
        // that dropped them would swallow them with no error anywhere.
        let _guard = desk_test();
        let child = desk_over_cat();

        let _ = queued(&InputDesk::write_frame(frame(0, b"hi ")));
        assert_eq!(
            InputDesk::close(CloseInput {
                after_seq: Some(0),
                trailing: b"SEK".to_vec(),
            }),
            StreamInputResult::Closed
        );

        let out = child.wait_with_output().expect("cat exits after EOF");
        assert_eq!(out.stdout, b"hi SEK");
    }

    #[test]
    fn a_close_that_overtook_a_delivered_frame_is_refused() {
        let _guard = desk_test();
        let child = desk_over_cat();

        let _ = queued(&InputDesk::write_frame(frame(7, b"delivered")));
        let refused = InputDesk::close(CloseInput {
            after_seq: Some(2),
            trailing: b"lost".to_vec(),
        });
        assert_eq!(refusal_kind(&refused), StreamInputRefusal::OutOfOrder);

        // And the stream is still open, so the writer can close it properly.
        assert_eq!(
            InputDesk::close(CloseInput {
                after_seq: Some(7),
                trailing: b"!".to_vec(),
            }),
            StreamInputResult::Closed
        );
        let out = child.wait_with_output().expect("cat exits after EOF");
        assert_eq!(out.stdout, b"delivered!");
    }

    #[test]
    fn a_guest_with_no_open_workload_refuses_input_rather_than_buffering_it() {
        // Default-deny's shape on this side: with no call holding a stdin
        // open there is nowhere for bytes to go, and inventing a buffer for
        // them would be inventing a workload.
        let _guard = desk_test();
        InputDesk::abandon();
        assert_eq!(
            refusal_kind(&InputDesk::write_frame(frame(0, b"nobody home"))),
            StreamInputRefusal::NoWorkload
        );
        assert_eq!(
            refusal_kind(&InputDesk::close(CloseInput::default())),
            StreamInputRefusal::NoWorkload
        );
    }

    #[test]
    fn a_closed_stream_takes_no_further_frames() {
        let _guard = desk_test();
        let child = desk_over_cat();
        InputDesk::close(CloseInput::default());
        assert_eq!(
            refusal_kind(&InputDesk::write_frame(frame(0, b"after the end"))),
            StreamInputRefusal::NoWorkload
        );
        let out = child.wait_with_output().expect("cat exits after EOF");
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn a_workload_that_never_reads_answers_with_back_pressure_not_a_stall() {
        // The desk answers on the control connection, so a frame it cannot
        // queue has to come back as a refusal the writer can act on. Blocking
        // instead would hold the connection for as long as the workload runs.
        let _guard = desk_test();
        let mut child = spawn("/bin/sh", &["-c", "sleep 5"]);
        InputDesk::open(child.stdin.take().expect("piped stdin"));

        let mut refusal = None;
        for seq in 0..64 {
            let result = InputDesk::write_frame(frame(seq, &vec![b'x'; 64 * 1024]));
            if let StreamInputResult::Refused { kind, .. } = result {
                refusal = Some(kind);
                break;
            }
        }
        assert_eq!(
            refusal,
            Some(StreamInputRefusal::QueueFull),
            "an unread queue must stop growing at its budget"
        );

        InputDesk::abandon();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn an_accepted_frame_reports_what_is_still_undelivered() {
        let _guard = desk_test();
        let mut child = spawn("/bin/sh", &["-c", "sleep 5"]);
        InputDesk::open(child.stdin.take().expect("piped stdin"));

        // Far more than a pipe holds, into a child that reads none of it, so
        // the figure is a real backlog rather than a rounding artefact.
        let mut last = 0;
        for seq in 0..4 {
            last = queued(&InputDesk::write_frame(frame(seq, &vec![b'y'; 128 * 1024])));
        }
        assert!(last > 0, "a wedged workload must report a backlog");

        InputDesk::abandon();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn an_empty_frame_is_accepted_without_reaching_the_workload() {
        // A zero-length write into a pipe is a no-op, not an EOF. Delivering it
        // would be harmless; refusing it would make a legal frame an error.
        let mut child = spawn("/bin/cat", &[]);
        let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
        sink.write_frame(frame(0, b""))
            .expect("empty frame accepted");
        assert_eq!(sink.queued_bytes(), 0);
        sink.close();
        let out = child.wait_with_output().expect("cat exits after EOF");
        assert!(out.stdout.is_empty());
    }
}
