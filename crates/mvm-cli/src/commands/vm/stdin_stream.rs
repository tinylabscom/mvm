//! Carrying the caller's own stdin into a running workload's stdin.
//!
//! Everything that decides *whether* those bytes may move already exists — the
//! signed grant, the single-writer lease, the cross-frame secret scan, the
//! chain-signed record of the decision, and the route that keeps delivery
//! order equal to acceptance order. This module is the thing that was missing:
//! something that actually reads a caller's stdin and offers it, while the
//! workload runs.
//!
//! Three properties shape the code, and each one is a way the naive version
//! breaks:
//!
//! - **Nothing here may stall the call.** A workload that stops reading its
//!   stdin fills the guest's queue, and the guest answers rather than blocks;
//!   the route mirrors that cap and refuses rather than growing. Both are
//!   errors this pump backs off on, so a wedged workload costs a bounded
//!   amount of host memory and a sleeping thread — never the thread streaming
//!   the workload's *output*, which is why the pump runs on its own thread and
//!   is never joined. Joining it would make `mvmctl` wait on the caller's
//!   stdin to exit, which is precisely the stall the whole plane avoids.
//!
//! - **A frame the gate accepted is never offered again.** The route's errors
//!   fall into two classes and they are not interchangeable.
//!   [`InputRouteError::Backlogged`] is raised *before* the gate sees the
//!   frame, so those bytes may be re-offered. [`InputRouteError::Transport`]
//!   is raised *after* — the gate scanned them, numbered them and queued them
//!   — so re-offering would write the caller's bytes into the workload twice,
//!   with neither end's ordering check able to see it. The pump therefore
//!   re-offers only the first, and drains the second by asking the route to
//!   flush what it is already holding.
//!
//! - **Somebody has to attend a writer that has stopped typing.** Two things
//!   go wrong while a reader is parked in `read` and neither is visible from
//!   there. A writer thinking for longer than the lease TTL comes back to find
//!   its next write refused *and* its close refused, which drops the tail the
//!   gate withheld. And on a secret-bearing VM the gate is withholding a
//!   blanket tail of everything typed so far, which it releases only once the
//!   writer has been quiet for long enough — so a pause is exactly when the
//!   typed line becomes deliverable. Both are answered by
//!   [`WorkloadInput::refresh`], and neither can be something the read loop
//!   does between reads, because the read is where it is stuck. They get their
//!   own attendant thread.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use mvm_contract::stream::input::InputFrame;
use mvm_hostd::stream::{DEFAULT_IDLE_FLUSH_AFTER, InputRouteError, StreamPlane};

/// How much of the caller's stdin travels in one frame.
///
/// Well under the megabyte the guest and the route each hold for a workload
/// that stopped reading, so an ordinary writer never meets either cap; large
/// enough that a `cat`-sized pipe does not cost a vsock round trip per line.
const CHUNK_BYTES: usize = 32 * 1024;

/// How long to wait before offering again after the route would not take it.
const RETRY_PAUSE: Duration = Duration::from_millis(25);

/// How long delivery may keep failing before the pump stops trying.
///
/// The first frames of a call routinely fail: the route opens as soon as the
/// plan is admitted, and the guest only has a stdin to hand them to once the
/// entrypoint's child has spawned. That window is milliseconds. This bound is
/// for the other case — a guest that is never going to answer — where retrying
/// forever would leave a thread spinning against a dead VM.
const DELIVERY_PATIENCE: Duration = Duration::from_secs(60);

/// How often the attendant tells the gate its writer is idle but alive.
///
/// Set by the tighter of the two deadlines it serves, which is the gate's idle
/// release rather than the lease. The gate hands over the tail its secret scan
/// withheld once the writer has been silent for [`DEFAULT_IDLE_FLUSH_AFTER`],
/// and nothing happens until somebody asks — so the operator's wait for a
/// typed line is the threshold plus however long the attendant takes to come
/// round.
/// Half the threshold keeps that under one and a half thresholds, well inside
/// what a person reads as instant, and it refreshes the lease two orders of
/// magnitude more often than the TTL needs.
fn attend_period() -> Duration {
    DEFAULT_IDLE_FLUSH_AFTER / 2
}

/// One workload's stdin, as the pump reaches it.
///
/// A trait because the production destination is a per-VM route inside the
/// process's [`StreamPlane`] and a test's is the same plane over a transport
/// it can inspect — and because the pump's retry rules are defined in terms of
/// which error came back, which is the part worth testing without a microVM.
pub(in crate::commands::vm) trait WorkloadInput: Send + Sync {
    /// Offer one frame. The gate may accept it and the transport still fail;
    /// the two outcomes are different [`InputRouteError`] variants and the
    /// pump treats them differently.
    fn write(&self, frame: InputFrame) -> Result<(), InputRouteError>;
    /// Say the writer is idle but alive: hold the lease, and let the gate
    /// release the tail its secret scan withheld.
    fn refresh(&self) -> Result<(), InputRouteError>;
    /// Deliver the withheld tail and close the workload's stdin.
    fn close(&self) -> Result<(), InputRouteError>;
}

/// The production destination: the route this process's plane holds for `vm`.
pub(in crate::commands::vm) struct PlaneInput {
    plane: Arc<StreamPlane>,
    vm: String,
}

impl PlaneInput {
    pub(in crate::commands::vm) fn new(plane: Arc<StreamPlane>, vm: impl Into<String>) -> Self {
        Self {
            plane,
            vm: vm.into(),
        }
    }
}

impl WorkloadInput for PlaneInput {
    fn write(&self, frame: InputFrame) -> Result<(), InputRouteError> {
        self.plane.write_input(&self.vm, frame)
    }

    fn refresh(&self) -> Result<(), InputRouteError> {
        self.plane.refresh_input(&self.vm)
    }

    fn close(&self) -> Result<(), InputRouteError> {
        self.plane.close_input(&self.vm)
    }
}

/// What the pump did, for the caller to report once the call is over.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(in crate::commands::vm) struct StreamedInputReport {
    /// Frames the gate accepted.
    pub frames: u64,
    /// Bytes of the caller's stdin offered.
    pub bytes: u64,
    /// Whether the caller's stdin reached EOF, and so the workload's stdin was
    /// closed by the writer rather than by teardown.
    pub reached_eof: bool,
    /// Why the pump stopped early, when it did.
    pub stopped_because: Option<String>,
}

/// A live host→guest stdin stream: the reader thread, the idle attendant,
/// and the flag that ends both.
pub(in crate::commands::vm) struct StdinStream {
    stop: Arc<AtomicBool>,
    input: Arc<dyn WorkloadInput>,
    report: Arc<Mutex<StreamedInputReport>>,
    attendant: Option<std::thread::JoinHandle<()>>,
}

impl StdinStream {
    /// Start pumping `reader` into `input`.
    ///
    /// The reader thread is deliberately not retained: see the module docs on
    /// why joining a thread parked in `read` would make the workload's exit
    /// wait on the caller's keyboard.
    pub(in crate::commands::vm) fn start<R>(input: Arc<dyn WorkloadInput>, reader: R) -> Self
    where
        R: Read + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let report = Arc::new(Mutex::new(StreamedInputReport::default()));

        let pump_stop = Arc::clone(&stop);
        let pump_input = Arc::clone(&input);
        let pump_report = Arc::clone(&report);
        std::thread::spawn(move || {
            let outcome = pump(reader, pump_input.as_ref(), &pump_stop, &pump_report);
            if let Err(error) = outcome {
                note_stop(&pump_report, &error);
            }
        });

        let tick_stop = Arc::clone(&stop);
        let tick_input = Arc::clone(&input);
        let period = attend_period();
        let attendant = std::thread::spawn(move || {
            attend_idle_writer(tick_input.as_ref(), &tick_stop, period);
        });

        Self {
            stop,
            input,
            report,
            attendant: Some(attendant),
        }
    }

    /// End the stream and take the report.
    ///
    /// Closes the workload's stdin if the pump has not already — a second
    /// close finds no session and is not an error, which is the whole reason
    /// both ends may call it.
    pub(in crate::commands::vm) fn finish(mut self) -> StreamedInputReport {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(attendant) = self.attendant.take() {
            let _ = attendant.join();
        }
        match self.input.close() {
            Ok(()) | Err(InputRouteError::NoSession) => {}
            Err(error) => note_stop(&self.report, &error),
        }
        self.report
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for StdinStream {
    fn drop(&mut self) {
        // A `finish` that never ran (an early `?` on the dispatch path) must
        // still stop the threads; the close it skips is the plane's to do at
        // release.
        self.stop.store(true, Ordering::SeqCst);
        if let Some(attendant) = self.attendant.take() {
            let _ = attendant.join();
        }
    }
}

fn note_stop(report: &Mutex<StreamedInputReport>, error: &dyn std::fmt::Display) {
    let mut report = report.lock().unwrap_or_else(PoisonError::into_inner);
    if report.stopped_because.is_none() {
        report.stopped_because = Some(error.to_string());
    }
}

/// What happened to one offered frame.
enum Offered {
    /// The gate took it and the guest has it.
    Delivered,
    /// The gate took it; the guest does not have it yet. Its bytes must not be
    /// offered again — only flushed.
    Queued,
    /// The gate never saw it. The same bytes may be offered again.
    Refused(Vec<u8>),
    /// Nothing more will be accepted on this stream.
    Ended(InputRouteError),
}

/// Offer one payload under `seq`, advancing `seq` when the gate took it.
fn offer(input: &dyn WorkloadInput, seq: &mut u64, payload: Vec<u8>) -> Offered {
    // The route consumes the frame, and `Backlogged` does not hand it back, so
    // the pump keeps its own copy to re-offer. One copy of a chunk of the
    // caller's own stdin, inside the caller's own process.
    let frame = InputFrame {
        seq: *seq,
        payload: payload.clone(),
    };
    match input.write(frame) {
        Ok(()) => {
            *seq += 1;
            Offered::Delivered
        }
        Err(InputRouteError::Transport(_)) => {
            *seq += 1;
            Offered::Queued
        }
        Err(InputRouteError::Backlogged { .. }) => Offered::Refused(payload),
        Err(other) => Offered::Ended(other),
    }
}

/// Ask the route to hand the guest what it is already holding.
///
/// An empty frame is the only way to say "flush" through this interface, and
/// it is a real one: the route mints a wire frame per accepted frame including
/// empty ones, flushes its queue ahead of it, and the guest queues nothing for
/// a payload with no bytes. Nothing is added to the caller's stream by asking.
fn flush_queue(
    input: &dyn WorkloadInput,
    seq: &mut u64,
    stop: &AtomicBool,
) -> Result<(), InputRouteError> {
    let deadline = Instant::now() + DELIVERY_PATIENCE;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        match offer(input, seq, Vec::new()) {
            Offered::Delivered => return Ok(()),
            // A flush cannot itself backlog — it adds no bytes — but treat it
            // like a failed delivery rather than assuming, so an unexpected
            // refusal waits its turn instead of spinning.
            Offered::Queued | Offered::Refused(_) => {}
            Offered::Ended(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(InputRouteError::Transport(anyhow::anyhow!(
                "the workload did not take streamed input within {}s",
                DELIVERY_PATIENCE.as_secs()
            )));
        }
        std::thread::sleep(RETRY_PAUSE);
    }
}

/// Read `reader` to EOF, offering each chunk in the order it arrived.
fn pump<R: Read>(
    mut reader: R,
    input: &dyn WorkloadInput,
    stop: &AtomicBool,
    report: &Mutex<StreamedInputReport>,
) -> Result<(), InputRouteError> {
    let mut seq = 0u64;
    let mut buf = vec![0u8; CHUNK_BYTES];
    // A chunk the route refused before the gate saw it, waiting to go again.
    let mut carried: Option<Vec<u8>> = None;
    // Only a read of zero bytes sets this. A stop, or a read error, ends the
    // loop the same way but means something different to the caller: their
    // stdin did not finish, and what came after it was never sent.
    let mut reached_eof = false;

    while !stop.load(Ordering::SeqCst) {
        let payload = match carried.take() {
            Some(payload) => payload,
            None => match reader.read(&mut buf) {
                Ok(0) => {
                    reached_eof = true;
                    break;
                }
                Ok(read) => buf[..read].to_vec(),
                Err(error) => {
                    note_stop(report, &format!("reading stdin: {error}"));
                    break;
                }
            },
        };
        let offered = payload.len() as u64;
        match offer(input, &mut seq, payload) {
            Offered::Delivered => count(report, offered),
            Offered::Queued => {
                count(report, offered);
                flush_queue(input, &mut seq, stop)?;
            }
            Offered::Refused(payload) => {
                carried = Some(payload);
                std::thread::sleep(RETRY_PAUSE);
            }
            Offered::Ended(error) => return Err(error),
        }
    }

    // EOF on the caller's side is EOF on the workload's: closing here rather
    // than at teardown is what lets a read-to-EOF workload finish while the
    // caller is still waiting for its output.
    let closed = input.close();
    let mut held = report.lock().unwrap_or_else(PoisonError::into_inner);
    held.reached_eof = reached_eof;
    drop(held);
    match closed {
        Ok(()) | Err(InputRouteError::NoSession) => Ok(()),
        Err(error) => Err(error),
    }
}

fn count(report: &Mutex<StreamedInputReport>, bytes: u64) {
    let mut report = report.lock().unwrap_or_else(PoisonError::into_inner);
    report.frames = report.frames.saturating_add(1);
    report.bytes = report.bytes.saturating_add(bytes);
}

/// Tell the gate every `period` that this writer is idle but alive, until the
/// stream ends.
///
/// One call does both jobs: it holds the lease a parked reader would otherwise
/// let lapse, and it is what makes the gate release the tail its secret scan
/// withheld — so a workload waiting on a request line gets one. A loop that
/// only refreshed on the lease's own schedule would leave the second job
/// running two orders of magnitude too slowly.
///
/// `period` is a parameter rather than a constant read inside so a test can
/// watch it working without waiting out the real interval.
fn attend_idle_writer(input: &dyn WorkloadInput, stop: &AtomicBool, period: Duration) {
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(period);
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match input.refresh() {
            // The stream ended under us; there is no lease left to hold.
            Err(InputRouteError::NoSession) => return,
            Err(error) => {
                tracing::debug!(error = %error, "could not attend the idle workload input writer");
            }
            Ok(()) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use mvm_hostd::stream::DEFAULT_LEASE_TTL;

    /// A destination that records what it was offered, in the order it was
    /// offered, and can be told to fail a given number of times first.
    #[derive(Default)]
    struct Recorder {
        frames: Mutex<Vec<InputFrame>>,
        closes: Mutex<u32>,
        refreshes: Mutex<u32>,
        /// Deliveries still to fail with a transport error.
        transport_failures: Mutex<u32>,
        /// Deliveries still to refuse as backlogged.
        backlog_refusals: Mutex<u32>,
    }

    impl Recorder {
        fn take_one(counter: &Mutex<u32>) -> bool {
            let mut left = counter.lock().expect("no test panics under this lock");
            if *left == 0 {
                return false;
            }
            *left -= 1;
            true
        }

        fn refreshes(&self) -> u32 {
            *self
                .refreshes
                .lock()
                .expect("no test panics under this lock")
        }

        fn closes(&self) -> u32 {
            *self.closes.lock().expect("no test panics under this lock")
        }

        fn delivered(&self) -> Vec<InputFrame> {
            self.frames
                .lock()
                .expect("no test panics under this lock")
                .clone()
        }

        /// The bytes the workload would have on its stdin, in delivery order.
        fn stdin_bytes(&self) -> Vec<u8> {
            self.delivered()
                .into_iter()
                .flat_map(|frame| frame.payload)
                .collect()
        }
    }

    impl WorkloadInput for Recorder {
        fn write(&self, frame: InputFrame) -> Result<(), InputRouteError> {
            if Self::take_one(&self.backlog_refusals) {
                return Err(InputRouteError::Backlogged {
                    queued: 1,
                    limit: 1,
                });
            }
            if Self::take_one(&self.transport_failures) {
                return Err(InputRouteError::Transport(anyhow!("no workload yet")));
            }
            self.frames
                .lock()
                .expect("no test panics under this lock")
                .push(frame);
            Ok(())
        }

        fn refresh(&self) -> Result<(), InputRouteError> {
            *self.refreshes.lock().expect("no test panics here") += 1;
            Ok(())
        }

        fn close(&self) -> Result<(), InputRouteError> {
            *self.closes.lock().expect("no test panics here") += 1;
            Ok(())
        }
    }

    fn run(reader: &[u8], recorder: &Recorder) -> StreamedInputReport {
        let stop = AtomicBool::new(false);
        let report = Mutex::new(StreamedInputReport::default());
        pump(reader, recorder, &stop, &report).expect("the pump must not fail");
        report.into_inner().expect("no test panics under this lock")
    }

    #[test]
    fn every_byte_arrives_in_the_order_it_was_read() {
        // Bigger than one chunk, so the ordering assertion is about frames
        // rather than about a single write.
        let source: Vec<u8> = (0..(CHUNK_BYTES * 3 + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        let recorder = Recorder::default();
        let report = run(&source, &recorder);

        assert_eq!(recorder.stdin_bytes(), source);
        assert_eq!(report.bytes, source.len() as u64);
        assert!(report.reached_eof);
    }

    #[test]
    fn frame_numbers_advance_by_one_and_never_repeat() {
        let source: Vec<u8> = vec![7u8; CHUNK_BYTES * 2 + 1];
        let recorder = Recorder::default();
        run(&source, &recorder);

        let seqs: Vec<u64> = recorder.delivered().iter().map(|f| f.seq).collect();
        assert_eq!(seqs, (0..seqs.len() as u64).collect::<Vec<_>>());
    }

    #[test]
    fn eof_on_the_callers_stdin_closes_the_workloads() {
        // Without this a `cat`-shaped workload never terminates, which is the
        // failure the whole close path exists to prevent.
        let recorder = Recorder::default();
        let report = run(b"one line\n", &recorder);

        assert_eq!(*recorder.closes.lock().expect("no panic"), 1);
        assert!(report.reached_eof);
    }

    #[test]
    fn a_backlogged_frame_is_offered_again_with_the_same_bytes_and_number() {
        // Backlogged is raised before the gate sees the frame, so those bytes
        // are still the writer's to send — and must arrive exactly once.
        let recorder = Recorder::default();
        *recorder.backlog_refusals.lock().expect("no panic") = 2;
        run(b"payload", &recorder);

        assert_eq!(recorder.stdin_bytes(), b"payload");
        assert_eq!(recorder.delivered().len(), 1, "delivered exactly once");
        assert_eq!(recorder.delivered()[0].seq, 0, "the number was not spent");
    }

    #[test]
    fn a_frame_the_gate_took_is_never_offered_again() {
        // The other half of the retry rule. A transport failure means the gate
        // already scanned and numbered those bytes; re-offering them would put
        // the caller's input into the workload twice. The pump must flush
        // instead — with an empty frame, which adds nothing to the stream.
        let recorder = Recorder::default();
        *recorder.transport_failures.lock().expect("no panic") = 1;
        run(b"once", &recorder);

        let payloads: Vec<Vec<u8>> = recorder
            .delivered()
            .into_iter()
            .map(|frame| frame.payload)
            .collect();
        assert_eq!(
            payloads.iter().filter(|p| p.as_slice() == b"once").count(),
            0,
            "the failed frame's bytes were queued, not re-sent"
        );
        assert!(
            payloads.iter().any(Vec::is_empty),
            "the pump must ask the route to flush what it is holding: {payloads:?}"
        );
        assert_eq!(recorder.stdin_bytes(), b"", "no duplicate of the payload");
    }

    #[test]
    fn a_refusal_that_is_not_retryable_ends_the_stream() {
        struct Ungranted;
        impl WorkloadInput for Ungranted {
            fn write(&self, _frame: InputFrame) -> Result<(), InputRouteError> {
                Err(InputRouteError::NoSession)
            }
            fn refresh(&self) -> Result<(), InputRouteError> {
                Err(InputRouteError::NoSession)
            }
            fn close(&self) -> Result<(), InputRouteError> {
                Err(InputRouteError::NoSession)
            }
        }
        let stop = AtomicBool::new(false);
        let report = Mutex::new(StreamedInputReport::default());
        let error = pump(&b"bytes"[..], &Ungranted, &stop, &report)
            .expect_err("a stream nobody granted must not be pumped");
        assert!(matches!(error, InputRouteError::NoSession));
    }

    #[test]
    fn a_stopped_pump_reports_that_it_did_not_reach_eof() {
        // The caller must be able to tell "the writer finished" from "the call
        // ended first" — one of those closed the workload's stdin on purpose.
        let recorder = Recorder::default();
        let stop = AtomicBool::new(true);
        let report = Mutex::new(StreamedInputReport::default());
        pump(&b"never read"[..], &recorder, &stop, &report).expect("stopping is not a failure");
        assert!(!report.into_inner().expect("no panic").reached_eof);
    }

    #[test]
    fn the_attendant_stops_when_the_stream_does() {
        let recorder = Arc::new(Recorder::default());
        let stop = Arc::new(AtomicBool::new(false));
        let held = Arc::clone(&recorder);
        let flag = Arc::clone(&stop);
        let attendant = std::thread::spawn(move || {
            attend_idle_writer(held.as_ref(), &flag, attend_period());
        });
        stop.store(true, Ordering::SeqCst);
        attendant
            .join()
            .expect("the attendant must not outlive the stop");
    }

    /// Spin until `ready` or the deadline. Returns whether it happened, so the
    /// caller asserts rather than hangs when it does not.
    fn within(limit: Duration, ready: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if ready() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        ready()
    }

    #[test]
    fn the_attendant_keeps_visiting_an_idle_writer() {
        // Two silent failures ride on this one call, and an attendant that
        // loops without calling `refresh` looks identical to one that works.
        // An operator who stops typing for longer than the TTL comes back to a
        // lapsed lease, so the next write *and* the close are refused and the
        // withheld tail is dropped with nothing on screen to say so. And on a
        // secret-bearing VM the line they already typed is sitting in the
        // gate's carry, released only when somebody says the writer went quiet.
        let recorder = Arc::new(Recorder::default());
        let stop = Arc::new(AtomicBool::new(false));
        let held = Arc::clone(&recorder);
        let flag = Arc::clone(&stop);
        let attendant = std::thread::spawn(move || {
            attend_idle_writer(held.as_ref(), &flag, Duration::from_millis(10));
        });

        let refreshed = within(Duration::from_secs(5), || recorder.refreshes() >= 3);
        stop.store(true, Ordering::SeqCst);
        attendant
            .join()
            .expect("the attendant must not outlive the stop");
        assert!(
            refreshed,
            "an idle writer must keep being attended; saw {} visit(s)",
            recorder.refreshes()
        );
    }

    #[test]
    fn the_attend_period_serves_both_deadlines_it_is_responsible_for() {
        // The period is one number answering to two clocks, and drifting past
        // either is silent. Too slow against the gate's idle release and a
        // typed line waits whole tick-times for a delivery the gate is already
        // willing to make; too slow against the lease and the writer loses its
        // place while it was still there.
        assert!(
            attend_period() <= DEFAULT_IDLE_FLUSH_AFTER,
            "attend period {:?} is longer than the {:?} idle release it exists to \
             collect, so a released line waits on the tick rather than the threshold",
            attend_period(),
            DEFAULT_IDLE_FLUSH_AFTER
        );
        assert!(
            attend_period() * 2 < DEFAULT_LEASE_TTL,
            "attend period {:?} leaves no room for a missed visit inside the {:?} lease",
            attend_period(),
            DEFAULT_LEASE_TTL
        );
    }

    /// A reader that blocks until the test feeds it, and reports EOF once the
    /// test drops the sender — the shape of a person typing, which is what
    /// makes the pump's parked-in-`read` state reproducible.
    ///
    /// `entered` counts reads *before* they block, so a test can wait for the
    /// pump to be committed to a read it cannot leave: from there nothing but
    /// the test's own sender can move it, and any close that follows is the
    /// caller's rather than the writer's.
    struct Typed {
        keys: std::sync::mpsc::Receiver<Vec<u8>>,
        entered: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Read for Typed {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            match self.keys.recv() {
                Ok(bytes) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    Ok(n)
                }
                Err(_) => Ok(0),
            }
        }
    }

    /// A blocking reader and the count of reads it has begun.
    fn typed() -> (
        std::sync::mpsc::Sender<Vec<u8>>,
        Typed,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let (keys, rx) = std::sync::mpsc::channel();
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reader = Typed {
            keys: rx,
            entered: Arc::clone(&entered),
        };
        (keys, reader, entered)
    }

    #[test]
    fn finish_closes_a_workload_stdin_the_writer_left_open() {
        // The composition the pump tests never run: start, deliver while the
        // caller is still typing, then end the call first. Nobody else is
        // going to send the EOF here, and a workload reading to EOF hangs
        // without it.
        let (keys, reader, entered) = typed();
        let recorder = Arc::new(Recorder::default());
        let stream = StdinStream::start(Arc::clone(&recorder) as Arc<dyn WorkloadInput>, reader);
        keys.send(b"typed while it runs".to_vec())
            .expect("the pump is reading");
        assert!(
            within(Duration::from_secs(5), || entered.load(Ordering::SeqCst)
                >= 2),
            "the pump must offer what the caller typed and go back for more"
        );

        // The writer is parked in a read only this test can end, so every
        // close from here is `finish`'s.
        let report = stream.finish();
        assert_eq!(recorder.stdin_bytes(), b"typed while it runs");
        assert_eq!(report.frames, 1);
        assert_eq!(report.bytes, "typed while it runs".len() as u64);
        assert!(
            !report.reached_eof,
            "the call ended before the caller's stdin did"
        );
        assert_eq!(
            recorder.closes(),
            1,
            "finish must close the workload's stdin the writer left open"
        );
    }

    #[test]
    fn dropping_a_stream_ends_its_attendant() {
        // An early `?` on the dispatch path drops the stream without ever
        // calling `finish`, and the attendant holds a lease for a writer that
        // no longer exists. `Drop` joins it, so a stop it failed to set parks
        // the dropping thread on a loop that never ends — run it somewhere
        // this test can outlive rather than hanging in it.
        let (keys, reader, _entered) = typed();
        let held: Arc<dyn WorkloadInput> = Arc::new(Recorder::default());
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&dropped);
        std::thread::spawn(move || {
            drop(StdinStream::start(held, reader));
            flag.store(true, Ordering::SeqCst);
        });

        assert!(
            within(Duration::from_secs(5), || dropped.load(Ordering::SeqCst)),
            "dropping the stream must stop the ticker, not join a thread that never ends"
        );
        drop(keys);
    }

    #[test]
    fn the_cli_holds_no_workload_secret_for_the_input_gate_to_scan_for() {
        // The gate refuses stdin that looks like one of the host's own
        // secrets. Recognising a byte sequence normally means having it, and
        // this process must not: the substitution endpoint that resolves raw
        // credentials is a separate process, and that separation is load
        // bearing. So what the gate matches is a fingerprint — a length, a
        // hash and a category — and the CLI's part is to hold none of the
        // machinery that could carry a value.
        //
        // Asserted on the surface, not on a comment: the fingerprint type has
        // no accessor that returns bytes, and this crate names neither it nor
        // the gate binding that takes it.
        let fingerprint = mvm_contract::stream::secret_fingerprint::SecretFingerprint::of(
            b"AKIAIOSFODNN7EXAMPLE",
            mvm_contract::stream::secret_fingerprint::SecretCategory::HostSecret,
        )
        .expect("a non-empty secret fingerprints");
        assert!(!format!("{fingerprint:?}").contains("AKIA"));
        assert_eq!(
            std::mem::size_of_val(&fingerprint),
            std::mem::size_of::<u64>() * 2,
            "fixed-width and inline: no room for a pointer to a value"
        );

        let named = cli_sources_naming(&["InputBinding", "with_fingerprint", "SecretFingerprint"]);
        assert!(
            named.is_empty(),
            "the CLI must reach the gate only through `StreamPlane::open_input`, which \
             installs the fingerprint set the substitution endpoint reported; naming the \
             binding here would be this crate acquiring a reason to hold secret shapes \
             of its own: {named:?}"
        );
    }

    /// Files under this crate's `src/` mentioning any of `needles`, excluding
    /// this test's own source (which names them to assert their absence).
    fn cli_sources_naming(needles: &[&str]) -> Vec<String> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&root, &mut files);
        files
            .into_iter()
            .filter(|path| path.file_name().is_some_and(|n| n != "stdin_stream.rs"))
            .filter(|path| {
                std::fs::read_to_string(path)
                    .is_ok_and(|src| needles.iter().any(|needle| src.contains(needle)))
            })
            .map(|path| path.display().to_string())
            .collect()
    }
}
