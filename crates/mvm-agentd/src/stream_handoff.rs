//! Bounded best-effort stream handoff shared by pipe readers and RPC capture.
//! Allocation-conscious: per-stream rings bound bytes and chunk count; control
//! records must already have passed the cumulative fd-3 budget. Queue admission
//! never waits for capacity, and completion transfers ownership instead of sending.

use std::collections::VecDeque;
use std::sync::mpsc::{SyncSender, TrySendError};

use mvm_core::transcript::{Admission, GapTally, RingState};

use crate::entrypoint::CallCaps;
use crate::stream_pump::{CapturedStream, StreamGap, stream_retention_ring};
use crate::vsock::EntrypointEvent;

/// Fixed event slots in addition to the producer's retention rings.
pub(crate) const HANDOFF_CAPACITY: usize = 8;

enum CaptureStage {
    PipeReader,
    ConsumerHandoff,
}

impl CaptureStage {
    fn name(&self) -> &'static str {
        match self {
            Self::PipeReader => "pipe_reader",
            Self::ConsumerHandoff => "consumer_handoff",
        }
    }
}

/// The producer side of the handoff: bounded, with no wait for queue capacity,
/// and explicit loss accounting under backpressure.
pub(crate) struct Handoff {
    tx: SyncSender<EntrypointEvent>,
    pending: Pending,
    stage: CaptureStage,
    /// The consumer unwound. Nothing is left to deliver to, so events are
    /// dropped on the floor rather than queued for a receiver that is gone.
    hung_up: bool,
}

impl Handoff {
    pub(crate) fn new(tx: SyncSender<EntrypointEvent>, caps: &CallCaps) -> Self {
        Self {
            tx,
            pending: Pending::new(caps),
            stage: CaptureStage::ConsumerHandoff,
            hung_up: false,
        }
    }

    /// Take one event from the pump. Queues it, then moves as much of the
    /// queue as the channel will accept without waiting for capacity. The pump
    /// keeps checking the child's deadline no matter what the consumer does.
    pub(crate) fn offer(&mut self, event: EntrypointEvent) {
        // The pump reports how a run ended through its return value, and
        // `stream_call`'s caller writes exactly one terminal from that. A
        // terminal arriving here would be a second one on the wire, and a host
        // reading until terminal would take everything after it for a new
        // response. Refusing structurally beats trusting every future pump to
        // remember.
        if self.hung_up || event.is_terminal() {
            return;
        }
        self.pending.queue(event);
        self.flush();
    }

    /// Deliver what the channel will take right now, oldest first, stopping at
    /// the first event that would block.
    fn flush(&mut self) {
        while let Some(event) = self.pending.events.pop_front() {
            let stream = CapturedStream::of(&event);
            match self.tx.try_send(event) {
                Ok(()) => self.pending.release(stream),
                Err(TrySendError::Full(event)) => {
                    // Still queued and still charged to its ring, so nothing
                    // newer overtakes it.
                    self.pending.events.push_front(event);
                    return;
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.hung_up = true;
                    self.pending.events.clear();
                    return;
                }
            }
        }
    }

    /// Transfer the bounded tail to its owner without waiting for the consumer.
    /// The sender is dropped on return, even if its channel is full.
    pub(crate) fn finish(mut self) -> VecDeque<EntrypointEvent> {
        for gap in self.pending.gaps() {
            self.pending
                .queue(gap.control_record_at(self.stage.name()).into());
        }
        self.pending.events
    }

    pub(crate) fn for_pipe_reader(mut self) -> Self {
        self.stage = CaptureStage::PipeReader;
        self
    }

    pub(crate) fn is_disconnected(&self) -> bool {
        self.hung_up
    }
}

/// Events the pump produced that the consumer has not taken yet.
///
/// One FIFO, so what survives is a subsequence of arrival order. Each byte
/// stream carries its own [`RingState`] bounding how much of it may wait here;
/// over that bound the oldest queued events *of that stream* are evicted and
/// tallied into the gap the call reports. Control records are not
/// ring-bounded — the fd-3 reader already caps their total bytes for the whole
/// call, and they are the records a reader can least afford to lose.
struct Pending {
    events: VecDeque<EntrypointEvent>,
    stdout: BoundedStream,
    stderr: BoundedStream,
}

impl Pending {
    fn new(caps: &CallCaps) -> Self {
        Self {
            events: VecDeque::new(),
            stdout: BoundedStream::new(caps.stdout_max),
            stderr: BoundedStream::new(caps.stderr_max),
        }
    }

    /// Add one event to the back of the queue, evicting the oldest queued
    /// events of its stream if it no longer fits that stream's bound.
    fn queue(&mut self, event: EntrypointEvent) {
        if let Some(stream) = CapturedStream::of(&event) {
            let size = chunk_len(&event) as u64;
            let admission = self.bound_mut(stream).ring.admit(size);
            if let Admission::AcceptAfterPruning { pruned_seqs, .. } = &admission {
                let _examined = evict_oldest(&mut self.events, stream, pruned_seqs.len());
            }
            self.bound_mut(stream).gap.record(&admission);
        }
        self.events.push_back(event);
    }

    /// Stop charging a delivered event against its stream's bound. `None` is
    /// an event that was never charged (a control record).
    fn release(&mut self, stream: Option<CapturedStream>) {
        if let Some(stream) = stream {
            self.bound_mut(stream).ring.release_oldest();
        }
    }

    fn gaps(&self) -> Vec<StreamGap> {
        StreamGap::from_markers(self.stdout.gap.marker(), self.stderr.gap.marker())
    }

    fn bound_mut(&mut self, stream: CapturedStream) -> &mut BoundedStream {
        match stream {
            CapturedStream::Stdout => &mut self.stdout,
            CapturedStream::Stderr => &mut self.stderr,
        }
    }
}

/// One byte stream's share of the pending queue: how much of it may wait, and
/// what waiting cost it.
struct BoundedStream {
    ring: RingState,
    gap: GapTally,
}

impl BoundedStream {
    fn new(max_bytes: usize) -> Self {
        Self {
            ring: stream_retention_ring(max_bytes),
            gap: GapTally::default(),
        }
    }
}

/// Drop the `count` oldest queued events belonging to `stream`, leaving every
/// other stream's events where they are.
///
/// Walks the front and stops the moment `count` of them are gone, rather than
/// filtering the whole queue. The queue is oldest-first, so what has to go is
/// already at the front — and eviction happens once per event of a stream that
/// is over its bound, which for a chatty workload is every event it writes. A
/// pass over the whole queue there costs the queue's length per event, and the
/// drain loop stops keeping up with the reader threads feeding it.
/// Returns how many events the walk examined.
///
/// That count is the work done, and it is what makes the cost observable to a
/// test without timing anything: a walk that stops at its targets examines
/// `count` events plus whatever it stepped over, while one that filters the
/// whole queue examines all of it. Callers have no use for the number and
/// discard it.
fn evict_oldest(
    events: &mut VecDeque<EntrypointEvent>,
    stream: CapturedStream,
    count: usize,
) -> usize {
    let mut left = count;
    let mut examined = 0usize;
    // What the walk passed over to reach its targets — the other byte stream's
    // events, and control records, which are never evicted. All older than
    // everything dropped, so they go back at the front in the order they came.
    let mut stepped_over = Vec::new();
    while left > 0 {
        let Some(event) = events.pop_front() else {
            break;
        };
        examined += 1;
        if CapturedStream::of(&event) == Some(stream) {
            left -= 1;
        } else {
            stepped_over.push(event);
        }
    }
    for event in stepped_over.into_iter().rev() {
        events.push_front(event);
    }
    examined
}

/// Bytes an event holds. Zero for anything that is not a byte-stream chunk —
/// only chunks are charged against a stream's bound.
fn chunk_len(event: &EntrypointEvent) -> usize {
    match event {
        EntrypointEvent::Stdout { chunk } | EntrypointEvent::Stderr { chunk } => chunk.len(),
        EntrypointEvent::Control { .. }
        | EntrypointEvent::Exit { .. }
        | EntrypointEvent::Error { .. } => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_pump::{GAP_RECORD_KIND, MIN_RETENTION_CHUNKS, RETENTION_BYTES_PER_CHUNK};
    use crate::vsock::RunEntrypointError;
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    /// A hand-off whose consumer never reads, with a stdout bound of
    /// `stdout_max` bytes.
    fn stopped_consumer(stdout_max: usize) -> (Handoff, Receiver<EntrypointEvent>) {
        let (tx, rx) = mpsc::sync_channel(HANDOFF_CAPACITY);
        let caps = CallCaps {
            stdout_max,
            ..CallCaps::default()
        };
        (Handoff::new(tx, &caps), rx)
    }

    fn stdout(bytes: &[u8]) -> EntrypointEvent {
        EntrypointEvent::Stdout {
            chunk: bytes.to_vec(),
        }
    }

    /// Fill the channel, then send `count` four-byte chunks numbered in order,
    /// so which part of a burst survives is readable off the payloads.
    fn offer_numbered(handoff: &mut Handoff, count: usize) {
        for i in 0..count {
            handoff.offer(stdout(format!("{i:04}").as_bytes()));
        }
    }

    /// Collect channel data before the producer-owned completion tail.
    fn drain_and_finish(handoff: Handoff, rx: Receiver<EntrypointEvent>) -> Vec<EntrypointEvent> {
        let mut delivered: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let tail = handoff.finish();
        delivered.extend(rx);
        delivered.extend(tail);
        delivered
    }

    fn chunks_of(events: &[EntrypointEvent]) -> Vec<Vec<u8>> {
        events
            .iter()
            .filter_map(|event| match event {
                EntrypointEvent::Stdout { chunk } | EntrypointEvent::Stderr { chunk } => {
                    Some(chunk.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn controls_of(events: &[EntrypointEvent]) -> Vec<&EntrypointEvent> {
        events
            .iter()
            .filter(|event| matches!(event, EntrypointEvent::Control { .. }))
            .collect()
    }

    #[test]
    fn a_terminal_event_is_never_forwarded_to_the_consumer() {
        // The pump does not emit terminals today, so this is structural rather
        // than a live bug: a future one that did — say on a cap breach — would
        // otherwise put a second terminal on a wire whose reader stops at the
        // first, silently desyncing the rest of the call.
        let (mut handoff, rx) = stopped_consumer(1024);
        handoff.offer(EntrypointEvent::Exit { code: 0 });
        handoff.offer(EntrypointEvent::Error {
            kind: RunEntrypointError::InternalError,
            message: "not the caller's terminal".to_string(),
        });
        handoff.offer(stdout(b"real output"));
        drop(handoff);

        let delivered: Vec<_> = rx.into_iter().collect();
        assert_eq!(delivered, vec![stdout(b"real output")]);
    }

    #[test]
    fn a_stopped_consumer_costs_a_bounded_amount_of_memory() {
        // The regression this exists for: with an unbounded hand-off, a
        // consumer that stops reading grows the queue at the child's write
        // rate for the whole deadline. 400 KiB of output against a 32 KiB
        // bound must leave the queue at the bound, not at 400 KiB. The channel
        // holds a further `HANDOFF_CAPACITY` events; both terms are fixed,
        // which is the whole property.
        const BOUND: usize = 32 * 1024;
        let (mut handoff, _rx) = stopped_consumer(BOUND);
        for _ in 0..100 {
            handoff.offer(stdout(&[b'x'; 4096]));
        }
        let queued: usize = handoff.pending.events.iter().map(chunk_len).sum();
        assert!(
            queued <= BOUND,
            "queue held {queued} bytes against a {BOUND} byte bound"
        );
    }

    #[test]
    fn a_flood_of_one_byte_writes_is_bounded_in_events_as_well_as_bytes() {
        // A byte bound alone prices a one-byte write the same as a 48 KiB one,
        // so a workload doing unbuffered single-byte writes queues one event
        // per byte — 64 Ki of them here. Each is an event slot plus its own
        // allocation, which is most of a hundred bytes the cap never named, and
        // a queue that long is no longer free to walk. Both dimensions have to
        // be bounded or the figure the caller chose means nothing.
        const BOUND: usize = 64 * 1024;
        let event_bound =
            (BOUND as u64 / RETENTION_BYTES_PER_CHUNK).max(MIN_RETENTION_CHUNKS) as usize;

        let (mut handoff, _rx) = stopped_consumer(BOUND);
        for _ in 0..100_000 {
            handoff.offer(stdout(b"x"));
        }

        let queued_bytes: usize = handoff.pending.events.iter().map(chunk_len).sum();
        assert!(
            queued_bytes <= BOUND,
            "queue held {queued_bytes} bytes against a {BOUND} byte bound"
        );
        let queued_events = handoff.pending.events.len();
        assert!(
            queued_events <= event_bound,
            "queue held {queued_events} events against a {event_bound} event bound"
        );
    }

    /// Work one eviction does against a queue held at `queued` events: the
    /// number of events the walk examines.
    fn eviction_work(queued: usize) -> usize {
        let mut events: VecDeque<EntrypointEvent> = std::iter::repeat_with(|| stdout(b"x"))
            .take(queued)
            .collect();
        evict_oldest(&mut events, CapturedStream::Stdout, 1)
    }

    /// Complexity, asserted directly rather than inferred from a clock.
    ///
    /// The property is that eviction stops at its target instead of filtering
    /// the queue: fifty times the queue must not cost fifty times the work.
    ///
    /// This was previously timed — `long <= short * 8 + 50ms` over two 50,000
    /// eviction runs. That could not fail for the reason it named. With every
    /// event on one stream the walk pops exactly `count` from the front, so
    /// the cost is already independent of length by construction, and what the
    /// clock actually compared was cache locality on a 50k deque against a 1k
    /// one. On a machine where the larger deque falls out of cache it failed
    /// deterministically — observed red on `main`, on hardware that had
    /// nothing to do with the change under test.
    #[test]
    fn evicting_one_event_costs_the_same_on_a_long_queue_as_on_a_short_one() {
        let short = eviction_work(1_000);
        let long = eviction_work(50_000);

        assert_eq!(
            short, 1,
            "one eviction on a single-stream queue examines exactly its target"
        );
        assert_eq!(
            long, short,
            "eviction work scaled with queue length: {long} examined on a 50k-event queue \
             against {short} on a 1k-event one — the walk is filtering rather than stopping"
        );
    }

    #[test]
    fn the_newest_output_survives_and_one_gap_names_the_loss() {
        // Which end of a burst is dropped matters: a crash loop's last words
        // are the reason the ring evicts the oldest rather than refusing the
        // newest. Four-byte chunks against an eight-byte bound, past the
        // channel's own depth, so the ring is what decides.
        let (mut handoff, rx) = stopped_consumer(8);
        offer_numbered(&mut handoff, HANDOFF_CAPACITY + 4);
        let delivered = drain_and_finish(handoff, rx);

        let chunks = chunks_of(&delivered);
        assert_eq!(
            chunks.last().map(Vec::as_slice),
            Some(format!("{:04}", HANDOFF_CAPACITY + 3).as_bytes()),
            "the newest chunk must survive; got {chunks:?}"
        );
        assert!(
            chunks.len() < HANDOFF_CAPACITY + 4,
            "nothing was evicted, so the bound did not hold: {chunks:?}"
        );

        let controls = controls_of(&delivered);
        assert_eq!(
            controls.len(),
            1,
            "expected one gap record, got {controls:?}"
        );
        match controls[0] {
            EntrypointEvent::Control { header_json, .. } => {
                let header: serde_json::Value =
                    serde_json::from_str(header_json).expect("gap header is JSON");
                assert_eq!(header["kind"], GAP_RECORD_KIND);
                assert_eq!(header["stream"], "stdout");
                assert!(
                    header["dropped_bytes"].as_u64().is_some_and(|n| n > 0),
                    "gap reported no loss: {header}"
                );
            }
            other => panic!("expected a control record, got {other:?}"),
        }
    }

    #[test]
    fn stepping_over_another_stream_leaves_it_in_place_and_in_order() {
        // The walk has to pop events it is not evicting to reach the ones it
        // is. Putting them back in the wrong order, or behind the survivors,
        // would reorder a stream against itself — the one thing the FIFO is
        // there to guarantee.
        let stderr = |bytes: &[u8]| EntrypointEvent::Stderr {
            chunk: bytes.to_vec(),
        };
        let mut events: VecDeque<EntrypointEvent> = [
            stderr(b"e1"),
            stdout(b"o1"),
            stderr(b"e2"),
            stdout(b"o2"),
            stdout(b"o3"),
        ]
        .into();

        evict_oldest(&mut events, CapturedStream::Stdout, 2);

        assert_eq!(
            events.into_iter().collect::<Vec<_>>(),
            vec![stderr(b"e1"), stderr(b"e2"), stdout(b"o3")]
        );
    }

    #[test]
    fn a_call_that_never_evicted_reports_no_gap() {
        // A gap record is a claim that output was lost. Emitting one when the
        // ring never evicted would make every quiet call look lossy.
        let (mut handoff, rx) = stopped_consumer(1024);
        handoff.offer(stdout(b"small"));
        let delivered = drain_and_finish(handoff, rx);
        assert_eq!(delivered, vec![stdout(b"small")]);
    }

    #[test]
    fn completion_transfers_fifo_tail_and_exact_stage_loss() {
        let (mut handoff, rx) = stopped_consumer(8);
        handoff = handoff.for_pipe_reader();
        offer_numbered(&mut handoff, HANDOFF_CAPACITY + 4);
        let tail = handoff.finish();
        let events: Vec<_> = rx.into_iter().chain(tail).collect();
        let chunks = chunks_of(&events);
        let expected: Vec<_> = (0..HANDOFF_CAPACITY)
            .chain(HANDOFF_CAPACITY + 2..HANDOFF_CAPACITY + 4)
            .map(|n| format!("{n:04}").into_bytes())
            .collect();
        assert_eq!(chunks, expected);
        let controls = controls_of(&events);
        assert_eq!(controls.len(), 1);
        let EntrypointEvent::Control { header_json, .. } = controls[0] else {
            panic!("expected gap");
        };
        let gap: serde_json::Value = serde_json::from_str(header_json).unwrap();
        assert_eq!(gap["stage"], "pipe_reader");
        assert_eq!(gap["dropped_chunks"], 2);
        assert_eq!(gap["dropped_bytes"], 8);
        assert_eq!(gap["after_seq"], HANDOFF_CAPACITY + 1);
        assert_eq!(chunks.iter().map(Vec::len).sum::<usize>() + 8, 48);
    }

    #[test]
    fn disconnected_consumer_does_not_retain_further_output() {
        let (mut handoff, rx) = stopped_consumer(1024);
        drop(rx);
        for _ in 0..100 {
            handoff.offer(stdout(b"discarded"));
        }
        assert!(handoff.hung_up);
        assert!(handoff.pending.events.is_empty());
        assert!(handoff.finish().is_empty());
    }

    #[test]
    fn consumer_handoff_loss_has_a_distinct_stage() {
        let (mut handoff, rx) = stopped_consumer(8);
        offer_numbered(&mut handoff, HANDOFF_CAPACITY + 4);
        let events = drain_and_finish(handoff, rx);
        let controls = controls_of(&events);
        let EntrypointEvent::Control { header_json, .. } = controls[0] else {
            panic!("expected gap");
        };
        let gap: serde_json::Value = serde_json::from_str(header_json).unwrap();
        assert_eq!(gap["stage"], "consumer_handoff");
    }

    #[test]
    fn finishing_does_not_wait_for_a_stopped_consumer() {
        let (mut handoff, rx) = stopped_consumer(1024);
        offer_numbered(&mut handoff, HANDOFF_CAPACITY + 3);
        let (done_tx, done_rx) = mpsc::channel();
        let producer = std::thread::spawn(move || {
            handoff.finish();
            done_tx.send(()).unwrap();
        });
        let finished = done_rx.recv_timeout(Duration::from_secs(10));
        // Release the old blocking implementation even when the assertion fails.
        drop(rx);
        producer.join().unwrap();
        assert!(
            finished.is_ok(),
            "producer completion waited for its consumer"
        );
    }

    #[test]
    fn a_delivered_chunk_stops_counting_against_the_bound() {
        // Without releasing what the channel took, the ring would go on
        // charging for delivered chunks and evict live ones to free room that
        // is already free — a call whose consumer keeps up would still report
        // losing output.
        let (mut handoff, rx) = stopped_consumer(8 * 1024);
        // Thirty-two times the bound in total, but drained after every event,
        // so nothing ever waits.
        for _ in 0..64 {
            handoff.offer(stdout(&[b'x'; 4096]));
            rx.try_recv()
                .expect("a drained channel accepts every event");
        }
        let pending = handoff.finish();
        let tail: Vec<_> = rx.into_iter().chain(pending).collect();
        assert!(
            tail.is_empty(),
            "a fully drained call has nothing left to deliver and no gap to report, got {tail:?}"
        );
    }

    #[test]
    fn control_records_are_not_evicted_by_a_chatty_stream() {
        // fd-3 records are already capped for the whole call and carry the
        // structured half of a workload's output; a burst of stdout must not
        // push one out of the queue. The stdout offers before the record are
        // what fill the channel, so the record itself waits in the queue where
        // eviction could reach it.
        let (mut handoff, rx) = stopped_consumer(8);
        offer_numbered(&mut handoff, HANDOFF_CAPACITY);
        handoff.offer(EntrypointEvent::Control {
            header_json: r#"{"kind":"app.log"}"#.to_string(),
            payload: b"kept".to_vec(),
        });
        offer_numbered(&mut handoff, HANDOFF_CAPACITY);
        let delivered = drain_and_finish(handoff, rx);

        assert!(
            delivered.iter().any(|event| matches!(
                event,
                EntrypointEvent::Control { payload, .. } if payload == b"kept"
            )),
            "the workload's control record was evicted: {delivered:?}"
        );
    }
}
