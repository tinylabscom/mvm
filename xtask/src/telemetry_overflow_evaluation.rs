//! Offline policy models, not alternate production outboxes.
//!
//! Store only source, sequence and length: no payload copy, zeroing, encoding,
//! transport, shutdown or production loss counters. Timings compare model work
//! only; they cannot establish production admission-budget compliance.

use std::collections::VecDeque;
use std::sync::{Barrier, Mutex};

use serde::Serialize;

use super::{Distribution, distribution, timed_ns};

const SOURCES: usize = 2;
const SLOTS: usize = 16;
const BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Policy {
    DropNewest,
    DropOldest,
    ReservedDropNewest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct Record {
    source: usize,
    sequence: usize,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
struct Count {
    records: usize,
    bytes: usize,
}

impl Count {
    fn add(&mut self, record: Record) {
        self.records += 1;
        self.bytes += record.bytes;
    }
}

#[derive(Default, Debug, Serialize)]
struct Source {
    attempted: Count,
    admitted: Count,
    rejected: Count,
    contended: Count,
    evicted: Count,
    drained: Count,
    /// Delivered sequence numbers, including a final drain. Missing numbers
    /// are loss evidence in this closed trace, not transport acknowledgements.
    drained_sequences: Vec<usize>,
}

#[derive(Debug, Serialize)]
struct Trace {
    sources: [Source; SOURCES],
    observed_peak_records: usize,
    observed_peak_bytes: usize,
}

impl Trace {
    fn new() -> Self {
        Self {
            sources: std::array::from_fn(|_| Source::default()),
            observed_peak_records: 0,
            observed_peak_bytes: 0,
        }
    }

    fn offered(&mut self, record: Record, outcome: Outcome) {
        let source = &mut self.sources[record.source];
        source.attempted.add(record);
        match outcome {
            Outcome::Admitted(evicted) => {
                source.admitted.add(record);
                for victim in evicted {
                    self.sources[victim.source].evicted.add(victim);
                }
            }
            Outcome::Rejected => source.rejected.add(record),
            Outcome::Contended => source.contended.add(record),
        }
    }

    fn drained(&mut self, record: Record) {
        let source = &mut self.sources[record.source];
        source.drained.add(record);
        source.drained_sequences.push(record.sequence);
    }

    fn check(&self) {
        for source in &self.sources {
            assert_eq!(
                source.attempted.records,
                source.rejected.records + source.contended.records + source.admitted.records
            );
            assert_eq!(
                source.attempted.bytes,
                source.rejected.bytes + source.contended.bytes + source.admitted.bytes
            );
            assert_eq!(
                source.admitted.records,
                source.evicted.records + source.drained.records
            );
            assert_eq!(
                source.admitted.bytes,
                source.evicted.bytes + source.drained.bytes
            );
        }
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Admitted(Vec<Record>),
    Rejected,
    Contended,
}

struct Queue {
    policy: Policy,
    records: Mutex<VecDeque<Record>>,
}

impl Queue {
    fn new(policy: Policy) -> Self {
        Self {
            policy,
            records: Mutex::new(VecDeque::with_capacity(SLOTS)),
        }
    }

    fn offer(&self, record: Record) -> Outcome {
        // Exactly one lock attempt: no retry, notification or waiting.
        let Ok(mut records) = self.records.try_lock() else {
            return Outcome::Contended;
        };
        let reserved = self.policy == Policy::ReservedDropNewest;
        let (slots, bytes) = if reserved {
            (SLOTS / SOURCES, BYTES / SOURCES)
        } else {
            (SLOTS, BYTES)
        };
        // Impossible records must not evict useful history.
        if record.bytes > bytes {
            return Outcome::Rejected;
        }
        let fits = |records: &VecDeque<Record>| {
            let mut count = 0;
            let mut used = 0;
            for queued in records {
                if !reserved || queued.source == record.source {
                    count += 1;
                    used += queued.bytes;
                }
            }
            count < slots && record.bytes <= bytes - used
        };
        let mut evicted = Vec::new();
        if !fits(&records) && self.policy != Policy::DropOldest {
            return Outcome::Rejected;
        }
        // Variable sizes can require several evictions, bounded by SLOTS.
        while !fits(&records) {
            evicted.push(records.pop_front().expect("nonempty full model queue"));
        }
        records.push_back(record);
        Outcome::Admitted(evicted)
    }

    fn take(&self) -> Option<Record> {
        self.records.lock().expect("model worker lock").pop_front()
    }

    fn observe_bounds(&self, trace: &mut Trace) {
        let records = self.records.lock().expect("model observation");
        let bytes = records.iter().map(|r| r.bytes).sum();
        assert!(records.len() <= SLOTS && bytes <= BYTES);
        trace.observed_peak_records = trace.observed_peak_records.max(records.len());
        trace.observed_peak_bytes = trace.observed_peak_bytes.max(bytes);
    }
}

/// Source 0 floods; source 1 emits once per eight records. Vary both sizes.
fn record(source: usize, sequence: usize) -> Record {
    Record {
        source,
        sequence,
        bytes: [64, 512, 128, 1024][(sequence + source) % 4],
    }
}

fn scenario(policy: Policy, drain_every: Option<usize>) -> (Trace, Vec<f64>) {
    let queue = Queue::new(policy);
    let mut trace = Trace::new();
    let mut timings = Vec::new();
    for sequence in 0..128 {
        for source in 0..SOURCES {
            if source == 1 && sequence % 8 != 0 {
                continue;
            }
            let record = record(source, if source == 0 { sequence } else { sequence / 8 });
            let mut outcome = Outcome::Rejected;
            timings.push(timed_ns(|| outcome = queue.offer(record)));
            trace.offered(record, outcome);
            queue.observe_bounds(&mut trace);
        }
        if drain_every.is_some_and(|period| sequence % period == period - 1)
            && let Some(record) = queue.take()
        {
            trace.drained(record);
        }
    }
    while let Some(record) = queue.take() {
        trace.drained(record);
    }
    trace.check();
    (trace, timings)
}

/// A real concurrent worker, with a finite drain schedule rather than a
/// polling loop. Results are scheduler-dependent, unlike the scripted trace.
fn concurrent(policy: Policy) -> Trace {
    let queue = Queue::new(policy);
    let barrier = Barrier::new(SOURCES + 1);
    let mut trace = Trace::new();
    std::thread::scope(|scope| {
        let producers: Vec<_> = (0..SOURCES)
            .map(|source| {
                let queue = &queue;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    (0..128)
                        .map(|sequence| {
                            let record = record(source, sequence);
                            (record, queue.offer(record))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        barrier.wait();
        for _ in 0..128 {
            if let Some(record) = queue.take() {
                trace.drained(record);
            }
            queue.observe_bounds(&mut trace);
        }
        for producer in producers {
            for (record, outcome) in producer.join().expect("model producer") {
                trace.offered(record, outcome);
            }
        }
    });
    while let Some(record) = queue.take() {
        trace.drained(record);
    }
    trace.check();
    trace
}

#[derive(Debug, Serialize)]
pub(super) struct Evaluation {
    model_schema_version: u32,
    disclaimer: &'static str,
    toolchain: String,
    slots: usize,
    byte_limit: usize,
    reserved_slots_per_source: usize,
    reserved_bytes_per_source: usize,
    policies: Vec<PolicyReport>,
}

#[derive(Debug, Serialize)]
struct PolicyReport {
    policy: Policy,
    stalled_worker: Trace,
    periodic_worker: Trace,
    /// Mixed outcomes, metadata scanning and eviction-vector allocation are
    /// included; payload copies and production counters are not.
    mixed_model_offer_ns: Distribution,
    concurrent_worker_rounds: Vec<Trace>,
}

pub(super) fn measure(rounds: usize) -> Evaluation {
    Evaluation {
        model_schema_version: 1,
        disclaimer: "EXPERIMENTAL metadata-only models; timings are NOT production offer overhead \
                     or evidence of compliance with the committed 63 ns budget",
        toolchain: std::process::Command::new("rustc")
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_else(|| "unknown".to_owned()),
        slots: SLOTS,
        byte_limit: BYTES,
        reserved_slots_per_source: SLOTS / SOURCES,
        reserved_bytes_per_source: BYTES / SOURCES,
        policies: [
            Policy::DropNewest,
            Policy::DropOldest,
            Policy::ReservedDropNewest,
        ]
        .into_iter()
        .map(|policy| {
            let (stalled_worker, mut timings) = scenario(policy, None);
            let (periodic_worker, periodic_timings) = scenario(policy, Some(4));
            timings.extend(periodic_timings);
            PolicyReport {
                policy,
                stalled_worker,
                periodic_worker,
                mixed_model_offer_ns: distribution(&timings),
                concurrent_worker_rounds: (0..rounds).map(|_| concurrent(policy)).collect(),
            }
        })
        .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(sequence: usize, bytes: usize) -> Record {
        Record {
            source: 0,
            sequence,
            bytes,
        }
    }

    #[test]
    fn count_and_byte_bounds_and_multiple_evictions() {
        for policy in [
            Policy::DropNewest,
            Policy::DropOldest,
            Policy::ReservedDropNewest,
        ] {
            let queue = Queue::new(policy);
            let slots = if policy == Policy::ReservedDropNewest {
                SLOTS / SOURCES
            } else {
                SLOTS
            };
            for sequence in 0..slots {
                assert_eq!(queue.offer(fixed(sequence, 1)), Outcome::Admitted(vec![]));
            }
            let outcome = queue.offer(fixed(slots, 1));
            if policy == Policy::DropOldest {
                assert_eq!(outcome, Outcome::Admitted(vec![fixed(0, 1)]));
            } else {
                assert_eq!(outcome, Outcome::Rejected);
            }
            queue.observe_bounds(&mut Trace::new());
        }
        let queue = Queue::new(Policy::DropOldest);
        for sequence in 0..4 {
            assert_eq!(
                queue.offer(fixed(sequence, 1024)),
                Outcome::Admitted(vec![])
            );
        }
        assert_eq!(queue.offer(fixed(4, BYTES + 1)), Outcome::Rejected);
        assert_eq!(
            queue.offer(fixed(5, 3000)),
            Outcome::Admitted((0..3).map(|sequence| fixed(sequence, 1024)).collect())
        );
        assert_eq!(queue.take(), Some(fixed(3, 1024)));
        assert_eq!(queue.take(), Some(fixed(5, 3000)));
    }

    #[test]
    fn reserved_capacity_protects_quiet_source_but_cannot_borrow() {
        let queue = Queue::new(Policy::ReservedDropNewest);
        for sequence in 0..SLOTS / SOURCES {
            assert_eq!(queue.offer(fixed(sequence, 1)), Outcome::Admitted(vec![]));
        }
        assert_eq!(queue.offer(fixed(8, 1)), Outcome::Rejected);
        let quiet = Record {
            source: 1,
            sequence: 0,
            bytes: 1,
        };
        assert_eq!(queue.offer(quiet), Outcome::Admitted(vec![]));
        queue.observe_bounds(&mut Trace::new());

        let queue = Queue::new(Policy::ReservedDropNewest);
        assert_eq!(
            queue.offer(fixed(0, BYTES / SOURCES)),
            Outcome::Admitted(vec![])
        );
        assert_eq!(queue.offer(fixed(1, 1)), Outcome::Rejected);
        let quiet = Record {
            source: 1,
            sequence: 0,
            bytes: BYTES / SOURCES,
        };
        assert_eq!(queue.offer(quiet), Outcome::Admitted(vec![]));
        queue.observe_bounds(&mut Trace::new());
        assert_eq!(queue.take(), Some(fixed(0, BYTES / SOURCES)));
        assert_eq!(queue.take(), Some(quiet));
    }

    #[test]
    fn admission_returns_while_worker_still_holds_lock() {
        for policy in [
            Policy::DropNewest,
            Policy::DropOldest,
            Policy::ReservedDropNewest,
        ] {
            let queue = Queue::new(policy);
            let held = queue.records.lock().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                scope.spawn(|| tx.send(queue.offer(fixed(0, 64))).unwrap());
                let result = rx.recv_timeout(std::time::Duration::from_secs(2));
                drop(held); // Release even on failure so a blocking regression can join.
                assert_eq!(result.unwrap(), Outcome::Contended);
                let mut trace = Trace::new();
                trace.offered(fixed(0, 64), Outcome::Contended);
                trace.check();
                assert_eq!(
                    trace.sources[0].contended,
                    Count {
                        records: 1,
                        bytes: 64
                    }
                );
            });
        }
    }

    #[test]
    fn draining_owns_popped_record_and_gaps_move_from_tail_to_history() {
        for policy in [Policy::DropNewest, Policy::DropOldest] {
            let queue = Queue::new(policy);
            assert_eq!(queue.offer(fixed(0, BYTES)), Outcome::Admitted(vec![]));
            let in_flight = queue.take();
            assert_eq!(queue.offer(fixed(1, BYTES)), Outcome::Admitted(vec![]));
            let result = queue.offer(fixed(2, BYTES));
            assert_eq!(in_flight, Some(fixed(0, BYTES)));
            match policy {
                Policy::DropNewest => {
                    assert_eq!(result, Outcome::Rejected);
                    assert_eq!(queue.take(), Some(fixed(1, BYTES)));
                }
                Policy::DropOldest => {
                    assert_eq!(result, Outcome::Admitted(vec![fixed(1, BYTES)]));
                    assert_eq!(queue.take(), Some(fixed(2, BYTES)));
                }
                Policy::ReservedDropNewest => unreachable!(),
            }
        }
    }

    #[test]
    fn every_trace_accounts_records_and_bytes_and_serializes() {
        let report = measure(3);
        for policy in &report.policies {
            policy.stalled_worker.check();
            policy.periodic_worker.check();
            for trace in &policy.concurrent_worker_rounds {
                trace.check();
            }
        }
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["policies"].as_array().unwrap().len(), 3);
        assert!(
            json["disclaimer"]
                .as_str()
                .unwrap()
                .contains("NOT production")
        );
    }
}
