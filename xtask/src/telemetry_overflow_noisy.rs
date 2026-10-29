//! Noisy-producer comparison of drop-newest and drop-oldest admission on the
//! production storage shape: `cargo xtask telemetry-baseline --noisy`.
//!
//! The metadata models beside this file stop at descriptors. This harness
//! keeps everything that makes the two policies cost different amounts in
//! the real outbox: fixed 32 KiB slots, the payload copy under the one
//! `try_lock`, zeroing a slot when its record leaves, per-source loss
//! counters as single atomic adds, and a worker that drains on the capture
//! session's 25 ms cadence by copying each record out under the lock. The
//! drop-newest arm is the production admission rule byte for byte; the
//! drop-oldest arm differs only in evicting the head until the arrival fits.
//!
//! Two producers share one queue. The noisy one offers back to back without
//! pause, the quiet one offers once a millisecond. Each round runs a live
//! phase, an outage in which the worker stops draining (a stalled host), and
//! a recovery phase. What a UI consumer cares about is measured directly:
//! how old a record is when the worker takes it, and how stale the first
//! batch after an outage is.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use mvm_core::protocol::telemetry::MAX_RECORD_BYTES;
use serde::Serialize;

/// Sources sharing the queue in this harness.
pub(super) const NOISY: usize = 0;
pub(super) const QUIET: usize = 1;
const SOURCES: usize = 2;

/// The guest agent's capture queue: 128 slots, byte limit equal to storage.
pub(super) const CAPTURE_SLOTS: usize = 128;
/// The capture session's drain cadence.
const DRAIN_INTERVAL: Duration = Duration::from_millis(25);
/// The quiet source's emission period.
const QUIET_PERIOD: Duration = Duration::from_millis(1);
/// Payload prefix carrying the producer's emission time (ns since start).
const STAMP_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Policy {
    DropNewest,
    DropOldest,
}

/// Outcome of one admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admit {
    Queued,
    /// Admitted after evicting this many older records.
    QueuedEvicting(usize),
    Full,
    Contended,
}

struct Slot {
    bytes: [u8; MAX_RECORD_BYTES],
    len: usize,
    source: usize,
}

struct Ring {
    slots: Box<[Slot]>,
    head: usize,
    len: usize,
    bytes: usize,
}

impl Ring {
    /// Remove the head record, zeroing its storage as the production pop
    /// does. Returns the departed record's source and length.
    fn pop_head(&mut self) -> (usize, usize) {
        let head = self.head;
        let slot = &mut self.slots[head];
        let (source, len) = (slot.source, slot.len);
        slot.bytes[..len].fill(0);
        slot.len = 0;
        self.bytes -= len;
        self.len -= 1;
        self.head = (head + 1) % self.slots.len();
        (source, len)
    }
}

#[derive(Default)]
struct PerSource {
    records: [AtomicU64; SOURCES],
}

impl PerSource {
    fn add(&self, source: usize) {
        self.records[source].fetch_add(1, Ordering::Relaxed);
    }

    fn get(&self, source: usize) -> u64 {
        self.records[source].load(Ordering::Relaxed)
    }
}

/// Fixed-storage queue with a selectable overflow rule.
pub(super) struct PolicyOutbox {
    state: Mutex<Ring>,
    policy: Policy,
    byte_limit: usize,
    shed: PerSource,
    evicted: PerSource,
    contended: PerSource,
}

impl PolicyOutbox {
    pub(super) fn new(policy: Policy, slots: usize, byte_limit: usize) -> Self {
        let slots = (0..slots)
            .map(|_| Slot {
                bytes: [0; MAX_RECORD_BYTES],
                len: 0,
                source: 0,
            })
            .collect();
        let state = Mutex::new(Ring {
            slots,
            head: 0,
            len: 0,
            bytes: 0,
        });
        drop(state.lock().expect("fresh lock"));
        Self {
            state,
            policy,
            byte_limit,
            shed: PerSource::default(),
            evicted: PerSource::default(),
            contended: PerSource::default(),
        }
    }

    /// One admission attempt: one `try_lock`, never a wait or retry.
    pub(super) fn offer(&self, source: usize, record: &[u8]) -> Admit {
        let mut ring = match self.state.try_lock() {
            Ok(ring) => ring,
            Err(TryLockError::WouldBlock) => {
                self.contended.add(source);
                return Admit::Contended;
            }
            Err(TryLockError::Poisoned(_)) => panic!("harness queue poisoned"),
        };
        let does_not_fit = |ring: &Ring| {
            ring.len == ring.slots.len() || record.len() > self.byte_limit - ring.bytes
        };
        let mut evicted = 0;
        match self.policy {
            Policy::DropNewest => {
                if does_not_fit(&ring) {
                    self.shed.add(source);
                    return Admit::Full;
                }
            }
            Policy::DropOldest => {
                if record.len() > self.byte_limit {
                    self.shed.add(source);
                    return Admit::Full;
                }
                while does_not_fit(&ring) {
                    let (victim, _) = ring.pop_head();
                    self.evicted.add(victim);
                    evicted += 1;
                }
            }
        }
        let index = (ring.head + ring.len) % ring.slots.len();
        let slot = &mut ring.slots[index];
        slot.bytes[..record.len()].copy_from_slice(record);
        slot.len = record.len();
        slot.source = source;
        ring.bytes += record.len();
        ring.len += 1;
        if evicted == 0 {
            Admit::Queued
        } else {
            Admit::QueuedEvicting(evicted)
        }
    }

    /// Worker pop: copy the head out under the lock, as production does.
    pub(super) fn take(&self) -> Option<(usize, Vec<u8>)> {
        let mut ring = self.state.lock().expect("harness queue lock");
        if ring.len == 0 {
            return None;
        }
        let head = ring.head;
        let record = ring.slots[head].bytes[..ring.slots[head].len].to_vec();
        let (source, _) = ring.pop_head();
        Some((source, record))
    }

    pub(super) fn shed(&self, source: usize) -> u64 {
        self.shed.get(source)
    }

    pub(super) fn evicted(&self, source: usize) -> u64 {
        self.evicted.get(source)
    }

    pub(super) fn contended(&self, source: usize) -> u64 {
        self.contended.get(source)
    }

    #[cfg(test)]
    fn hold(&self) -> std::sync::MutexGuard<'_, Ring> {
        self.state.lock().expect("harness queue lock")
    }
}

/// Latency histogram with no per-sample allocation: exact nanosecond
/// buckets below 4096 ns, power-of-two buckets above.
pub(super) struct Histogram {
    exact: Vec<u64>,
    log: [u64; 64],
    count: u64,
    max: u64,
}

const EXACT_NS: usize = 4096;

impl Histogram {
    pub(super) fn new() -> Self {
        Self {
            exact: vec![0; EXACT_NS],
            log: [0; 64],
            count: 0,
            max: 0,
        }
    }

    pub(super) fn record(&mut self, ns: u64) {
        if (ns as usize) < EXACT_NS {
            self.exact[ns as usize] += 1;
        } else {
            self.log[63 - ns.leading_zeros() as usize] += 1;
        }
        self.count += 1;
        self.max = self.max.max(ns);
    }

    fn merge(&mut self, other: &Histogram) {
        for (a, b) in self.exact.iter_mut().zip(&other.exact) {
            *a += b;
        }
        for (a, b) in self.log.iter_mut().zip(&other.log) {
            *a += b;
        }
        self.count += other.count;
        self.max = self.max.max(other.max);
    }

    /// Nearest-rank percentile; a power-of-two bucket reports its upper edge,
    /// so values above 4096 ns are conservative.
    pub(super) fn percentile(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let rank = ((p / 100.0) * self.count as f64).ceil().max(1.0) as u64;
        let mut seen = 0;
        for (ns, n) in self.exact.iter().enumerate() {
            seen += n;
            if seen >= rank {
                return ns as u64;
            }
        }
        for (bit, n) in self.log.iter().enumerate() {
            seen += n;
            if seen >= rank {
                return (1u64 << (bit + 1)).min(self.max);
            }
        }
        self.max
    }

    fn summary(&self) -> Percentiles {
        Percentiles {
            samples: self.count,
            p50: self.percentile(50.0),
            p99: self.percentile(99.0),
            p999: self.percentile(99.9),
            max: self.max,
        }
    }
}

#[derive(Debug, Serialize, Clone, Copy)]
pub(super) struct Percentiles {
    pub(super) samples: u64,
    pub(super) p50: u64,
    pub(super) p99: u64,
    pub(super) p999: u64,
    pub(super) max: u64,
}

/// Phase lengths for one round.
#[derive(Debug, Clone, Copy, Serialize)]
pub(super) struct Phases {
    pub(super) live_ms: u64,
    pub(super) outage_ms: u64,
    pub(super) recovery_ms: u64,
}

impl Phases {
    pub(super) const DEFAULT: Phases = Phases {
        live_ms: 1000,
        outage_ms: 500,
        recovery_ms: 500,
    };

    fn total(&self) -> Duration {
        Duration::from_millis(self.live_ms + self.outage_ms + self.recovery_ms)
    }
}

/// Per-source totals across every round; conservation is asserted.
#[derive(Debug, Default, Serialize, Clone, Copy)]
pub(super) struct SourceTotals {
    pub(super) attempted: u64,
    pub(super) queued: u64,
    pub(super) shed: u64,
    pub(super) contended: u64,
    pub(super) evicted: u64,
    pub(super) delivered: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct PolicyResult {
    pub(super) policy: Policy,
    pub(super) noisy_offer_ns: Percentiles,
    pub(super) quiet_offer_ns: Percentiles,
    pub(super) noisy: SourceTotals,
    pub(super) quiet: SourceTotals,
    /// Fraction of quiet attempts the worker took, per round.
    pub(super) quiet_delivered_ratio: Vec<f64>,
    /// Age of each record when the worker took it, live phase only (µs).
    pub(super) live_age_us: Percentiles,
    /// Age of the oldest record in the first drain after each outage (ms).
    pub(super) reconnect_oldest_age_ms: Vec<u64>,
    /// Most evictions any single admission performed.
    pub(super) max_evictions_per_offer: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct WorstCase {
    pub(super) policy: Policy,
    /// Offers against a full queue of typical records.
    pub(super) full_typical_ns: Percentiles,
    /// Offers of a maximum-size (32 KiB) record against a full queue.
    pub(super) full_max_size_ns: Percentiles,
}

#[derive(Debug, Serialize)]
pub(super) struct NoisyReport {
    pub(super) rounds: usize,
    pub(super) phases: Phases,
    pub(super) capture_slots: usize,
    pub(super) record_bytes: usize,
    pub(super) results: Vec<PolicyResult>,
    pub(super) worst_case: Vec<WorstCase>,
}

fn stamp(buffer: &mut [u8], start: Instant) {
    let ns = start.elapsed().as_nanos() as u64;
    buffer[..STAMP_BYTES].copy_from_slice(&ns.to_le_bytes());
}

fn stamped_ns(record: &[u8]) -> u64 {
    u64::from_le_bytes(record[..STAMP_BYTES].try_into().expect("stamp prefix"))
}

struct ProducerRun {
    histogram: Histogram,
    totals: SourceTotals,
    max_evictions: usize,
}

fn produce(
    outbox: &PolicyOutbox,
    source: usize,
    template: &[u8],
    start: Instant,
    done: &AtomicBool,
    period: Option<Duration>,
) -> ProducerRun {
    let mut buffer = template.to_vec();
    let mut run = ProducerRun {
        histogram: Histogram::new(),
        totals: SourceTotals::default(),
        max_evictions: 0,
    };
    while !done.load(Ordering::Relaxed) {
        stamp(&mut buffer, start);
        let begin = Instant::now();
        let outcome = outbox.offer(source, &buffer);
        run.histogram.record(begin.elapsed().as_nanos() as u64);
        run.totals.attempted += 1;
        match outcome {
            Admit::Queued => run.totals.queued += 1,
            Admit::QueuedEvicting(n) => {
                run.totals.queued += 1;
                run.max_evictions = run.max_evictions.max(n);
            }
            Admit::Full | Admit::Contended => {}
        }
        if let Some(period) = period {
            std::thread::sleep(period);
        }
    }
    run
}

struct WorkerRun {
    delivered: [u64; SOURCES],
    live_age_us: Histogram,
    reconnect_oldest_ns: u64,
}

fn drain(outbox: &PolicyOutbox, start: Instant, phases: Phases, done: &AtomicBool) -> WorkerRun {
    let live_end = Duration::from_millis(phases.live_ms);
    let outage_end = Duration::from_millis(phases.live_ms + phases.outage_ms);
    let mut run = WorkerRun {
        delivered: [0; SOURCES],
        live_age_us: Histogram::new(),
        reconnect_oldest_ns: 0,
    };
    let mut first_after_outage = true;
    while !done.load(Ordering::Relaxed) {
        let now = start.elapsed();
        let stalled = now >= live_end && now < outage_end;
        if !stalled {
            let reconnect = now >= outage_end && first_after_outage;
            while let Some((source, record)) = outbox.take() {
                run.delivered[source] += 1;
                let age = start.elapsed().as_nanos() as u64 - stamped_ns(&record);
                if now < live_end {
                    run.live_age_us.record(age / 1000);
                }
                if reconnect {
                    run.reconnect_oldest_ns = run.reconnect_oldest_ns.max(age);
                }
            }
            if reconnect {
                first_after_outage = false;
            }
        }
        std::thread::sleep(DRAIN_INTERVAL);
    }
    while let Some((source, _)) = outbox.take() {
        run.delivered[source] += 1;
    }
    run
}

struct Round {
    noisy: ProducerRun,
    quiet: ProducerRun,
    worker: WorkerRun,
    outbox: PolicyOutbox,
}

fn quiesce<T>(
    stop: &AtomicBool,
    producers_done: &AtomicBool,
    join_producers: impl FnOnce() -> T,
) -> T {
    stop.store(true, Ordering::Relaxed);
    let producers = join_producers();
    // A producer may already have passed its stop check. Quiesce both
    // producers before allowing the worker to perform its final drain.
    producers_done.store(true, Ordering::Relaxed);
    producers
}

fn round(policy: Policy, template: &[u8], phases: Phases) -> Round {
    let outbox = PolicyOutbox::new(policy, CAPTURE_SLOTS, CAPTURE_SLOTS * MAX_RECORD_BYTES);
    let done = AtomicBool::new(false);
    let producers_done = AtomicBool::new(false);
    let start = Instant::now();
    let (noisy, quiet, worker) = std::thread::scope(|scope| {
        let noisy = scope.spawn(|| produce(&outbox, NOISY, template, start, &done, None));
        let quiet =
            scope.spawn(|| produce(&outbox, QUIET, template, start, &done, Some(QUIET_PERIOD)));
        let worker = scope.spawn(|| drain(&outbox, start, phases, &producers_done));
        std::thread::sleep(phases.total());
        let (noisy, quiet) = quiesce(&done, &producers_done, || (noisy.join(), quiet.join()));
        (
            noisy.expect("noisy producer"),
            quiet.expect("quiet producer"),
            worker.join().expect("worker"),
        )
    });
    Round {
        noisy,
        quiet,
        worker,
        outbox,
    }
}

fn totals(
    producer: &ProducerRun,
    outbox: &PolicyOutbox,
    delivered: u64,
    source: usize,
) -> SourceTotals {
    let totals = SourceTotals {
        shed: outbox.shed(source),
        contended: outbox.contended(source),
        evicted: outbox.evicted(source),
        delivered,
        ..producer.totals
    };
    assert_eq!(
        totals.attempted,
        totals.queued + totals.shed + totals.contended,
        "every attempt has exactly one outcome"
    );
    assert_eq!(
        totals.queued,
        totals.evicted + totals.delivered,
        "every admitted record is evicted or delivered after the final drain"
    );
    totals
}

fn add(into: &mut SourceTotals, from: SourceTotals) {
    into.attempted += from.attempted;
    into.queued += from.queued;
    into.shed += from.shed;
    into.contended += from.contended;
    into.evicted += from.evicted;
    into.delivered += from.delivered;
}

pub(super) fn compare(
    policy: Policy,
    template: &[u8],
    rounds: usize,
    phases: Phases,
) -> PolicyResult {
    let mut noisy_ns = Histogram::new();
    let mut quiet_ns = Histogram::new();
    let mut live_age = Histogram::new();
    let mut noisy = SourceTotals::default();
    let mut quiet = SourceTotals::default();
    let mut ratios = Vec::with_capacity(rounds);
    let mut reconnect = Vec::with_capacity(rounds);
    let mut max_evictions = 0;
    for _ in 0..rounds {
        let r = round(policy, template, phases);
        let n = totals(&r.noisy, &r.outbox, r.worker.delivered[NOISY], NOISY);
        let q = totals(&r.quiet, &r.outbox, r.worker.delivered[QUIET], QUIET);
        ratios.push(if q.attempted == 0 {
            0.0
        } else {
            q.delivered as f64 / q.attempted as f64
        });
        reconnect.push(r.worker.reconnect_oldest_ns / 1_000_000);
        add(&mut noisy, n);
        add(&mut quiet, q);
        noisy_ns.merge(&r.noisy.histogram);
        quiet_ns.merge(&r.quiet.histogram);
        live_age.merge(&r.worker.live_age_us);
        max_evictions = max_evictions
            .max(r.noisy.max_evictions)
            .max(r.quiet.max_evictions);
    }
    PolicyResult {
        policy,
        noisy_offer_ns: noisy_ns.summary(),
        quiet_offer_ns: quiet_ns.summary(),
        noisy,
        quiet,
        quiet_delivered_ratio: ratios,
        live_age_us: live_age.summary(),
        reconnect_oldest_age_ms: reconnect,
        max_evictions_per_offer: max_evictions,
    }
}

/// Uncontended admission against an already-full queue, the path where the
/// two rules differ most: drop-newest returns, drop-oldest copies.
pub(super) fn worst_case(policy: Policy, template: &[u8], samples: usize) -> WorstCase {
    let measure = |record: &[u8]| {
        let outbox = PolicyOutbox::new(policy, CAPTURE_SLOTS, CAPTURE_SLOTS * MAX_RECORD_BYTES);
        while outbox.offer(NOISY, template) == Admit::Queued {}
        let mut histogram = Histogram::new();
        for _ in 0..samples {
            let begin = Instant::now();
            let outcome = outbox.offer(NOISY, record);
            histogram.record(begin.elapsed().as_nanos() as u64);
            std::hint::black_box(outcome);
        }
        histogram.summary()
    };
    let max_size = vec![0x5a; MAX_RECORD_BYTES];
    WorstCase {
        policy,
        full_typical_ns: measure(template),
        full_max_size_ns: measure(&max_size),
    }
}

pub(super) fn measure(
    template: &[u8],
    rounds: usize,
    phases: Phases,
    samples: usize,
) -> NoisyReport {
    assert!(template.len() > STAMP_BYTES, "record must carry a stamp");
    let policies = [Policy::DropNewest, Policy::DropOldest];
    NoisyReport {
        rounds,
        phases,
        capture_slots: CAPTURE_SLOTS,
        record_bytes: template.len(),
        results: policies
            .iter()
            .map(|p| compare(*p, template, rounds, phases))
            .collect(),
        worst_case: policies
            .iter()
            .map(|p| worst_case(*p, template, samples))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(len: usize) -> Vec<u8> {
        vec![7; len]
    }

    #[test]
    fn drop_newest_refuses_the_arrival_and_keeps_queued_history() {
        let outbox = PolicyOutbox::new(Policy::DropNewest, 2, 2 * MAX_RECORD_BYTES);
        assert_eq!(outbox.offer(QUIET, &record(16)), Admit::Queued);
        assert_eq!(outbox.offer(QUIET, &record(16)), Admit::Queued);
        assert_eq!(outbox.offer(NOISY, &record(16)), Admit::Full);
        assert_eq!(outbox.shed(NOISY), 1);
        assert_eq!(outbox.evicted(QUIET), 0);
        assert_eq!(outbox.take().unwrap().0, QUIET);
    }

    #[test]
    fn drop_oldest_evicts_the_head_and_charges_the_victims_source() {
        let outbox = PolicyOutbox::new(Policy::DropOldest, 2, 2 * MAX_RECORD_BYTES);
        assert_eq!(outbox.offer(QUIET, &record(16)), Admit::Queued);
        assert_eq!(outbox.offer(NOISY, &record(16)), Admit::Queued);
        assert_eq!(outbox.offer(NOISY, &record(16)), Admit::QueuedEvicting(1));
        // The noisy arrival cost the quiet source its record.
        assert_eq!(outbox.evicted(QUIET), 1);
        assert_eq!(outbox.shed(NOISY), 0);
        assert_eq!(outbox.take().unwrap().0, NOISY);
        assert_eq!(outbox.take().unwrap().0, NOISY);
        assert!(outbox.take().is_none());
    }

    #[test]
    fn drop_oldest_evicts_until_the_byte_limit_admits_and_never_for_oversize() {
        let outbox = PolicyOutbox::new(Policy::DropOldest, 8, 64);
        for _ in 0..4 {
            assert_eq!(outbox.offer(QUIET, &record(16)), Admit::Queued);
        }
        assert_eq!(outbox.offer(NOISY, &record(40)), Admit::QueuedEvicting(3));
        assert_eq!(outbox.evicted(QUIET), 3);
        assert_eq!(outbox.offer(NOISY, &record(65)), Admit::Full);
        assert_eq!(outbox.evicted(QUIET), 3, "oversize evicts nothing");
    }

    #[test]
    fn a_held_queue_is_contention_not_a_wait_under_either_policy() {
        for policy in [Policy::DropNewest, Policy::DropOldest] {
            let outbox = PolicyOutbox::new(policy, 2, 2 * MAX_RECORD_BYTES);
            let guard = outbox.hold();
            std::thread::scope(|scope| {
                let offered = scope.spawn(|| outbox.offer(NOISY, &record(16))).join();
                assert_eq!(offered.unwrap(), Admit::Contended);
            });
            drop(guard);
            assert_eq!(outbox.contended(NOISY), 1);
        }
    }

    #[test]
    fn the_histogram_reports_nearest_rank_and_conservative_upper_buckets() {
        let mut h = Histogram::new();
        for ns in 1..=100 {
            h.record(ns);
        }
        assert_eq!(h.percentile(50.0), 50);
        assert_eq!(h.percentile(99.0), 99);
        h.record(10_000);
        assert_eq!(h.percentile(100.0), 10_000);
        assert_eq!(h.max, 10_000);
    }

    #[test]
    fn final_drain_waits_for_an_admission_already_in_flight() {
        for policy in [Policy::DropNewest, Policy::DropOldest] {
            let outbox = PolicyOutbox::new(policy, 1, MAX_RECORD_BYTES);
            let stop = AtomicBool::new(false);
            let producers_done = AtomicBool::new(false);
            let checked_stop = std::sync::Barrier::new(2);
            let finish_offer = std::sync::Barrier::new(2);
            std::thread::scope(|scope| {
                let producer = scope.spawn(|| {
                    assert!(!stop.load(Ordering::Relaxed));
                    checked_stop.wait();
                    finish_offer.wait();
                    outbox.offer(NOISY, &record(512))
                });
                checked_stop.wait();
                let outcome = quiesce(&stop, &producers_done, || {
                    let stopped = stop.load(Ordering::Relaxed);
                    let worker_stopped = producers_done.load(Ordering::Relaxed);
                    // The worker can observe an empty queue while the last
                    // admitted record is still waiting to be offered.
                    let empty = outbox.take().is_none();
                    finish_offer.wait();
                    let outcome = producer.join().unwrap();
                    assert!(stopped);
                    assert!(!worker_stopped);
                    assert!(empty);
                    outcome
                });
                assert_eq!(outcome, Admit::Queued);
                assert!(producers_done.load(Ordering::Relaxed));
                let worker = drain(
                    &outbox,
                    Instant::now(),
                    Phases {
                        live_ms: 0,
                        outage_ms: 0,
                        recovery_ms: 0,
                    },
                    &producers_done,
                );
                assert_eq!(worker.delivered[NOISY] + outbox.evicted(NOISY), 1);
                assert!(outbox.take().is_none());
            });
        }
    }

    #[test]
    fn a_short_round_conserves_every_record_under_both_policies() {
        let phases = Phases {
            live_ms: 60,
            outage_ms: 60,
            recovery_ms: 60,
        };
        for policy in [Policy::DropNewest, Policy::DropOldest] {
            // `compare` asserts conservation per source internally.
            let result = compare(policy, &record(512), 1, phases);
            assert!(result.noisy.attempted > result.quiet.attempted);
            assert!(result.quiet.attempted > 0);
            if policy == Policy::DropNewest {
                assert_eq!(result.noisy.evicted + result.quiet.evicted, 0);
            } else {
                assert_eq!(result.noisy.shed + result.quiet.shed, 0);
            }
        }
    }

    #[test]
    fn worst_case_measures_full_queue_offers_for_both_sizes() {
        let w = worst_case(Policy::DropOldest, &record(512), 100);
        assert_eq!(w.full_typical_ns.samples, 100);
        assert_eq!(w.full_max_size_ns.samples, 100);
    }
}
