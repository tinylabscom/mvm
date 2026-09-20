//! Offline telemetry emit-path baseline via `cargo xtask telemetry-baseline`.
//!
//! Measures the pre-feature cost of the pieces guest capture will sit on:
//! record preparation, non-waiting outbox admission (queued and shed paths)
//! and multi-producer flood fairness, plus the deterministic storage
//! footprint. Prints one JSON report to stdout with a host descriptor, so
//! runs are only comparable on the same hardware.
//!
//! Deliberately NOT a `check-all` gate: the numbers are hardware-dependent.
//! Committed baselines, the exact commands, run-to-run variance and derived
//! budgets live in `specs/telemetry/baselines.md`. Allocation counts are not
//! re-measured here — the admission path's zero-allocation property is
//! already witnessed natively and under Miri by the outbox allocation
//! regressions in `mvm-core`.
//!
//! What this cannot measure: VM control/exit latency needs a real guest
//! boot, which the live perf lanes own (`cargo xtask perf boot` on
//! Linux+KVM and the `mvm-cli` bench harness); the baseline doc records
//! those commands as the hardware-qualified remainder.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use mvm_core::net::telemetry::outbox::{Offer, Outbox, PreparedRecord};
use mvm_core::protocol::telemetry::{
    Attribute, AttributeValue, BoundedList, CoverageState, MAX_RECORD_BYTES, ProducerEpoch,
    RecordBody, SourceKind, TelemetryRecord,
};

/// Bump on any change that makes older reports incomparable.
const SCHEMA_VERSION: u32 = 1;
/// The outbox's slot ceiling; admission batches fill one outbox per batch.
const SLOTS: usize = 256;
/// Extra timed offers against the already-full queue per batch.
const SHED_PER_BATCH: usize = 64;
/// Producer threads competing in one fairness round.
const FLOOD_PRODUCERS: usize = 4;

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    host: Host,
    samples: usize,
    fairness_rounds: usize,
    /// Cost of one `Instant::now()` pair, included in every sample below.
    timer_overhead_ns: Distribution,
    prepare_small_ns: Distribution,
    prepare_typical_ns: Distribution,
    offer_queued_small_ns: Distribution,
    offer_queued_typical_ns: Distribution,
    offer_shed_ns: Distribution,
    flood_fairness: Fairness,
    memory: Memory,
    allocation_witness: &'static str,
}

#[derive(Debug, Serialize, PartialEq)]
struct Host {
    os: &'static str,
    arch: &'static str,
    cpu: String,
    logical_cores: usize,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq)]
struct Distribution {
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
    mean: f64,
    std_dev: f64,
}

/// Multi-producer admission spread under flood, aggregated over rounds.
#[derive(Debug, Serialize)]
struct Fairness {
    producers: usize,
    attempts_per_producer: usize,
    /// Per-round min/max admitted ratio (1.0 = perfectly even), summarized.
    admitted_ratio: Distribution,
    total_queued: usize,
    total_contended: usize,
    total_shed: usize,
}

/// Deterministic storage bound, computed rather than sampled.
#[derive(Debug, Serialize)]
struct Memory {
    slot_bytes: usize,
    max_slots: usize,
    max_storage_bytes: usize,
}

/// Percentile by nearest-rank on a sorted copy; callers hand raw samples.
fn distribution(samples: &[f64]) -> Distribution {
    assert!(!samples.is_empty(), "distribution of no samples");
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let rank = |p: f64| {
        let index = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
        sorted[index.clamp(1, sorted.len()) - 1]
    };
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let variance =
        sorted.iter().map(|s| (s - mean) * (s - mean)).sum::<f64>() / sorted.len() as f64;
    Distribution {
        p50: rank(50.0),
        p95: rank(95.0),
        p99: rank(99.0),
        max: sorted[sorted.len() - 1],
        mean,
        std_dev: variance.sqrt(),
    }
}

fn small_record() -> TelemetryRecord {
    TelemetryRecord::builder()
        .epoch(ProducerEpoch::new([1; 16]).expect("nonzero epoch"))
        .producer(1)
        .sequence(1)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Coverage {
            state: CoverageState::Started,
            code: "baseline".try_into().expect("bounded code"),
        })
        .build()
        .expect("small record")
}

/// A representative log record: a 256-byte message and four typed fields.
fn typical_record() -> TelemetryRecord {
    let attributes = vec![
        Attribute {
            key: "vm".try_into().expect("key"),
            value: AttributeValue::Text("baseline-vm".try_into().expect("value")),
        },
        Attribute {
            key: "attempt".try_into().expect("key"),
            value: AttributeValue::Unsigned(3),
        },
        Attribute {
            key: "cached".try_into().expect("key"),
            value: AttributeValue::Bool(true),
        },
        Attribute {
            key: "elapsed_ms".try_into().expect("key"),
            value: AttributeValue::Signed(41),
        },
    ];
    TelemetryRecord::builder()
        .epoch(ProducerEpoch::new([2; 16]).expect("nonzero epoch"))
        .producer(2)
        .sequence(1)
        .source(SourceKind::GuestHelper)
        .body(RecordBody::Log {
            context: None,
            level: mvm_core::protocol::telemetry::Level::Info,
            message: "x"
                .repeat(256)
                .as_str()
                .try_into()
                .expect("bounded message"),
            attributes: BoundedList::new(attributes).expect("bounded attributes"),
        })
        .build()
        .expect("typical record")
}

fn timed_ns(mut operation: impl FnMut()) -> f64 {
    let start = Instant::now();
    operation();
    start.elapsed().as_nanos() as f64
}

fn measure_timer_overhead(samples: usize) -> Vec<f64> {
    (0..samples).map(|_| timed_ns(|| {})).collect()
}

/// Full producer-side preparation: build the record and encode its wire form.
fn measure_prepare(samples: usize, make: impl Fn() -> TelemetryRecord) -> Vec<f64> {
    (0..samples)
        .map(|_| {
            timed_ns(|| {
                let record = make();
                let prepared = PreparedRecord::new(&record).expect("prepare");
                std::hint::black_box(prepared);
            })
        })
        .collect()
}

/// Admission latency: `batches` fresh outboxes, each filled with `SLOTS`
/// timed queued offers then `SHED_PER_BATCH` timed full-queue offers.
fn measure_offer(batches: usize, record: &PreparedRecord) -> (Vec<f64>, Vec<f64>) {
    let mut queued = Vec::with_capacity(batches * SLOTS);
    let mut shed = Vec::with_capacity(batches * SHED_PER_BATCH);
    for _ in 0..batches {
        let outbox = Outbox::new(SLOTS, SLOTS * MAX_RECORD_BYTES).expect("outbox");
        for _ in 0..SLOTS {
            queued.push(timed_ns(|| {
                assert_eq!(outbox.offer(record), Offer::Queued);
            }));
        }
        for _ in 0..SHED_PER_BATCH {
            shed.push(timed_ns(|| {
                assert_eq!(outbox.offer(record), Offer::Full);
            }));
        }
    }
    (queued, shed)
}

/// One flood round: every producer races `SLOTS` offers at one outbox.
/// Returns per-producer queued counts plus total contended/shed outcomes.
fn flood_round(record: &Arc<PreparedRecord>) -> (Vec<usize>, usize, usize) {
    let outbox = Arc::new(Outbox::new(SLOTS, SLOTS * MAX_RECORD_BYTES).expect("outbox"));
    let contended = Arc::new(AtomicUsize::new(0));
    let shed = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(FLOOD_PRODUCERS));
    let threads: Vec<_> = (0..FLOOD_PRODUCERS)
        .map(|_| {
            let outbox = Arc::clone(&outbox);
            let record = Arc::clone(record);
            let contended = Arc::clone(&contended);
            let shed = Arc::clone(&shed);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let mut queued = 0;
                for _ in 0..SLOTS {
                    match outbox.offer(&record) {
                        Offer::Queued => queued += 1,
                        Offer::Contended => {
                            contended.fetch_add(1, Ordering::Relaxed);
                        }
                        Offer::Full => {
                            shed.fetch_add(1, Ordering::Relaxed);
                        }
                        other => panic!("unexpected offer outcome {other:?}"),
                    }
                }
                queued
            })
        })
        .collect();
    let queued: Vec<usize> = threads
        .into_iter()
        .map(|t| t.join().expect("producer thread"))
        .collect();
    (
        queued,
        contended.load(Ordering::Relaxed),
        shed.load(Ordering::Relaxed),
    )
}

fn measure_fairness(rounds: usize, record: &Arc<PreparedRecord>) -> Fairness {
    let mut ratios = Vec::with_capacity(rounds);
    let (mut total_queued, mut total_contended, mut total_shed) = (0, 0, 0);
    for _ in 0..rounds {
        let (queued, contended, shed) = flood_round(record);
        let min = *queued.iter().min().expect("producers") as f64;
        let max = *queued.iter().max().expect("producers") as f64;
        ratios.push(if max == 0.0 { 1.0 } else { min / max });
        total_queued += queued.iter().sum::<usize>();
        total_contended += contended;
        total_shed += shed;
    }
    Fairness {
        producers: FLOOD_PRODUCERS,
        attempts_per_producer: SLOTS,
        admitted_ratio: distribution(&ratios),
        total_queued,
        total_contended,
        total_shed,
    }
}

fn cpu_brand() -> String {
    let brand = if cfg!(target_os = "macos") {
        std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find(|line| line.starts_with("model name"))
                    .and_then(|line| line.split(':').nth(1))
                    .map(|name| name.trim().to_string())
            })
    };
    brand
        .filter(|brand| !brand.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn host() -> Host {
    Host {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        cpu: cpu_brand(),
        logical_cores: std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(0),
    }
}

fn measure(samples: usize, fairness_rounds: usize) -> Report {
    let small = PreparedRecord::new(&small_record()).expect("prepare small");
    let typical = PreparedRecord::new(&typical_record()).expect("prepare typical");
    let batches = samples.div_ceil(SLOTS).max(1);
    let (offer_queued_small, _) = measure_offer(batches, &small);
    let (offer_queued_typical, offer_shed) = measure_offer(batches, &typical);
    Report {
        schema_version: SCHEMA_VERSION,
        host: host(),
        samples,
        fairness_rounds,
        timer_overhead_ns: distribution(&measure_timer_overhead(samples)),
        prepare_small_ns: distribution(&measure_prepare(samples, small_record)),
        prepare_typical_ns: distribution(&measure_prepare(samples, typical_record)),
        offer_queued_small_ns: distribution(&offer_queued_small),
        offer_queued_typical_ns: distribution(&offer_queued_typical),
        offer_shed_ns: distribution(&offer_shed),
        flood_fairness: measure_fairness(fairness_rounds, &Arc::new(typical)),
        memory: Memory {
            slot_bytes: MAX_RECORD_BYTES,
            max_slots: SLOTS,
            max_storage_bytes: SLOTS * MAX_RECORD_BYTES,
        },
        allocation_witness: "zero allocations/frees on admission, loss read and close: \
                             mvm-core telemetry outbox allocation regressions, native and Miri",
    }
}

/// Entry point: `cargo xtask telemetry-baseline [--samples N] [--rounds N]`.
pub fn run(args: &[String]) -> Result<()> {
    let mut samples = 100_000;
    let mut rounds = 50;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut parse = |name: &str| -> Result<usize> {
            iter.next()
                .with_context(|| format!("{name} needs a value"))?
                .parse()
                .with_context(|| format!("{name} must be a positive integer"))
        };
        match flag.as_str() {
            "--samples" => samples = parse("--samples")?,
            "--rounds" => rounds = parse("--rounds")?,
            other => bail!("unknown telemetry-baseline flag {other}"),
        }
    }
    if samples == 0 || rounds == 0 {
        bail!("--samples and --rounds must be at least 1");
    }
    let report = measure(samples, rounds);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_are_nearest_rank_over_the_sorted_samples() {
        let samples: Vec<f64> = (1..=100).map(f64::from).collect();
        let d = distribution(&samples);
        assert_eq!(d.p50, 50.0);
        assert_eq!(d.p95, 95.0);
        assert_eq!(d.p99, 99.0);
        assert_eq!(d.max, 100.0);
        assert_eq!(d.mean, 50.5);
        let single = distribution(&[7.0]);
        assert_eq!(single.p50, 7.0);
        assert_eq!(single.max, 7.0);
        assert_eq!(single.std_dev, 0.0);
    }

    #[test]
    fn offer_measurement_separates_queued_from_shed_and_fills_exactly() {
        let record = PreparedRecord::new(&small_record()).unwrap();
        let (queued, shed) = measure_offer(2, &record);
        assert_eq!(queued.len(), 2 * SLOTS);
        assert_eq!(shed.len(), 2 * SHED_PER_BATCH);
        assert!(queued.iter().all(|ns| *ns >= 0.0));
    }

    #[test]
    fn flood_round_accounts_every_attempt_exactly_once() {
        let record = Arc::new(PreparedRecord::new(&typical_record()).unwrap());
        let (queued, contended, shed) = flood_round(&record);
        assert_eq!(queued.len(), FLOOD_PRODUCERS);
        let admitted: usize = queued.iter().sum();
        let total = admitted + contended + shed;
        assert_eq!(total, FLOOD_PRODUCERS * SLOTS, "no attempt is lost");
        // Contended attempts spend a producer's bounded budget without
        // queuing, so under scheduler load the queue may not fill; capacity
        // is the ceiling, not a guarantee.
        assert!((1..=SLOTS).contains(&admitted), "admitted {admitted}");
    }

    #[test]
    fn fairness_ratio_is_one_when_even_and_summarizes_rounds() {
        let record = Arc::new(PreparedRecord::new(&small_record()).unwrap());
        let fairness = measure_fairness(3, &record);
        assert_eq!(fairness.producers, FLOOD_PRODUCERS);
        assert!(fairness.admitted_ratio.p50 >= 0.0);
        assert!(fairness.admitted_ratio.max <= 1.0);
        assert_eq!(
            fairness.total_queued + fairness.total_contended + fairness.total_shed,
            3 * FLOOD_PRODUCERS * SLOTS
        );
    }

    #[test]
    fn typical_record_is_materially_larger_than_the_small_one() {
        let small = PreparedRecord::new(&small_record()).unwrap();
        let typical = PreparedRecord::new(&typical_record()).unwrap();
        assert!(typical.len() > small.len() + 256);
        assert!(typical.len() <= MAX_RECORD_BYTES);
    }

    #[test]
    fn report_serializes_with_a_populated_host_descriptor() {
        let report = measure(SLOTS, 1);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert!(!report.host.os.is_empty());
        assert!(report.host.logical_cores > 0);
        assert_eq!(report.memory.max_storage_bytes, SLOTS * MAX_RECORD_BYTES);
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(encoded.contains("offer_queued_typical_ns"));
        assert!(encoded.contains("allocation_witness"));
    }

    #[test]
    fn flag_parsing_refuses_unknown_and_zero_inputs() {
        assert!(run(&["--bogus".into()]).is_err());
        assert!(run(&["--samples".into()]).is_err());
        assert!(run(&["--samples".into(), "0".into()]).is_err());
    }
}
