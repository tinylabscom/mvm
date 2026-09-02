//! Stable reports and comparison gates for workload-networking benchmarks.
//!
//! Backend-specific probes own traffic generation. This command validates the
//! reports they emit and compares a candidate against a baseline only when the
//! host, backend, storage, build profile, and sample matrix are identical.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Current raw-probe and report schema version.
pub const SCHEMA_VERSION: u32 = 1;
/// Minimum number of independent measurement waves at every matrix point.
pub const MIN_SAMPLES_PER_CASE: u32 = 30;
const LIVE_PROBE_ENV: &str = "MVM_NETWORK_PERF_LIVE";

pub const MAX_OPAQUE_LATENCY_RATIO: f64 = 1.05;
pub const MIN_OPAQUE_THROUGHPUT_RATIO: f64 = 0.95;
pub const MAX_PEAK_RSS_RATIO: f64 = 1.10;
pub const MAX_TRANSFORMED_HTTP_LATENCY_RATIO: f64 = 1.10;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPerfReport {
    pub schema_version: u32,
    pub implementation: Implementation,
    pub host: HostLabel,
    pub backend: String,
    pub storage: String,
    pub build: BuildLabel,
    pub matrix: SampleMatrix,
    pub cases: Vec<CaseReport>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Implementation {
    LegacyL3,
    FlowMux,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostLabel {
    pub id: String,
    pub os: String,
    pub arch: String,
    pub cpu: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildLabel {
    pub profile: String,
    pub source_commit: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SampleMatrix {
    pub payload_bytes: Vec<u64>,
    pub concurrency: Vec<u32>,
    pub samples_per_case: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaseReport {
    pub path: NetworkPath,
    pub payload_bytes: u64,
    pub concurrency: u32,
    pub samples: u32,
    pub metrics: CaseMetrics,
}

/// Raw observations emitted by a backend-specific traffic probe.
///
/// The probe owns traffic generation, but not aggregation: `xtask` computes
/// every published percentile and throughput value from these counters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPerfProbe {
    pub schema_version: u32,
    pub implementation: Implementation,
    pub host: HostLabel,
    pub backend: String,
    pub storage: String,
    pub build: BuildLabel,
    pub matrix: SampleMatrix,
    pub cases: Vec<ProbeCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeCase {
    pub path: NetworkPath,
    pub payload_bytes: u64,
    pub concurrency: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_latency_micros: Option<Vec<u64>>,
    pub request_latency_micros: Vec<u64>,
    pub elapsed_nanos: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transferred_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_operations: Option<u64>,
    pub cpu_time_nanos: u64,
    pub peak_rss_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_copied: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPath {
    OpaqueTcp,
    Udp,
    Dns,
    TransformedHttp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaseMetrics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_latency_micros: Option<LatencyDistribution>,
    pub request_latency_micros: LatencyDistribution,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throughput_bytes_per_second: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operations_per_second: Option<u64>,
    pub cpu_time_nanos: u64,
    pub peak_rss_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_copied: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LatencyDistribution {
    pub p50: u64,
    pub p95: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComparisonReport {
    pub schema_version: u32,
    pub baseline_commit: String,
    pub candidate_commit: String,
    pub passed: bool,
    pub checks: Vec<ComparisonCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComparisonCheck {
    pub path: NetworkPath,
    pub payload_bytes: u64,
    pub concurrency: u32,
    pub metric: String,
    pub baseline: u64,
    pub candidate: u64,
    pub required_ratio: f64,
    pub actual_ratio: f64,
    pub direction: ThresholdDirection,
    pub passed: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdDirection {
    AtMost,
    AtLeast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CaseKey {
    path: NetworkPath,
    payload_bytes: u64,
    concurrency: u32,
}

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("validate") => {
            let report = read_report(&required_path(args, "--report")?)?;
            report.validate()?;
            println!("network performance report is valid");
            Ok(())
        }
        Some("compare") => {
            let baseline = read_report(&required_path(args, "--baseline")?)?;
            let candidate = read_report(&required_path(args, "--candidate")?)?;
            let comparison = compare(&baseline, &candidate)?;
            let encoded = serde_json::to_string_pretty(&comparison)?;
            if let Some(output) = optional_path(args, "--output")? {
                write_report(&output, &encoded)?;
            } else {
                println!("{encoded}");
            }
            if comparison.passed {
                Ok(())
            } else {
                bail!("network performance comparison exceeded one or more thresholds")
            }
        }
        Some("thresholds") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "opaque_latency_max_ratio": MAX_OPAQUE_LATENCY_RATIO,
                    "opaque_throughput_min_ratio": MIN_OPAQUE_THROUGHPUT_RATIO,
                    "peak_rss_max_ratio": MAX_PEAK_RSS_RATIO,
                    "transformed_http_latency_max_ratio": MAX_TRANSFORMED_HTTP_LATENCY_RATIO,
                    "minimum_samples_per_case": MIN_SAMPLES_PER_CASE,
                }))?
            );
            Ok(())
        }
        Some("run-probe") => run_probe(args),
        Some(other) => bail!(
            "unknown network-perf subcommand {other:?}; available: validate, compare, run-probe, thresholds"
        ),
        None => bail!(
            "usage: cargo xtask network-perf <validate --report PATH | compare --baseline PATH --candidate PATH [--output PATH] | run-probe --backend NAME --output PATH -- PROGRAM [ARG ...] | thresholds>"
        ),
    }
}

fn run_probe(args: &[String]) -> Result<()> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .context("run-probe requires `-- PROGRAM [ARG ...]`")?;
    let harness_args = &args[..separator];
    let backend = required_value(harness_args, "--backend")?;
    let output = required_path(harness_args, "--output")?;
    require_live_opt_in(&backend)?;
    let program = args
        .get(separator + 1)
        .context("run-probe requires a program after `--`")?;
    let result = Command::new(program)
        .args(&args[separator + 2..])
        .env("MVM_NETWORK_PERF_BACKEND", &backend)
        .env("MVM_NETWORK_PERF_SAMPLES", MIN_SAMPLES_PER_CASE.to_string())
        .output()
        .with_context(|| format!("run network performance probe {program}"))?;
    if !result.status.success() {
        bail!(
            "network performance probe exited with status {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    let probe: NetworkPerfProbe = serde_json::from_slice(&result.stdout)
        .context("parse raw network performance probe stdout as JSON")?;
    let report = probe.into_report()?;
    report.validate()?;
    if report.backend != backend {
        bail!(
            "probe reported backend {:?}, but the harness requested {:?}",
            report.backend,
            backend
        );
    }
    write_report(&output, &serde_json::to_string_pretty(&report)?)
}

impl NetworkPerfProbe {
    fn into_report(self) -> Result<NetworkPerfReport> {
        let NetworkPerfProbe {
            schema_version,
            implementation,
            host,
            backend,
            storage,
            build,
            matrix,
            cases,
        } = self;
        let cases = cases
            .into_iter()
            .map(|case| case.aggregate(&matrix))
            .collect::<Result<Vec<_>>>()?;
        let report = NetworkPerfReport {
            schema_version,
            implementation,
            host,
            backend,
            storage,
            build,
            matrix,
            cases,
        };
        report.validate()?;
        Ok(report)
    }
}

impl ProbeCase {
    fn aggregate(self, matrix: &SampleMatrix) -> Result<CaseReport> {
        let observations = usize::try_from(matrix.samples_per_case)
            .ok()
            .and_then(|samples| {
                usize::try_from(self.concurrency)
                    .ok()
                    .and_then(|concurrency| samples.checked_mul(concurrency))
            })
            .context("case observation count does not fit this host")?;
        validate_samples("request", &self.request_latency_micros, observations)?;
        let connect_latency_micros = match (self.path, self.connect_latency_micros) {
            (NetworkPath::OpaqueTcp | NetworkPath::TransformedHttp, Some(samples)) => {
                validate_samples("connect", &samples, observations)?;
                Some(distribution(samples))
            }
            (NetworkPath::OpaqueTcp | NetworkPath::TransformedHttp, None) => {
                bail!("{:?} raw probe requires connect samples", self.path)
            }
            (NetworkPath::Udp | NetworkPath::Dns, Some(_)) => {
                bail!("{:?} raw probe must not report connect samples", self.path)
            }
            (NetworkPath::Udp | NetworkPath::Dns, None) => None,
        };
        if self.elapsed_nanos == 0 {
            bail!("raw probe elapsed time must be positive");
        }
        let (throughput_bytes_per_second, operations_per_second) = match self.path {
            NetworkPath::OpaqueTcp | NetworkPath::Udp | NetworkPath::TransformedHttp => {
                if self.completed_operations.is_some() {
                    bail!("byte-oriented raw probe must not report completed_operations");
                }
                (
                    Some(rate_per_second(
                        self.transferred_bytes
                            .context("byte-oriented raw probe requires transferred_bytes")?,
                        self.elapsed_nanos,
                    )?),
                    None,
                )
            }
            NetworkPath::Dns => {
                if self.transferred_bytes.is_some() {
                    bail!("DNS raw probe must not report transferred_bytes");
                }
                (
                    None,
                    Some(rate_per_second(
                        self.completed_operations
                            .context("DNS raw probe requires completed_operations")?,
                        self.elapsed_nanos,
                    )?),
                )
            }
        };
        Ok(CaseReport {
            path: self.path,
            payload_bytes: self.payload_bytes,
            concurrency: self.concurrency,
            samples: matrix.samples_per_case,
            metrics: CaseMetrics {
                connect_latency_micros,
                request_latency_micros: distribution(self.request_latency_micros),
                throughput_bytes_per_second,
                operations_per_second,
                cpu_time_nanos: self.cpu_time_nanos,
                peak_rss_bytes: self.peak_rss_bytes,
                bytes_copied: self.bytes_copied,
            },
        })
    }
}

fn validate_samples(label: &str, samples: &[u64], expected: usize) -> Result<()> {
    if samples.len() != expected {
        bail!(
            "raw {label} sample count is {}; expected {expected}",
            samples.len()
        );
    }
    if samples.contains(&0) {
        bail!("raw {label} samples must be positive");
    }
    Ok(())
}

fn distribution(mut samples: Vec<u64>) -> LatencyDistribution {
    samples.sort_unstable();
    LatencyDistribution {
        p50: nearest_rank(&samples, 50),
        p95: nearest_rank(&samples, 95),
    }
}

fn nearest_rank(samples: &[u64], percentile: usize) -> u64 {
    let rank = samples
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1);
    samples[rank]
}

fn rate_per_second(count: u64, elapsed_nanos: u64) -> Result<u64> {
    if count == 0 {
        bail!("raw throughput counter must be positive");
    }
    let scaled = u128::from(count)
        .checked_mul(1_000_000_000)
        .context("raw throughput counter overflow")?
        / u128::from(elapsed_nanos);
    let rate = u64::try_from(scaled).context("computed throughput does not fit u64")?;
    if rate == 0 {
        bail!("computed throughput rounded to zero");
    }
    Ok(rate)
}

fn require_live_opt_in(backend: &str) -> Result<()> {
    if backend == "host-loopback" {
        return Ok(());
    }
    if std::env::var(LIVE_PROBE_ENV).as_deref() == Ok("1") {
        return Ok(());
    }
    bail!(
        "backend {backend:?} is a live probe; set {LIVE_PROBE_ENV}=1 explicitly after entering its required host environment"
    )
}

impl NetworkPerfReport {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!(
                "unsupported network performance schema {}; expected {SCHEMA_VERSION}",
                self.schema_version
            );
        }
        validate_label("host.id", &self.host.id)?;
        validate_label("host.os", &self.host.os)?;
        validate_label("host.arch", &self.host.arch)?;
        validate_label("host.cpu", &self.host.cpu)?;
        validate_label("backend", &self.backend)?;
        validate_label("storage", &self.storage)?;
        validate_label("build.profile", &self.build.profile)?;
        validate_label("build.source_commit", &self.build.source_commit)?;
        validate_label("build.command", &self.build.command)?;
        if self.build.profile != "release" {
            bail!("network performance reports must use the release build profile");
        }
        if self.matrix.samples_per_case < MIN_SAMPLES_PER_CASE {
            bail!("sample matrix requires at least {MIN_SAMPLES_PER_CASE} samples per case");
        }
        if self.matrix.payload_bytes.is_empty() || self.matrix.concurrency.is_empty() {
            bail!("sample matrix payload and concurrency axes must be non-empty");
        }
        if self.matrix.payload_bytes.contains(&0) || self.matrix.concurrency.contains(&0) {
            bail!("sample matrix payload and concurrency values must be positive");
        }
        ensure_unique("payload", &self.matrix.payload_bytes)?;
        ensure_unique("concurrency", &self.matrix.concurrency)?;

        let indexed = self.indexed_cases()?;
        let expected = self
            .matrix
            .payload_bytes
            .len()
            .checked_mul(self.matrix.concurrency.len())
            .and_then(|n| n.checked_mul(4))
            .context("network performance matrix size overflow")?;
        if indexed.len() != expected {
            bail!(
                "network performance matrix has {} cases; expected {expected}",
                indexed.len()
            );
        }
        for payload_bytes in &self.matrix.payload_bytes {
            for concurrency in &self.matrix.concurrency {
                for path in [
                    NetworkPath::OpaqueTcp,
                    NetworkPath::Udp,
                    NetworkPath::Dns,
                    NetworkPath::TransformedHttp,
                ] {
                    let key = CaseKey {
                        path,
                        payload_bytes: *payload_bytes,
                        concurrency: *concurrency,
                    };
                    if !indexed.contains_key(&key) {
                        bail!(
                            "missing {path:?} case for payload {payload_bytes} and concurrency {concurrency}"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn indexed_cases(&self) -> Result<BTreeMap<CaseKey, &CaseReport>> {
        let mut indexed = BTreeMap::new();
        for case in &self.cases {
            case.validate(&self.matrix)?;
            let key = CaseKey {
                path: case.path,
                payload_bytes: case.payload_bytes,
                concurrency: case.concurrency,
            };
            if indexed.insert(key, case).is_some() {
                bail!(
                    "duplicate {:?} case for payload {} and concurrency {}",
                    case.path,
                    case.payload_bytes,
                    case.concurrency
                );
            }
        }
        Ok(indexed)
    }
}

impl CaseReport {
    fn validate(&self, matrix: &SampleMatrix) -> Result<()> {
        if !matrix.payload_bytes.contains(&self.payload_bytes)
            || !matrix.concurrency.contains(&self.concurrency)
        {
            bail!("case coordinates are outside the declared sample matrix");
        }
        if self.samples != matrix.samples_per_case {
            bail!(
                "case {:?} has {} samples; expected exactly {}",
                self.path,
                self.samples,
                matrix.samples_per_case
            );
        }
        self.metrics.request_latency_micros.validate("request")?;
        if let Some(connect) = self.metrics.connect_latency_micros {
            connect.validate("connect")?;
        }
        if (self.path == NetworkPath::OpaqueTcp || self.path == NetworkPath::TransformedHttp)
            && self.metrics.connect_latency_micros.is_none()
        {
            bail!("{:?} requires connect latency", self.path);
        }
        match self.path {
            NetworkPath::OpaqueTcp | NetworkPath::Udp | NetworkPath::TransformedHttp => {
                if !matches!(self.metrics.throughput_bytes_per_second, Some(value) if value > 0) {
                    bail!("{:?} requires byte throughput", self.path);
                }
            }
            NetworkPath::Dns => {
                if !matches!(self.metrics.operations_per_second, Some(value) if value > 0) {
                    bail!("DNS requires operations-per-second throughput");
                }
            }
        }
        if self.metrics.cpu_time_nanos == 0 || self.metrics.peak_rss_bytes == 0 {
            bail!("CPU time and peak RSS measurements must be positive");
        }
        Ok(())
    }
}

impl LatencyDistribution {
    fn validate(self, label: &str) -> Result<()> {
        if self.p50 == 0 || self.p95 == 0 || self.p50 > self.p95 {
            bail!("{label} latency must satisfy 0 < p50 <= p95");
        }
        Ok(())
    }
}

pub fn compare(
    baseline: &NetworkPerfReport,
    candidate: &NetworkPerfReport,
) -> Result<ComparisonReport> {
    baseline.validate().context("baseline report")?;
    candidate.validate().context("candidate report")?;
    if baseline.implementation != Implementation::LegacyL3 {
        bail!("baseline implementation must be legacy_l3");
    }
    if candidate.implementation != Implementation::FlowMux {
        bail!("candidate implementation must be flow_mux");
    }
    comparable_labels(baseline, candidate)?;

    let baseline_cases = baseline.indexed_cases()?;
    let candidate_cases = candidate.indexed_cases()?;
    let mut checks = Vec::new();
    for (key, baseline_case) in baseline_cases {
        let candidate_case = candidate_cases
            .get(&key)
            .context("candidate matrix lost a validated baseline case")?;
        checks.push(at_most(
            key,
            "peak_rss_bytes",
            baseline_case.metrics.peak_rss_bytes,
            candidate_case.metrics.peak_rss_bytes,
            MAX_PEAK_RSS_RATIO,
        ));

        match key.path {
            NetworkPath::OpaqueTcp => {
                let baseline_connect = baseline_case
                    .metrics
                    .connect_latency_micros
                    .context("validated TCP baseline connect latency")?;
                let candidate_connect = candidate_case
                    .metrics
                    .connect_latency_micros
                    .context("validated TCP candidate connect latency")?;
                latency_checks(
                    &mut checks,
                    key,
                    "connect_latency_micros",
                    baseline_connect,
                    candidate_connect,
                    MAX_OPAQUE_LATENCY_RATIO,
                );
                latency_checks(
                    &mut checks,
                    key,
                    "request_latency_micros",
                    baseline_case.metrics.request_latency_micros,
                    candidate_case.metrics.request_latency_micros,
                    MAX_OPAQUE_LATENCY_RATIO,
                );
                throughput_check(&mut checks, key, baseline_case, candidate_case)?;
            }
            NetworkPath::Udp => {
                latency_checks(
                    &mut checks,
                    key,
                    "request_latency_micros",
                    baseline_case.metrics.request_latency_micros,
                    candidate_case.metrics.request_latency_micros,
                    MAX_OPAQUE_LATENCY_RATIO,
                );
                throughput_check(&mut checks, key, baseline_case, candidate_case)?;
            }
            NetworkPath::TransformedHttp => {
                let baseline_connect = baseline_case
                    .metrics
                    .connect_latency_micros
                    .context("validated HTTP baseline connect latency")?;
                let candidate_connect = candidate_case
                    .metrics
                    .connect_latency_micros
                    .context("validated HTTP candidate connect latency")?;
                latency_checks(
                    &mut checks,
                    key,
                    "connect_latency_micros",
                    baseline_connect,
                    candidate_connect,
                    MAX_TRANSFORMED_HTTP_LATENCY_RATIO,
                );
                latency_checks(
                    &mut checks,
                    key,
                    "request_latency_micros",
                    baseline_case.metrics.request_latency_micros,
                    candidate_case.metrics.request_latency_micros,
                    MAX_TRANSFORMED_HTTP_LATENCY_RATIO,
                );
            }
            NetworkPath::Dns => {}
        }
    }
    Ok(ComparisonReport {
        schema_version: SCHEMA_VERSION,
        baseline_commit: baseline.build.source_commit.clone(),
        candidate_commit: candidate.build.source_commit.clone(),
        passed: checks.iter().all(|check| check.passed),
        checks,
    })
}

fn comparable_labels(baseline: &NetworkPerfReport, candidate: &NetworkPerfReport) -> Result<()> {
    if baseline.host != candidate.host {
        bail!("network performance reports were recorded on different hosts");
    }
    if baseline.backend != candidate.backend {
        bail!("network performance reports use different backends");
    }
    if baseline.storage != candidate.storage {
        bail!("network performance reports use different storage configurations");
    }
    if baseline.build.profile != candidate.build.profile {
        bail!("network performance reports use different build profiles");
    }
    if baseline.matrix != candidate.matrix {
        bail!("network performance reports use different sample matrices");
    }
    Ok(())
}

fn throughput_check(
    checks: &mut Vec<ComparisonCheck>,
    key: CaseKey,
    baseline: &CaseReport,
    candidate: &CaseReport,
) -> Result<()> {
    checks.push(at_least(
        key,
        "throughput_bytes_per_second",
        baseline
            .metrics
            .throughput_bytes_per_second
            .context("validated baseline throughput")?,
        candidate
            .metrics
            .throughput_bytes_per_second
            .context("validated candidate throughput")?,
        MIN_OPAQUE_THROUGHPUT_RATIO,
    ));
    Ok(())
}

fn latency_checks(
    checks: &mut Vec<ComparisonCheck>,
    key: CaseKey,
    prefix: &str,
    baseline: LatencyDistribution,
    candidate: LatencyDistribution,
    ratio: f64,
) {
    checks.push(at_most(
        key,
        &format!("{prefix}.p50"),
        baseline.p50,
        candidate.p50,
        ratio,
    ));
    checks.push(at_most(
        key,
        &format!("{prefix}.p95"),
        baseline.p95,
        candidate.p95,
        ratio,
    ));
}

fn at_most(
    key: CaseKey,
    metric: &str,
    baseline: u64,
    candidate: u64,
    required_ratio: f64,
) -> ComparisonCheck {
    comparison_check(
        key,
        metric,
        baseline,
        candidate,
        required_ratio,
        ThresholdDirection::AtMost,
    )
}

fn at_least(
    key: CaseKey,
    metric: &str,
    baseline: u64,
    candidate: u64,
    required_ratio: f64,
) -> ComparisonCheck {
    comparison_check(
        key,
        metric,
        baseline,
        candidate,
        required_ratio,
        ThresholdDirection::AtLeast,
    )
}

fn comparison_check(
    key: CaseKey,
    metric: &str,
    baseline: u64,
    candidate: u64,
    required_ratio: f64,
    direction: ThresholdDirection,
) -> ComparisonCheck {
    let actual_ratio = candidate as f64 / baseline as f64;
    let passed = match direction {
        ThresholdDirection::AtMost => actual_ratio <= required_ratio,
        ThresholdDirection::AtLeast => actual_ratio >= required_ratio,
    };
    ComparisonCheck {
        path: key.path,
        payload_bytes: key.payload_bytes,
        concurrency: key.concurrency,
        metric: metric.to_owned(),
        baseline,
        candidate,
        required_ratio,
        actual_ratio,
        direction,
        passed,
    }
}

fn validate_label(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(())
}

fn ensure_unique<T: Ord + Copy>(name: &str, values: &[T]) -> Result<()> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("sample matrix {name} axis contains a duplicate");
    }
    Ok(())
}

fn read_report(path: &Path) -> Result<NetworkPerfReport> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn write_report(path: &Path, encoded: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, encoded).with_context(|| format!("write {}", path.display()))
}

fn required_path(args: &[String], flag: &str) -> Result<PathBuf> {
    optional_path(args, flag)?.with_context(|| format!("{flag} is required"))
}

fn required_value(args: &[String], flag: &str) -> Result<String> {
    optional_value(args, flag)?.with_context(|| format!("{flag} is required"))
}

fn optional_path(args: &[String], flag: &str) -> Result<Option<PathBuf>> {
    Ok(optional_value(args, flag)?.map(PathBuf::from))
}

fn optional_value(args: &[String], flag: &str) -> Result<Option<String>> {
    let mut found = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            if found.is_some() {
                bail!("{flag} may only be specified once");
            }
            let value = iter
                .next()
                .with_context(|| format!("{flag} requires a path"))?;
            found = Some(value.clone());
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(implementation: Implementation) -> NetworkPerfReport {
        let matrix = SampleMatrix {
            payload_bytes: vec![1024],
            concurrency: vec![1],
            samples_per_case: 30,
        };
        let cases = [
            NetworkPath::OpaqueTcp,
            NetworkPath::Udp,
            NetworkPath::Dns,
            NetworkPath::TransformedHttp,
        ]
        .into_iter()
        .map(|path| CaseReport {
            path,
            payload_bytes: 1024,
            concurrency: 1,
            samples: 30,
            metrics: CaseMetrics {
                connect_latency_micros: matches!(
                    path,
                    NetworkPath::OpaqueTcp | NetworkPath::TransformedHttp
                )
                .then_some(LatencyDistribution { p50: 100, p95: 200 }),
                request_latency_micros: LatencyDistribution { p50: 100, p95: 200 },
                throughput_bytes_per_second: (path != NetworkPath::Dns).then_some(1_000),
                operations_per_second: (path == NetworkPath::Dns).then_some(1_000),
                cpu_time_nanos: 1_000,
                peak_rss_bytes: 10_000,
                bytes_copied: None,
            },
        })
        .collect();
        NetworkPerfReport {
            schema_version: 1,
            implementation,
            host: HostLabel {
                id: "host-a".into(),
                os: "macos".into(),
                arch: "aarch64".into(),
                cpu: "test-cpu".into(),
            },
            backend: "host-loopback".into(),
            storage: "none".into(),
            build: BuildLabel {
                profile: "release".into(),
                source_commit: "abc123".into(),
                command: "cargo test --release".into(),
            },
            matrix,
            cases,
        }
    }

    fn probe(implementation: Implementation) -> NetworkPerfProbe {
        let report = report(implementation);
        let cases = report
            .cases
            .iter()
            .map(|case| ProbeCase {
                path: case.path,
                payload_bytes: case.payload_bytes,
                concurrency: case.concurrency,
                connect_latency_micros: matches!(
                    case.path,
                    NetworkPath::OpaqueTcp | NetworkPath::TransformedHttp
                )
                .then(|| (1..=30).map(|sample| sample * 10).collect()),
                request_latency_micros: (1..=30).map(|sample| sample * 10).collect(),
                elapsed_nanos: 1_000_000_000,
                transferred_bytes: (case.path != NetworkPath::Dns).then_some(30_000),
                completed_operations: (case.path == NetworkPath::Dns).then_some(30),
                cpu_time_nanos: 1_000,
                peak_rss_bytes: 10_000,
                bytes_copied: None,
            })
            .collect();
        NetworkPerfProbe {
            schema_version: report.schema_version,
            implementation: report.implementation,
            host: report.host,
            backend: report.backend,
            storage: report.storage,
            build: report.build,
            matrix: report.matrix,
            cases,
        }
    }

    #[test]
    fn report_round_trips_and_validates() {
        let expected = report(Implementation::LegacyL3);
        expected.validate().unwrap();
        let encoded = serde_json::to_vec(&expected).unwrap();
        let decoded: NetworkPerfReport = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn raw_probe_is_aggregated_by_the_harness() {
        let report = probe(Implementation::LegacyL3).into_report().unwrap();
        let tcp = report
            .cases
            .iter()
            .find(|case| case.path == NetworkPath::OpaqueTcp)
            .unwrap();
        assert_eq!(
            tcp.metrics.request_latency_micros,
            LatencyDistribution { p50: 150, p95: 290 }
        );
        assert_eq!(tcp.metrics.throughput_bytes_per_second, Some(30_000));
        assert_eq!(tcp.samples, 30);
    }

    #[test]
    fn raw_probe_refuses_missing_observations() {
        let mut probe = probe(Implementation::FlowMux);
        probe.cases[0].request_latency_micros.pop();
        assert!(
            probe
                .into_report()
                .unwrap_err()
                .to_string()
                .contains("expected 30")
        );
    }

    #[test]
    fn validation_refuses_an_incomplete_matrix() {
        let mut incomplete = report(Implementation::LegacyL3);
        incomplete.cases.pop();
        assert!(
            incomplete
                .validate()
                .unwrap_err()
                .to_string()
                .contains("cases")
        );
    }

    #[test]
    fn comparison_accepts_exact_threshold_boundaries() {
        let baseline = report(Implementation::LegacyL3);
        let mut candidate = report(Implementation::FlowMux);
        candidate.build.source_commit = "def456".into();
        for case in &mut candidate.cases {
            case.metrics.peak_rss_bytes = 11_000;
            match case.path {
                NetworkPath::OpaqueTcp | NetworkPath::Udp => {
                    case.metrics.request_latency_micros =
                        LatencyDistribution { p50: 105, p95: 210 };
                    case.metrics.throughput_bytes_per_second = Some(950);
                }
                NetworkPath::TransformedHttp => {
                    case.metrics.request_latency_micros =
                        LatencyDistribution { p50: 110, p95: 220 };
                }
                NetworkPath::Dns => {}
            }
            if case.path == NetworkPath::OpaqueTcp {
                case.metrics.connect_latency_micros =
                    Some(LatencyDistribution { p50: 105, p95: 210 });
            }
        }
        let comparison = compare(&baseline, &candidate).unwrap();
        assert!(comparison.passed, "{:#?}", comparison.checks);
    }

    #[test]
    fn comparison_reports_a_threshold_failure() {
        let baseline = report(Implementation::LegacyL3);
        let mut candidate = report(Implementation::FlowMux);
        candidate
            .cases
            .iter_mut()
            .find(|case| case.path == NetworkPath::Udp)
            .unwrap()
            .metrics
            .throughput_bytes_per_second = Some(949);
        let comparison = compare(&baseline, &candidate).unwrap();
        assert!(!comparison.passed);
        assert!(comparison.checks.iter().any(|check| !check.passed));
    }

    #[test]
    fn comparison_refuses_different_hosts() {
        let baseline = report(Implementation::LegacyL3);
        let mut candidate = report(Implementation::FlowMux);
        candidate.host.id = "host-b".into();
        assert!(
            compare(&baseline, &candidate)
                .unwrap_err()
                .to_string()
                .contains("different hosts")
        );
    }

    #[test]
    fn validation_refuses_a_case_with_a_different_sample_count() {
        let mut mismatched = report(Implementation::LegacyL3);
        mismatched.cases[0].samples += 1;
        assert!(
            mismatched
                .validate()
                .unwrap_err()
                .to_string()
                .contains("expected exactly")
        );
    }

    #[test]
    fn comparison_gates_transformed_http_connect_latency() {
        let baseline = report(Implementation::LegacyL3);
        let mut candidate = report(Implementation::FlowMux);
        candidate
            .cases
            .iter_mut()
            .find(|case| case.path == NetworkPath::TransformedHttp)
            .unwrap()
            .metrics
            .connect_latency_micros = Some(LatencyDistribution { p50: 111, p95: 221 });
        let comparison = compare(&baseline, &candidate).unwrap();
        assert!(!comparison.passed);
        assert!(comparison.checks.iter().any(|check| {
            check.path == NetworkPath::TransformedHttp
                && check.metric == "connect_latency_micros.p50"
                && !check.passed
        }));
    }

    #[test]
    fn host_loopback_probe_is_hermetic_by_default() {
        require_live_opt_in("host-loopback").unwrap();
    }
}
