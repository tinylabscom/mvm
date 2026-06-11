//! Auditing-grade metering API.
//!
//! mvm/mvmd is multi-tenant; downstream operators want to attribute
//! resource consumption per-tenant for cost or capacity planning.
//! The motivating requirement is **metering for auditing**, not
//! pricing. The data must be tamper-evident:
//! signed and chained into the audit log so a host operator cannot
//! retroactively delete or modify resource consumption records.
//!
//! This module provides the data shapes only — no sampling daemon,
//! no exporter wiring. Producers (the supervisor's instance sampler,
//! when it lands) emit `MeteringSample`s; consumers aggregate them
//! into per-minute `MeteringBucket`s and chain each bucket into the
//! audit log via the existing `LocalAuditKind::MeteringEpoch`
//! variant. JSONL serialization helpers are included for the
//! per-tenant rollup file at `~/.mvm/metering/<tenant>/<date>.jsonl`.
//!
//! # Three-axis decomposition
//!
//! Established sandbox-runtime platforms typically decompose their
//! metering on three axes — CPU, memory, and storage. This mirrors
//! that, with a cold/hot storage split that aligns with the dm-thin
//! pool layout:
//!
//! - `cpu_ns` — CPU nanoseconds.
//! - `mem_byte_seconds` — Memory bytes × seconds resident.
//! - `storage_byte_seconds_cold` — Pool-backed storage (spilled).
//! - `storage_byte_seconds_hot` — NVMe-resident pages.
//!
//! Pricing is **out of scope**. Downstream systems (mvmd? a separate
//! billing service?) apply prices to these raw resource-time values.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::SystemTime;

/// One metering sample for one instance at one tick. Producers emit
/// these at the supervisor's existing tick (≥1 Hz, jittered) when
/// the sampler integration lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeteringSample {
    pub instance_id: String,
    pub tenant_id: String,
    /// Tag values inherited from `InstanceState::tags`.
    /// Empty map for un-tagged instances. Roll-up keying uses the
    /// full tag set so per-(tenant, tag-set) attribution works.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    /// Sample timestamp. Producer-supplied so backfill from logged
    /// metrics is consistent with realtime sampling.
    pub ts: SystemTime,
    /// CPU nanoseconds since the previous sample (delta, not cumulative).
    pub cpu_ns: u64,
    /// Memory byte-seconds since the previous sample.
    pub mem_byte_seconds: u64,
    /// Pool-backed storage byte-seconds (cold tier).
    pub storage_byte_seconds_cold: u64,
    /// NVMe-resident storage byte-seconds (hot tier).
    pub storage_byte_seconds_hot: u64,
}

/// Per-minute aggregation. Each bucket sums samples in
/// `[bucket_start, bucket_start + 60s)` for one
/// `(tenant_id, instance_id, tags)` triple. Buckets are signed and
/// chained into the audit log via `LocalAuditKind::MeteringEpoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeteringBucket {
    pub tenant_id: String,
    pub instance_id: String,
    /// Tag set captured at bucket open time. Tag changes mid-bucket
    /// open a new bucket; never aggregated across tag deltas.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    /// Inclusive start of the bucket. Aligned to clock minute by
    /// the aggregator.
    pub bucket_start: SystemTime,
    /// Bucket width in seconds. Default 60. Configurable in case a
    /// finer granularity is needed for sub-minute accuracy.
    pub bucket_secs: u64,
    pub cpu_ns: u64,
    pub mem_byte_seconds: u64,
    pub storage_byte_seconds_cold: u64,
    pub storage_byte_seconds_hot: u64,
    /// Number of samples summed into this bucket. Useful for the
    /// reaper to detect under-sampled buckets.
    pub sample_count: u32,
}

impl MeteringBucket {
    /// Aggregate consecutive samples for one
    /// `(tenant_id, instance_id, tags)` triple into per-minute
    /// buckets. Samples must already be sorted by `ts` ascending;
    /// callers typically batch by reading from the supervisor's
    /// per-tick emission queue.
    ///
    /// Returns one bucket per minute that contained at least one
    /// sample. Empty minutes produce no bucket — the reaper detects
    /// gaps via missing audit entries.
    pub fn aggregate(samples: &[MeteringSample]) -> Vec<MeteringBucket> {
        let mut out: Vec<MeteringBucket> = Vec::new();
        for s in samples {
            let bucket_start = align_to_minute(s.ts);
            let key = (
                s.tenant_id.as_str(),
                s.instance_id.as_str(),
                &s.tags,
                bucket_start,
            );
            if let Some(last) = out.last_mut()
                && (
                    last.tenant_id.as_str(),
                    last.instance_id.as_str(),
                    &last.tags,
                    last.bucket_start,
                ) == key
            {
                last.cpu_ns = last.cpu_ns.saturating_add(s.cpu_ns);
                last.mem_byte_seconds = last.mem_byte_seconds.saturating_add(s.mem_byte_seconds);
                last.storage_byte_seconds_cold = last
                    .storage_byte_seconds_cold
                    .saturating_add(s.storage_byte_seconds_cold);
                last.storage_byte_seconds_hot = last
                    .storage_byte_seconds_hot
                    .saturating_add(s.storage_byte_seconds_hot);
                last.sample_count = last.sample_count.saturating_add(1);
            } else {
                out.push(MeteringBucket {
                    tenant_id: s.tenant_id.clone(),
                    instance_id: s.instance_id.clone(),
                    tags: s.tags.clone(),
                    bucket_start,
                    bucket_secs: 60,
                    cpu_ns: s.cpu_ns,
                    mem_byte_seconds: s.mem_byte_seconds,
                    storage_byte_seconds_cold: s.storage_byte_seconds_cold,
                    storage_byte_seconds_hot: s.storage_byte_seconds_hot,
                    sample_count: 1,
                });
            }
        }
        out
    }

    /// Serialize this bucket as a single JSONL line (no trailing
    /// newline). Caller appends `\n` when writing to the rollup file.
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Round `ts` down to the nearest UTC minute boundary.
fn align_to_minute(ts: SystemTime) -> SystemTime {
    let secs = ts
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let aligned = secs - (secs % 60);
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(aligned)
}

/// Format a slice of buckets as Prometheus exposition. One gauge per
/// resource axis, labeled by tenant + instance + tag keys. Caller
/// hooks the returned string into the supervisor's metrics endpoint.
pub fn to_prometheus(buckets: &[MeteringBucket]) -> String {
    let mut out = String::new();
    out.push_str("# HELP mvm_metering_cpu_ns Cumulative CPU nanoseconds per bucket.\n");
    out.push_str("# TYPE mvm_metering_cpu_ns counter\n");
    for b in buckets {
        out.push_str(&format!(
            "mvm_metering_cpu_ns{} {}\n",
            prom_labels(b),
            b.cpu_ns
        ));
    }
    out.push_str("# HELP mvm_metering_mem_byte_seconds Memory byte-seconds per bucket.\n");
    out.push_str("# TYPE mvm_metering_mem_byte_seconds counter\n");
    for b in buckets {
        out.push_str(&format!(
            "mvm_metering_mem_byte_seconds{} {}\n",
            prom_labels(b),
            b.mem_byte_seconds
        ));
    }
    out.push_str("# HELP mvm_metering_storage_byte_seconds Storage byte-seconds per bucket.\n");
    out.push_str("# TYPE mvm_metering_storage_byte_seconds counter\n");
    for b in buckets {
        out.push_str(&format!(
            "mvm_metering_storage_byte_seconds{} {}\n",
            prom_labels_with_tier(b, "cold"),
            b.storage_byte_seconds_cold
        ));
        out.push_str(&format!(
            "mvm_metering_storage_byte_seconds{} {}\n",
            prom_labels_with_tier(b, "hot"),
            b.storage_byte_seconds_hot
        ));
    }
    out
}

fn prom_labels(b: &MeteringBucket) -> String {
    let mut parts: Vec<String> = vec![
        format!("tenant=\"{}\"", escape_label(&b.tenant_id)),
        format!("instance=\"{}\"", escape_label(&b.instance_id)),
    ];
    for (k, v) in &b.tags {
        parts.push(format!(
            "tag_{}=\"{}\"",
            escape_label_key(k),
            escape_label(v)
        ));
    }
    format!("{{{}}}", parts.join(","))
}

fn prom_labels_with_tier(b: &MeteringBucket, tier: &str) -> String {
    let base = prom_labels(b);
    // Insert tier label before closing brace.
    format!("{},tier=\"{}\"}}", &base[..base.len() - 1], tier)
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace('\n', r"\n")
}

fn escape_label_key(key: &str) -> String {
    // Prometheus label names match `[a-zA-Z_][a-zA-Z0-9_]*`. Replace
    // anything else with `_` so user-supplied tag keys are safe.
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ts(unix_secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(unix_secs)
    }

    fn sample(tenant: &str, instance: &str, ts_secs: u64, cpu_ns: u64) -> MeteringSample {
        MeteringSample {
            instance_id: instance.to_string(),
            tenant_id: tenant.to_string(),
            tags: BTreeMap::new(),
            ts: ts(ts_secs),
            cpu_ns,
            mem_byte_seconds: 1024 * 1024,
            storage_byte_seconds_cold: 0,
            storage_byte_seconds_hot: 0,
        }
    }

    #[test]
    fn aggregate_single_sample_makes_one_bucket() {
        let buckets = MeteringBucket::aggregate(&[sample("acme", "i-1", 0, 100)]);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].cpu_ns, 100);
        assert_eq!(buckets[0].sample_count, 1);
        assert_eq!(buckets[0].bucket_start, ts(0));
        assert_eq!(buckets[0].bucket_secs, 60);
    }

    #[test]
    fn aggregate_sums_within_minute() {
        let samples = vec![
            sample("acme", "i-1", 0, 100),
            sample("acme", "i-1", 30, 200),
            sample("acme", "i-1", 59, 50),
        ];
        let buckets = MeteringBucket::aggregate(&samples);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].cpu_ns, 350);
        assert_eq!(buckets[0].sample_count, 3);
    }

    #[test]
    fn aggregate_splits_across_minute_boundaries() {
        let samples = vec![
            sample("acme", "i-1", 0, 100),
            sample("acme", "i-1", 60, 200),
            sample("acme", "i-1", 120, 300),
        ];
        let buckets = MeteringBucket::aggregate(&samples);
        assert_eq!(buckets.len(), 3);
        assert_eq!(buckets[0].bucket_start, ts(0));
        assert_eq!(buckets[1].bucket_start, ts(60));
        assert_eq!(buckets[2].bucket_start, ts(120));
    }

    #[test]
    fn aggregate_separates_by_instance() {
        let samples = vec![sample("acme", "i-1", 0, 100), sample("acme", "i-2", 0, 200)];
        let buckets = MeteringBucket::aggregate(&samples);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].instance_id, "i-1");
        assert_eq!(buckets[1].instance_id, "i-2");
    }

    #[test]
    fn aggregate_separates_by_tenant() {
        let samples = vec![
            sample("acme", "i-1", 0, 100),
            sample("globex", "i-1", 0, 200),
        ];
        let buckets = MeteringBucket::aggregate(&samples);
        assert_eq!(buckets.len(), 2);
    }

    #[test]
    fn aggregate_separates_by_tags() {
        let mut a = sample("acme", "i-1", 0, 100);
        a.tags.insert("env".to_string(), "prod".to_string());
        let mut b = sample("acme", "i-1", 30, 200);
        b.tags.insert("env".to_string(), "dev".to_string());
        let buckets = MeteringBucket::aggregate(&[a, b]);
        assert_eq!(buckets.len(), 2);
    }

    #[test]
    fn aligns_timestamp_to_minute() {
        assert_eq!(align_to_minute(ts(0)), ts(0));
        assert_eq!(align_to_minute(ts(59)), ts(0));
        assert_eq!(align_to_minute(ts(60)), ts(60));
        assert_eq!(align_to_minute(ts(119)), ts(60));
        assert_eq!(align_to_minute(ts(3661)), ts(3660));
    }

    #[test]
    fn jsonl_round_trips() {
        let buckets = MeteringBucket::aggregate(&[sample("acme", "i-1", 0, 100)]);
        let line = buckets[0].to_jsonl().unwrap();
        let decoded: MeteringBucket = serde_json::from_str(&line).unwrap();
        assert_eq!(decoded, buckets[0]);
    }

    #[test]
    fn prometheus_exposition_includes_all_three_axes() {
        let mut s = sample("acme", "i-1", 0, 100);
        s.storage_byte_seconds_cold = 200;
        s.storage_byte_seconds_hot = 300;
        let buckets = MeteringBucket::aggregate(&[s]);
        let text = to_prometheus(&buckets);
        assert!(text.contains("mvm_metering_cpu_ns{"));
        assert!(text.contains("mvm_metering_mem_byte_seconds{"));
        assert!(text.contains(r#"tier="cold""#));
        assert!(text.contains(r#"tier="hot""#));
        assert!(text.contains("100"));
        assert!(text.contains("200"));
        assert!(text.contains("300"));
    }

    #[test]
    fn prometheus_label_keys_sanitize_special_chars() {
        let mut s = sample("acme", "i-1", 0, 100);
        s.tags.insert("env-prod".to_string(), "us-east".to_string());
        let buckets = MeteringBucket::aggregate(&[s]);
        let text = to_prometheus(&buckets);
        // Hyphen in key replaced with underscore.
        assert!(text.contains(r#"tag_env_prod="us-east""#));
    }

    #[test]
    fn prometheus_label_values_escape_special_chars() {
        let mut s = sample("acme\\1", "i-\"1\"", 0, 100);
        s.tags.insert("k".to_string(), "v\nl".to_string());
        let buckets = MeteringBucket::aggregate(&[s]);
        let text = to_prometheus(&buckets);
        assert!(text.contains(r#"tenant="acme\\1""#));
        assert!(text.contains(r#"instance="i-\"1\"""#));
        assert!(text.contains(r#"tag_k="v\nl""#));
    }
}
