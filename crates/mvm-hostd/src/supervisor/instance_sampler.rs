//! Per-VM metrics sampler — A3 of the filesystem-volumes plan.
//!
//! Pulls CPU, memory, disk, and network counters for one VM and
//! pushes them into `mvm_core::observability::instance_metrics`.
//! Designed pure-logic-first behind a `Sources` trait so unit tests
//! can stub the readings without touching `/proc` or `/sys`; the
//! production `OsSources` impl reads the live host filesystem.
//!
//! The supervisor's tick loop (Wave 1.4 of plan 37) drives the
//! sampler on a 5-second cadence. Until that loop lands, callers
//! invoke `Sampler::sample_once` directly — it's idempotent and
//! safe to call from any thread.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mvm_core::observability::instance_metrics::{
    InstanceLabels, InstanceMetricsRegistry, InstanceMetricsValues,
};

/// One VM's resource readings as taken at a single instant.
/// Optional fields are `None` when the underlying source is
/// unavailable (e.g. `/sys/class/net/<tap>/...` doesn't exist on
/// macOS Lima dev hosts).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sample {
    pub cpu_user_us: Option<u64>,
    pub cpu_system_us: Option<u64>,
    pub mem_resident_bytes: Option<u64>,
    pub disk_read_bytes: Option<u64>,
    pub disk_write_bytes: Option<u64>,
    pub net_rx_bytes: Option<u64>,
    pub net_tx_bytes: Option<u64>,
    pub net_rx_packets: Option<u64>,
    pub net_tx_packets: Option<u64>,
}

/// Shape of a VM the sampler will read from. Held inside the
/// registry so a sample-loop pass can iterate without taking the
/// registry lock per VM.
#[derive(Debug, Clone)]
pub struct SampleTarget {
    pub labels: InstanceLabels,
    /// Process id of the running Firecracker VMM. Used for
    /// `/proc/<pid>/stat` (CPU + memory).
    pub vmm_pid: Option<u32>,
    /// TAP interface name, e.g. `tap-foo`. Used for
    /// `/sys/class/net/<tap>/statistics/...`.
    pub tap_iface: Option<String>,
    /// Block-device IO stat path. Optional — set when the backend
    /// exposes per-VM disk counters via a sysfs node.
    pub disk_stat_path: Option<PathBuf>,
    /// Wall-clock unix-seconds when the supervisor first saw this
    /// VM running. Used to compute `uptime_secs`.
    pub started_at_unix_secs: u64,
}

/// Trait for the per-source readings. The production impl
/// (`OsSources`) hits the live host fs; the test impl returns
/// canned values. Each method is allowed to return `None` —
/// missing sources are not an error.
pub trait Sources {
    fn read_proc_stat(&self, pid: u32) -> Sample;
    fn read_tap_stats(&self, iface: &str) -> Sample;
    fn read_disk_stats(&self, path: &std::path::Path) -> Sample;
}

/// Production `Sources` impl.
pub struct OsSources;

impl Sources for OsSources {
    fn read_proc_stat(&self, pid: u32) -> Sample {
        read_os_proc_stat(pid)
    }

    fn read_tap_stats(&self, iface: &str) -> Sample {
        read_os_tap_stats(iface)
    }

    fn read_disk_stats(&self, path: &std::path::Path) -> Sample {
        read_os_disk_stats(path)
    }
}

/// Sample one VM and push the resulting values into the registry.
/// Any `Some` field overwrites the registry's previous value;
/// `None` fields leave the previous value in place (they're
/// "couldn't read this time"). Returns `true` if the registry had
/// the VM and was updated.
pub fn sample_once<S: Sources>(
    registry: &InstanceMetricsRegistry,
    sources: &S,
    target: &SampleTarget,
) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut combined = Sample::default();
    if let Some(pid) = target.vmm_pid {
        merge(&mut combined, sources.read_proc_stat(pid));
    }
    if let Some(iface) = target.tap_iface.as_deref() {
        merge(&mut combined, sources.read_tap_stats(iface));
    }
    if let Some(path) = target.disk_stat_path.as_deref() {
        merge(&mut combined, sources.read_disk_stats(path));
    }

    // Preserve previous values where the latest reading returned
    // `None` (source temporarily unavailable). Building on the
    // last-seen values lets `mvmctl metrics --instance` always
    // produce a meaningful snapshot.
    let prev = registry
        .get(&target.labels.instance_id)
        .map(|(_, v)| v)
        .unwrap_or_default();
    let uptime_secs = now.saturating_sub(target.started_at_unix_secs);
    let values = InstanceMetricsValues {
        cpu_user_us: combined.cpu_user_us.unwrap_or(prev.cpu_user_us),
        cpu_system_us: combined.cpu_system_us.unwrap_or(prev.cpu_system_us),
        mem_resident_bytes: combined
            .mem_resident_bytes
            .unwrap_or(prev.mem_resident_bytes),
        disk_read_bytes: combined.disk_read_bytes.unwrap_or(prev.disk_read_bytes),
        disk_write_bytes: combined.disk_write_bytes.unwrap_or(prev.disk_write_bytes),
        net_rx_bytes: combined.net_rx_bytes.unwrap_or(prev.net_rx_bytes),
        net_tx_bytes: combined.net_tx_bytes.unwrap_or(prev.net_tx_bytes),
        net_rx_packets: combined.net_rx_packets.unwrap_or(prev.net_rx_packets),
        net_tx_packets: combined.net_tx_packets.unwrap_or(prev.net_tx_packets),
        uptime_secs,
        last_sample_unix_secs: now,
    };
    registry.update(&target.labels.instance_id, values)
}

fn merge(into: &mut Sample, from: Sample) {
    if from.cpu_user_us.is_some() {
        into.cpu_user_us = from.cpu_user_us;
    }
    if from.cpu_system_us.is_some() {
        into.cpu_system_us = from.cpu_system_us;
    }
    if from.mem_resident_bytes.is_some() {
        into.mem_resident_bytes = from.mem_resident_bytes;
    }
    if from.disk_read_bytes.is_some() {
        into.disk_read_bytes = from.disk_read_bytes;
    }
    if from.disk_write_bytes.is_some() {
        into.disk_write_bytes = from.disk_write_bytes;
    }
    if from.net_rx_bytes.is_some() {
        into.net_rx_bytes = from.net_rx_bytes;
    }
    if from.net_tx_bytes.is_some() {
        into.net_tx_bytes = from.net_tx_bytes;
    }
    if from.net_rx_packets.is_some() {
        into.net_rx_packets = from.net_rx_packets;
    }
    if from.net_tx_packets.is_some() {
        into.net_tx_packets = from.net_tx_packets;
    }
}

// ============================================================================
// Linux source readers
// ============================================================================

#[cfg(target_os = "linux")]
fn read_os_proc_stat(pid: u32) -> Sample {
    // /proc/<pid>/stat fields per `man proc`:
    //   utime  = field 14 (user-mode jiffies)
    //   stime  = field 15 (kernel-mode jiffies)
    //   rss    = field 24 (pages)
    // Convert jiffies → microseconds via sysconf(_SC_CLK_TCK).
    // Convert pages → bytes via sysconf(_SC_PAGESIZE).
    let stat_path = format!("/proc/{pid}/stat");
    let content = match std::fs::read_to_string(&stat_path) {
        Ok(s) => s,
        Err(_) => return Sample::default(),
    };
    // The second field is `(comm)` and may itself contain spaces —
    // skip past the trailing `)` before tokenising the rest.
    let close = match content.rfind(')') {
        Some(i) => i,
        None => return Sample::default(),
    };
    let rest = &content[close + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 22 {
        return Sample::default();
    }
    // After `)` the next field is `state`, so:
    //   fields[0] = state         → original field 3
    //   fields[11] = utime        → original field 14
    //   fields[12] = stime        → original field 15
    //   fields[21] = rss          → original field 24
    let utime: u64 = fields[11].parse().unwrap_or(0);
    let stime: u64 = fields[12].parse().unwrap_or(0);
    let rss_pages: u64 = fields[21].parse().unwrap_or(0);

    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    let to_us = |jiffies: u64| jiffies.saturating_mul(1_000_000) / clk_tck;

    Sample {
        cpu_user_us: Some(to_us(utime)),
        cpu_system_us: Some(to_us(stime)),
        mem_resident_bytes: Some(rss_pages.saturating_mul(pagesize)),
        ..Sample::default()
    }
}

#[cfg(not(target_os = "linux"))]
fn read_os_proc_stat(_pid: u32) -> Sample {
    // /proc not available on macOS dev hosts. Returning the
    // empty sample is documented as "couldn't read"; the sampler
    // preserves the previous values rather than zeroing.
    Sample::default()
}

#[cfg(target_os = "linux")]
fn read_os_tap_stats(iface: &str) -> Sample {
    fn read_u64(p: &str) -> Option<u64> {
        std::fs::read_to_string(p).ok()?.trim().parse().ok()
    }
    let base = format!("/sys/class/net/{iface}/statistics");
    Sample {
        net_rx_bytes: read_u64(&format!("{base}/rx_bytes")),
        net_tx_bytes: read_u64(&format!("{base}/tx_bytes")),
        net_rx_packets: read_u64(&format!("{base}/rx_packets")),
        net_tx_packets: read_u64(&format!("{base}/tx_packets")),
        ..Sample::default()
    }
}

#[cfg(not(target_os = "linux"))]
fn read_os_tap_stats(_iface: &str) -> Sample {
    Sample::default()
}

#[cfg(target_os = "linux")]
fn read_os_disk_stats(path: &std::path::Path) -> Sample {
    // Linux block-device `stat` file format: see `Documentation/
    // block/stat.rst`. Field 3 = sectors read; field 7 = sectors
    // written. Sector is 512 bytes by historical convention.
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Sample::default(),
    };
    let fields: Vec<&str> = content.split_whitespace().collect();
    if fields.len() < 11 {
        return Sample::default();
    }
    let sectors_read: u64 = fields[2].parse().unwrap_or(0);
    let sectors_written: u64 = fields[6].parse().unwrap_or(0);
    Sample {
        disk_read_bytes: Some(sectors_read.saturating_mul(512)),
        disk_write_bytes: Some(sectors_written.saturating_mul(512)),
        ..Sample::default()
    }
}

#[cfg(not(target_os = "linux"))]
fn read_os_disk_stats(_path: &std::path::Path) -> Sample {
    Sample::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    /// Test source that returns canned samples and counts calls
    /// per kind so tests can assert which readers fired.
    struct StubSources {
        proc: Mutex<Sample>,
        tap: Mutex<Sample>,
        disk: Mutex<Sample>,
    }

    impl StubSources {
        fn new() -> Self {
            Self {
                proc: Mutex::new(Sample::default()),
                tap: Mutex::new(Sample::default()),
                disk: Mutex::new(Sample::default()),
            }
        }
    }

    impl Sources for StubSources {
        fn read_proc_stat(&self, _pid: u32) -> Sample {
            self.proc.lock().unwrap().clone()
        }
        fn read_tap_stats(&self, _iface: &str) -> Sample {
            self.tap.lock().unwrap().clone()
        }
        fn read_disk_stats(&self, _path: &Path) -> Sample {
            self.disk.lock().unwrap().clone()
        }
    }

    fn target(id: &str) -> SampleTarget {
        SampleTarget {
            labels: InstanceLabels {
                instance_id: id.to_string(),
                tenant: "acme".to_string(),
                template: "python-3.12".to_string(),
            },
            vmm_pid: Some(123),
            tap_iface: Some("tap-foo".to_string()),
            disk_stat_path: Some(PathBuf::from("/sys/block/vda/stat")),
            started_at_unix_secs: 1_000,
        }
    }

    #[test]
    fn sample_once_returns_false_for_unknown_instance() {
        let reg = InstanceMetricsRegistry::new();
        let sources = StubSources::new();
        let t = target("ghost");
        assert!(!sample_once(&reg, &sources, &t));
    }

    #[test]
    fn sample_once_combines_sources_per_field() {
        let reg = InstanceMetricsRegistry::new();
        reg.register(target("i-1").labels);

        let sources = StubSources::new();
        *sources.proc.lock().unwrap() = Sample {
            cpu_user_us: Some(1_000_000),
            cpu_system_us: Some(500_000),
            mem_resident_bytes: Some(256 * 1024 * 1024),
            ..Sample::default()
        };
        *sources.tap.lock().unwrap() = Sample {
            net_rx_bytes: Some(2048),
            net_tx_bytes: Some(1024),
            net_rx_packets: Some(20),
            net_tx_packets: Some(10),
            ..Sample::default()
        };
        *sources.disk.lock().unwrap() = Sample {
            disk_read_bytes: Some(4096),
            disk_write_bytes: Some(8192),
            ..Sample::default()
        };

        assert!(sample_once(&reg, &sources, &target("i-1")));
        let (_, v) = reg.get("i-1").unwrap();
        assert_eq!(v.cpu_user_us, 1_000_000);
        assert_eq!(v.cpu_system_us, 500_000);
        assert_eq!(v.mem_resident_bytes, 256 * 1024 * 1024);
        assert_eq!(v.net_rx_bytes, 2048);
        assert_eq!(v.net_tx_bytes, 1024);
        assert_eq!(v.disk_read_bytes, 4096);
        assert_eq!(v.disk_write_bytes, 8192);
        assert!(v.last_sample_unix_secs > 0);
    }

    #[test]
    fn sample_once_preserves_previous_values_on_missing_source() {
        let reg = InstanceMetricsRegistry::new();
        reg.register(target("i-1").labels);

        // First sample populates everything.
        let sources = StubSources::new();
        *sources.proc.lock().unwrap() = Sample {
            cpu_user_us: Some(100),
            mem_resident_bytes: Some(1024),
            ..Sample::default()
        };
        *sources.tap.lock().unwrap() = Sample {
            net_rx_bytes: Some(50),
            ..Sample::default()
        };
        sample_once(&reg, &sources, &target("i-1"));
        let (_, after_first) = reg.get("i-1").unwrap();
        assert_eq!(after_first.cpu_user_us, 100);
        assert_eq!(after_first.net_rx_bytes, 50);

        // Second sample: tap source briefly unavailable. Net counter
        // should hold steady; cpu should advance.
        *sources.proc.lock().unwrap() = Sample {
            cpu_user_us: Some(200),
            mem_resident_bytes: Some(2048),
            ..Sample::default()
        };
        *sources.tap.lock().unwrap() = Sample::default();
        sample_once(&reg, &sources, &target("i-1"));
        let (_, after_second) = reg.get("i-1").unwrap();
        assert_eq!(after_second.cpu_user_us, 200);
        assert_eq!(after_second.mem_resident_bytes, 2048);
        assert_eq!(after_second.net_rx_bytes, 50);
    }

    #[test]
    fn sample_once_uptime_advances_with_wall_clock() {
        let reg = InstanceMetricsRegistry::new();
        let mut t = target("i-1");
        // started_at = 100s before the unix epoch — `now - started_at`
        // is an enormous positive number, so uptime_secs should be
        // very large.
        t.started_at_unix_secs = 1;
        reg.register(t.labels.clone());
        let sources = StubSources::new();
        sample_once(&reg, &sources, &t);
        let (_, v) = reg.get("i-1").unwrap();
        assert!(
            v.uptime_secs > 1_000_000,
            "uptime should reflect wall-clock delta, got {}",
            v.uptime_secs
        );
    }

    #[test]
    fn sample_once_uptime_does_not_underflow_on_future_started_at() {
        let reg = InstanceMetricsRegistry::new();
        let mut t = target("i-1");
        t.started_at_unix_secs = u64::MAX; // pretend the VM "started" in the far future
        reg.register(t.labels.clone());
        let sources = StubSources::new();
        sample_once(&reg, &sources, &t);
        let (_, v) = reg.get("i-1").unwrap();
        assert_eq!(v.uptime_secs, 0);
    }

    #[test]
    fn sample_once_skips_missing_source_targets() {
        let reg = InstanceMetricsRegistry::new();
        let mut t = target("i-1");
        t.vmm_pid = None;
        t.tap_iface = None;
        t.disk_stat_path = None;
        reg.register(t.labels.clone());
        let sources = StubSources::new();
        // Sample succeeds even with no sources — only last_sample
        // / uptime change.
        assert!(sample_once(&reg, &sources, &t));
        let (_, v) = reg.get("i-1").unwrap();
        assert!(v.last_sample_unix_secs > 0);
        assert_eq!(v.cpu_user_us, 0);
    }

    #[test]
    fn merge_only_overwrites_some_fields() {
        let mut acc = Sample {
            cpu_user_us: Some(100),
            net_rx_bytes: Some(50),
            ..Sample::default()
        };
        merge(
            &mut acc,
            Sample {
                cpu_user_us: Some(200), // overwrite
                disk_read_bytes: Some(4096),
                ..Sample::default()
            },
        );
        assert_eq!(acc.cpu_user_us, Some(200));
        assert_eq!(acc.net_rx_bytes, Some(50)); // preserved
        assert_eq!(acc.disk_read_bytes, Some(4096));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn os_proc_stat_returns_default_for_missing_pid() {
        // pid 1 always exists on Linux but our parser may still
        // return defaults if the format mismatches; this test just
        // ensures no panic on a known-bad pid.
        let s = read_os_proc_stat(0xFFFF_FFFF);
        assert!(s.cpu_user_us.is_none() || s.cpu_user_us == Some(0));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn os_sources_return_empty_on_non_linux() {
        // Confirms the Lima-dev-host fallback compiles and yields
        // `None` rather than panicking. The supervisor will fall
        // through to "no metrics" in that case.
        assert_eq!(read_os_proc_stat(1), Sample::default());
        assert_eq!(read_os_tap_stats("tap-foo"), Sample::default());
        assert_eq!(
            read_os_disk_stats(Path::new("/sys/block/vda/stat")),
            Sample::default()
        );
    }
}
