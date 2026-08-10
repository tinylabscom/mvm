//! Orchestration (probe-generic, so tests use a mock).

#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::thread;

use anyhow::{Context, Result, bail};

use crate::commands::vm::launch_sample::ProcessMemorySnapshot;

use super::report::{BenchReport, build_report};
use super::report::{HostDescriptor, LaunchDistributionReport, build_launch_distribution_report};
use super::stats::IterationTiming;

/// One cold launch measurement. Implementors boot a guest, time it to
/// readiness, and tear it down before returning. The live impl MUST go
/// through signed-plan admission (claim 8).
pub trait LaunchProbe {
    fn measure_once(&mut self) -> Result<IterationTiming>;
    fn host_descriptor(&self) -> HostDescriptor;
}

/// Run `warmup` discarded iterations, then `runs` measured ones, and
/// summarise. The warmup boots absorb first-run dylib-load / codesign
/// cost so they don't skew the measured set.
pub fn run_benchmark<P: LaunchProbe>(probe: &mut P, runs: u32, warmup: u32) -> Result<BenchReport> {
    if runs == 0 {
        bail!("--runs must be >= 1");
    }
    for i in 0..warmup {
        probe
            .measure_once()
            .with_context(|| format!("warmup iteration {i}"))?;
    }
    let mut raw = Vec::with_capacity(runs as usize);
    for i in 0..runs {
        raw.push(
            probe
                .measure_once()
                .with_context(|| format!("measured iteration {i}"))?,
        );
    }
    Ok(build_report(probe.host_descriptor(), runs, warmup, raw))
}

/// Run one concurrent launch wave. Each worker gets its own probe instance so
/// the live path uses distinct VM names, signed plans, nonces, and state dirs.
pub fn run_launch_distribution<F, P>(
    host: HostDescriptor,
    concurrency: u32,
    max_concurrency: u32,
    make_probe: F,
) -> Result<LaunchDistributionReport>
where
    F: Fn(u32) -> Result<P> + Send + Sync,
    P: LaunchProbe + Send + 'static,
{
    if concurrency == 0 {
        bail!("--concurrency must be >= 1");
    }
    if max_concurrency == 0 {
        bail!("--max-concurrency must be >= 1");
    }
    if concurrency > max_concurrency {
        bail!("--concurrency {concurrency} exceeds --max-concurrency {max_concurrency}");
    }

    let make_probe = &make_probe;
    let raw = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(concurrency as usize);
        for index in 0..concurrency {
            handles.push(scope.spawn(move || {
                let mut probe = make_probe(index)?;
                probe
                    .measure_once()
                    .with_context(|| format!("concurrent launch worker {index}"))
            }));
        }

        let mut raw = Vec::with_capacity(concurrency as usize);
        for handle in handles {
            raw.push(
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("launch worker panicked"))??,
            );
        }
        Ok::<_, anyhow::Error>(raw)
    })?;

    Ok(build_launch_distribution_report(host, concurrency, raw))
}

/// Linux `/proc/<pid>/smaps_rollup` reports proportional set size in KiB.
#[cfg(any(test, target_os = "linux"))]
pub fn parse_linux_smaps_rollup_pss_bytes(input: &str) -> Result<u64> {
    for line in input.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("Pss:") {
            let mut parts = rest.split_whitespace();
            let kib = parts
                .next()
                .context("Pss line missing numeric value")?
                .parse::<u64>()
                .context("parsing Pss KiB value")?;
            let unit = parts.next().unwrap_or("kB");
            if unit != "kB" {
                bail!("unsupported Pss unit {unit:?}; expected kB");
            }
            return kib
                .checked_mul(1024)
                .context("Pss KiB value overflowed bytes");
        }
    }
    bail!("smaps_rollup did not contain a Pss line")
}

/// Parse the process's own minor and major page-fault counters from Linux
/// `/proc/<pid>/stat`. The command name is parenthesized and may contain
/// whitespace or parentheses, so fields are counted only after its final `)`.
#[cfg(any(test, target_os = "linux"))]
pub fn parse_linux_proc_stat_faults(input: &str) -> Result<(u64, u64)> {
    let command_end = input
        .rfind(')')
        .context("proc stat did not contain a parenthesized command")?;
    let fields: Vec<&str> = input[command_end + 1..].split_whitespace().collect();
    let minor = fields
        .get(7)
        .context("proc stat did not contain minflt field 10")?
        .parse::<u64>()
        .context("parsing proc stat minflt field")?;
    let major = fields
        .get(9)
        .context("proc stat did not contain majflt field 12")?
        .parse::<u64>()
        .context("parsing proc stat majflt field")?;
    Ok((minor, major))
}

#[cfg(target_os = "linux")]
pub fn read_process_footprint_bytes(pid: u32) -> Result<u64> {
    let body = read_linux_proc_file(pid, "smaps_rollup")?;
    parse_linux_smaps_rollup_pss_bytes(&body)
}

/// Read one proc file, retrying through non-interactive sudo for root-owned
/// VMMs such as Firecracker. The fallback passes the path as an argument to
/// `cat`, never through a shell, and fails rather than prompting during a
/// benchmark.
#[cfg(target_os = "linux")]
fn read_linux_proc_file(pid: u32, file: &str) -> Result<String> {
    let path = PathBuf::from("/proc").join(pid.to_string()).join(file);
    match std::fs::read_to_string(&path) {
        Ok(body) => Ok(body),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            read_linux_proc_file_as_root(&path).with_context(|| {
                format!(
                    "reading {} directly was denied and the non-interactive privileged read failed",
                    path.display()
                )
            })
        }
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(target_os = "linux")]
fn read_linux_proc_file_as_root(path: &std::path::Path) -> Result<String> {
    let output = Command::new("sudo")
        .args(["-n", "cat", path.to_string_lossy().as_ref()])
        .output()
        .with_context(|| format!("running sudo -n cat {}", path.display()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let suffix = if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        };
        anyhow::bail!(
            "sudo -n cat {} exited with {}{}",
            path.display(),
            output.status,
            suffix
        );
    }
    String::from_utf8(output.stdout).context("sudo returned non-UTF-8 proc data")
}

/// Read whole-process working-set and fault counters for one Linux VMM.
#[cfg(target_os = "linux")]
pub fn read_process_memory_snapshot(pid: u32) -> Result<ProcessMemorySnapshot> {
    let working_set_bytes = read_process_footprint_bytes(pid)?;
    let stat = read_linux_proc_file(pid, "stat")?;
    let (minor_faults, major_faults) = parse_linux_proc_stat_faults(&stat)?;
    Ok(ProcessMemorySnapshot {
        working_set_bytes,
        minor_faults: Some(minor_faults),
        major_faults: Some(major_faults),
    })
}

#[cfg(target_os = "macos")]
pub fn read_process_footprint_bytes(pid: u32) -> Result<u64> {
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v4>::zeroed();
    let rc = unsafe {
        libc::proc_pid_rusage(
            pid as libc::c_int,
            libc::RUSAGE_INFO_V4,
            info.as_mut_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("proc_pid_rusage(RUSAGE_INFO_V4) for pid {pid}"));
    }
    let info = unsafe { info.assume_init() };
    Ok(info.ri_phys_footprint)
}

/// Read whole-process physical footprint for one macOS VMM. macOS does not
/// expose Linux-equivalent minor/major fault counters through this API.
#[cfg(target_os = "macos")]
pub fn read_process_memory_snapshot(pid: u32) -> Result<ProcessMemorySnapshot> {
    Ok(ProcessMemorySnapshot {
        working_set_bytes: read_process_footprint_bytes(pid)?,
        minor_faults: None,
        major_faults: None,
    })
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
pub fn read_process_footprint_bytes(_pid: u32) -> Result<u64> {
    bail!("process footprint sampling is only implemented on Linux and macOS")
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
pub fn read_process_memory_snapshot(_pid: u32) -> Result<ProcessMemorySnapshot> {
    bail!("process memory sampling is only implemented on Linux and macOS")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(arch: &str) -> HostDescriptor {
        HostDescriptor {
            os: "macos".to_string(),
            arch: arch.to_string(),
            hypervisor: "libkrun".to_string(),
            libkrun_version: Some("1.0".to_string()),
            kernel_sha256: Some("deadbeef".to_string()),
            cmdline: Some("root=/dev/vda rw init=/init".to_string()),
            readiness_boundary: Some("guest-agent-ping".to_string()),
        }
    }

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected {b}, got {a}");
    }

    #[test]
    fn smaps_rollup_pss_parser_reads_kib_as_bytes() {
        let fixture = "\
Rss:                1720 kB
Pss:                 384 kB
Pss_Dirty:           128 kB
";
        assert_eq!(
            parse_linux_smaps_rollup_pss_bytes(fixture).unwrap(),
            384 * 1024
        );
    }

    #[test]
    fn smaps_rollup_pss_parser_rejects_missing_pss() {
        let err = parse_linux_smaps_rollup_pss_bytes("Rss: 10 kB\n").unwrap_err();
        assert!(err.to_string().contains("Pss"), "unexpected error: {err:#}");
    }

    #[test]
    fn proc_stat_parser_handles_spaces_and_parentheses_in_command() {
        let fixture = "4321 (vmm worker (ready)) S 1 2 3 4 5 6 701 8 11 9 10";
        assert_eq!(parse_linux_proc_stat_faults(fixture).unwrap(), (701, 11));
    }

    #[test]
    fn proc_stat_parser_rejects_missing_fault_fields() {
        let err = parse_linux_proc_stat_faults("4321 (vmm) S 1 2").unwrap_err();
        assert!(
            err.to_string().contains("minflt"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn proc_file_reader_reads_the_current_process() {
        let stat = read_linux_proc_file(std::process::id(), "stat").unwrap();
        assert!(!stat.is_empty());
        assert!(parse_linux_proc_stat_faults(&stat).is_ok());
    }

    /// Deterministic probe so the orchestration loop is testable
    /// without a VM: it yields a fixed timing per call and counts
    /// calls so the test can assert warmup boots are discarded.
    struct MockProbe {
        timing: IterationTiming,
        calls: usize,
    }

    impl LaunchProbe for MockProbe {
        fn measure_once(&mut self) -> Result<IterationTiming> {
            self.calls += 1;
            Ok(self.timing)
        }
        fn host_descriptor(&self) -> HostDescriptor {
            host("aarch64")
        }
    }

    #[test]
    fn run_launch_distribution_enforces_concurrency_cap() {
        let err = run_launch_distribution(host("aarch64"), 5, 4, |_i| {
            Ok(MockProbe {
                timing: IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 1.0,
                    handshake_ms: 1.0,
                    total_ready_ms: 1.0,
                },
                calls: 0,
            })
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn run_launch_distribution_summarises_probe_wave() {
        let report = run_launch_distribution(host("aarch64"), 3, 4, |i| {
            Ok(MockProbe {
                timing: IterationTiming {
                    start_to_pid_ms: f64::from(i + 1),
                    pid_to_connect_ms: 1.0,
                    handshake_ms: 1.0,
                    total_ready_ms: f64::from((i + 1) * 100),
                },
                calls: 0,
            })
        })
        .unwrap();

        assert_eq!(report.concurrency, 3);
        assert_eq!(report.raw.len(), 3);
        approx(report.total_ready_tail_ms.p50, 200.0);
        approx(report.total_ready_tail_ms.p95, 290.0);
    }

    #[test]
    fn run_benchmark_discards_warmup_and_summarises_measured() {
        let mut probe = MockProbe {
            timing: IterationTiming {
                start_to_pid_ms: 5.0,
                pid_to_connect_ms: 3.0,
                handshake_ms: 2.0,
                total_ready_ms: 50.0,
            },
            calls: 0,
        };
        let report = run_benchmark(&mut probe, 4, 2).unwrap();
        // warmup(2) + runs(4) boots total.
        assert_eq!(probe.calls, 6);
        assert_eq!(report.runs, 4);
        assert_eq!(report.warmup, 2);
        // Only the 4 measured iterations are summarised.
        assert_eq!(report.raw.len(), 4);
        approx(report.total_ready_ms.p50, 50.0);
        approx(report.start_to_pid_ms.mean, 5.0);
    }

    #[test]
    fn run_benchmark_rejects_zero_runs() {
        let mut probe = MockProbe {
            timing: IterationTiming {
                start_to_pid_ms: 1.0,
                pid_to_connect_ms: 1.0,
                handshake_ms: 1.0,
                total_ready_ms: 1.0,
            },
            calls: 0,
        };
        assert!(run_benchmark(&mut probe, 0, 0).is_err());
    }
}
