//! Host process memory sampling for the bench and the launch sampler.

#[cfg(target_os = "linux")]
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::commands::vm::launch_sample::ProcessMemorySnapshot;

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
                anyhow::bail!("unsupported Pss unit {unit:?}; expected kB");
            }
            return kib
                .checked_mul(1024)
                .context("Pss KiB value overflowed bytes");
        }
    }
    anyhow::bail!("smaps_rollup did not contain a Pss line")
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
    let path = PathBuf::from("/proc")
        .join(pid.to_string())
        .join("smaps_rollup");
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    parse_linux_smaps_rollup_pss_bytes(&body)
}

/// Read whole-process resident memory and fault counters for one Linux VMM.
#[cfg(target_os = "linux")]
pub fn read_process_memory_snapshot(pid: u32) -> Result<ProcessMemorySnapshot> {
    let resident_bytes = mvm_agentd::worker_pool::process_rss_bytes(pid)
        .with_context(|| format!("reading unprivileged RSS for host process {pid}"))?;
    let path = PathBuf::from("/proc").join(pid.to_string()).join("stat");
    let stat =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let (minor_faults, major_faults) = parse_linux_proc_stat_faults(&stat)?;
    Ok(ProcessMemorySnapshot {
        resident_bytes,
        minor_faults: Some(minor_faults),
        major_faults: Some(major_faults),
    })
}

#[cfg(target_os = "macos")]
pub fn read_process_footprint_bytes(pid: u32) -> Result<u64> {
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v4>::zeroed();
    // SAFETY: `info.as_mut_ptr()` addresses a writable rusage_info_v4 sized for
    // RUSAGE_INFO_V4; proc_pid_rusage only writes within it.
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
    // SAFETY: proc_pid_rusage returned 0, so it fully initialised `info`.
    let info = unsafe { info.assume_init() };
    Ok(info.ri_phys_footprint)
}

/// Read whole-process physical footprint for one macOS VMM. macOS does not
/// expose Linux-equivalent minor/major fault counters through this API.
#[cfg(target_os = "macos")]
pub fn read_process_memory_snapshot(pid: u32) -> Result<ProcessMemorySnapshot> {
    Ok(ProcessMemorySnapshot {
        resident_bytes: read_process_footprint_bytes(pid)?,
        minor_faults: None,
        major_faults: None,
    })
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
pub fn read_process_footprint_bytes(_pid: u32) -> Result<u64> {
    anyhow::bail!("process footprint sampling is only implemented on Linux and macOS")
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
pub fn read_process_memory_snapshot(_pid: u32) -> Result<ProcessMemorySnapshot> {
    anyhow::bail!("process memory sampling is only implemented on Linux and macOS")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn process_memory_reader_uses_unprivileged_rss() {
        let sample = read_process_memory_snapshot(std::process::id()).unwrap();
        assert!(sample.resident_bytes > 0);
        assert!(sample.minor_faults.is_some());
    }
}
