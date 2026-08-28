//! Host-side readings of the process that owns a guest.
//!
//! Every reading here is taken by the host about itself or about a child it
//! reaped. Nothing in this module consults the guest, which is what allows the
//! results to be stamped as measured rather than reported.

use mvm_core::usage_capture::{Mechanism, Metric};

/// Resident high-water mark of this process, in MiB.
///
/// The kernel keeps the high-water mark, so this is a single read at teardown
/// rather than a sampler running for the life of the VM.
#[must_use]
pub fn peak_rss_mib_self() -> Metric {
    peak_rss_bytes_self()
        .map(|bytes| Metric::measured(bytes / (1024 * 1024), Mechanism::HostProcessRss))
        .unwrap_or_else(Metric::unavailable)
}

#[cfg(target_os = "linux")]
fn peak_rss_bytes_self() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some(kib * 1024)
}

#[cfg(target_os = "macos")]
fn peak_rss_bytes_self() -> Option<u64> {
    let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info>::uninit();
    let mut count = (std::mem::size_of::<libc::mach_task_basic_info>()
        / std::mem::size_of::<libc::natural_t>())
        as libc::mach_msg_type_number_t;
    // libc's Mach bindings are deprecated in favor of the `mach2` crate, but
    // this project deliberately avoids adding that dependency. The
    // deprecation is confined to this small macOS-only block.
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    // SAFETY: `task_info` fills the provided buffer when it returns KERN_SUCCESS,
    // and `count` describes that buffer's size in natural_t units.
    let rc = unsafe {
        libc::task_info(
            task,
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if rc != libc::KERN_SUCCESS {
        return None;
    }
    // SAFETY: KERN_SUCCESS means the buffer was initialized.
    Some(unsafe { info.assume_init() }.resident_size_max)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peak_rss_bytes_self() -> Option<u64> {
    None
}

/// CPU consumed by this process — user plus system — in milliseconds.
///
/// On the in-process VMM tiers this process *is* the VMM, so the reading
/// covers guest execution together with device emulation and vsock pumping.
/// That is why the metric names [`Mechanism::HostProcessCpu`] rather than
/// claiming to be guest time.
#[must_use]
pub fn process_cpu_ms_self() -> Metric {
    // SAFETY: `usage` is fully overwritten by `getrusage` below before it is
    // read; zeroing it here only establishes a valid initial bit pattern.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a valid, fully-owned rusage the kernel writes into.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return Metric::unavailable();
    }
    Metric::measured(rusage_cpu_ms(&usage), Mechanism::HostProcessCpu)
}

/// CPU consumed by a reaped child, in milliseconds.
#[must_use]
pub fn child_cpu_ms(usage: &libc::rusage) -> Metric {
    Metric::measured(rusage_cpu_ms(usage), Mechanism::HostChildRusage)
}

fn rusage_cpu_ms(usage: &libc::rusage) -> u64 {
    let to_ms = |timeval: libc::timeval| -> u64 {
        let seconds = u64::try_from(timeval.tv_sec).unwrap_or(0);
        let micros = u64::try_from(timeval.tv_usec).unwrap_or(0);
        seconds.saturating_mul(1000).saturating_add(micros / 1000)
    };
    to_ms(usage.ru_utime).saturating_add(to_ms(usage.ru_stime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_has_a_resident_high_water_mark() {
        // Any live process has resident pages, so an unavailable answer here
        // means the probe failed rather than that there was nothing to see.
        let rss = peak_rss_mib_self();
        assert_eq!(rss.source(), mvm_core::usage_capture::UsageSource::Measured);
        assert!(rss.value().expect("a measured metric carries a value") > 0);
    }

    #[test]
    fn this_process_has_consumed_cpu() {
        let cpu = process_cpu_ms_self();
        assert_eq!(cpu.source(), mvm_core::usage_capture::UsageSource::Measured);
    }

    #[test]
    fn a_reaped_childs_cpu_is_tagged_as_child_rusage() {
        // SAFETY: a zeroed rusage is a valid bit pattern for this POD struct.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        usage.ru_utime.tv_sec = 4;
        usage.ru_stime.tv_usec = 210_000;
        assert_eq!(
            child_cpu_ms(&usage),
            Metric::measured(4210, Mechanism::HostChildRusage)
        );
    }
}
