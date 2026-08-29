//! What a per-VM supervisor consumed on behalf of its machine.
//!
//! On the in-process VMM tiers the supervisor *is* the VMM, so the supervisor
//! measures itself: no child to reap, no exit to race. That makes the reading a
//! host observation rather than a guest report, which is the whole reason it can
//! be stamped as measured.
//!
//! Deliberately feature-independent and free of any backend's types. The
//! per-VM supervisor binaries that call this are gated — `mvm-libkrun-supervisor`
//! behind `libkrun-sys`, and no default build compiles it — so a copy living in
//! the binary would be a measurement nothing exercised. Here it compiles and is
//! tested under the crate's default feature set.
//!
//! Registration of *when* to take the reading stays with each binary, because
//! that is the part that genuinely differs: libkrun ends its process from inside
//! the VMM's own run loop, so its supervisor hooks `atexit` rather than calling
//! this after a return that never happens.

use std::path::Path;

use mvm_core::usage_capture::UsageCapture;
use mvm_vmm::host::process_usage::{peak_rss_mib_self, process_cpu_ms_self};

/// Take a reading of this process and persist it beside the exit code.
///
/// The VMM shares this process, so the reading covers guest execution together
/// with device emulation and vsock pumping — which is what the recorded
/// mechanisms say, rather than claiming to be guest time.
///
/// Best-effort by contract: a workload that already ran must never fail its
/// teardown over evidence, so a write failure is swallowed and the caller's exit
/// code is untouched. A probe that fails yields an unavailable metric, never a
/// zero — a failed reading is not a reading of nothing.
///
/// `host_state_bytes` and `wall_ms` are left unobserved on purpose. The host
/// measures both when it reports the exit and is better placed to; a number
/// written here would be overwritten at best and contradict the host at worst.
pub fn record_self_usage(vm_state_dir: &Path) {
    let usage = UsageCapture {
        cpu_ms: process_cpu_ms_self(),
        peak_rss_mib: peak_rss_mib_self(),
        ..UsageCapture::default()
    };
    let _ = mvm_core::usage_capture::write_captured(vm_state_dir, &usage);
}

#[cfg(test)]
mod tests {
    use super::record_self_usage;
    use mvm_core::usage_capture::{Mechanism, Metric, UsageSource, read_captured};

    #[test]
    fn the_supervisor_records_its_own_consumption_as_the_machines() {
        // The VMM is in-process, so this process's CPU is the machine's CPU plus
        // this process's own overhead — which is why the mechanism says so.
        let dir = tempfile::tempdir().expect("tempdir");
        record_self_usage(dir.path());
        let captured = read_captured(dir.path());
        assert_eq!(captured.cpu_ms.source(), UsageSource::Measured);
        assert!(matches!(
            captured.cpu_ms,
            Metric::Measured {
                mechanism: Mechanism::HostProcessCpu,
                ..
            }
        ));
        assert_eq!(captured.peak_rss_mib.source(), UsageSource::Measured);
        assert!(matches!(
            captured.peak_rss_mib,
            Metric::Measured {
                mechanism: Mechanism::HostProcessRss,
                ..
            }
        ));
    }

    #[test]
    fn the_supervisor_claims_only_the_two_dimensions_it_observes() {
        // The host fills the state-dir size and the wall span when it reports the
        // exit. Writing a number for either here would be overwritten at best,
        // and at worst would contradict the host's own reading.
        let dir = tempfile::tempdir().expect("tempdir");
        record_self_usage(dir.path());
        let captured = read_captured(dir.path());
        assert_eq!(captured.host_state_bytes, Metric::Unavailable);
        assert_eq!(captured.wall_ms, Metric::Unavailable);
    }

    #[test]
    fn a_state_dir_that_cannot_be_written_does_not_panic_the_teardown() {
        // The one property the `let _ =` is there for. A supervisor whose state
        // dir vanished under it still has to finish exiting: the workload
        // already ran, and losing the process over a missing sidecar would turn
        // an evidence gap into an outage.
        let dir = tempfile::tempdir().expect("tempdir");
        let gone = dir.path().join("no-such-directory");
        record_self_usage(&gone);
        assert_eq!(
            mvm_core::usage_capture::read_captured(&gone),
            mvm_core::usage_capture::UsageCapture::default(),
            "an unwritable reading reads back as nothing observed, not as a zero"
        );
    }
}
