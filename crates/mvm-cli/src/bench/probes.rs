//! Live libkrun probe driving the interaction-latency gate — see the
//! `bench` module docs. This whole module requires `libkrun-live` (it
//! boots a real guest), matching the gate's own feature gate.

use anyhow::{Context, Result};

use super::harness::LaunchProbe;
use super::harness::read_process_footprint_bytes;
use super::report::HostDescriptor;
use super::report::{DensityReport, InstanceFootprint, build_density_report};
use super::stats::IterationTiming;

pub(super) struct LibkrunProbe {
    os: String,
    arch: String,
    name_prefix: String,
    // Per-iteration counter so each boot gets a unique VM name and the
    // teardown of run N never races the cold start of run N+1.
    iter: u32,
}

impl LibkrunProbe {
    pub(super) fn new_with_prefix(name_prefix: impl Into<String>) -> Result<Self> {
        Ok(Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            name_prefix: name_prefix.into(),
            iter: 0,
        })
    }
}

impl LaunchProbe for LibkrunProbe {
    fn measure_once(&mut self) -> Result<IterationTiming> {
        // Boot a real guest through the claim-8 admission path and
        // convert the captured marks to spans. Unique name per
        // iteration so teardown of run N never races the cold start
        // of run N+1.
        self.iter += 1;
        let name = format!("{}-{}", self.name_prefix, self.iter);
        let marks = super::probe::boot_measure_once(&name)?;
        Ok(marks.to_timing())
    }

    fn host_descriptor(&self) -> HostDescriptor {
        // Hash the canonical kernel so the regression gate refuses to
        // compare across a kernel swap (a faster/slower kernel must
        // invalidate the baseline, not silently mis-compare). Resolved
        // from the same default-microvm image the probe boots.
        let kernel_sha256 = super::probe::resolve_probe_image().ok().and_then(|img| {
            mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&img.kernel)).ok()
        });
        HostDescriptor {
            os: self.os.clone(),
            arch: self.arch.clone(),
            hypervisor: "libkrun".to_string(),
            libkrun_version: None,
            kernel_sha256,
            // The runtime libkrun cmdline (Apple Silicon HVF / virtio
            // console), matching the backend's supervisor config.
            cmdline: Some("console=hvc0 root=/dev/vda rw init=/init".to_string()),
            readiness_boundary: Some("guest-agent-ping".to_string()),
        }
    }
}

/// Boot and hold a bounded set of admitted libkrun guests, then report the
/// host footprint of each live supervisor/VMM process.
///
/// Each guest reaches authenticated readiness before its footprint is read.
/// The returned report measures host process residency, not the guest's
/// configured memory capacity. If any sample fails, already-started guests
/// are dropped and their normal backend cleanup runs before the error returns.
pub fn run_density(count: u32, max_count: u32) -> Result<DensityReport> {
    let count_usize = density_shape(count, max_count)?;
    let host = LibkrunProbe::new_with_prefix("mvm-density")?.host_descriptor();
    let process_id = std::process::id();
    let mut held = Vec::with_capacity(count_usize);
    let mut samples = Vec::with_capacity(count_usize);

    for index in 0..count {
        let vm_name = format!("mvm-density-{process_id}-{index}");
        let vm = super::probe::boot_hold_once(&vm_name)
            .with_context(|| format!("booting density sample {index}"))?;
        let bytes = read_process_footprint_bytes(vm.pid())
            .with_context(|| format!("sampling footprint for density sample {index}"))?;
        let instance_dir = super::probe::probe_state_dir(&vm_name);
        let guest_agent_rss_bytes =
            mvm_agentd::vsock::query_resource_usage(&instance_dir.to_string_lossy())
                .with_context(|| format!("sampling guest-agent RSS for density sample {index}"))?;
        samples.push(InstanceFootprint {
            vm_name,
            pid: vm.pid(),
            bytes,
            guest_agent_rss_bytes: Some(guest_agent_rss_bytes),
        });
        held.push(vm);
    }

    let report = build_density_report(host, count, max_count, samples);
    drop(held);
    Ok(report)
}

fn density_shape(count: u32, max_count: u32) -> Result<usize> {
    if count == 0 {
        anyhow::bail!("density count must be positive");
    }
    if max_count == 0 {
        anyhow::bail!("density maximum must be positive");
    }
    if count > max_count {
        anyhow::bail!("density count {count} exceeds maximum {max_count}");
    }
    usize::try_from(count).context("density count does not fit in usize")
}

/// Persist a guest-monotonic boot timing cross-check beside the bench reports.
/// The host-clock report remains the regression metric; this sidecar audits the
/// guest's own phase timing without mixing clock domains.
pub(crate) fn write_boot_timing_sidecar(
    vm_name: &str,
    boot_millis: &mvm_agentd::vsock::BootTimingReport,
) -> Result<()> {
    let path = std::path::PathBuf::from(mvm_core::config::mvm_state_dir())
        .join("bench")
        .join(format!("boot-timing-{vm_name}.json"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating boot timing dir {}", parent.display()))?;
    }
    let json =
        serde_json::to_string_pretty(boot_millis).context("serializing boot timing report")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn density_shape_requires_a_bounded_positive_count() {
        assert_eq!(density_shape(3, 4).unwrap(), 3);
        assert!(density_shape(0, 4).is_err());
        assert!(density_shape(3, 0).is_err());
        assert!(density_shape(5, 4).is_err());
    }

    /// Live boot of the canonical default-microvm image through the
    /// real admission path. Gated behind `libkrun-live` so stock CI
    /// (no Hypervisor.framework nested virt) skips it; runs on a dev
    /// host / self-hosted macOS runner with the slp/krun trio + an
    /// `mvm-libkrun-supervisor` on the launch path.
    #[test]
    fn live_probe_returns_finite_ordered_spans() {
        let mut probe = LibkrunProbe::new_with_prefix("mvm-bench").unwrap();
        let it = probe
            .measure_once()
            .expect("live boot should succeed on a libkrun host");
        for v in [
            it.start_to_pid_ms,
            it.pid_to_connect_ms,
            it.handshake_ms,
            it.total_ready_ms,
        ] {
            assert!(
                v.is_finite() && v >= 0.0,
                "span must be finite and non-negative: {v}"
            );
        }
        assert!(it.total_ready_ms >= it.start_to_pid_ms);
    }

    /// The libkrun probe must stamp the kernel sha into the
    /// `HostDescriptor` so a kernel swap invalidates the baseline (a
    /// `None` kernel sha would let a different kernel mis-compare as a
    /// regression-free run). Needs the cached image present, not a
    /// boot — gated under `libkrun-live` because it touches
    /// `~/.mvm/cache`.
    #[test]
    fn host_descriptor_is_populated() {
        let probe = LibkrunProbe::new_with_prefix("mvm-bench").unwrap();
        let h = probe.host_descriptor();
        assert!(
            h.kernel_sha256.is_some(),
            "kernel sha must be set so a kernel swap invalidates the baseline"
        );
    }
}
