//! Live libkrun / HVF / Firecracker probes (tracked follow-up — see the
//! `bench` module docs).

use anyhow::{Context, Result};

use super::MicrovmLaunchArgs;
use super::harness::LaunchProbe;
use super::report::HostDescriptor;
use super::stats::{BootMarks, IterationTiming};

pub(super) struct LibkrunProbe {
    os: String,
    arch: String,
    #[cfg(feature = "libkrun-live")]
    name_prefix: String,
    // Per-iteration counter so each boot gets a unique VM name and the
    // teardown of run N never races the cold start of run N+1. Only
    // read on the `libkrun-live` path.
    #[allow(dead_code)]
    iter: u32,
}

impl LibkrunProbe {
    pub(super) fn new(_args: &MicrovmLaunchArgs) -> Result<Self> {
        Self::new_with_prefix("mvm-bench")
    }

    pub(super) fn new_with_prefix(name_prefix: impl Into<String>) -> Result<Self> {
        let name_prefix = name_prefix.into();
        #[cfg(not(feature = "libkrun-live"))]
        let _ = name_prefix;
        Ok(Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            #[cfg(feature = "libkrun-live")]
            name_prefix,
            iter: 0,
        })
    }
}

impl LaunchProbe for LibkrunProbe {
    fn measure_once(&mut self) -> Result<IterationTiming> {
        // Under `libkrun-live`, boot a real guest through the claim-8
        // admission path and convert the captured marks to spans.
        // Without the feature, fail honestly rather than fake a number —
        // a stock binary cannot boot a libkrun guest.
        #[cfg(feature = "libkrun-live")]
        {
            // Unique name per iteration so teardown of run N never races
            // the cold start of run N+1.
            self.iter += 1;
            let name = format!("{}-{}", self.name_prefix, self.iter);
            let marks = crate::commands::ops::bench_probe::boot_measure_once(&name)?;
            Ok(marks.to_timing())
        }
        #[cfg(not(feature = "libkrun-live"))]
        {
            anyhow::bail!(
                "bench microvm-launch: this binary was built without the \
                 `libkrun-live` feature, so it cannot boot a real guest. \
                 Rebuild with `cargo build -p mvm-cli --features libkrun-live` \
                 on a host where libkrun boots (the slp/krun Homebrew trio \
                 installed). The measurement substrate is otherwise complete."
            )
        }
    }

    fn host_descriptor(&self) -> HostDescriptor {
        // Hash the canonical kernel so the regression gate refuses to
        // compare across a kernel swap (a faster/slower kernel must
        // invalidate the baseline, not silently mis-compare). Resolved
        // from the same default-microvm image the probe boots.
        let kernel_sha256 = crate::commands::ops::bench_probe::resolve_probe_image()
            .ok()
            .and_then(|img| {
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

#[cfg(target_os = "macos")]
pub(super) struct HvfProbe {
    os: String,
    arch: String,
    name_prefix: String,
    iter: u32,
}

#[cfg(target_os = "macos")]
impl HvfProbe {
    pub(super) fn new(_args: &MicrovmLaunchArgs) -> Result<Self> {
        Self::new_with_prefix("mvm-bench-hvf")
    }

    pub(super) fn new_with_prefix(name_prefix: impl Into<String>) -> Result<Self> {
        Ok(Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            name_prefix: name_prefix.into(),
            iter: 0,
        })
    }
}

#[cfg(target_os = "macos")]
impl LaunchProbe for HvfProbe {
    fn measure_once(&mut self) -> Result<IterationTiming> {
        self.iter += 1;
        let name = format!("{}-{}", self.name_prefix, self.iter);
        let held = boot_hvf_hold_once(&name)?;
        let marks = held.marks;
        drop(held);
        assert_hvf_bench_cleanup(&name)?;
        Ok(marks.to_timing())
    }

    fn host_descriptor(&self) -> HostDescriptor {
        let kernel_sha256 = crate::commands::ops::bench_probe::resolve_probe_image()
            .ok()
            .and_then(|img| {
                mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&img.kernel)).ok()
            });
        HostDescriptor {
            os: self.os.clone(),
            arch: self.arch.clone(),
            hypervisor: "hvf".to_string(),
            libkrun_version: None,
            kernel_sha256,
            cmdline: Some("console=hvc0 root=/dev/vda rw init=/init".to_string()),
            readiness_boundary: Some("guest-agent-readiness".to_string()),
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) struct HeldHvfVm {
    vm_name: String,
    pid: u32,
    marks: BootMarks,
}

#[cfg(target_os = "macos")]
impl HeldHvfVm {
    pub(super) fn vm_name(&self) -> &str {
        &self.vm_name
    }

    pub(super) fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(target_os = "macos")]
impl Drop for HeldHvfVm {
    fn drop(&mut self) {
        use mvm_core::vm_backend::VmId;

        let backend = mvm_runtime::backend::AnyBackend::from_hypervisor("hvf");
        let _ = backend.stop(&VmId(self.vm_name.clone()));
    }
}

#[cfg(target_os = "macos")]
pub(super) fn boot_hvf_hold_once(vm_name: &str) -> Result<HeldHvfVm> {
    use mvm_core::vm_backend::VmStartConfig;
    use std::time::Instant;

    use mvm_hostd::plan_admission::populate_audit_substrate;

    let img = crate::commands::ops::bench_probe::resolve_probe_image()?;
    let admitted = crate::commands::ops::bench_probe::admit_probe_plan(
        std::path::Path::new(&img.rootfs),
        vm_name,
        "hvf",
        None,
    )?;

    let mut cfg = VmStartConfig {
        name: vm_name.to_string(),
        rootfs_path: img.rootfs.clone(),
        kernel_path: Some(img.kernel.clone()),
        cpus: 2,
        memory_mib: 2048,
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg, &admitted, None)?;

    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor("hvf");
    let start = Instant::now();
    backend.start(&cfg).context("probe hvf backend.start")?;

    let (pid, pid_seen) = wait_for_hvf_pid_file(vm_name)?;
    let (connected, ready) = wait_for_guest_readiness_and_record(vm_name)?;

    Ok(HeldHvfVm {
        vm_name: vm_name.to_string(),
        pid,
        marks: BootMarks {
            start,
            pid_seen,
            connected,
            ready,
        },
    })
}

#[cfg(target_os = "macos")]
fn wait_for_hvf_pid_file(vm_name: &str) -> Result<(u32, std::time::Instant)> {
    use mvm_agentd::vsock::adaptive_backoff;

    let pid_path = mvm_core::config::vm_state_dir(vm_name).join("hvf.pid");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut attempt = 0u32;
    loop {
        if let Ok(body) = std::fs::read_to_string(&pid_path)
            && let Ok(pid) = body.trim().parse::<u32>()
        {
            return Ok((pid, std::time::Instant::now()));
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "probe: HVF supervisor pid file never appeared or was invalid at {}",
                pid_path.display()
            );
        }
        std::thread::sleep(adaptive_backoff(attempt));
        attempt += 1;
    }
}

#[cfg(target_os = "macos")]
fn wait_for_guest_readiness_and_record(
    vm_name: &str,
) -> Result<(std::time::Instant, std::time::Instant)> {
    use mvm_agentd::vsock::adaptive_backoff;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut attempt = 0u32;
    loop {
        if let Ok(report) = crate::commands::vm::wait::fetch_readiness(vm_name) {
            let now = std::time::Instant::now();
            write_boot_timing_sidecar(vm_name, &report.boot_millis)?;
            return Ok((now, now));
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "probe: guest control plane never reached Ready (readiness) for {vm_name}"
            );
        }
        std::thread::sleep(adaptive_backoff(attempt));
        attempt += 1;
    }
}

#[cfg(target_os = "macos")]
pub(super) fn assert_hvf_bench_cleanup(vm_name: &str) -> Result<()> {
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor("hvf");
    let list = backend
        .list()
        .with_context(|| format!("listing HVF VMs after bench cleanup for {vm_name}"))?;
    if list.iter().any(|vm| vm.name == vm_name) {
        anyhow::bail!("bench cleanup leaked HVF VM registry entry for {vm_name}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) struct FirecrackerProbe {
    os: String,
    arch: String,
    name_prefix: String,
    warm_pool_size: u32,
    iter: u32,
}

#[cfg(target_os = "linux")]
impl FirecrackerProbe {
    pub(super) fn new(args: &MicrovmLaunchArgs) -> Result<Self> {
        Self::new_with_prefix_and_warm_pool_size("mvm-bench-fc", args.warm_pool_size)
    }

    pub(super) fn new_with_prefix(name_prefix: impl Into<String>) -> Result<Self> {
        Self::new_with_prefix_and_warm_pool_size(name_prefix, 0)
    }

    pub(super) fn new_with_prefix_and_warm_pool_size(
        name_prefix: impl Into<String>,
        warm_pool_size: u32,
    ) -> Result<Self> {
        Ok(Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            name_prefix: name_prefix.into(),
            warm_pool_size,
            iter: 0,
        })
    }
}

#[cfg(target_os = "linux")]
impl LaunchProbe for FirecrackerProbe {
    fn measure_once(&mut self) -> Result<IterationTiming> {
        self.iter += 1;
        let name = format!("{}-{}", self.name_prefix, self.iter);
        let held = boot_firecracker_hold_once(&name, self.warm_pool_size)?;
        let marks = held.marks;
        drop(held);
        assert_firecracker_bench_cleanup(&name)?;
        Ok(marks.to_timing())
    }

    fn host_descriptor(&self) -> HostDescriptor {
        let kernel_sha256 = crate::commands::ops::bench_probe::resolve_probe_image()
            .ok()
            .and_then(|img| {
                mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&img.kernel)).ok()
            });
        HostDescriptor {
            os: self.os.clone(),
            arch: self.arch.clone(),
            hypervisor: "firecracker".to_string(),
            libkrun_version: None,
            kernel_sha256,
            cmdline: Some("console=ttyS0 reboot=k panic=1 net.ifnames=0 ip=<per-slot>".to_string()),
            readiness_boundary: Some("firecracker-pid".to_string()),
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) struct HeldFirecrackerVm {
    vm_name: String,
    pid: u32,
    marks: BootMarks,
}

#[cfg(target_os = "linux")]
impl HeldFirecrackerVm {
    pub(super) fn vm_name(&self) -> &str {
        &self.vm_name
    }

    pub(super) fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(target_os = "linux")]
impl Drop for HeldFirecrackerVm {
    fn drop(&mut self) {
        use mvm_core::vm_backend::VmId;

        let backend = mvm_runtime::backend::AnyBackend::from_hypervisor("firecracker");
        let _ = backend.stop(&VmId(self.vm_name.clone()));
    }
}

#[cfg(target_os = "linux")]
pub(super) fn boot_firecracker_hold_once(
    vm_name: &str,
    warm_pool_size: u32,
) -> Result<HeldFirecrackerVm> {
    use mvm_core::vm_backend::VmStartConfig;
    use std::time::Instant;

    use mvm_hostd::plan_admission::populate_audit_substrate;

    let img = crate::commands::ops::bench_probe::resolve_probe_image()?;
    let admitted = crate::commands::ops::bench_probe::admit_probe_plan(
        std::path::Path::new(&img.rootfs),
        vm_name,
        "firecracker",
        None,
    )?;

    let mut cfg = VmStartConfig {
        name: vm_name.to_string(),
        rootfs_path: img.rootfs.clone(),
        kernel_path: Some(img.kernel.clone()),
        cpus: 2,
        memory_mib: 2048,
        warm_pool_size,
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg, &admitted, None)?;

    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor("firecracker");
    let start = Instant::now();
    backend
        .start(&cfg)
        .context("probe firecracker backend.start")?;

    let abs_dir = mvm_runtime::microvm::resolve_running_vm_dir(vm_name)?;
    let (pid, pid_seen) = wait_for_firecracker_pid(&abs_dir)?;
    // The current Linux proof image used by the Firecracker host boots
    // successfully but does not expose the mvm guest-agent ping endpoint.
    // Report backend-accepted/PID-observed timing honestly and fingerprint
    // that boundary in HostDescriptor so it cannot be baseline-compared
    // against guest-agent-ready libkrun reports.
    let connected = pid_seen;
    let ready = pid_seen;

    Ok(HeldFirecrackerVm {
        vm_name: vm_name.to_string(),
        pid,
        marks: BootMarks {
            start,
            pid_seen,
            connected,
            ready,
        },
    })
}

#[cfg(target_os = "linux")]
pub(super) fn assert_firecracker_bench_cleanup(vm_name: &str) -> Result<()> {
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor("firecracker");
    let list = backend
        .list()
        .with_context(|| format!("listing VMs after bench cleanup for {vm_name}"))?;
    if list.iter().any(|vm| vm.name == vm_name) {
        anyhow::bail!("bench cleanup leaked VM registry entry for {vm_name}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_for_firecracker_pid(abs_dir: &str) -> Result<(u32, std::time::Instant)> {
    use mvm_agentd::vsock::adaptive_backoff;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut attempt = 0u32;
    loop {
        if let Ok(pid) = mvm_runtime::microvm::read_firecracker_pid(abs_dir) {
            return Ok((pid, std::time::Instant::now()));
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("probe: Firecracker pid file never appeared under {abs_dir}");
        }
        std::thread::sleep(adaptive_backoff(attempt));
        attempt += 1;
    }
}

/// Persist a guest-monotonic boot timing cross-check beside the bench reports.
/// The host-clock report remains the regression metric; this sidecar audits the
/// guest's own phase timing without mixing clock domains.
#[cfg(any(feature = "libkrun-live", target_os = "macos"))]
pub(in crate::commands::ops) fn write_boot_timing_sidecar(
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
    #[cfg(feature = "libkrun-live")]
    use super::*;

    #[cfg(feature = "libkrun-live")]
    fn launch_args() -> MicrovmLaunchArgs {
        MicrovmLaunchArgs {
            runs: 1,
            warmup: 0,
            concurrency: 1,
            max_concurrency: 64,
            hypervisor: "libkrun".to_string(),
            warm_pool_size: 0,
            out: None,
            json: false,
            baseline: None,
            max_regression_pct: 10.0,
        }
    }

    /// Live boot of the canonical default-microvm image through the
    /// real admission path. Gated behind `libkrun-live` so stock CI
    /// (no Hypervisor.framework nested virt) skips it; runs on a dev
    /// host / self-hosted macOS runner with the slp/krun trio + an
    /// `mvm-libkrun-supervisor` on the launch path.
    #[cfg(feature = "libkrun-live")]
    #[test]
    fn live_probe_returns_finite_ordered_spans() {
        let args = launch_args();
        let mut probe = LibkrunProbe::new(&args).unwrap();
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
    #[cfg(feature = "libkrun-live")]
    #[test]
    fn host_descriptor_is_populated() {
        let args = launch_args();
        let probe = LibkrunProbe::new(&args).unwrap();
        let h = probe.host_descriptor();
        assert!(
            h.kernel_sha256.is_some(),
            "kernel sha must be set so a kernel swap invalidates the baseline"
        );
    }
}
