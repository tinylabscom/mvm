//! Live boot orchestration for the interaction-latency gate. Kept
//! out of `bench.rs` so the pure stats/schema substrate stays
//! VM-free.

use anyhow::{Context, Result};

use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy};

use crate::commands::env::builder_vm::ensure_default_microvm_image;
use mvm_core::plan::SynthesisInput;
use mvm_hostd::plan_admission::{AdmittedPlan, InMemoryNonceLedger, SystemClock, admit_for_run};

/// Keep the live probe above the current default-image kernel load floor. Smaller
/// values can fail before readiness on Linux/libkrun, which makes the benchmark
/// measure an invalid launch shape rather than runtime startup.
const PROBE_MEM_MIB: u32 = 2048;

/// Resolved inputs for one benchmarked boot. `kernel`/`rootfs` come
/// from the same `ensure_default_microvm_image()` `mvmctl up` uses —
/// the canonical runtime image, NOT the interactive rootfs.
// Fields are read by the live `boot_measure_once` + the HostDescriptor
// kernel-sha; until then only the test reads them.
#[allow(dead_code)]
pub struct ProbeImage {
    pub kernel: String,
    pub rootfs: String,
}

/// Resolve the canonical default-microvm image (kernel + rootfs) the
/// same way `mvmctl up` does. No artifact override flags: the bench
/// measures the real runtime launch path, so it pins to one canonical
/// target (a `HostDescriptor`-comparable baseline).
#[allow(dead_code)]
pub fn resolve_probe_image() -> Result<ProbeImage> {
    // Bench baseline boots the published, admitted prod default image.
    let (kernel, rootfs) = ensure_default_microvm_image(mvm_build::pipeline::BuildMode::Prod)
        .context("resolving default-microvm bench image")?;
    Ok(ProbeImage { kernel, rootfs })
}

/// Synthesize → sign → verify → window → nonce a minimal plan for the
/// probe's boot, mirroring `up.rs::admit_plan_for_boot` minus bundle /
/// deps / policy. `keys_dir` is the host-signer directory: production /
/// live-boot callers pass `None` (the real `~/.mvm/keys/`, so the
/// supervisor's re-verify trusts the signature); tests pass
/// `Some(tempdir)` so they never touch the real user's home. Drives the
/// real claim-8 admission path — the bench must never benchmark a boot
/// that bypasses admission.
#[allow(dead_code)]
pub fn admit_probe_plan(
    rootfs: &std::path::Path,
    vm_name: &str,
    backend_name: &str,
    keys_dir: Option<&std::path::Path>,
) -> Result<AdmittedPlan> {
    let sha = mvm_core::crypto::image_verify::sha256_file(rootfs)
        .with_context(|| format!("hashing probe rootfs {}", rootfs.display()))?;
    let input = SynthesisInput {
        grants: None,
        stream_edges: Vec::new(),
        kernel_sha256: None,
        network_mode: Default::default(),
        ingress: Vec::new(),
        vm_name,
        tenant: Some("bench"),
        backend_name,
        image_name: vm_name,
        image_sha256: &sha,
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier: PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: SecretReleasePolicy::default(),
        secrets: Vec::new(),
        audit_event_prefix: None,
        cpus: 2,
        mem_mib: u64::from(PROBE_MEM_MIB),
        disk_mib: 0,
        boot_timeout_secs: 60,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        assets: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        caller_commitment: None,
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        extensions: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
    };
    let ledger = InMemoryNonceLedger::new();
    admit_for_run(
        &input,
        &SystemClock,
        &ledger,
        keys_dir,
        None,
        mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
    )
    .context("admitting probe plan")
}

// ──────────────────────────────────────────────────────────────────
// Live boot orchestration (libkrun-live only). Composes
// resolve_probe_image + admit_probe_plan + the libkrun backend + a
// vsock readiness poll into one boot-measure-teardown cycle. Excluded
// from stock builds — see the `libkrun-live` feature.
// ──────────────────────────────────────────────────────────────────

#[cfg(feature = "libkrun-live")]
use super::stats::BootMarks;

/// A live probe VM held only long enough for density sampling. Drop is
/// best-effort teardown so a sampling error cannot leak the supervisor.
#[cfg(feature = "libkrun-live")]
pub struct HeldProbeVm {
    vm_name: String,
    pid: u32,
    marks: BootMarks,
}

#[cfg(feature = "libkrun-live")]
impl HeldProbeVm {
    pub fn vm_name(&self) -> &str {
        &self.vm_name
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The four boot marks captured for this VM (`BootMarks` is `Copy`).
    pub fn marks(&self) -> BootMarks {
        self.marks
    }
}

#[cfg(feature = "libkrun-live")]
impl Drop for HeldProbeVm {
    fn drop(&mut self) {
        use mvm_core::vm_backend::VmId;

        let backend = mvm_runtime::AnyBackend::from_hypervisor("libkrun").into_dyn();
        let _ = backend.stop(&VmId(self.vm_name.clone()));
    }
}

/// Per-VM state dir the libkrun backend writes the supervisor PID file and host-side
/// vsock socket into (`~/.mvm/vms/<name>`). Delegate to the
/// canonical `mvm_core::config::vm_state_dir` the backend itself uses, instead of building
/// the path from `mvm_state_dir()` — that's the state dir (`~/.mvm/state`),
/// which the supervisor never writes to, so the `start_to_pid` mark never resolved and the
/// probe timed out on every dev-host run.
#[cfg(feature = "libkrun-live")]
pub(super) fn probe_state_dir(vm_name: &str) -> std::path::PathBuf {
    mvm_core::config::vm_state_dir(vm_name)
}

/// Boot the canonical default-microvm image once through real
/// admission, time the four boot marks, and tear down. Order mirrors
/// `up.rs`: resolve image → admit (real host signer) → build
/// `VmStartConfig` → `populate_audit_substrate` (threads tenant_id /
/// plan_json so libkrun re-verifies + boots the admitted plan) →
/// `start` → poll readiness → `stop`.
#[cfg(feature = "libkrun-live")]
pub fn boot_measure_once(vm_name: &str) -> Result<BootMarks> {
    let held = boot_hold_once(vm_name)?;
    let marks = held.marks;
    drop(held);
    Ok(marks)
}

/// Boot the canonical default-microvm image once and keep it running
/// until the returned guard is dropped. Used by the density bench so it
/// can sample the live supervisor process footprint.
#[cfg(feature = "libkrun-live")]
pub fn boot_hold_once(vm_name: &str) -> Result<HeldProbeVm> {
    use mvm_core::vm_backend::VmStartConfig;
    use std::time::Instant;

    use mvm_hostd::plan_admission::populate_audit_substrate;

    let img = resolve_probe_image()?;
    // `None` keys_dir → the real ~/.mvm/keys host signer, so the
    // supervisor's in-process re-verify trusts the plan signature.
    let admitted = admit_probe_plan(std::path::Path::new(&img.rootfs), vm_name, "libkrun", None)?;

    let mut cfg = VmStartConfig {
        name: vm_name.to_string(),
        rootfs_path: img.rootfs.clone(),
        kernel_path: Some(img.kernel.clone()),
        cpus: 2,
        memory_mib: PROBE_MEM_MIB,
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg, &admitted, None)?;

    let backend = mvm_runtime::AnyBackend::from_hypervisor("libkrun").into_dyn();
    let start = Instant::now();
    backend.start(&cfg).context("probe backend.start")?;

    let (pid, pid_seen) = wait_for_pid_file(vm_name)?;
    let (connected, ready) = wait_for_ready(vm_name)?;
    record_boot_timing_report(vm_name)?;

    let marks = BootMarks {
        start,
        pid_seen,
        connected,
        ready,
    };

    Ok(HeldProbeVm {
        vm_name: vm_name.to_string(),
        pid,
        marks,
    })
}

/// Poll for the supervisor PID file (`start_to_pid` mark). Deadline at
/// 30 s — the PID file is written almost immediately after spawn.
#[cfg(feature = "libkrun-live")]
fn wait_for_pid_file(vm_name: &str) -> Result<(u32, std::time::Instant)> {
    use mvm_agentd::vsock::adaptive_backoff;

    let pid_path = probe_state_dir(vm_name).join("libkrun.pid");
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
                "probe: supervisor pid file never appeared or was invalid at {}",
                pid_path.display()
            );
        }
        std::thread::sleep(adaptive_backoff(attempt));
        attempt += 1;
    }
}

/// Poll the guest vsock control plane to readiness (`connected` +
/// `ready` marks). `ping` is atomic (connect + Ping + Pong), so the
/// connect instant is not separately observable without replicating
/// the host-side socket-path resolution; for v1 the first successful
/// ping is both `connected` and `ready`, folding `handshake_ms` into
/// `total_ready_ms`. The decision-relevant spans — `start_to_pid_ms`
/// (process spawn, the span a warm pool collapses) and
/// `total_ready_ms` (headline) — are measured accurately. Deadline at
/// 90 s.
#[cfg(feature = "libkrun-live")]
fn wait_for_ready(vm_name: &str) -> Result<(std::time::Instant, std::time::Instant)> {
    use mvm_agentd::vsock::{adaptive_backoff, ping};

    let dir = probe_state_dir(vm_name);
    let dir_str = dir.to_string_lossy().into_owned();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut attempt = 0u32;
    loop {
        if let Ok(true) = ping(&dir_str) {
            let now = std::time::Instant::now();
            return Ok((now, now));
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("probe: guest control plane never reached Ready (ping) for {vm_name}");
        }
        std::thread::sleep(adaptive_backoff(attempt));
        attempt += 1;
    }
}

/// Record the guest-monotonic boot timing cross-check next to the
/// bench reports. The host-clock spans remain the regression metric;
/// this sidecar exists only to audit the guest's own phase timing.
#[cfg(feature = "libkrun-live")]
fn record_boot_timing_report(vm_name: &str) -> Result<()> {
    let report = crate::commands::vm::wait::fetch_readiness(vm_name)
        .with_context(|| format!("fetching readiness report for {vm_name}"))?;
    super::write_boot_timing_sidecar(vm_name, &report.boot_millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The probe pid path must resolve under the backend's data dir
    // (`~/.mvm`, honouring MVM_HOME), NOT the state dir the supervisor never
    // writes to. Regression guard for the `start_to_pid` timeout this fix closed.
    #[cfg(feature = "libkrun-live")]
    #[test]
    fn probe_state_dir_resolves_under_mvm_home_not_xdg_state() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", "/tmp/mvm-bench-probe-test/mvm-home");
        let dir = probe_state_dir("vm-x");
        assert_eq!(dir, mvm_core::config::vm_state_dir("vm-x"));
        assert!(dir.starts_with("/tmp/mvm-bench-probe-test/mvm-home"));
        assert!(!dir.to_string_lossy().contains(".local/state"));
    }

    #[test]
    #[ignore = "touches ~/.mvm/cache; run on a host with the image cached"]
    fn resolve_probe_image_returns_existing_paths() {
        let img = resolve_probe_image().unwrap();
        assert!(std::path::Path::new(&img.kernel).exists());
        assert!(std::path::Path::new(&img.rootfs).exists());
    }

    #[test]
    fn admit_probe_plan_produces_admitted_plan_with_tempdir_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"not a real rootfs but hashable").unwrap();
        let admitted =
            admit_probe_plan(&rootfs, "bench-probe", "libkrun", Some(tmp.path())).unwrap();
        // The admitted plan binds the workload name we passed.
        assert_eq!(admitted.plan().image.name, "bench-probe");
        assert_eq!(admitted.plan().resources.mem_mib, u64::from(PROBE_MEM_MIB));
    }

    #[test]
    fn admit_probe_plan_generates_distinct_nonces_per_boot() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"not a real rootfs but hashable").unwrap();

        let first =
            admit_probe_plan(&rootfs, "bench-probe-a", "firecracker", Some(tmp.path())).unwrap();
        let second =
            admit_probe_plan(&rootfs, "bench-probe-b", "firecracker", Some(tmp.path())).unwrap();

        assert_ne!(first.plan().nonce, second.plan().nonce);
    }
}
