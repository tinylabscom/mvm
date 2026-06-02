//! Live boot orchestration for `mvmctl bench microvm-launch`. Kept
//! out of `bench.rs` so the pure stats/schema substrate stays
//! VM-free. See Plan 119
//! (`specs/plans/119-live-bench-probe-impl-plan.md`).

use anyhow::{Context, Result};

use mvm_plan::{PlanSeccompTier, SecretReleasePolicy};

use crate::commands::env::apple_container::ensure_default_microvm_image;
use crate::commands::vm::plan_admission::{
    AdmittedPlan, InMemoryNonceLedger, SystemClock, admit_for_run,
};
use crate::commands::vm::plan_builder::SynthesisInput;

/// Resolved inputs for one benchmarked boot. `kernel`/`rootfs` come
/// from the same `ensure_default_microvm_image()` `mvmctl up` uses —
/// the canonical runtime image, NOT the dev-shell rootfs.
// Fields are read by Task 5's live `boot_measure_once` + Task 9's
// HostDescriptor kernel-sha; until then only the test reads them.
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
    let (kernel, rootfs) =
        ensure_default_microvm_image().context("resolving default-microvm bench image")?;
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
    keys_dir: Option<&std::path::Path>,
) -> Result<AdmittedPlan> {
    let sha = mvm_security::image_verify::sha256_file(rootfs)
        .with_context(|| format!("hashing probe rootfs {}", rootfs.display()))?;
    let input = SynthesisInput {
        vm_name,
        tenant: Some("bench"),
        backend_name: "libkrun",
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
        mem_mib: 512,
        disk_mib: 0,
        boot_timeout_secs: 60,
        exec_timeout_secs: 0,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
    };
    let ledger = InMemoryNonceLedger::new();
    admit_for_run(&input, &SystemClock, &ledger, keys_dir, None).context("admitting probe plan")
}

// ──────────────────────────────────────────────────────────────────
// Live boot orchestration (libkrun-live only). Composes
// resolve_probe_image + admit_probe_plan + the libkrun backend + a
// vsock readiness poll into one boot-measure-teardown cycle. Excluded
// from stock builds — see the `libkrun-live` feature.
// ──────────────────────────────────────────────────────────────────

#[cfg(feature = "libkrun-live")]
use crate::commands::ops::bench::BootMarks;

/// Per-VM state dir the libkrun backend writes the supervisor PID file
/// and host-side vsock socket into (`~/.mvm/vms/<name>`). Mirrors the
/// backend's private `vm_state_dir`; kept in lockstep with it.
#[cfg(feature = "libkrun-live")]
fn probe_state_dir(vm_name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::mvm_state_dir())
        .join("vms")
        .join(vm_name)
}

/// Boot the canonical default-microvm image once through real
/// admission, time the four boot marks, and tear down. Order mirrors
/// `up.rs`: resolve image → admit (real host signer) → build
/// `VmStartConfig` → `populate_audit_substrate` (threads tenant_id /
/// plan_json so libkrun re-verifies + boots the admitted plan) →
/// `start` → poll readiness → `stop`.
#[cfg(feature = "libkrun-live")]
pub fn boot_measure_once(vm_name: &str) -> Result<BootMarks> {
    use std::time::Instant;

    use mvm_core::vm_backend::{VmBackend, VmId, VmStartConfig};

    use crate::commands::vm::plan_admission::populate_audit_substrate;

    let img = resolve_probe_image()?;
    // `None` keys_dir → the real ~/.mvm/keys host signer, so the
    // supervisor's in-process re-verify trusts the plan signature.
    let admitted = admit_probe_plan(std::path::Path::new(&img.rootfs), vm_name, None)?;

    let mut cfg = VmStartConfig {
        name: vm_name.to_string(),
        rootfs_path: img.rootfs.clone(),
        kernel_path: Some(img.kernel.clone()),
        cpus: 2,
        memory_mib: 512,
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg, &admitted)?;

    let backend = mvm_backend::LibkrunBackend;
    let start = Instant::now();
    backend.start(&cfg).context("probe backend.start")?;

    let pid_seen = wait_for_pid_file(vm_name)?;
    let (connected, ready) = wait_for_ready(vm_name)?;

    // Teardown: SIGTERM the supervisor + clean state so iteration N+1 is
    // a true cold start.
    backend
        .stop(&VmId(vm_name.to_string()))
        .context("probe backend.stop")?;

    Ok(BootMarks {
        start,
        pid_seen,
        connected,
        ready,
    })
}

/// Poll for the supervisor PID file (`start_to_pid` mark). Deadline at
/// 30 s — the PID file is written almost immediately after spawn.
#[cfg(feature = "libkrun-live")]
fn wait_for_pid_file(vm_name: &str) -> Result<std::time::Instant> {
    use mvm_guest::vsock::adaptive_backoff;

    let pid_path = probe_state_dir(vm_name).join("libkrun.pid");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut attempt = 0u32;
    loop {
        if pid_path.exists() {
            return Ok(std::time::Instant::now());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "probe: supervisor pid file never appeared at {}",
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
/// (process spawn, the span PR-10b's warm pool collapses) and
/// `total_ready_ms` (headline) — are measured accurately. Deadline at
/// 90 s.
#[cfg(feature = "libkrun-live")]
fn wait_for_ready(vm_name: &str) -> Result<(std::time::Instant, std::time::Instant)> {
    use mvm_guest::vsock::{adaptive_backoff, ping};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "touches ~/.cache/mvm; run on a host with the image cached"]
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
        let admitted = admit_probe_plan(&rootfs, "bench-probe", Some(tmp.path())).unwrap();
        // The admitted plan binds the workload name we passed.
        assert_eq!(admitted.plan.image.name, "bench-probe");
    }
}
