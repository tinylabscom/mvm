//! `WarmLease` + `ExecBuilder` end-to-end: the canonical "verification loop".
//!
//! Acquire a warm VM, stage a script + run a compile-and-run batch, and drop the
//! handle. The point of this DX layer is the **caller body below** — it never
//! touches the standby pool, a vsock transport, a stop call, or a replenish:
//! `acquire` claims a compatible standby (or cold-boots on a miss), `exec()`
//! pipelines the staged files + commands over one stream, and `Drop` stops the
//! VM (and tops the pool back up for a claimed lease).
//!
//! Run it: `cargo run --example verification_loop`. It uses the mock backend so
//! it runs anywhere — the guest-exec step needs a live guest agent, so it
//! degrades cleanly here while still showing the exact call shape your code
//! writes against a real backend.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::vm_backend::{StandbyClaim, StandbyCompat, VmBackend, VmStartConfig, WarmLaunchMode};
use mvm_runtime::MockBackend;
use mvm_runtime::standby_pool::SupervisorStandbyPool;
use mvm_runtime::{AcquireSpec, WarmLease};

fn main() -> Result<()> {
    // --- setup: a backend + a standby pool + the admitted workload to attach.
    // In production these come from the launch path; here they are a mock VM and
    // an empty pool so the example runs on any host.
    let pool_dir = tempfile::tempdir()?;
    let pool = SupervisorStandbyPool::at(pool_dir.path());
    let backend: Arc<dyn VmBackend> = Arc::new(MockBackend::new());
    let spec = AcquireSpec {
        want: standby_compat(),
        mode: WarmLaunchMode::Optional,
        claim: admitted_claim("verify-vm"),
    };

    // ======================================================================
    // The caller body. Note what is NOT here: no pool.claim/remove, no
    // transport().connect, no backend.stop, no replenish — the lease owns all
    // of it.
    // ======================================================================
    let mut lease = WarmLease::acquire(backend, &pool, &spec, None)?;
    println!("acquired warm VM: {}", lease.id());

    // Stage a verification script, then run it and a follow-up check on one
    // stream — the chain stops at the first non-zero exit.
    let verify = lease
        .exec()
        .stage_file("/work/verify.sh", "#!/bin/sh\nset -e\necho verified\n")
        .argv(["sh", "/work/verify.sh"])
        .chain(["true"])
        .timeout(Duration::from_secs(30))
        .output();

    match verify {
        Ok(out) => println!(
            "verification exit={} stdout={:?}",
            out.status,
            String::from_utf8_lossy(&out.stdout)
        ),
        // The mock VM has no guest agent listening; against a real backend this
        // is where the staged batch actually runs.
        Err(e) => println!("(exec needs a live guest agent — skipped on the mock: {e})"),
    }

    // Surface the teardown error instead of letting `Drop` swallow it; dropping
    // the lease would do the same stop + pool replenish silently.
    lease.release()?;
    println!("released — pool is back at target idle count");
    Ok(())
}

/// What a standby must match to be claimable (kernel + fixed resources + image
/// + whether the guest boots an egress client).
fn standby_compat() -> StandbyCompat {
    StandbyCompat {
        template_id: None,
        kernel_sha256: "kernel-sha-placeholder".to_string(),
        vcpus: 2,
        mem_mib: 512,
        image_sha256: None,
        root_strategy: Default::default(),
        vsock_egress: false,
    }
}

/// The admitted, signed workload to attach. `start_config` doubles as the
/// cold-boot config used on a pool miss.
fn admitted_claim(name: &str) -> StandbyClaim {
    StandbyClaim {
        start_config: Some(VmStartConfig {
            name: name.to_string(),
            rootfs_path: "/var/lib/mvm/rootfs.ext4".to_string(),
            cpus: 2,
            memory_mib: 512,
            ..Default::default()
        }),
        rootfs_path: "/var/lib/mvm/rootfs.ext4".to_string(),
        tenant_id: "local".to_string(),
        audit_dir: std::path::PathBuf::from("/var/lib/mvm/audit"),
        gateway_audit_socket: std::path::PathBuf::from("/run/mvm/gw-audit.sock"),
        gateway_events_socket: None,
        plan_json: "{}".to_string(),
        bundle_json: None,
        network_policy: NetworkPolicy::deny_all(),
    }
}
