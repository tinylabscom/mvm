use anyhow::{Context, Result};
use tracing::{instrument, warn};

use super::disk;
use super::fc_config;
use super::net;
use super::snapshot;
use crate::security::{audit, cgroups, encryption, jailer, keystore, metadata, seccomp};
use crate::shell;
use crate::vm::bridge;
use crate::vm::pool::lifecycle::pool_load;
use crate::vm::tenant::lifecycle::tenant_load;
use crate::vm::tenant::quota;
use mvm_core::config::is_production_mode;
use mvm_core::idle_metrics::IdleMetrics;
use mvm_core::instance::{InstanceState, InstanceStatus, validate_transition};
use mvm_core::naming;
use mvm_core::pool::{pool_artifacts_dir, pool_instances_dir};
use mvm_core::tenant::{tenant_secrets_path, tenant_ssh_key_path};
use mvm_core::time;

/// Filesystem path for an instance directory.
fn instance_dir(tenant_id: &str, pool_id: &str, instance_id: &str) -> String {
    format!("{}/{}", pool_instances_dir(tenant_id, pool_id), instance_id)
}

/// Path to instance.json for a specific instance.
fn instance_state_path(tenant_id: &str, pool_id: &str, instance_id: &str) -> String {
    format!(
        "{}/instance.json",
        instance_dir(tenant_id, pool_id, instance_id)
    )
}

/// Load an instance's persisted state.
pub(crate) fn load_instance(
    tenant_id: &str,
    pool_id: &str,
    instance_id: &str,
) -> Result<InstanceState> {
    let path = instance_state_path(tenant_id, pool_id, instance_id);
    let json = shell::run_in_vm_stdout(&format!("cat {}", path)).with_context(|| {
        format!(
            "Failed to load instance: {}/{}/{}",
            tenant_id, pool_id, instance_id
        )
    })?;
    let state: InstanceState = serde_json::from_str(&json)?;
    Ok(state)
}

/// Persist instance state atomically.
fn save_instance(
    tenant_id: &str,
    pool_id: &str,
    instance_id: &str,
    state: &InstanceState,
) -> Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    let path = instance_state_path(tenant_id, pool_id, instance_id);
    shell::run_in_vm(&format!("cat > {} << 'MVMEOF'\n{}\nMVMEOF", path, json))?;
    Ok(())
}

/// Create a new instance in a pool. Returns the generated instance_id.
///
/// Allocates an IP from the tenant subnet, creates the instance directory,
/// and writes initial InstanceState with status=Created.
#[instrument(skip_all, fields(tenant_id, pool_id))]
pub fn instance_create(tenant_id: &str, pool_id: &str) -> Result<String> {
    let tenant = tenant_load(tenant_id)?;
    let spec = pool_load(tenant_id, pool_id)?;

    let instance_id = naming::generate_instance_id();
    let ip_offset = net::allocate_ip_offset(tenant_id, pool_id)?;
    let instance_net = net::build_instance_net(&tenant.net, ip_offset);

    let dir = instance_dir(tenant_id, pool_id, &instance_id);
    shell::run_in_vm(&format!(
        "mkdir -p {dir}/runtime {dir}/volumes {dir}/snapshots/delta"
    ))?;

    let state = InstanceState {
        instance_id: instance_id.clone(),
        pool_id: pool_id.to_string(),
        tenant_id: tenant_id.to_string(),
        status: InstanceStatus::Created,
        net: instance_net,
        role: spec.role.clone(),
        revision_hash: None,
        firecracker_pid: None,
        last_started_at: None,
        last_stopped_at: None,
        idle_metrics: IdleMetrics::default(),
        healthy: None,
        last_health_check_at: None,
        manual_override_until: None,
        config_version: None,
        secrets_epoch: None,
        entered_running_at: None,
        entered_warm_at: None,
        last_busy_at: None,
    };

    save_instance(tenant_id, pool_id, &instance_id, &state)?;

    audit::log_event(
        tenant_id,
        Some(pool_id),
        Some(&instance_id),
        audit::AuditAction::InstanceCreated,
        None,
    )?;

    Ok(instance_id)
}

/// Start an instance (Ready/Stopped -> Running).
///
/// Flow:
/// 1. Load instance + pool + tenant state
/// 2. Validate state transition
/// 3. Check tenant quota
/// 4. Ensure tenant bridge is up
/// 5. Set up TAP device
/// 6. Create cgroup
/// 7. Prepare disks (data + secrets)
/// 8. Generate FC config from pool artifacts + instance net
/// 9. Launch Firecracker
/// 10. Record PID, update status to Running
#[instrument(skip_all, fields(tenant_id, pool_id, instance_id))]
pub fn instance_start(tenant_id: &str, pool_id: &str, instance_id: &str) -> Result<()> {
    let mut state = load_instance(tenant_id, pool_id, instance_id)?;
    let spec = pool_load(tenant_id, pool_id)?;
    let tenant = tenant_load(tenant_id)?;

    // For Ready -> Running, first transition Created -> Ready if artifacts exist
    if state.status == InstanceStatus::Created {
        // Check if pool has been built (current artifacts symlink exists)
        let arts_dir = pool_artifacts_dir(tenant_id, pool_id);
        let has_artifacts = shell::run_in_vm_stdout(&format!(
            "test -L {}/current && echo yes || echo no",
            arts_dir
        ))?;
        if has_artifacts.trim() == "yes" {
            // Read current revision hash
            let rev = shell::run_in_vm_stdout(&format!(
                "readlink {}/current | xargs basename",
                arts_dir
            ))?;
            state.revision_hash = Some(rev.trim().to_string());
            state.status = InstanceStatus::Ready;
            save_instance(tenant_id, pool_id, instance_id, &state)?;
        } else {
            anyhow::bail!(
                "Pool {}/{} has not been built yet. Run 'mvm pool build {}/{}'",
                tenant_id,
                pool_id,
                tenant_id,
                pool_id
            );
        }
    }

    validate_transition(state.status, InstanceStatus::Running)?;

    // Check tenant quotas
    let usage = quota::compute_tenant_usage(tenant_id)?;
    quota::check_quota(
        &tenant.quotas,
        &usage,
        spec.instance_resources.vcpus as u32,
        spec.instance_resources.mem_mib as u64,
    )?;

    // Ensure tenant bridge
    bridge::ensure_tenant_bridge(&tenant.net)?;

    // Set up TAP device
    net::setup_tap(&state.net, &tenant.net.bridge_name)?;

    // Create cgroup (Phase 7 will add real limits, currently a no-op)
    cgroups::create_instance_cgroup(
        tenant_id,
        instance_id,
        spec.instance_resources.vcpus,
        spec.instance_resources.mem_mib,
    )?;

    let inst_dir = instance_dir(tenant_id, pool_id, instance_id);
    let arts_dir = pool_artifacts_dir(tenant_id, pool_id);

    // Resolve current artifact paths
    let kernel_path = format!("{}/current/vmlinux", arts_dir);
    let rootfs_path = format!("{}/current/rootfs.ext4", arts_dir);

    // Prepare disks (with optional LUKS encryption for data volumes)
    let data_disk_path = if spec.instance_resources.data_disk_mib > 0 {
        let raw_path = disk::ensure_data_disk(&inst_dir, spec.instance_resources.data_disk_mib)?;

        // LUKS encryption: if tenant has a key, encrypt the data volume
        if keystore::has_key(tenant_id) {
            let provider = keystore::default_provider();
            let key = provider.get_data_key(tenant_id)?;
            let mapper_name = encryption::luks_mapper_name(tenant_id, instance_id);

            if !encryption::is_luks_volume(&raw_path)? {
                encryption::create_encrypted_volume(
                    &raw_path,
                    spec.instance_resources.data_disk_mib,
                    &key,
                )?;
            }
            let mapper_path = encryption::open_encrypted_volume(&raw_path, &mapper_name, &key)?;

            // Format the mapper device if new
            if let Err(e) = shell::run_in_vm(&format!(
                "if ! blkid {} >/dev/null 2>&1; then mkfs.ext4 -q {}; fi",
                mapper_path, mapper_path
            )) {
                warn!("failed to format encrypted volume: {e}");
            }
            Some(mapper_path)
        } else {
            Some(raw_path)
        }
    } else {
        None
    };

    let secrets_path = tenant_secrets_path(tenant_id);
    let secrets_disk_path = disk::create_secrets_disk(&inst_dir, &secrets_path, &[])?;

    // Create config drive with instance/pool metadata
    let config_meta = serde_json::json!({
        "instance_id": instance_id,
        "pool_id": pool_id,
        "tenant_id": tenant_id,
        "guest_ip": state.net.guest_ip,
        "vcpus": spec.instance_resources.vcpus,
        "mem_mib": spec.instance_resources.mem_mib,
        "min_runtime_policy": spec.runtime_policy,
    });
    let config_disk_path = disk::create_config_disk(&inst_dir, &config_meta.to_string(), &[])?;

    let vsock_path = format!("{}/runtime/v.sock", inst_dir);

    // Generate FC config
    let fc_json = fc_config::generate(
        &spec.instance_resources,
        &state.net,
        &kernel_path,
        &rootfs_path,
        Some(&config_disk_path),
        data_disk_path.as_deref(),
        Some(&secrets_disk_path),
        Some(&vsock_path),
    )?;

    let runtime_dir = format!("{}/runtime", inst_dir);
    let config_path = format!("{}/fc.json", runtime_dir);
    let socket_path = format!("{}/firecracker.socket", runtime_dir);
    let log_path = format!("{}/firecracker.log", runtime_dir);
    let pid_path = format!("{}/fc.pid", runtime_dir);

    // Write FC config
    shell::run_in_vm(&format!(
        "cat > {} << 'MVMEOF'\n{}\nMVMEOF",
        config_path, fc_json
    ))?;

    // Ensure strict seccomp profile if configured
    if spec.seccomp_policy == "strict" {
        seccomp::ensure_strict_profile()?;
    }
    let seccomp_filter = seccomp::seccomp_filter_path(&spec.seccomp_policy);

    // In production mode, refuse to start without jailer
    if is_production_mode() && !jailer::jailer_available().unwrap_or(false) {
        anyhow::bail!(
            "Production mode (MVM_PRODUCTION=1) requires jailer. \
             Install jailer or unset MVM_PRODUCTION for dev mode."
        );
    }

    // Launch Firecracker via jailer (with chroot) or directly
    let pid = if jailer::jailer_available().unwrap_or(false) {
        let ip_offset = jailer::ip_offset_from_guest_ip(&state.net.guest_ip);
        let (pid, _jail_socket) = jailer::launch_jailed(
            &inst_dir,
            instance_id,
            tenant.net.tenant_net_id,
            ip_offset,
            &kernel_path,
            &rootfs_path,
            Some(&config_path),
            data_disk_path.as_deref(),
            Some(&secrets_disk_path),
            seccomp_filter.as_deref(),
            &log_path,
            &pid_path,
        )?;
        pid
    } else {
        jailer::launch_direct(
            Some(&config_path),
            &socket_path,
            &log_path,
            &pid_path,
            seccomp_filter.as_deref(),
        )?
    };

    // Set up metadata endpoint if configured
    if spec.metadata_enabled {
        if let Err(e) = metadata::setup_metadata_endpoint(
            tenant_id,
            &tenant.net.bridge_name,
            &tenant.net.gateway_ip,
        ) {
            warn!("failed to set up metadata endpoint: {e}");
        }
    }

    // Update state
    let now = time::utc_now();
    state.status = InstanceStatus::Running;
    state.firecracker_pid = Some(pid);
    state.last_started_at = Some(now.clone());
    state.entered_running_at = Some(now);
    state.entered_warm_at = None;
    save_instance(tenant_id, pool_id, instance_id, &state)?;

    audit::log_event(
        tenant_id,
        Some(pool_id),
        Some(instance_id),
        audit::AuditAction::InstanceStarted,
        Some(&format!("pid={}", pid)),
    )?;

    Ok(())
}

/// Stop an instance (Running/Warm/Sleeping -> Stopped).
///
/// Kills the Firecracker process, cleans up cgroup, updates state.
/// TAP device is preserved for potential restart.
#[instrument(skip_all, fields(tenant_id, pool_id, instance_id))]
pub fn instance_stop(tenant_id: &str, pool_id: &str, instance_id: &str) -> Result<()> {
    let mut state = load_instance(tenant_id, pool_id, instance_id)?;
    validate_transition(state.status, InstanceStatus::Stopped)?;

    // Kill Firecracker if running
    if let Some(pid) = state.firecracker_pid {
        if let Err(e) = shell::run_in_vm(&format!(
            "kill {} 2>/dev/null || true; sleep 1; kill -9 {} 2>/dev/null || true",
            pid, pid
        )) {
            warn!("failed to kill firecracker process: {e}");
        }
    }

    // Close LUKS volume if open
    let mapper_name = encryption::luks_mapper_name(tenant_id, instance_id);
    if let Err(e) = encryption::close_encrypted_volume(&mapper_name) {
        warn!("failed to close LUKS volume: {e}");
    }

    // Kill remaining cgroup processes and clean up cgroup
    if let Err(e) = cgroups::kill_cgroup_processes(tenant_id, instance_id) {
        warn!("failed to kill cgroup processes: {e}");
    }
    cgroups::remove_instance_cgroup(tenant_id, instance_id)?;

    // Tear down TAP device
    net::teardown_tap(&state.net.tap_dev)?;

    // Clean up runtime files (socket, pid, log) and ephemeral disks (secrets, config)
    let inst_dir = instance_dir(tenant_id, pool_id, instance_id);
    if let Err(e) = shell::run_in_vm(&format!(
        "rm -f {dir}/runtime/firecracker.socket {dir}/runtime/fc.pid \
         {dir}/runtime/v.sock {dir}/volumes/secrets.ext4 {dir}/volumes/config.ext4",
        dir = inst_dir
    )) {
        warn!("failed to clean up runtime files: {e}");
    }

    state.status = InstanceStatus::Stopped;
    state.firecracker_pid = None;
    state.last_stopped_at = Some(time::utc_now());
    state.entered_running_at = None;
    state.entered_warm_at = None;
    save_instance(tenant_id, pool_id, instance_id, &state)?;

    audit::log_event(
        tenant_id,
        Some(pool_id),
        Some(instance_id),
        audit::AuditAction::InstanceStopped,
        None,
    )?;

    Ok(())
}

/// Pause vCPUs (Running -> Warm).
#[instrument(skip_all, fields(tenant_id, pool_id, instance_id))]
pub fn instance_warm(tenant_id: &str, pool_id: &str, instance_id: &str) -> Result<()> {
    let mut state = load_instance(tenant_id, pool_id, instance_id)?;
    validate_transition(state.status, InstanceStatus::Warm)?;

    // Pause vCPUs via Firecracker API
    let inst_dir = instance_dir(tenant_id, pool_id, instance_id);
    let socket_path = format!("{}/runtime/firecracker.socket", inst_dir);

    shell::run_in_vm(&format!(
        r#"curl -s --unix-socket {socket} -X PATCH \
            -H 'Content-Type: application/json' \
            -d '{{"state": "Paused"}}' \
            'http://localhost/vm'"#,
        socket = socket_path,
    ))?;

    state.status = InstanceStatus::Warm;
    state.entered_warm_at = Some(time::utc_now());
    save_instance(tenant_id, pool_id, instance_id, &state)?;

    audit::log_event(
        tenant_id,
        Some(pool_id),
        Some(instance_id),
        audit::AuditAction::InstanceWarmed,
        None,
    )?;

    Ok(())
}

/// Snapshot and shutdown (Warm -> Sleeping).
///
/// Flow:
/// 1. Validate Warm -> Sleeping transition
/// 2. Signal guest sleep-prep (if not --force)
/// 3. Create delta snapshot (instance-level) via FC API
/// 4. Compress if pool configured for compression
/// 5. Kill FC process, cleanup cgroup
/// 6. Keep TAP device and data disk for wake
/// 7. Update status to Sleeping
#[instrument(skip_all, fields(tenant_id, pool_id, instance_id, force))]
pub fn instance_sleep(
    tenant_id: &str,
    pool_id: &str,
    instance_id: &str,
    force: bool,
) -> Result<()> {
    let mut state = load_instance(tenant_id, pool_id, instance_id)?;
    let spec = pool_load(tenant_id, pool_id)?;
    validate_transition(state.status, InstanceStatus::Sleeping)?;

    let inst_dir = instance_dir(tenant_id, pool_id, instance_id);

    // If not forced, try to signal guest sleep-prep via vsock and wait for ACK
    if !force {
        let drain_timeout = spec.runtime_policy.drain_timeout_seconds;
        match mvm_guest::vsock::request_sleep_prep(&inst_dir, drain_timeout) {
            Ok(true) => {
                // Guest ACKed: OpenClaw idle, data flushed
            }
            Ok(false) => {
                // Drain timeout exceeded — log and force
                if let Err(e) = audit::log_event(
                    tenant_id,
                    Some(pool_id),
                    Some(instance_id),
                    audit::AuditAction::MinRuntimeOverridden,
                    Some("drain_timeout exceeded, forcing sleep"),
                ) {
                    warn!("failed to log drain timeout audit event: {e}");
                }
            }
            Err(_) => {
                // Vsock not available (e.g. guest agent not running) — best-effort
            }
        }
    }

    // Ensure instance is paused (may already be Warm=Paused)
    // The state machine requires Warm -> Sleeping, so vCPUs are already paused

    // Create delta snapshot
    snapshot::create_delta_snapshot(&inst_dir, &spec.snapshot_compression)?;

    // Kill Firecracker process with graceful shutdown timeout
    let graceful = spec.runtime_policy.graceful_shutdown_seconds;
    if let Some(pid) = state.firecracker_pid {
        if let Err(e) = shell::run_in_vm(&format!(
            "kill {pid} 2>/dev/null || true; \
             for i in $(seq 1 {graceful}); do kill -0 {pid} 2>/dev/null || break; sleep 1; done; \
             kill -9 {pid} 2>/dev/null || true",
        )) {
            warn!("failed to kill firecracker process during sleep: {e}");
        }
    }

    // Cleanup cgroup
    cgroups::remove_instance_cgroup(tenant_id, instance_id)?;

    // Clean up runtime files but keep socket path info
    if let Err(e) = shell::run_in_vm(&format!(
        "rm -f {dir}/runtime/firecracker.socket {dir}/runtime/fc.pid {dir}/runtime/v.sock",
        dir = inst_dir
    )) {
        warn!("failed to clean up runtime files during sleep: {e}");
    }

    // TAP device is intentionally kept for wake

    state.status = InstanceStatus::Sleeping;
    state.firecracker_pid = None;
    state.last_stopped_at = Some(time::utc_now());
    state.entered_running_at = None;
    state.entered_warm_at = None;
    save_instance(tenant_id, pool_id, instance_id, &state)?;

    audit::log_event(
        tenant_id,
        Some(pool_id),
        Some(instance_id),
        audit::AuditAction::InstanceSlept,
        Some(&format!("compression={}", spec.snapshot_compression)),
    )?;

    Ok(())
}

/// Restore from snapshot (Sleeping -> Running).
///
/// Flow:
/// 1. Validate Sleeping -> Running transition
/// 2. Check tenant quota
/// 3. Ensure tenant bridge + TAP device
/// 4. Create fresh secrets disk
/// 5. Launch new Firecracker process
/// 6. Load snapshot (base + delta) via FC API
/// 7. Resume vCPUs
/// 8. Update status to Running
#[instrument(skip_all, fields(tenant_id, pool_id, instance_id))]
pub fn instance_wake(tenant_id: &str, pool_id: &str, instance_id: &str) -> Result<()> {
    let mut state = load_instance(tenant_id, pool_id, instance_id)?;
    let spec = pool_load(tenant_id, pool_id)?;
    let tenant = tenant_load(tenant_id)?;
    validate_transition(state.status, InstanceStatus::Running)?;

    // Check tenant quotas
    let usage = quota::compute_tenant_usage(tenant_id)?;
    quota::check_quota(
        &tenant.quotas,
        &usage,
        spec.instance_resources.vcpus as u32,
        spec.instance_resources.mem_mib as u64,
    )?;

    // Ensure bridge and TAP
    bridge::ensure_tenant_bridge(&tenant.net)?;
    net::setup_tap(&state.net, &tenant.net.bridge_name)?;

    // Create cgroup
    cgroups::create_instance_cgroup(
        tenant_id,
        instance_id,
        spec.instance_resources.vcpus,
        spec.instance_resources.mem_mib,
    )?;

    // Create fresh secrets disk and config drive
    let inst_dir = instance_dir(tenant_id, pool_id, instance_id);
    let secrets_path = tenant_secrets_path(tenant_id);
    let _ = disk::create_secrets_disk(&inst_dir, &secrets_path, &[])?;

    let config_meta = serde_json::json!({
        "instance_id": instance_id,
        "pool_id": pool_id,
        "tenant_id": tenant_id,
        "guest_ip": state.net.guest_ip,
        "vcpus": spec.instance_resources.vcpus,
        "mem_mib": spec.instance_resources.mem_mib,
        "min_runtime_policy": spec.runtime_policy,
    });
    let _ = disk::create_config_disk(&inst_dir, &config_meta.to_string(), &[])?;

    let runtime_dir = format!("{}/runtime", inst_dir);
    let socket_path = format!("{}/firecracker.socket", runtime_dir);
    let log_path = format!("{}/firecracker.log", runtime_dir);
    let pid_path = format!("{}/fc.pid", runtime_dir);

    // Launch Firecracker in snapshot-load mode (no --config-file, we load via API)
    let pid = jailer::launch_direct(
        None,
        &socket_path,
        &log_path,
        &pid_path,
        None, // no seccomp for snapshot restore
    )?;

    // Restore from snapshot (this also resumes vCPUs)
    let restored = snapshot::restore_snapshot(tenant_id, pool_id, &inst_dir, &socket_path)?;

    if !restored {
        // No snapshot available, kill the empty FC and bail
        if let Err(e) = shell::run_in_vm(&format!("kill -9 {} 2>/dev/null || true", pid)) {
            warn!("failed to kill empty firecracker process: {e}");
        }
        anyhow::bail!(
            "No snapshot available for {}/{}/{}. Use 'instance start' for a fresh boot.",
            tenant_id,
            pool_id,
            instance_id
        );
    }

    // Signal guest wake via vsock (best-effort: guest reinitializes connections and refreshes secrets)
    if let Err(e) = mvm_guest::vsock::signal_wake(&inst_dir) {
        warn!("failed to signal guest wake via vsock: {e}");
    }

    // Update state
    let now = time::utc_now();
    state.status = InstanceStatus::Running;
    state.firecracker_pid = Some(pid);
    state.last_started_at = Some(now.clone());
    state.entered_running_at = Some(now);
    state.entered_warm_at = None;
    save_instance(tenant_id, pool_id, instance_id, &state)?;

    audit::log_event(
        tenant_id,
        Some(pool_id),
        Some(instance_id),
        audit::AuditAction::InstanceWoken,
        Some(&format!("pid={}", pid)),
    )?;

    Ok(())
}

/// SSH into a running instance.
///
/// Uses process replacement for clean TTY pass-through.
pub fn instance_ssh(tenant_id: &str, pool_id: &str, instance_id: &str) -> Result<()> {
    let state = load_instance(tenant_id, pool_id, instance_id)?;

    if state.status != InstanceStatus::Running {
        anyhow::bail!(
            "Instance {}/{}/{} is not running (status: {})",
            tenant_id,
            pool_id,
            instance_id,
            state.status
        );
    }

    let ssh_key = tenant_ssh_key_path(tenant_id);
    let guest_ip = &state.net.guest_ip;

    // Use process replacement for clean TTY pass-through
    // The SSH command runs inside the Lima VM
    shell::replace_process(
        "limactl",
        &[
            "shell",
            crate::config::VM_NAME,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            &ssh_key,
            &format!("root@{}", guest_ip),
        ],
    )
}

/// Destroy an instance and optionally wipe volumes.
///
/// Stops the instance if running, tears down TAP, removes cgroup,
/// then removes the instance directory.
#[instrument(skip_all, fields(tenant_id, pool_id, instance_id, wipe_volumes))]
pub fn instance_destroy(
    tenant_id: &str,
    pool_id: &str,
    instance_id: &str,
    wipe_volumes: bool,
) -> Result<()> {
    let state = load_instance(tenant_id, pool_id, instance_id)?;

    // Stop first if running/warm
    if matches!(state.status, InstanceStatus::Running | InstanceStatus::Warm) {
        instance_stop(tenant_id, pool_id, instance_id)?;
    } else if let Some(pid) = state.firecracker_pid {
        // Kill stale process
        if let Err(e) = shell::run_in_vm(&format!("kill -9 {} 2>/dev/null || true", pid)) {
            warn!("failed to kill stale firecracker process: {e}");
        }
    }

    // Close LUKS volume and wipe header if destroying
    let mapper_name = encryption::luks_mapper_name(tenant_id, instance_id);
    if let Err(e) = encryption::close_encrypted_volume(&mapper_name) {
        warn!("failed to close LUKS volume during destroy: {e}");
    }

    // Tear down TAP if still present
    if let Err(e) = net::teardown_tap(&state.net.tap_dev) {
        warn!("failed to tear down TAP device during destroy: {e}");
    }

    // Remove cgroup
    cgroups::remove_instance_cgroup(tenant_id, instance_id)?;

    // Remove instance directory
    let inst_dir = instance_dir(tenant_id, pool_id, instance_id);
    if wipe_volumes {
        shell::run_in_vm(&format!("rm -rf {}", inst_dir))?;
    } else {
        // Keep volumes, remove everything else
        shell::run_in_vm(&format!(
            "rm -rf {dir}/runtime {dir}/snapshots {dir}/instance.json {dir}/jail",
            dir = inst_dir
        ))?;
    }

    audit::log_event(
        tenant_id,
        Some(pool_id),
        Some(instance_id),
        audit::AuditAction::InstanceDestroyed,
        None,
    )?;

    Ok(())
}

/// List all instance states for a given tenant/pool combination.
pub fn instance_list(tenant_id: &str, pool_id: &str) -> Result<Vec<InstanceState>> {
    let instances_dir = pool_instances_dir(tenant_id, pool_id);
    let output = shell::run_in_vm_stdout(&format!("ls -1 {} 2>/dev/null || true", instances_dir))?;

    let mut states = Vec::new();
    for id in output.lines().filter(|l| !l.is_empty()) {
        if let Ok(state) = load_instance(tenant_id, pool_id, id) {
            states.push(state);
        }
    }
    Ok(states)
}

/// Check if a Firecracker PID is still alive.
pub fn is_pid_alive(pid: u32) -> Result<bool> {
    let out = shell::run_in_vm_stdout(&format!(
        "kill -0 {} 2>/dev/null && echo yes || echo no",
        pid
    ))?;
    Ok(out.trim() == "yes")
}

/// Read Firecracker logs for an instance.
pub fn instance_logs(tenant_id: &str, pool_id: &str, instance_id: &str) -> Result<String> {
    let inst_dir = instance_dir(tenant_id, pool_id, instance_id);
    let log_path = format!("{}/runtime/firecracker.log", inst_dir);
    shell::run_in_vm_stdout(&format!(
        "cat {} 2>/dev/null || echo 'No logs found.'",
        log_path
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_dir_path() {
        assert_eq!(
            instance_dir("acme", "workers", "i-a3f7b2c1"),
            "/var/lib/mvm/tenants/acme/pools/workers/instances/i-a3f7b2c1"
        );
    }

    #[test]
    fn test_instance_state_path() {
        assert_eq!(
            instance_state_path("acme", "workers", "i-a3f7b2c1"),
            "/var/lib/mvm/tenants/acme/pools/workers/instances/i-a3f7b2c1/instance.json"
        );
    }

    #[test]
    fn test_instance_create_with_mock() {
        use crate::shell_mock;

        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let pool_json = shell_mock::pool_fixture("acme", "workers");
        let (_guard, fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .with_file(
                "/var/lib/mvm/tenants/acme/pools/workers/pool.json",
                &pool_json,
            )
            .install();

        let instance_id = instance_create("acme", "workers").unwrap();
        assert!(instance_id.starts_with("i-"));

        // Verify instance.json was written to mock fs
        let state_path = instance_state_path("acme", "workers", &instance_id);
        let fs_lock = fs.lock().unwrap();
        assert!(fs_lock.contains_key(&state_path));

        // Parse the written state and verify
        let state: InstanceState = serde_json::from_str(&fs_lock[&state_path]).unwrap();
        assert_eq!(state.instance_id, instance_id);
        assert_eq!(state.tenant_id, "acme");
        assert_eq!(state.pool_id, "workers");
        assert_eq!(state.status, InstanceStatus::Created);
        assert!(state.net.guest_ip.starts_with("10.240.3."));
        assert_eq!(state.net.cidr, 24);
    }

    #[test]
    fn test_instance_create_and_list() {
        use crate::shell_mock;

        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let pool_json = shell_mock::pool_fixture("acme", "workers");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .with_file(
                "/var/lib/mvm/tenants/acme/pools/workers/pool.json",
                &pool_json,
            )
            .install();

        let id1 = instance_create("acme", "workers").unwrap();
        let id2 = instance_create("acme", "workers").unwrap();
        assert_ne!(id1, id2);

        let instances = instance_list("acme", "workers").unwrap();
        assert_eq!(instances.len(), 2);
    }

    #[test]
    fn test_instance_create_assigns_unique_ips() {
        use crate::shell_mock;

        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let pool_json = shell_mock::pool_fixture("acme", "workers");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .with_file(
                "/var/lib/mvm/tenants/acme/pools/workers/pool.json",
                &pool_json,
            )
            .install();

        let id1 = instance_create("acme", "workers").unwrap();
        let id2 = instance_create("acme", "workers").unwrap();
        let id3 = instance_create("acme", "workers").unwrap();

        let instances = instance_list("acme", "workers").unwrap();
        let ips: Vec<&str> = instances.iter().map(|i| i.net.guest_ip.as_str()).collect();

        // All IPs should be unique
        let mut unique_ips = ips.clone();
        unique_ips.sort();
        unique_ips.dedup();
        assert_eq!(ips.len(), unique_ips.len());

        // All IPs should be in 10.240.3.x range, starting from .3
        for ip in &ips {
            assert!(ip.starts_with("10.240.3."));
            let offset: u8 = ip.rsplit('.').next().unwrap().parse().unwrap();
            assert!(offset >= 3);
        }

        // Verify distinct instance IDs
        let ids = vec![id1, id2, id3];
        let mut unique_ids = ids.clone();
        unique_ids.sort();
        unique_ids.dedup();
        assert_eq!(ids.len(), unique_ids.len());
    }

}
