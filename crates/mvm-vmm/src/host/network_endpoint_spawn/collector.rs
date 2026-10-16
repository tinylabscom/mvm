//! The telemetry collector's half of endpoint provisioning: its config
//! section, the signer and records key it needs, and the collector-only
//! process a VM without an endpoint gets instead.

use std::path::Path;

use anyhow::{Result, anyhow};

use super::stderr_log::open_collector_stderr_log;
use super::{
    EndpointLifetime, kill, pid_alive, read_pid, resolve_network_endpoint_path, select_lifetime,
};

/// The collector's inputs for the VM at `state_dir`, without its records key.
/// The collector authenticates through the tenant's resident signer helper.
pub(super) fn telemetry_section(tenant: &str, state_dir: &Path) -> serde_json::Value {
    serde_json::json!({
        "state_dir": state_dir,
        "telemetry_sock": mvm_core::config::vm_hvf_vsock_port_socket_at(
            state_dir,
            mvm_core::protocol::telemetry::TELEMETRY_PORT,
        ),
        "signer_sock": mvm_core::config::host_agent_signer_helper_socket(tenant),
        "host_anchor_path": mvm_core::config::mvm_keys_dir()
            .join(crate::host::broker_services_spawn::HOST_SIGNER_PUB),
        "records_byte_cap": crate::host::telemetry_provisioning::DEFAULT_RECORDS_BYTE_CAP,
    })
}

/// Provision what the collector needs beyond its config: the tenant's
/// resident signer it authenticates through, and this VM's records key.
///
/// The signer helper belongs to the host-agent daemon; making sure the daemon
/// runs is idempotent and, once it is up, a socket probe. A daemon that cannot
/// start costs this VM its telemetry (the collector reports the failed
/// authentication), never its launch.
///
/// The endpoint is confined away from the host key directory, so it is handed
/// the records data key itself over its private stdin pipe. On disk the key
/// exists only wrapped.
pub(super) fn provision_collector(
    section: &mut serde_json::Value,
    tenant: &str,
    state_dir: &Path,
) -> Result<()> {
    use base64::Engine as _;
    if let Err(error) = crate::host::host_agent_spawn::ensure_host_agent_daemon(tenant) {
        tracing::warn!(
            tenant,
            error = format!("{error:#}"),
            "host-agent daemon unavailable; the telemetry collector cannot authenticate"
        );
    }
    let key = crate::host::telemetry_provisioning::provision_records_key(
        state_dir,
        &mvm_core::config::mvm_keys_dir(),
    )
    .map_err(|e| anyhow!("provisioning the telemetry records key: {e}"))?;
    section["records_key_b64"] =
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(key.expose_bytes()));
    Ok(())
}

/// Where the collector-only process's pid is recorded, beside the VM.
pub const TELEMETRY_COLLECTOR_PID_FILE: &str = "telemetry-collector.pid";

/// Start the VM-lifetime telemetry collector for a VM that has no network
/// endpoint to embed it in: the endpoint binary in collector-only mode, under
/// a keeper that ends it with the VM.
///
/// Never waits on the collector. It reports no handshake, the guest's
/// listener waits to be dialed, and the collector's status file says whether
/// it came up — so starting it costs a launch one process spawn and nothing
/// that scales with the guest.
pub fn spawn_telemetry_collector(
    vm_name: &str,
    tenant: &str,
    state_dir: &Path,
    redaction: &mvm_core::policy::RedactionPolicy,
) -> Result<()> {
    use std::io::Write;
    let mut telemetry = telemetry_section(tenant, state_dir);
    provision_collector(&mut telemetry, tenant, state_dir)?;
    let cfg = serde_json::json!({
        "telemetry_only": {
            "instance_id": vm_name,
            "redaction": serde_json::to_value(redaction)
                .expect("RedactionPolicy serializes to JSON"),
            "telemetry": telemetry,
        }
    });

    let bin = resolve_network_endpoint_path()?;
    let log_file = open_collector_stderr_log(state_dir)?;
    let mut cmd = mvm_core::env_hygiene::helper_command(&bin);
    select_lifetime(&mut cmd, EndpointLifetime::Vm, state_dir);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(log_file);
    // Detach into its own session so it survives this `mvmctl` process.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // SAFETY: post-fork, pre-exec; setsid has no preconditions.
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn telemetry collector ({}): {e}", bin.display()))?;
    let written = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("telemetry collector stdin was not piped"))
        .and_then(|mut stdin| {
            stdin
                .write_all(cfg.to_string().as_bytes())
                .map_err(|e| anyhow!("pipe the collector config: {e}"))
        });
    if let Err(error) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    std::fs::write(
        state_dir.join(TELEMETRY_COLLECTOR_PID_FILE),
        child.id().to_string(),
    )
    .map_err(|e| anyhow!("record the telemetry collector pid: {e}"))?;
    Ok(())
}

/// Stop a collector-only process this VM started, if one is running.
pub fn reap_telemetry_collector(state_dir: &Path) {
    let pid_file = state_dir.join(TELEMETRY_COLLECTOR_PID_FILE);
    if let Some(pid) = read_pid(&pid_file)
        && pid_alive(pid)
    {
        kill(pid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(pid_file);
}
