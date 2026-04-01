use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use mvm_core::agent::{DesiredPool, DesiredState, DesiredTenant, DesiredTenantNetwork};
use mvm_core::pool::{DesiredCounts, InstanceResources, Role};
use mvm_core::tenant::TenantQuota;
use mvm_runtime::security::certs;

use crate::ui;

const DEV_CLUSTER_DIR: &str = ".mvm/dev-cluster";
const DESIRED_FILE: &str = "desired.json";
const COORD_FILE: &str = "coordinator.toml";
const AGENT_PID: &str = "agent.pid";
const COORD_PID: &str = "coordinator.pid";
const AGENT_LOG: &str = "agent.log";
const COORD_LOG: &str = "coordinator.log";

struct Paths {
    base: PathBuf,
    desired: PathBuf,
    coord: PathBuf,
    agent_pid: PathBuf,
    coord_pid: PathBuf,
    agent_log: PathBuf,
    coord_log: PathBuf,
}

fn paths() -> Result<Paths> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let base = Path::new(&home).join(DEV_CLUSTER_DIR);
    Ok(Paths {
        base: base.clone(),
        desired: base.join(DESIRED_FILE),
        coord: base.join(COORD_FILE),
        agent_pid: base.join(AGENT_PID),
        coord_pid: base.join(COORD_PID),
        agent_log: base.join(AGENT_LOG),
        coord_log: base.join(COORD_LOG),
    })
}

/// Create dev cluster configs and self-signed certs.
pub fn init() -> Result<()> {
    let p = paths()?;
    fs::create_dir_all(&p.base)?;

    // Self-signed certs for local QUIC.
    certs::generate_self_signed("dev-node")
        .with_context(|| "Failed to generate dev TLS certificates (Lima VM must be running)")?;

    // Desired state: dev tenant with gateway + worker pools.
    let desired = default_desired_state();
    let json = serde_json::to_string_pretty(&desired)?;
    write_file(&p.desired, &json)?;

    // Coordinator config: single node, localhost routes.
    let coord_toml = default_coordinator_toml();
    write_file(&p.coord, &coord_toml)?;

    ui::success(&format!("Dev cluster initialized at {}", p.base.display()));
    Ok(())
}

/// Start agent + coordinator in the background.
pub fn up() -> Result<()> {
    let p = paths()?;
    if !p.desired.exists() || !p.coord.exists() {
        init()?; // ensure configs exist
    }

    // Agent
    if !is_running(&p.agent_pid) {
        let exe = std::env::current_exe()
            .with_context(|| "Failed to locate current executable for agent spawn")?;
        let mut cmd = Command::new(exe);
        cmd.args([
            "agent",
            "serve",
            "--interval-secs",
            "15",
            "--desired",
            p.desired
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid desired path"))?,
            "--listen",
            "127.0.0.1:4433",
        ]);
        spawn_background(cmd, &p.agent_pid, &p.agent_log)
            .with_context(|| "Failed to start agent")?;
        ui::info("Agent started (dev cluster)");
    } else {
        ui::info("Agent already running");
    }

    // Coordinator
    if !is_running(&p.coord_pid) {
        let exe = std::env::current_exe()
            .with_context(|| "Failed to locate current executable for coordinator spawn")?;
        let mut cmd = Command::new(exe);
        cmd.args(["coordinator", "serve", "--config"]).arg(&p.coord);
        spawn_background(cmd, &p.coord_pid, &p.coord_log)
            .with_context(|| "Failed to start coordinator")?;
        ui::info("Coordinator started (dev cluster)");
    } else {
        ui::info("Coordinator already running");
    }

    ui::success("Dev cluster up");
    Ok(())
}

/// Show status for agent + coordinator.
pub fn status() -> Result<()> {
    let p = paths()?;
    let agent = describe_status("agent", &p.agent_pid)?;
    let coord = describe_status("coordinator", &p.coord_pid)?;

    ui::status_line("Agent", &agent);
    ui::status_line("Coordinator", &coord);

    Ok(())
}

/// Stop agent + coordinator.
pub fn down() -> Result<()> {
    let p = paths()?;
    let mut stopped = false;

    if stop_pid(&p.agent_pid)? {
        ui::info("Agent stopped");
        stopped = true;
    }
    if stop_pid(&p.coord_pid)? {
        ui::info("Coordinator stopped");
        stopped = true;
    }

    if stopped {
        ui::success("Dev cluster down");
    } else {
        ui::info("Dev cluster was not running");
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

fn write_file(path: &Path, content: &str) -> Result<()> {
    let mut f =
        File::create(path).with_context(|| format!("Failed to create {}", path.display()))?;
    f.write_all(content.as_bytes())
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn spawn_background(mut cmd: Command, pid_path: &Path, log_path: &Path) -> Result<()> {
    let log = File::create(log_path)
        .with_context(|| format!("Failed to open log {}", log_path.display()))?;
    let log_err = log.try_clone()?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));

    let child = cmd.spawn()?;
    let pid = child.id();
    write_file(pid_path, &pid.to_string())?;
    Ok(())
}

fn is_running(pid_path: &Path) -> bool {
    if let Ok(pid_str) = fs::read_to_string(pid_path)
        && let Ok(pid) = pid_str.trim().parse::<i32>()
    {
        let status = Command::new("kill").args(["-0", &pid.to_string()]).status();
        return status.map(|s| s.success()).unwrap_or(false);
    }
    false
}

fn describe_status(name: &str, pid_path: &Path) -> Result<String> {
    if !pid_path.exists() {
        return Ok("stopped".to_string());
    }
    if let Ok(pid_str) = fs::read_to_string(pid_path)
        && let Ok(pid) = pid_str.trim().parse::<i32>()
    {
        if is_running(pid_path) {
            return Ok(format!("running (pid {})", pid));
        } else {
            return Ok(format!("stopped (stale pid {})", pid));
        }
    }
    Ok(format!("{} status unknown", name))
}

fn stop_pid(pid_path: &Path) -> Result<bool> {
    if !pid_path.exists() {
        return Ok(false);
    }
    if let Ok(pid_str) = fs::read_to_string(pid_path)
        && let Ok(pid) = pid_str.trim().parse::<i32>()
    {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        fs::remove_file(pid_path).ok();
        return Ok(true);
    }
    Ok(false)
}

fn default_desired_state() -> DesiredState {
    DesiredState {
        schema_version: 1,
        node_id: "dev-node".to_string(),
        prune_unknown_tenants: false,
        prune_unknown_pools: false,
        sequence: 0,
        tenants: vec![DesiredTenant {
            tenant_id: "dev".to_string(),
            network: DesiredTenantNetwork {
                tenant_net_id: 100,
                ipv4_subnet: "10.240.100.0/24".to_string(),
            },
            quotas: TenantQuota {
                max_vcpus: 16,
                max_mem_mib: 32768,
                max_running: 8,
                max_warm: 4,
                max_pools: 4,
                max_instances_per_pool: 16,
                max_disk_gib: 200,
            },
            secrets_hash: None,
            pools: vec![
                DesiredPool {
                    pool_id: "gateways".to_string(),
                    flake_ref: ".".to_string(),
                    profile: "minimal".to_string(),
                    role: Role::Gateway,
                    instance_resources: InstanceResources {
                        vcpus: 2,
                        mem_mib: 1024,
                        data_disk_mib: 0,
                    },
                    desired_counts: DesiredCounts {
                        running: 1,
                        warm: 0,
                        sleeping: 0,
                    },
                    runtime_policy: Default::default(),
                    seccomp_policy: "baseline".to_string(),
                    snapshot_compression: "none".to_string(),
                    routing_table: None,
                    secret_scopes: vec![],
                },
                DesiredPool {
                    pool_id: "workers".to_string(),
                    flake_ref: ".".to_string(),
                    profile: "minimal".to_string(),
                    role: Role::Worker,
                    instance_resources: InstanceResources {
                        vcpus: 2,
                        mem_mib: 2048,
                        data_disk_mib: 2048,
                    },
                    desired_counts: DesiredCounts {
                        running: 1,
                        warm: 0,
                        sleeping: 0,
                    },
                    runtime_policy: Default::default(),
                    seccomp_policy: "baseline".to_string(),
                    snapshot_compression: "none".to_string(),
                    routing_table: None,
                    secret_scopes: vec![],
                },
            ],
        }],
    }
}

fn default_coordinator_toml() -> String {
    r#"[coordinator]
idle_timeout_secs = 120
wake_timeout_secs = 5
health_interval_secs = 10
max_connections_per_tenant = 100

[[nodes]]
address = "127.0.0.1:4433"
name = "dev-node"

[[routes]]
tenant_id = "dev"
pool_id = "gateways"
listen = "127.0.0.1:8443"
node = "127.0.0.1:4433"
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desired_state_has_dev_tenant() {
        let ds = default_desired_state();
        assert_eq!(ds.tenants.len(), 1);
        let t = &ds.tenants[0];
        assert_eq!(t.tenant_id, "dev");
        assert_eq!(t.pools.len(), 2);
    }
}
