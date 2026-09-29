//! Per-VM telemetry-collector subprocess spawn/reap, mirroring
//! [`super::broker_services_spawn`].
//!
//! The collector is its own process for the same reason the broker services
//! are: one VM, one owner, alive for the VM's lifetime regardless of which
//! CLI started it, and a crash confined to one VM's collection. It is
//! provisioned by the workload runner before boot; its pid file is what
//! gates the guest-facing `mvm.telemetry=1` launch assertion, so a boot
//! with no collector asserts nothing and the guest starts no listener.

use std::path::Path;
use std::time::Duration;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use super::broker_services_spawn::{
    kill, pid_alive, read_pid, resolve_subprocess_bin, spawn_detached_with_config,
};

/// Collector pid file, in the VM state dir. Presence means "telemetry is
/// provisioned for this boot".
pub const TELEMETRY_COLLECTOR_PID_FILE: &str = "telemetry-collector.pid";
/// Where the collector keeps its coverage-status snapshot for readers.
pub const TELEMETRY_COLLECTOR_STATUS_FILE: &str = "telemetry-collector-status.json";
/// Where the collector appends received records, size-capped.
pub const TELEMETRY_RECORDS_FILE: &str = "telemetry-records.jsonl";
/// How long the spawner waits for the collector to report itself alive.
pub const TELEMETRY_COLLECTOR_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// The configuration the collector subprocess reads from stdin.
/// `deny_unknown_fields` so a config from a newer spawner fails closed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TelemetryCollectorProcessConfig {
    /// The VM this collector owns.
    pub vm_name: String,
    /// The VM's state dir: registration, signer socket, and output live here.
    pub state_dir: std::path::PathBuf,
    /// The per-VM host UDS the backend bridges to the guest telemetry port.
    pub telemetry_sock: std::path::PathBuf,
    /// The delegated signer's UDS (the audit-signer subprocess).
    pub signer_sock: std::path::PathBuf,
    /// The host-signer public key the receiver authenticates itself under.
    pub host_anchor_path: std::path::PathBuf,
    /// Byte cap for the records file; beyond it records are shed and counted.
    pub records_byte_cap: u64,
}

/// Everything the spawner supplies; the builder keeps call sites flat.
#[derive(Debug)]
pub struct TelemetryCollectorSpawnParams<'a> {
    vm_name: &'a str,
    state_dir: &'a Path,
    telemetry_sock: &'a Path,
    signer_sock: &'a Path,
}

impl<'a> TelemetryCollectorSpawnParams<'a> {
    pub fn builder() -> TelemetryCollectorSpawnParamsBuilder<'a> {
        TelemetryCollectorSpawnParamsBuilder::new()
    }
}

#[derive(Default)]
pub struct TelemetryCollectorSpawnParamsBuilder<'a> {
    vm_name: Option<&'a str>,
    state_dir: Option<&'a Path>,
    telemetry_sock: Option<&'a Path>,
    signer_sock: Option<&'a Path>,
}

impl<'a> TelemetryCollectorSpawnParamsBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vm_name(mut self, vm_name: &'a str) -> Self {
        self.vm_name = Some(vm_name);
        self
    }

    pub fn state_dir(mut self, state_dir: &'a Path) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    pub fn telemetry_sock(mut self, telemetry_sock: &'a Path) -> Self {
        self.telemetry_sock = Some(telemetry_sock);
        self
    }

    pub fn signer_sock(mut self, signer_sock: &'a Path) -> Self {
        self.signer_sock = Some(signer_sock);
        self
    }

    pub fn build(self) -> Result<TelemetryCollectorSpawnParams<'a>> {
        Ok(TelemetryCollectorSpawnParams {
            vm_name: self.vm_name.ok_or_else(|| anyhow!("vm_name is required"))?,
            state_dir: self
                .state_dir
                .ok_or_else(|| anyhow!("state_dir is required"))?,
            telemetry_sock: self
                .telemetry_sock
                .ok_or_else(|| anyhow!("telemetry_sock is required"))?,
            signer_sock: self
                .signer_sock
                .ok_or_else(|| anyhow!("signer_sock is required"))?,
        })
    }
}

/// Default byte cap for the records file. Deliberately modest: retention is
/// its own workstream, and this file exists so collection is observable, not
/// as a durable store.
pub const DEFAULT_RECORDS_BYTE_CAP: u64 = 8 * 1024 * 1024;

/// Spawn the per-VM telemetry collector and wait for it to report alive.
///
/// Readiness is the status file appearing: the collector writes its first
/// snapshot before dialing anything, so a spawner timeout means the process
/// did not come up, never that the guest is slow. On timeout the child is
/// killed and the error names it.
pub fn spawn_telemetry_collector(params: TelemetryCollectorSpawnParams<'_>) -> Result<()> {
    spawn_telemetry_collector_with_timeout(params, TELEMETRY_COLLECTOR_READY_TIMEOUT)
}

fn spawn_telemetry_collector_with_timeout(
    params: TelemetryCollectorSpawnParams<'_>,
    ready_timeout: Duration,
) -> Result<()> {
    let TelemetryCollectorSpawnParams {
        vm_name,
        state_dir,
        telemetry_sock,
        signer_sock,
    } = params;

    let bin = resolve_subprocess_bin("mvm-telemetry-collector", "MVM_TELEMETRY_COLLECTOR_PATH")?;
    let config = TelemetryCollectorProcessConfig {
        vm_name: vm_name.to_string(),
        state_dir: state_dir.to_path_buf(),
        telemetry_sock: telemetry_sock.to_path_buf(),
        signer_sock: signer_sock.to_path_buf(),
        host_anchor_path: mvm_core::config::mvm_keys_dir()
            .join(super::broker_services_spawn::HOST_SIGNER_PUB),
        records_byte_cap: DEFAULT_RECORDS_BYTE_CAP,
    };
    let cfg = serde_json::to_value(&config)?;
    let child = spawn_detached_with_config(&bin, &cfg, "mvm-telemetry-collector")?;

    let status_file = state_dir.join(TELEMETRY_COLLECTOR_STATUS_FILE);
    wait_for_file("mvm-telemetry-collector", &status_file, ready_timeout)?;

    let pid_file = state_dir.join(TELEMETRY_COLLECTOR_PID_FILE);
    std::fs::write(&pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    Ok(())
}

fn wait_for_file(what: &str, path: &Path, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(anyhow!(
        "{what} did not report alive at {} within {timeout:?}",
        path.display()
    ))
}

/// Stop the collector for a VM, best-effort, via its pid file. Removes the
/// pid file so the guest-facing launch assertion disappears with the
/// provisioning; a later boot re-provisions or does not.
pub fn reap_telemetry_collector(state_dir: &Path) {
    let pid_file = state_dir.join(TELEMETRY_COLLECTOR_PID_FILE);
    if let Some(pid) = read_pid(&pid_file)
        && pid_alive(pid)
    {
        kill(pid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(&pid_file);
}

/// Whether telemetry is provisioned for this VM's current boot.
pub fn telemetry_provisioned(state_dir: &Path) -> bool {
    state_dir.join(TELEMETRY_COLLECTOR_PID_FILE).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_process_config_round_trips_and_refuses_unknown_fields() {
        let config = TelemetryCollectorProcessConfig {
            vm_name: "vm-a".into(),
            state_dir: "/tmp/state".into(),
            telemetry_sock: "/tmp/state/telemetry.sock".into(),
            signer_sock: "/tmp/state/audit-signer.sock".into(),
            host_anchor_path: "/tmp/keys/host-signer.pub".into(),
            records_byte_cap: 1024,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: TelemetryCollectorProcessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["surprise"] = serde_json::json!(true);
        let refused: Result<TelemetryCollectorProcessConfig, _> = serde_json::from_value(value);
        assert!(refused.is_err(), "unknown fields must fail closed");
    }

    #[test]
    fn the_builder_names_each_missing_field() {
        let err = TelemetryCollectorSpawnParams::builder()
            .vm_name("vm-a")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("state_dir"));
    }

    #[test]
    fn provisioning_follows_the_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!telemetry_provisioned(dir.path()));
        std::fs::write(dir.path().join(TELEMETRY_COLLECTOR_PID_FILE), "1234").unwrap();
        assert!(telemetry_provisioned(dir.path()));
        reap_telemetry_collector(dir.path());
        assert!(!telemetry_provisioned(dir.path()));
    }

    #[test]
    fn a_spawn_that_never_reports_alive_fails_within_its_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let err = wait_for_file(
            "mvm-telemetry-collector",
            &dir.path().join(TELEMETRY_COLLECTOR_STATUS_FILE),
            Duration::from_millis(80),
        )
        .unwrap_err();
        assert!(err.to_string().contains("did not report alive"));
    }
}
